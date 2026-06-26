"""
The credential broker — Tex's authority plane.

The move this module makes is from gating the *route* (the PEP/proxy verifies a
permit on an egress connection) to gating the *credential* (the agent holds NO
standing keys; every action that needs a credential obtains a fresh, short-lived,
action-scoped one from Tex, bound to its attested identity). When downstream
resources are configured to trust ONLY Tex-issued credentials, this is what makes
"Tex controls the action regardless of where the agent runs" true: you gate the
secret, not the path.

Shape (standards verified live this session):
  * Token exchange — RFC 8693: ``exchange`` accepts a subject assertion and
    returns a Tex-minted, action-scoped credential (an STS).
  * Proof-of-possession — RFC 7800 ``cnf`` + RFC 9449 (DPoP): a minted credential
    can be *sender-constrained* to a key the holder controls, so a stolen token
    is useless without the private key. See ``tex.authority.pop``.

Reuse (no duplicate crypto):
  * Secret resolution + HMAC discipline from ``tex.enforcement.permit`` — the
    SAME fail-closed rule (production-like env with no secret => refuse to mint).
    The MAC is domain-separated (``texauth.v1`` prefix) so a credential MAC can
    never be confused with a permit MAC even under a shared signing key.
  * ``tex.memory.permit_store.PermitStore`` (duck-typed via ``RevocationStore``)
    for single-use (one-shot) and revocation.
  * ``tex.identity.agent_credential`` for identity, via the ``IdentitySource``
    seam (``tex.authority.identity_source``).

HONEST BOUNDARY — what this package does and does NOT close:
  * ENFORCED HERE: mint a fresh short-lived action+scope-bound credential bound to
    a verified identity and (optionally) to a holder PoP key; verify issuer,
    audience, action, scope, expiry, identity binding, PoP, and revocation/single
    use; RFC-8693-shaped exchange with exchange-time possession proof. Fail-closed
    with no secret. Never mints for an unverified identity.
  * NOT CLOSED (RUNTIME-DEPENDENT / deployment): making a third-party resource
    DEMAND a Tex credential (federation / a sole-token-custody egress proxy that
    pins ``iss`` and requires the PoP header), and the live Entra/SPIFFE identity
    wiring (a real ``IdentitySource`` impl). This package supplies mint + verify +
    exchange; it does NOT by itself give the actuator-demands-Tex-credential
    property. Do not imply otherwise.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID, uuid4

from tex.authority import pop
from tex.authority.identity_source import IdentitySource, SubjectVerification
from tex.enforcement import permit as _permit

# Reuse the audited canonical-JSON / b64url / HMAC primitives directly so the
# credential signature bytes are produced by the SAME code as the permit path
# (the repo's own permit tests already treat these as a stable internal surface).
from tex.enforcement.permit import _b64url_decode, _canonical, _sign
from tex.identity.agent_credential import AttestedIdentity

__all__ = [
    "authority_secret",
    "authority_ed25519_key",
    "RevocationStore",
    "MintedCredential",
    "CredentialCheck",
    "ExchangeResult",
    "CredentialBroker",
    "TgPccClaims",
    "tgpcc_enabled",
    "tgpcc_public_jwks",
    "verify_with_jwks",
]

_logger = logging.getLogger(__name__)

_CRED_VERSION = 1
_CRED_TYPE = "tex-cred"
_DEFAULT_ISSUER = "tex-authority"
# Domain-separation prefix folded into every credential MAC. A permit body and a
# credential body can therefore never cross-verify even under a shared key.
_AUTHORITY_DOMAIN = "texauth.v1"
# Distinct domain prefix for the Ed25519 (asymmetric) signing leg. An HMAC body
# and an Ed25519 body are signed over DIFFERENT strings, so a verifier that picks
# the wrong algorithm can never be confused into accepting the other leg's bytes
# (same rationale as the permit-vs-cred MAC separation above).
_AUTHORITY_ED25519_DOMAIN = "texauth.ed25519.v1"
_ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

# Signing-algorithm discriminators. The HMAC leg is the default and carries NO
# ``alg`` claim (so its canonical body is byte-for-byte unchanged from the
# pre-B2 token — the existing govern/mint tests depend on that exact byte
# shape). The Ed25519 leg sets ``alg: "EdDSA"`` INSIDE the signed claims, so the
# algorithm itself is integrity-protected and cannot be downgraded.
_ALG_HMAC = "hmac"
_ALG_ED25519 = "ed25519"
# The value written into the signed claims for the asymmetric leg (JOSE/RFC 8037
# name for Ed25519 — what the published JWKS advertises as ``alg``).
_CLAIM_ALG_ED25519 = "EdDSA"


# --------------------------------------------------------------------------- #
# Secret resolution (reuses permit's fail-closed rule; optional key separation) #
# --------------------------------------------------------------------------- #


def authority_secret() -> str | None:
    """The credential signing secret, or None when production requires one and
    none is set.

    Prefers a dedicated ``TEX_AUTHORITY_SIGNING_SECRET`` (key separation between
    the permit and authority planes); otherwise falls back to
    ``tex.enforcement.permit.permit_secret`` — which itself returns None in a
    production-like env with no secret, so the fail-closed posture is inherited
    exactly: no guessable default ever signs a real credential.
    """
    configured = os.environ.get("TEX_AUTHORITY_SIGNING_SECRET")
    if configured:
        return configured
    return _permit.permit_secret()


def _sign_cred(secret: str, body: str) -> str:
    return _sign(secret, f"{_AUTHORITY_DOMAIN}.{body}")


# --------------------------------------------------------------------------- #
# Ed25519 (asymmetric) signing leg — B2 parity plumbing, default-OFF.          #
#                                                                              #
# HONESTY: this is the DEPLOYED shape of an offline-verifiable, attenuable     #
# capability token (AIP / Biscuit / Vouchsafe). It is necessary, fail-closed,  #
# table-stakes plumbing — NOT a novel mechanism. Its only worth is carrying    #
# the credential across a trust boundary so a remote verifier can check Tex's  #
# signature from a PUBLIC key (a pinned JWKS) with NO shared secret and NO     #
# network call. The HMAC leg above remains the default; the Ed25519 leg only   #
# engages when explicitly selected AND a key is configured.                    #
# --------------------------------------------------------------------------- #


def tgpcc_enabled() -> bool:
    """True iff the TG-PCC / Ed25519 capability plane is switched on.

    Default-OFF: with ``TEX_TGPCC`` unset the asymmetric path is inert, no JWKS
    key is published, and the broker keeps signing HMAC — so default boot is
    byte-for-byte unchanged.
    """
    return os.environ.get("TEX_TGPCC", "").strip().lower() in {"1", "true", "yes", "on"}


def authority_ed25519_key() -> Any | None:
    """Resolve the Ed25519 PRIVATE signing key for the asymmetric leg, or None.

    Mirrors the fail-closed posture of :func:`authority_secret` /
    :func:`tex.enforcement.permit.permit_secret`, but yields an
    ``Ed25519PrivateKey`` (not an HMAC string):

      * ``TEX_TGPCC_ED25519_SK`` set  -> decode + use it (the configured key);
      * production-like env, unset     -> return None (FAIL CLOSED — no guessable
        or ephemeral key ever signs a real capability token in prod);
      * dev env, unset                 -> warn + a per-process ephemeral key (so
        local tests / loopback work).

    Encoding of ``TEX_TGPCC_ED25519_SK`` (pick ONE, documented here): a
    base64url-encoded raw 32-byte Ed25519 seed (``from_private_bytes``), OR a
    PEM-encoded PKCS#8 private key (``-----BEGIN PRIVATE KEY-----`` …). The raw
    seed form is tried first; PEM is the fallback. This is the only place the
    key material is read.

    Returns None when the TG-PCC plane is OFF, so the Ed25519 path stays inert
    by default regardless of any stray env value.
    """
    if not tgpcc_enabled():
        return None

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    configured = os.environ.get("TEX_TGPCC_ED25519_SK")
    if configured:
        value = configured.strip()
        # 1) raw 32-byte seed, base64url (no-pad) — the compact env form.
        try:
            seed = _b64url_decode(value)
            if len(seed) == 32:
                return Ed25519PrivateKey.from_private_bytes(seed)
        except Exception:  # noqa: BLE001 — fall through to PEM
            pass
        # 2) PEM PKCS#8 private key.
        try:
            from cryptography.hazmat.primitives import serialization

            key = serialization.load_pem_private_key(value.encode("utf-8"), password=None)
            if isinstance(key, Ed25519PrivateKey):
                return key
        except Exception:  # noqa: BLE001 — unusable key material
            pass
        # Configured but unparseable: fail closed rather than silently fall back
        # to an ephemeral key the caller did not intend.
        _logger.error(
            "TEX_TGPCC_ED25519_SK is set but not a usable Ed25519 key "
            "(expected b64url raw 32-byte seed or PKCS#8 PEM) — refusing to sign."
        )
        return None

    if _permit.is_production_like():
        return None  # fail closed: no ephemeral asymmetric key in prod
    _logger.warning(
        "TEX_TGPCC_ED25519_SK unset in a non-production env — using an ephemeral "
        "per-process Ed25519 key for the TG-PCC capability leg (loopback only)."
    )
    return Ed25519PrivateKey.generate()


def _sign_cred_ed25519(private_key: Any, body: str) -> str:
    """Ed25519-sign the credential body under the asymmetric domain separation.

    Signs the SAME b64url body string the HMAC leg covers, but under a DISTINCT
    domain prefix (``texauth.ed25519.v1``) so an HMAC body and an Ed25519 body
    can never cross-verify. Returns the b64url (no-pad) signature — the token
    keeps its ``body.sig`` shape, only the signature algorithm differs.
    """
    from tex.authority.pop import _b64url as _pop_b64url

    msg = f"{_AUTHORITY_ED25519_DOMAIN}.{body}".encode("ascii")
    return _pop_b64url(private_key.sign(msg))


def _verify_cred_ed25519(public_key: Any, body: str, sig_b64: str) -> bool:
    """Verify an Ed25519 credential signature. Never raises; False on any defect.

    ``cryptography`` raises ``InvalidSignature`` (an ``Exception`` subclass) on a
    bad signature; the broad catch maps every defect — bad signature, malformed
    b64, wrong key type — to a fail-closed False.
    """
    from tex.authority.pop import _b64url_decode as _pop_b64url_decode

    msg = f"{_AUTHORITY_ED25519_DOMAIN}.{body}".encode("ascii")
    try:
        public_key.verify(_pop_b64url_decode(sig_b64), msg)
        return True
    except Exception:  # noqa: BLE001 — InvalidSignature & any defect fail closed
        return False


def _use_binding(token: str) -> str:
    """PoP ``bind`` for RESOURCE USE — locks a proof to this exact credential
    token (the token already commits aud/act/scope, so binding to it covers
    them). Analogous to DPoP's ``ath`` access-token hash."""
    return "tex-pop-use:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def _exchange_binding(subject_jkt: str, audience: str, action: str) -> str:
    """PoP ``bind`` for TOKEN EXCHANGE — proves the presenter holds the cnf key
    for THIS exchange request before any credential is minted."""
    return f"tex-pop-exchange:{subject_jkt}:{audience}:{action}"


# --------------------------------------------------------------------------- #
# Store seam (duck-typed; PermitStore satisfies it without importing psycopg)  #
# --------------------------------------------------------------------------- #


class RevocationStore(Protocol):
    """The subset of ``tex.memory.permit_store.PermitStore`` the broker uses for
    single-use + revocation. Declared structurally so the broker need not import
    the concrete store (and its psycopg dependency) at module load."""

    def issue(
        self,
        *,
        decision_id: UUID,
        nonce: str,
        signature: str,
        expiry: datetime,
        metadata: dict[str, Any] | None = ...,
    ) -> Any: ...

    def get_by_nonce(self, nonce: str) -> Any | None: ...

    def consume(self, permit_id: UUID) -> Any: ...

    def revoke(self, permit_id: UUID, *, reason: str | None = ...) -> Any: ...


# --------------------------------------------------------------------------- #
# Result types                                                                 #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class MintedCredential:
    """A freshly minted, ready-to-present Tex credential."""

    token: str  # compact "body.sig" — what the agent presents to the resource
    jti: str  # one-time-use id (the store nonce)
    subject: str  # the attested agent identity the credential is bound to
    audience: str
    action: str
    scope: tuple[str, ...]
    binding: str  # "pop" (sender-constrained) | "bearer"
    cnf_jkt: str | None  # the bound PoP key thumbprint (pop binding only)
    expiry: datetime  # tz-aware UTC
    issuer: str
    claims: dict[str, Any]
    permit_id: UUID | None = None  # the PermitStore row, when a store is wired

    @property
    def token_type(self) -> str:
        """The OAuth ``token_type`` a resource expects (DPoP iff sender-constrained)."""
        return "DPoP" if self.binding == "pop" else "Bearer"


@dataclass(frozen=True, slots=True)
class CredentialCheck:
    """The verdict of verifying a credential. Never carries a secret."""

    ok: bool
    reason: str
    claims: dict[str, Any] | None = None
    binding: str | None = None


@dataclass(frozen=True, slots=True)
class ExchangeResult:
    """RFC-8693-shaped token-exchange response."""

    ok: bool
    reason: str
    credential: MintedCredential | None = None
    token_type: str | None = None  # "DPoP" | "Bearer"
    expires_in: int | None = None
    scope: list[str] = field(default_factory=list)
    issued_token_type: str | None = None

    @property
    def access_token(self) -> str | None:
        return self.credential.token if self.credential is not None else None


# --------------------------------------------------------------------------- #
# Broker                                                                       #
# --------------------------------------------------------------------------- #


ScopePolicy = Callable[[AttestedIdentity, set[str]], Iterable[str]]


class CredentialBroker:
    """Mint / verify / exchange short-lived, action-scoped, identity-bound creds.

    All cryptographic state is process-external: the signing secret resolves
    fail-closed via :func:`authority_secret`, single-use/revocation live in the
    injected ``store``, and the holder's PoP key is the holder's own. The broker
    keeps no standing per-agent secret.
    """

    def __init__(
        self,
        *,
        issuer: str = _DEFAULT_ISSUER,
        store: RevocationStore | None = None,
        identity_source: IdentitySource | None = None,
        allow_bearer: bool = False,
        require_exchange_pop: bool = True,
        scope_policy: ScopePolicy | None = None,
        allow_unrestricted_exchange: bool = False,
    ) -> None:
        self._issuer = issuer
        self._store = store
        self._identity_source = identity_source
        # When False (default) the broker refuses to mint a non-PoP (bearer)
        # credential — PoP-by-default, the strong posture. Opt in for resources
        # whose channel binding (mTLS) already constrains the bearer token.
        self._allow_bearer = allow_bearer
        self._require_exchange_pop = require_exchange_pop
        self._scope_policy = scope_policy
        # Exchange is fail-closed on scope: with no ``scope_policy`` the broker
        # REFUSES to grant the agent's requested scope (RFC 8693 says the AS
        # decides scope — it must not blindly echo the request, or any proven
        # identity could mint any scope for any audience). Set this True only for
        # dev / a channel already constrained by mTLS to echo requested scope.
        self._allow_unrestricted_exchange = allow_unrestricted_exchange

    # ---- mint ---------------------------------------------------------- #

    def mint(
        self,
        attested_identity: AttestedIdentity,
        *,
        audience: str,
        action: str,
        scope: Iterable[str],
        ttl: int,
        cnf_public_key: Any | None = None,
        decision_id: UUID | str | None = None,
        single_use: bool = False,
        now: float | None = None,
        sign_alg: str = _ALG_HMAC,
        epoch: int | None = None,
        intent_commit: str | None = None,
        prov_commit: dict[str, Any] | None = None,
    ) -> MintedCredential | None:
        """Mint a credential bound to a VERIFIED identity, scoped to one action.

        Returns None (fail-closed) when: the identity is not verified, no signing
        secret is available in a production-like env, or a bearer credential is
        requested (no ``cnf_public_key``) while the broker is PoP-only.

        ``cnf_public_key`` (an ``Ed25519PublicKey``, raw 32 bytes, or a b64 str)
        sender-constrains the credential (RFC 7800/9449): using it then requires a
        PoP proof from the matching private key.

        ``sign_alg`` selects how the credential body is SIGNED:

          * ``"hmac"`` (default) — the existing ``texauth.v1`` HMAC leg. The
            token is byte-for-byte identical to the pre-B2 shape (no ``alg``
            claim is written). This is what the govern/mint route uses, so its
            behavior and tests are unchanged.
          * ``"ed25519"`` — the B2 asymmetric leg. Sets ``alg: "EdDSA"`` inside
            the signed claims and signs with the resolved Ed25519 key so a remote
            verifier can check the signature offline from a published JWKS public
            key. If ``ed25519`` is requested but no key resolves, mint FAILS
            CLOSED (returns None) rather than silently downgrading to HMAC.

        ``intent_commit`` / ``prov_commit`` (TG-PCC B1+) UNIFY the credential body
        with the TG-PCC claim set: when present they are embedded INSIDE the signed
        claims (so both are signature-covered on the HMAC and Ed25519 legs alike)
        so an offline verifier can re-check the bound action intent and the
        ``label ⊒ floor`` integrity predicate from the signed bytes alone.
        Both default to None and are OMITTED when None (the conditional-write
        keeps the canonical body byte-for-byte identical to the pre-B1+ token), so
        the default mint path and all existing tests are unchanged.
        """
        if attested_identity is None or not getattr(attested_identity, "verified", False):
            return None  # NEVER mint for an unverified identity
        subject = getattr(attested_identity, "claimed_agent_id", None)
        if not subject:
            return None

        alg = (sign_alg or _ALG_HMAC).strip().lower()
        ed25519_key: Any | None = None
        secret: str | None = None
        if alg == _ALG_ED25519:
            ed25519_key = authority_ed25519_key()
            if ed25519_key is None:
                # Asymmetric explicitly requested but no key (plane off / prod
                # unset / unparseable): fail closed. NEVER a silent HMAC downgrade
                # for a token the caller believed was asymmetric.
                return None
        elif alg == _ALG_HMAC:
            secret = authority_secret()
            if secret is None:
                return None  # fail closed: no guessable default signs a real credential
        else:
            return None  # unknown signing algorithm => fail closed

        cnf: dict[str, str] | None = None
        binding = "bearer"
        if cnf_public_key is not None:
            public_key = _coerce_public_key(cnf_public_key)
            if public_key is None:
                return None  # unusable PoP key => refuse rather than silently weaken
            cnf = {"jkt": pop.thumbprint(public_key)}
            binding = "pop"
        elif not self._allow_bearer:
            return None  # PoP-only broker: refuse to mint a bearer credential

        issued = int(now if now is not None else time.time())
        exp = issued + int(ttl)
        jti = _permit.new_nonce()
        scope_tuple = tuple(sorted({str(s) for s in scope}))

        claims: dict[str, Any] = {
            "v": _CRED_VERSION,
            "typ": _CRED_TYPE,
            "iss": self._issuer,
            "sub": subject,
            "idp": getattr(attested_identity, "issuer", None),
            "aud": audience,
            "act": action,
            "scope": list(scope_tuple),
            "cnf": cnf,
            "bnd": binding,
            "jti": jti,
            "iat": issued,
            "exp": exp,
        }
        # The ``alg`` discriminator is written ONLY for the asymmetric leg, and
        # INSIDE the signed claims (so it cannot be downgraded). The HMAC leg
        # omits it entirely, keeping the canonical body byte-for-byte identical
        # to the pre-B2 token (``_canonical`` sorts keys, so an absent key is a
        # no-op; a present null/empty would change the bytes — hence omit).
        if alg == _ALG_ED25519:
            claims["alg"] = _CLAIM_ALG_ED25519
        # Optional anti-rollback epoch (monotone counter). Written only when
        # explicitly supplied, so the default token bytes are unchanged.
        if epoch is not None:
            claims["epoch"] = int(epoch)
        # TG-PCC B1+ commitments — unify the credential body with the TG-PCC
        # claim set. Same conditional-write discipline as ``alg``/``epoch``: an
        # absent key is a no-op under ``_canonical`` (sorted keys), so with both
        # None the token is byte-for-byte the pre-B1+ shape. Reuse the EXACT claim
        # names ``TgPccClaims.to_claims`` uses so the offline verifier recovers
        # them with the same vocabulary.
        if intent_commit is not None:
            claims["intent_commit"] = intent_commit
        if prov_commit is not None:
            claims["prov_commit"] = prov_commit
        body = _canonical(claims)
        if alg == _ALG_ED25519:
            sig = _sign_cred_ed25519(ed25519_key, body)
        else:
            sig = _sign_cred(secret, body)  # type: ignore[arg-type]
        token = f"{body}.{sig}"
        expiry_dt = datetime.fromtimestamp(exp, tz=UTC)

        permit_id: UUID | None = None
        if self._store is not None:
            did = _coerce_uuid(decision_id)
            try:
                stored = self._store.issue(
                    decision_id=did,
                    nonce=jti,
                    signature=sig,
                    expiry=expiry_dt,
                    metadata={
                        "kind": "tex-credential",
                        "subject": subject,
                        "idp": claims["idp"],
                        "audience": audience,
                        "action": action,
                        "scope": list(scope_tuple),
                        "binding": binding,
                        "cnf_jkt": (cnf or {}).get("jkt"),
                        "single_use": bool(single_use),
                    },
                )
                permit_id = getattr(stored, "permit_id", None)
            except Exception:  # noqa: BLE001 — persistence failure must not silently
                # hand out an unrecorded single-use/revocable credential.
                _logger.exception("CredentialBroker: store.issue failed; refusing mint")
                return None

        return MintedCredential(
            token=token,
            jti=jti,
            subject=subject,
            audience=audience,
            action=action,
            scope=scope_tuple,
            binding=binding,
            cnf_jkt=(cnf or {}).get("jkt"),
            expiry=expiry_dt,
            issuer=self._issuer,
            claims=claims,
            permit_id=permit_id,
        )

    # ---- verify -------------------------------------------------------- #

    def verify(
        self,
        token: str | None,
        *,
        expected_audience: str | None = None,
        expected_action: str | None = None,
        now: float | None = None,
        required_scope: str | Iterable[str] | None = None,
        expected_issuer: str | None = None,
        expected_subject: str | None = None,
        pop_proof: str | None = None,
        pop_challenge: str | None = None,
        pop_max_age: int = 120,
        check_single_use: bool = False,
    ) -> CredentialCheck:
        """Verify a credential the way a resource (or Tex) would. Never raises.

        Checks, in order: signature, version/type, issuer, expiry/not-before,
        audience, action, subject, scope coverage, PoP binding, then
        revocation/single-use against the store (when wired). A credential that
        was minted sender-constrained (``cnf`` present) ALWAYS requires a valid
        ``pop_proof`` — it can never be downgraded to bearer use, because ``cnf``
        lives inside the signed claims.
        """
        try:
            if not token or "." not in token:
                return CredentialCheck(False, "malformed credential")

            body, _, sig = token.partition(".")

            # Read the (untrusted) alg discriminator from inside the body to PICK
            # a verifier, then verify the signature. A wrong-alg guess just fails
            # signature verification -> "bad signature"; ``alg`` lives inside the
            # signed claims so it cannot be silently downgraded. The HMAC leg
            # (no ``alg`` claim) keeps the exact pre-B2 verification path.
            try:
                claims = json.loads(_b64url_decode(body))
            except (ValueError, json.JSONDecodeError):
                return CredentialCheck(False, "unparseable claims")
            if not isinstance(claims, dict):
                return CredentialCheck(False, "unparseable claims")

            claim_alg = claims.get("alg")
            if claim_alg is None:
                # Default leg: symmetric HMAC over the shared authority secret.
                secret = authority_secret()
                if secret is None:
                    return CredentialCheck(False, "no signing secret (fail-closed)")
                if not hmac.compare_digest(sig, _sign_cred(secret, body)):
                    return CredentialCheck(False, "bad signature")
            elif claim_alg == _CLAIM_ALG_ED25519:
                # Asymmetric leg: verify offline against a pinned JWKS public key.
                ok = _verify_ed25519_via_jwks(claims, body, sig)
                if not ok:
                    return CredentialCheck(False, "bad signature")
            else:
                return CredentialCheck(False, "unsupported alg")

            if (
                claims.get("v") != _CRED_VERSION
                or claims.get("typ") != _CRED_TYPE
            ):
                return CredentialCheck(False, "unsupported credential")

            issuer_expected = expected_issuer if expected_issuer is not None else self._issuer
            if claims.get("iss") != issuer_expected:
                return CredentialCheck(False, "issuer mismatch", claims)

            clock = now if now is not None else time.time()
            if int(claims.get("exp", 0)) < int(clock):
                return CredentialCheck(False, "expired", claims)
            if int(claims.get("iat", 0)) > int(clock) + 5:
                return CredentialCheck(False, "not yet valid", claims)

            if expected_audience is not None and claims.get("aud") != expected_audience:
                return CredentialCheck(False, "audience mismatch", claims)
            if expected_action is not None and claims.get("act") != expected_action:
                return CredentialCheck(False, "action mismatch", claims)
            if expected_subject is not None and claims.get("sub") != expected_subject:
                return CredentialCheck(False, "subject mismatch", claims)

            if required_scope is not None:
                granted = {str(s) for s in (claims.get("scope") or [])}
                need = (
                    {required_scope}
                    if isinstance(required_scope, str)
                    else {str(s) for s in required_scope}
                )
                if not need.issubset(granted):
                    return CredentialCheck(False, "scope mismatch", claims)

            binding = claims.get("bnd")
            cnf = claims.get("cnf")
            cnf_jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
            if binding == "pop" or cnf_jkt:
                if not cnf_jkt:
                    return CredentialCheck(False, "pop binding without cnf", claims)
                if not pop_proof:
                    return CredentialCheck(False, "pop proof required", claims)
                pr = pop.verify_pop_proof(
                    pop_proof,
                    cnf_jkt=cnf_jkt,
                    bind=_use_binding(token),
                    now=now,
                    max_age=pop_max_age,
                    expected_challenge=pop_challenge,
                )
                if not pr.ok:
                    return CredentialCheck(False, f"pop: {pr.reason}", claims)

            if self._store is not None:
                record = self._store.get_by_nonce(claims.get("jti"))
                if record is None:
                    if check_single_use:
                        return CredentialCheck(
                            False, "unknown credential (not issued / store-expired)", claims
                        )
                else:
                    if getattr(record, "revoked_at", None) is not None:
                        return CredentialCheck(False, "revoked", claims)
                    if check_single_use and getattr(record, "consumed_at", None) is not None:
                        return CredentialCheck(False, "already used", claims)

            return CredentialCheck(True, "ok", claims, binding=binding)
        except Exception:  # noqa: BLE001 — never raise out of verify
            return CredentialCheck(False, "verification error")

    # ---- single-use / revocation --------------------------------------- #

    def consume(self, token_or_jti: str) -> bool:
        """Mark a single-use credential consumed (idempotent). Returns True iff a
        store row was found and consumed. No-op-False when no store is wired."""
        return self._mutate_store(token_or_jti, lambda store, pid: store.consume(pid))

    def revoke(self, token_or_jti: str, *, reason: str | None = None) -> bool:
        """Revoke a credential. Returns True iff a store row was found and revoked."""
        return self._mutate_store(
            token_or_jti, lambda store, pid: store.revoke(pid, reason=reason)
        )

    def redeem(
        self,
        token: str | None,
        *,
        expected_audience: str | None = None,
        expected_action: str | None = None,
        now: float | None = None,
        required_scope: str | Iterable[str] | None = None,
        pop_proof: str | None = None,
        pop_challenge: str | None = None,
        pop_max_age: int = 120,
    ) -> CredentialCheck:
        """Verify a ONE-SHOT credential and consume it on success.

        This is the resource-side path for single-use actions: it verifies with
        single-use semantics (an already-consumed credential is rejected) and, if
        valid, consumes the store row so a *later* replay of the same token is
        rejected.

        HONESTY — concurrency boundary: this is verify-then-consume, not a single
        atomic compare-and-set. Two redemptions of the SAME one-shot credential
        racing inside the same instant can both pass verify before either
        consumes (``PermitStore.consume`` is idempotent ``COALESCE`` and does not
        report whether THIS caller won the race). Strict once-only-under-
        concurrency requires a CAS consume (``... SET consumed_at=now WHERE
        consumed_at IS NULL`` + rowcount) in the store — a ``PermitStore`` change,
        out of this package's scope. For serial redemption (the common case) and
        replay-after-use, single-use holds and is tested.
        """
        check = self.verify(
            token,
            expected_audience=expected_audience,
            expected_action=expected_action,
            now=now,
            required_scope=required_scope,
            pop_proof=pop_proof,
            pop_challenge=pop_challenge,
            pop_max_age=pop_max_age,
            check_single_use=True,
        )
        if check.ok and self._store is not None and check.claims is not None:
            self.consume(str(check.claims.get("jti")))
        return check

    def _mutate_store(
        self, token_or_jti: str, op: Callable[[RevocationStore, UUID], Any]
    ) -> bool:
        if self._store is None or not token_or_jti:
            return False
        jti = _jti_of(token_or_jti)
        if not jti:
            return False
        try:
            record = self._store.get_by_nonce(jti)
            if record is None:
                return False
            permit_id = getattr(record, "permit_id", None)
            if permit_id is None:
                return False
            op(self._store, permit_id)
            return True
        except Exception:  # noqa: BLE001 — store errors are not a credential property
            _logger.exception("CredentialBroker: store mutation failed for jti")
            return False

    # ---- token exchange (RFC 8693) ------------------------------------- #

    def exchange(
        self,
        subject_assertion: Any,
        requested_scope: str | Iterable[str],
        *,
        audience: str,
        action: str,
        ttl: int = 300,
        now: float | None = None,
        exchange_pop_proof: str | None = None,
        single_use: bool = False,
        decision_id: UUID | str | None = None,
    ) -> ExchangeResult:
        """RFC 8693 token exchange: verify a subject assertion via the configured
        ``IdentitySource`` and return a fresh Tex-minted, action-scoped credential
        bound to the attested identity (and to the holder's cnf key when present).

        Fail-closed at every step: no identity source, an unverified subject, a
        missing/invalid exchange-time possession proof, a bearer request on a
        PoP-only broker, or a mint failure each yield ``ok=False`` and NO token.
        """
        if self._identity_source is None:
            return ExchangeResult(False, "no identity source configured")

        subject = self._identity_source.verify_subject_assertion(
            subject_assertion, now=now, expected_audience=audience
        )
        if not subject.verified:
            return ExchangeResult(False, f"subject not verified: {subject.status}")

        requested = (
            {requested_scope}
            if isinstance(requested_scope, str)
            else {str(s) for s in (requested_scope or [])}
        )
        if self._scope_policy is not None:
            # Down-scope only: the policy can shrink the grant, never escalate it
            # beyond what was requested (RFC 8693 lets the AS narrow scope).
            allowed = {str(s) for s in self._scope_policy(subject.as_attested_identity(), requested)}
            granted = allowed & requested
        elif self._allow_unrestricted_exchange:
            granted = requested  # opt-in echo (dev / mTLS-constrained channel)
        else:
            # FAIL-CLOSED: no scope policy => grant nothing. A proven identity does
            # not get to mint arbitrary scope just by asking; the deployment must
            # configure a scope_policy (or opt into allow_unrestricted_exchange).
            return ExchangeResult(
                False,
                "no scope_policy configured: exchange refuses to echo requested "
                "scope (set a scope_policy, or allow_unrestricted_exchange for dev)",
            )

        cnf_public_key = self._resolve_exchange_cnf(subject, audience, action, exchange_pop_proof, now)
        if isinstance(cnf_public_key, ExchangeResult):
            return cnf_public_key  # a fail-closed reason

        credential = self.mint(
            subject.as_attested_identity(),
            audience=audience,
            action=action,
            scope=granted,
            ttl=ttl,
            cnf_public_key=cnf_public_key,
            single_use=single_use,
            decision_id=decision_id,
            now=now,
        )
        if credential is None:
            return ExchangeResult(False, "mint failed (fail-closed)")

        return ExchangeResult(
            True,
            "ok",
            credential=credential,
            token_type=credential.token_type,
            expires_in=int(credential.claims["exp"] - credential.claims["iat"]),
            scope=list(credential.scope),
            issued_token_type=_ACCESS_TOKEN_TYPE,
        )

    def _resolve_exchange_cnf(
        self,
        subject: SubjectVerification,
        audience: str,
        action: str,
        exchange_pop_proof: str | None,
        now: float | None,
    ) -> Any | ExchangeResult:
        """Decide the cnf key to bind (or a fail-closed ExchangeResult).

        When the assertion carries a cnf key, the presenter MUST prove possession
        of it at exchange time (so a stolen assertion cannot mint a credential
        bound to a key the thief does not control). When it carries none, a
        bearer credential is minted only if the broker allows it."""
        if not subject.cnf_jwk:
            if not self._allow_bearer:
                return ExchangeResult(
                    False, "assertion carries no cnf key and bearer credentials are disabled"
                )
            return None
        try:
            public_key = pop.load_public_key(subject.cnf_jwk)
        except Exception:  # noqa: BLE001
            return ExchangeResult(False, "assertion cnf key unusable")
        if self._require_exchange_pop:
            if not exchange_pop_proof:
                return ExchangeResult(False, "exchange pop proof required")
            subject_jkt = pop.thumbprint(public_key)
            pr = pop.verify_pop_proof(
                exchange_pop_proof,
                cnf_jkt=subject_jkt,
                bind=_exchange_binding(subject_jkt, audience, action),
                now=now,
            )
            if not pr.ok:
                return ExchangeResult(False, f"exchange pop: {pr.reason}")
        return public_key


# --------------------------------------------------------------------------- #
# Coercion helpers                                                             #
# --------------------------------------------------------------------------- #


def _coerce_public_key(value: Any) -> Any | None:
    """Coerce an Ed25519 public key from a key object, raw 32 bytes, or b64 str."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if isinstance(value, Ed25519PublicKey):
        return value
    try:
        if isinstance(value, dict):  # a JWK
            return pop.load_public_key(value)
        if isinstance(value, str):
            import base64

            value = base64.b64decode(value.encode("ascii"))
        if isinstance(value, (bytes, bytearray)):
            return Ed25519PublicKey.from_public_bytes(bytes(value))
    except Exception:  # noqa: BLE001 — unusable key => None (caller fails closed)
        return None
    return None


def _coerce_uuid(value: UUID | str | None) -> UUID:
    if isinstance(value, UUID):
        return value
    if value:
        try:
            return UUID(str(value))
        except (ValueError, AttributeError):
            pass
    return uuid4()


# --------------------------------------------------------------------------- #
# TG-PCC claim schema (Step 0) — a frozen, forward-compatible capability claim  #
# set with a byte-stable canonical serializer.                                  #
#                                                                              #
# This is the claim SLOT definition + serialization for the Tex-Governed        #
# Proof-Carrying Capability. ``prov_commit`` MAY be None this step — it is the  #
# slot that B1+ populates later (label / floor / lineage_root / label_id). The  #
# serializer reuses the SAME audited canonicalizer the credential body uses, so #
# the bytes a signature covers are produced by one code path.                   #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class TgPccClaims:
    """The frozen TG-PCC (Tex-Governed Proof-Carrying Capability) claim set.

    Canonical, byte-stable serialization is via :func:`canonical_intent_commit`
    / :meth:`to_claims` + ``_canonical`` (the same b64url-of-sorted-compact-JSON
    the credential body uses), so the signed bytes are cross-process stable.

    ``prov_commit`` is the provenance-commitment slot (label{integrity,
    confidentiality}, floor, lineage_root, label_id). It MAY be None at this
    step — populated by the provenance leg later; Step 0 only defines + carries
    the slot.
    """

    iss: str
    sub: str  # the agent_id the capability is bound to
    aud: str
    act: dict[str, Any]  # canonical {"method": ..., "resource": ...}
    scp: tuple[str, ...]  # requested ∩ allowed
    cnf: dict[str, Any] | None  # {"jkt": ...} sender-binding (RFC 7800)
    intent_commit: str  # SHA-256(canonical(method, resource, params))
    exp: int
    nbf: int
    epoch: int
    prov_commit: dict[str, Any] | None = None  # populated by B1+; may be None now
    evidence: dict[str, Any] | None = None  # optional
    anchor: dict[str, Any] | None = None  # optional

    def to_claims(self) -> dict[str, Any]:
        """The ordered claim dict for canonical serialization.

        Optional slots that are None are OMITTED (not serialized as null) so the
        canonical bytes stay minimal and stable; ``_canonical`` sorts keys, so
        ordering here is cosmetic — the on-wire bytes are key-sorted regardless.
        """
        claims: dict[str, Any] = {
            "iss": self.iss,
            "sub": self.sub,
            "aud": self.aud,
            "act": self.act,
            "scp": list(self.scp),
            "intent_commit": self.intent_commit,
            "exp": self.exp,
            "nbf": self.nbf,
            "epoch": self.epoch,
        }
        if self.cnf is not None:
            claims["cnf"] = self.cnf
        if self.prov_commit is not None:
            claims["prov_commit"] = self.prov_commit
        if self.evidence is not None:
            claims["evidence"] = self.evidence
        if self.anchor is not None:
            claims["anchor"] = self.anchor
        return claims

    def serialize(self) -> str:
        """The canonical b64url body (the exact bytes a signature would cover)."""
        return _canonical(self.to_claims())

    @classmethod
    def deserialize(cls, body: str) -> "TgPccClaims":
        """Round-trip a canonical body back into a TG-PCC claim object."""
        claims = json.loads(_b64url_decode(body))
        if not isinstance(claims, dict):
            raise ValueError("malformed TG-PCC body")
        return cls(
            iss=claims["iss"],
            sub=claims["sub"],
            aud=claims["aud"],
            act=claims["act"],
            scp=tuple(claims.get("scp", ())),
            cnf=claims.get("cnf"),
            intent_commit=claims["intent_commit"],
            exp=int(claims["exp"]),
            nbf=int(claims["nbf"]),
            epoch=int(claims["epoch"]),
            prov_commit=claims.get("prov_commit"),
            evidence=claims.get("evidence"),
            anchor=claims.get("anchor"),
        )


def canonical_intent_commit(method: str, resource: str, params: Any) -> str:
    """SHA-256 hex of the canonical ``(method, resource, params)`` tuple.

    Byte-stable across processes: the input is serialized with the SAME
    sort-keys / compact-separators / ``ensure_ascii`` discipline the credential
    body uses (``permit._canonical`` -> b64url of UTF-8 JSON), then hashed. The
    hash input is the raw canonical JSON of the ordered structure (NOT the
    b64url wrapper) so it is a stable commitment over the action's intent.
    """
    canonical_json = json.dumps(
        {"method": method, "resource": resource, "params": params},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical_json).hexdigest()


def canonical_act(method: str, resource: str) -> dict[str, str]:
    """The canonical ``act`` claim — a fixed-key {method, resource} dict."""
    return {"method": str(method), "resource": str(resource)}


# --------------------------------------------------------------------------- #
# JWKS publication + pure offline (air-gapped) verify — B2.                     #
# --------------------------------------------------------------------------- #


def tgpcc_public_jwks() -> dict[str, Any]:
    """The JWKS document advertising ONLY Tex's Ed25519 PUBLIC signing key.

    Returns ``{"keys": []}`` when the TG-PCC plane is OFF or no key resolves —
    so default boot publishes no asymmetric key. NEVER includes private
    material: only ``{kty:OKP, crv:Ed25519, x, kid, use, alg}`` per key, where
    ``kid`` is the RFC-7638 thumbprint (the single canonical key id).
    """
    private_key = authority_ed25519_key()
    if private_key is None:
        return {"keys": []}
    raw_pub = pop.raw_public_bytes(private_key.public_key())
    jwk = pop.public_jwk(raw_pub)  # {crv, kty, x} only — no private bytes
    kid = pop.jwk_thumbprint(jwk)
    entry = {**jwk, "kid": kid, "use": "sig", "alg": _CLAIM_ALG_ED25519}
    return {"keys": [entry]}


def _select_jwk(jwks: dict[str, Any], kid: str | None) -> dict[str, Any] | None:
    """Pick the verifying JWK from a pinned JWKS, fail-closed.

    Mirrors ``identity_source._select_key`` discipline: filter to OKP/EdDSA
    signing keys; a named ``kid`` that matches nothing is a HARD miss (never
    "try any key"); a missing ``kid`` resolves only when exactly one candidate
    exists. No network — pure dict lookup.
    """
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, list):
        return None
    candidates = [
        k
        for k in keys
        if isinstance(k, dict)
        and k.get("kty") == "OKP"
        and k.get("crv") == "Ed25519"
        and k.get("use", "sig") == "sig"
        and k.get("alg", _CLAIM_ALG_ED25519) == _CLAIM_ALG_ED25519
    ]
    if not candidates:
        return None
    if kid:
        for k in candidates:
            if hmac.compare_digest(str(k.get("kid", "")), str(kid)):
                return k
        return None  # named kid miss => fail closed
    return candidates[0] if len(candidates) == 1 else None


def _verify_ed25519_via_jwks(
    claims: dict[str, Any], body: str, sig_b64: str
) -> bool:
    """Verify the Ed25519 credential signature against Tex's own published JWKS.

    Used by the broker's instance ``verify`` for a token it (or a peer Tex) minted
    — the verifying public key is the published TG-PCC key. PURE / offline: no
    network. Returns False on any defect.
    """
    jwks = tgpcc_public_jwks()
    kid = claims.get("kid")  # tokens may name a kid; otherwise single-key resolve
    jwk = _select_jwk(jwks, kid)
    if jwk is None:
        return False
    try:
        public_key = pop.load_public_key(jwk)
    except Exception:  # noqa: BLE001 — unusable key fails closed
        return False
    return _verify_cred_ed25519(public_key, body, sig_b64)


def verify_with_jwks(
    token: str | None,
    jwks: dict[str, Any],
    *,
    pinned_epoch: int | None = None,
    expected_issuer: str | None = None,
    now: float | None = None,
    expected_intent_commit: str | None = None,
) -> CredentialCheck:
    """Pure, offline (AIR-GAPPED) verify of a Tex Ed25519 capability token.

    Resolves ``iss`` + ``kid`` -> public key from the PINNED LOCAL ``jwks`` dict
    (passed in, NEVER fetched), verifies the Ed25519 signature, and applies the
    epoch / expiry / issuer floor. Constructs NO HTTP client and opens NO socket
    — the only inputs are the token bytes and the in-memory JWKS dict.

    Verdicts (B2 DoD):
      (a) a valid TG-PCC / Ed25519 credential        -> ok=True  ("ok")
      (b) a token signed by a non-published key       -> ok=False ("bad signature"
          or "no matching key" when the kid is absent from the pinned JWKS)
      (c) a token whose ``epoch`` is below the PEP's pinned epoch -> ok=False
          ("stale epoch")

    ``expected_intent_commit`` (TG-PCC B1+): when supplied, the token's signed
    ``intent_commit`` claim MUST equal it (constant-time) — this is the replay
    defense. Presenting a token minted for action A against action B's intent
    yields a different ``expected_intent_commit`` and DENIES ("intent mismatch").
    Fail-closed: a missing ``intent_commit`` claim under this check also denies.

    HONESTY: this is PARITY plumbing — offline public-key verify of an
    attenuable token, the DEPLOYED shape (AIP / Biscuit / Vouchsafe). It is
    table-stakes, not novel. The ``intent_commit`` binding is the one piece that
    closes the (C) replay vector. Never raises.
    """
    try:
        if not token or "." not in token:
            return CredentialCheck(False, "malformed credential")
        body, _, sig = token.partition(".")

        try:
            claims = json.loads(_b64url_decode(body))
        except (ValueError, json.JSONDecodeError):
            return CredentialCheck(False, "unparseable claims")
        if not isinstance(claims, dict):
            return CredentialCheck(False, "unparseable claims")

        if claims.get("alg") != _CLAIM_ALG_ED25519:
            # This pure verifier is for the asymmetric leg only.
            return CredentialCheck(False, "unsupported alg", claims)

        # Resolve the public key from the PINNED dict — no network.
        kid = claims.get("kid")
        jwk = _select_jwk(jwks, kid)
        if jwk is None:
            return CredentialCheck(False, "no matching key", claims)
        try:
            public_key = pop.load_public_key(jwk)
        except Exception:  # noqa: BLE001
            return CredentialCheck(False, "unsupported key", claims)

        # (b) signature must verify under the published key.
        if not _verify_cred_ed25519(public_key, body, sig):
            return CredentialCheck(False, "bad signature", claims)

        # (c) epoch floor — a token below the PEP's pinned epoch is stale (anti-
        # rollback). ``epoch`` is an integer monotone counter inside the claims.
        if pinned_epoch is not None:
            try:
                tok_epoch = int(claims.get("epoch"))
            except (TypeError, ValueError):
                return CredentialCheck(False, "missing epoch", claims)
            if tok_epoch < int(pinned_epoch):
                return CredentialCheck(False, "stale epoch", claims)

        # Expiry / not-before (the credential carries exp/iat; a TG-PCC carries
        # exp/nbf). Honor whichever is present, fail-closed on expiry.
        clock = now if now is not None else time.time()
        exp = claims.get("exp")
        if exp is not None and int(exp) < int(clock):
            return CredentialCheck(False, "expired", claims)
        nbf = claims.get("nbf")
        if nbf is not None and int(nbf) > int(clock) + 5:
            return CredentialCheck(False, "not yet valid", claims)
        iat = claims.get("iat")
        if iat is not None and int(iat) > int(clock) + 5:
            return CredentialCheck(False, "not yet valid", claims)

        if expected_issuer is not None and claims.get("iss") != expected_issuer:
            return CredentialCheck(False, "issuer mismatch", claims)

        # (TG-PCC B1+) intent binding — the presented call must be the committed
        # call. A token replayed against a DIFFERENT (method, resource, params)
        # carries an intent_commit that no longer matches => DENY. Fail-closed: a
        # missing claim under this check denies (the binding cannot be proven).
        if expected_intent_commit is not None:
            tok_intent = claims.get("intent_commit")
            if not isinstance(tok_intent, str) or not hmac.compare_digest(
                tok_intent, str(expected_intent_commit)
            ):
                return CredentialCheck(False, "intent mismatch", claims)

        return CredentialCheck(True, "ok", claims, binding=claims.get("bnd"))
    except Exception:  # noqa: BLE001 — never raise out of verify
        return CredentialCheck(False, "verification error")


def verify_prov_commit_floor(claims: dict[str, Any] | None) -> CredentialCheck:
    """Offline re-check of the TG-PCC ``prov_commit`` integrity floor (B1+).

    A THIN, additive step run AFTER ``verify_with_jwks`` confirms the signature:
    it reads the SIGNED ``prov_commit`` from the claims and re-enforces
    ``label ⊒ floor`` from the embedded integer label/floor alone — no network,
    no side state. The ``enc`` tag pins the numeric direction (CaMeL: lower int =
    more trusted; ⊒ means ``label.integrity <= floor.integrity`` and likewise for
    confidentiality).

    Fail-closed: a missing/malformed ``prov_commit``, an unknown ``enc``, or a
    label that does NOT dominate the floor all DENY. Because ``lineage_root`` is a
    COMMITMENT (not the DAG), this proves "Tex committed to this label/floor under
    its key and the label satisfies the floor" — NOT a re-derivation of the label
    from raw operands. Returns ok=True only when the floor is satisfied.
    """
    if not isinstance(claims, dict):
        return CredentialCheck(False, "no prov_commit")
    prov = claims.get("prov_commit")
    if not isinstance(prov, dict):
        return CredentialCheck(False, "no prov_commit", claims)
    # Lazy import: keeps the offline verify module free of camel at import time
    # for callers that never touch prov_commit.
    from tex.authority.taint_label import PROV_COMMIT_ENC

    if prov.get("enc") != PROV_COMMIT_ENC:
        return CredentialCheck(False, "unknown prov_commit enc", claims)
    label = prov.get("label")
    floor = prov.get("floor")
    if not isinstance(label, dict) or not isinstance(floor, dict):
        return CredentialCheck(False, "malformed prov_commit", claims)
    try:
        li = int(label["integrity"])
        lc = int(label["confidentiality"])
        fi = int(floor["integrity"])
        fc = int(floor["confidentiality"])
    except (KeyError, TypeError, ValueError):
        return CredentialCheck(False, "malformed prov_commit", claims)
    # ⊒ floor under the camel.fides.v1 encoding (lower int = more trusted).
    if li <= fi and lc <= fc:
        return CredentialCheck(True, "ok", claims)
    return CredentialCheck(False, "insufficient_integrity", claims)


def _jti_of(token_or_jti: str) -> str | None:
    """Extract the jti from a credential token, or treat the input as a raw jti."""
    if "." in token_or_jti:
        try:
            claims = json.loads(_b64url_decode(token_or_jti.partition(".")[0]))
            if isinstance(claims, dict) and claims.get("jti"):
                return str(claims["jti"])
        except Exception:  # noqa: BLE001
            return None
        return None
    return token_or_jti
