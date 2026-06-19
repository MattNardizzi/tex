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
    "RevocationStore",
    "MintedCredential",
    "CredentialCheck",
    "ExchangeResult",
    "CredentialBroker",
]

_logger = logging.getLogger(__name__)

_CRED_VERSION = 1
_CRED_TYPE = "tex-cred"
_DEFAULT_ISSUER = "tex-authority"
# Domain-separation prefix folded into every credential MAC. A permit body and a
# credential body can therefore never cross-verify even under a shared key.
_AUTHORITY_DOMAIN = "texauth.v1"
_ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


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
    ) -> MintedCredential | None:
        """Mint a credential bound to a VERIFIED identity, scoped to one action.

        Returns None (fail-closed) when: the identity is not verified, no signing
        secret is available in a production-like env, or a bearer credential is
        requested (no ``cnf_public_key``) while the broker is PoP-only.

        ``cnf_public_key`` (an ``Ed25519PublicKey``, raw 32 bytes, or a b64 str)
        sender-constrains the credential (RFC 7800/9449): using it then requires a
        PoP proof from the matching private key.
        """
        if attested_identity is None or not getattr(attested_identity, "verified", False):
            return None  # NEVER mint for an unverified identity
        subject = getattr(attested_identity, "claimed_agent_id", None)
        if not subject:
            return None

        secret = authority_secret()
        if secret is None:
            return None  # fail closed: no guessable default signs a real credential

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
        body = _canonical(claims)
        sig = _sign_cred(secret, body)
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
            secret = authority_secret()
            if secret is None:
                return CredentialCheck(False, "no signing secret (fail-closed)")
            if not token or "." not in token:
                return CredentialCheck(False, "malformed credential")

            body, _, sig = token.partition(".")
            if not hmac.compare_digest(sig, _sign_cred(secret, body)):
                return CredentialCheck(False, "bad signature")

            try:
                claims = json.loads(_b64url_decode(body))
            except (ValueError, json.JSONDecodeError):
                return CredentialCheck(False, "unparseable claims")
            if (
                not isinstance(claims, dict)
                or claims.get("v") != _CRED_VERSION
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
        granted = requested
        if self._scope_policy is not None:
            # Down-scope only: the policy can shrink the grant, never escalate it
            # beyond what was requested (RFC 8693 lets the AS narrow scope).
            allowed = {str(s) for s in self._scope_policy(subject.as_attested_identity(), requested)}
            granted = allowed & requested

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
