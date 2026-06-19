"""
Identity-provider seam for the authority plane.

Token exchange (RFC 8693) starts from a *subject assertion*: an inbound identity
token an agent presents to prove who it is (an Entra/Azure AD OIDC token, a
SPIFFE SVID, an A2A AgentCard, ...). The broker must verify that assertion before
it will mint a Tex credential bound to it. ``IdentitySource`` is that seam:
verify the inbound assertion and surface (a) the attested identity and (b) the
holder's ``cnf`` public key (the proof-of-possession key the agent controls).

What is CLOSED here vs the honest boundary:
  * CLOSED — the seam (``IdentitySource``) and a fully-working local
    implementation (``LocalEd25519IdentitySource``) that REUSES the existing,
    audited ``tex.identity.agent_credential.verify_agent_credential`` (Ed25519
    over the JCS-canonical payload, allow-listed issuer, exp/nbf + audience
    freshness). No new identity crypto is introduced — this composes the
    enforcement-side verifier.
  * NOT CLOSED (``RUNTIME-DEPENDENT``) — verifying a *real* Microsoft Entra OIDC
    JWT (JWKS fetch, RS256/ES256, ``iss``/``aud``/``tid`` checks) or a real
    SPIFFE SVID (SPIRE trust bundle, X.509-SVID / JWT-SVID). Those are separate
    ``IdentitySource`` implementations that this package deliberately does NOT
    ship — they require live IdP integration and key distribution. The seam is
    here; the live wiring is deployment. Do not read the presence of this seam as
    "Tex already trusts Entra/SPIFFE."
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from tex.identity.agent_credential import AttestedIdentity, verify_agent_credential

__all__ = [
    "SubjectVerification",
    "IdentitySource",
    "LocalEd25519IdentitySource",
    "JwksKeyProvider",
    "StaticJwksProvider",
    "JwksIdentitySource",
]


@dataclass(frozen=True, slots=True)
class SubjectVerification:
    """The result of verifying an inbound subject assertion at the broker's edge."""

    verified: bool
    status: str  # the fail-closed reason when not verified
    agent_id: str | None
    issuer: str | None  # the upstream IdP that attested the subject
    cnf_jwk: dict[str, Any] | None  # the holder's proof-of-possession public key
    claims: dict[str, Any] | None = None
    method: str = "token-exchange"

    def as_attested_identity(self) -> AttestedIdentity:
        """Project onto the enforcement-side ``AttestedIdentity`` the broker mints from."""
        return AttestedIdentity(
            verified=self.verified,
            status=self.status,
            issuer=self.issuer,
            claimed_agent_id=self.agent_id,
            method=self.method,
        )


@runtime_checkable
class IdentitySource(Protocol):
    """Verify an inbound subject assertion. Implementations MUST fail closed:
    any defect returns ``verified=False`` with a reason in ``status`` and never
    raises. A real Entra / SPIFFE source implements exactly this one method."""

    def verify_subject_assertion(
        self,
        assertion: Any,
        *,
        now: float | None = None,
        expected_audience: str | None = None,
    ) -> SubjectVerification: ...


class LocalEd25519IdentitySource:
    """A working local ``IdentitySource`` for tests and in-trust-boundary use.

    The subject assertion is an Ed25519-signed AgentCard (the same object
    ``tex.identity.agent_credential`` verifies): ``{"issuer", "payload",
    "signature_b64"}`` where ``payload`` carries ``agent_id`` and a ``cnf`` JWK
    (the holder's PoP public key). Verification is delegated wholesale to the
    audited ``verify_agent_credential`` — this class only extracts the cnf key.
    """

    def __init__(
        self,
        *,
        trusted_issuers: dict[str, str],
        require_expiry: bool = True,
        max_bytes: int = 64 * 1024,
    ) -> None:
        self._trusted_issuers = dict(trusted_issuers)
        self._require_expiry = require_expiry
        self._max_bytes = max_bytes

    def verify_subject_assertion(
        self,
        assertion: Any,
        *,
        now: float | None = None,
        expected_audience: str | None = None,
    ) -> SubjectVerification:
        if not isinstance(assertion, dict):
            return SubjectVerification(False, "malformed_assertion", None, None, None)

        attested = verify_agent_credential(
            assertion,
            trusted_issuers=self._trusted_issuers,
            max_bytes=self._max_bytes,
            now=now,
            expected_audience=expected_audience,
            require_expiry=self._require_expiry,
        )
        payload = assertion.get("payload")
        payload = payload if isinstance(payload, dict) else None
        cnf = payload.get("cnf") if payload else None
        return SubjectVerification(
            verified=attested.verified,
            status=attested.status,
            agent_id=attested.claimed_agent_id,
            issuer=attested.issuer,
            cnf_jwk=cnf if isinstance(cnf, dict) else None,
            claims=payload,
            method="local_ed25519_agent_card",
        )


# --------------------------------------------------------------------------- #
# JWKS-verifying source (Entra-Agent-ID / SPIFFE JWT-SVID shape)              #
# --------------------------------------------------------------------------- #
#
# HONEST BOUNDARY for this section — what is REAL vs a SHIM:
#   * REAL + unit-tested: the JWT verification logic — split header.payload.sig,
#     select the signing JWK by ``kid`` + ``alg``, verify an RS256 / ES256 / EdDSA
#     signature over the EXACT signed bytes (``header.payload``), and enforce
#     ``iss`` allow-list, ``aud``, and ``exp``/``nbf`` freshness. Fail-closed on
#     every defect; never raises. This is the part that decides "is this token
#     genuinely from the IdP and still valid".
#   * SHIM (``RUNTIME-DEPENDENT``): fetching the IdP's live JWKS document over the
#     network (the OIDC discovery + ``jwks_uri`` GET, key rotation/caching). That
#     is injected as the ``key_provider`` callable. The DEFAULT provider is a
#     static, in-memory map (good for tests / a pinned trust bundle) and the
#     network provider is deliberately NOT shipped here — a deployment supplies it.
#     Do not read this class as "Tex already trusts live Entra/SPIFFE": it trusts
#     exactly the keys the configured provider returns.


def _jwt_b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


@runtime_checkable
class JwksKeyProvider(Protocol):
    """Returns the candidate signing JWK(s) for a given issuer.

    A real Entra/SPIFFE deployment implements this over the network (OIDC
    discovery -> ``jwks_uri`` GET, with caching + rotation). The verification
    logic only ever asks for keys through this seam, so the network is isolated
    from the (real, tested) crypto.
    """

    def keys_for(self, issuer: str) -> list[dict[str, Any]]: ...


class StaticJwksProvider:
    """A non-network ``JwksKeyProvider`` over an in-memory ``{iss: [jwk, ...]}``
    map. This is what the unit tests and a pinned-trust-bundle deployment use; it
    is also the default so a JwksIdentitySource with no provider configured fails
    closed (empty map => no key => every token rejected)."""

    def __init__(self, keys_by_issuer: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self._keys = {str(k): list(v) for k, v in (keys_by_issuer or {}).items()}

    def keys_for(self, issuer: str) -> list[dict[str, Any]]:
        return list(self._keys.get(str(issuer), []))


class JwksIdentitySource:
    """An ``IdentitySource`` that verifies a JWS-compact IdP token (Entra-Agent-ID
    OIDC JWT / SPIFFE JWT-SVID) against JWKS keys from the injected provider.

    The subject assertion is the compact JWT string ``header.payload.sig``.
    Verification (all REAL, fail-closed):
      1. parse the JWS header + payload;
      2. require ``alg`` in the allow-list (default RS256/ES256/EdDSA) — never
         ``none``, never an alg the selected key cannot satisfy;
      3. select the key by ``iss`` (allow-listed) + ``kid`` from the provider;
      4. verify the signature over the ASCII ``header.payload`` bytes;
      5. enforce ``iss`` allow-list, ``aud`` (when expected), ``exp``/``nbf``.

    The holder PoP key is read from the standard RFC 7800 ``cnf.jwk`` claim, so a
    minted Tex credential can be sender-constrained to the same key the IdP token
    was bound to. ``agent_id`` is taken from the configured claim (default ``sub``).
    """

    _DEFAULT_ALGS = ("RS256", "ES256", "EdDSA")

    def __init__(
        self,
        *,
        trusted_issuers: set[str] | list[str],
        key_provider: JwksKeyProvider | None = None,
        audiences: set[str] | list[str] | None = None,
        allowed_algs: tuple[str, ...] | None = None,
        subject_claim: str = "sub",
        require_expiry: bool = True,
        leeway: int = 60,
        max_bytes: int = 16 * 1024,
    ) -> None:
        self._trusted = {str(i) for i in trusted_issuers}
        # Default to a fail-closed static provider with no keys: unconfigured =>
        # nothing verifies, never a silent allow.
        self._provider = key_provider or StaticJwksProvider()
        self._audiences = {str(a) for a in audiences} if audiences else None
        self._algs = tuple(allowed_algs or self._DEFAULT_ALGS)
        self._subject_claim = subject_claim
        self._require_expiry = require_expiry
        self._leeway = int(leeway)
        self._max_bytes = int(max_bytes)

    def verify_subject_assertion(
        self,
        assertion: Any,
        *,
        now: float | None = None,
        expected_audience: str | None = None,
    ) -> SubjectVerification:
        try:
            return self._verify(assertion, now=now, expected_audience=expected_audience)
        except Exception:  # noqa: BLE001 — the seam contract: NEVER raise.
            return SubjectVerification(
                False, "verification_error", None, None, None, method="jwks_jwt"
            )

    def _verify(
        self, assertion: Any, *, now: float | None, expected_audience: str | None
    ) -> SubjectVerification:
        def fail(status: str) -> SubjectVerification:
            return SubjectVerification(False, status, None, None, None, method="jwks_jwt")

        if not isinstance(assertion, str) or assertion.count(".") != 2:
            return fail("malformed_jwt")
        if len(assertion) > self._max_bytes:
            return fail("oversize_jwt")

        header_b64, payload_b64, sig_b64 = assertion.split(".")
        try:
            header = json.loads(_jwt_b64url_decode(header_b64))
            payload = json.loads(_jwt_b64url_decode(payload_b64))
            signature = _jwt_b64url_decode(sig_b64)
        except Exception:  # noqa: BLE001
            return fail("unparseable_jwt")
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return fail("unparseable_jwt")

        alg = header.get("alg")
        if alg not in self._algs:  # rejects "none" and any non-allow-listed alg
            return fail("alg_not_allowed")

        issuer = payload.get("iss")
        if not issuer or str(issuer) not in self._trusted:
            return fail("untrusted_issuer")

        jwk = self._select_key(str(issuer), header.get("kid"), alg)
        if jwk is None:
            return fail("no_matching_key")

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        if not _verify_jws(alg, jwk, signing_input, signature):
            return fail("bad_signature")

        clock = now if now is not None else time.time()
        exp = payload.get("exp")
        if exp is None:
            if self._require_expiry:
                return fail("missing_exp")
        elif float(exp) < clock - self._leeway:
            return fail("expired")
        nbf = payload.get("nbf")
        if nbf is not None and float(nbf) > clock + self._leeway:
            return fail("not_yet_valid")

        # Audience: an explicit per-call expectation wins; else the configured set.
        aud_claim = payload.get("aud")
        aud_values = {str(aud_claim)} if isinstance(aud_claim, str) else {
            str(a) for a in (aud_claim or [])
        }
        if expected_audience is not None:
            if str(expected_audience) not in aud_values:
                return fail("audience_mismatch")
        elif self._audiences is not None and not (aud_values & self._audiences):
            return fail("audience_mismatch")

        agent_id = payload.get(self._subject_claim)
        if not agent_id:
            return fail("missing_subject")

        cnf = payload.get("cnf")
        cnf_jwk = cnf.get("jwk") if isinstance(cnf, dict) else None

        return SubjectVerification(
            verified=True,
            status="verified",
            agent_id=str(agent_id),
            issuer=str(issuer),
            cnf_jwk=cnf_jwk if isinstance(cnf_jwk, dict) else None,
            claims=payload,
            method="jwks_jwt",
        )

    def _select_key(
        self, issuer: str, kid: Any, alg: str
    ) -> dict[str, Any] | None:
        candidates = self._provider.keys_for(issuer)
        kty = _kty_for_alg(alg)
        usable = [
            k
            for k in candidates
            if isinstance(k, dict)
            and (kty is None or k.get("kty") == kty)
            and (k.get("alg") in (None, alg))
        ]
        if kid is not None:
            by_kid = [k for k in usable if k.get("kid") == kid]
            if by_kid:
                return by_kid[0]
            # A kid that names no key is a fail-closed miss, never "try any key".
            return None
        # No kid in the header: accept iff exactly one candidate is unambiguous.
        return usable[0] if len(usable) == 1 else None


def _kty_for_alg(alg: str) -> str | None:
    if alg.startswith("RS") or alg.startswith("PS"):
        return "RSA"
    if alg.startswith("ES"):
        return "EC"
    if alg == "EdDSA":
        return "OKP"
    return None


def _verify_jws(
    alg: str, jwk: dict[str, Any], signing_input: bytes, signature: bytes
) -> bool:
    """Verify a JWS signature for the supported algs. Returns False on any defect
    (never raises) so the caller stays fail-closed."""
    from cryptography.exceptions import InvalidSignature

    try:
        if alg in ("RS256", "RS384", "RS512", "PS256"):
            return _verify_rsa(alg, jwk, signing_input, signature)
        if alg in ("ES256", "ES384", "ES512"):
            return _verify_ec(alg, jwk, signing_input, signature)
        if alg == "EdDSA":
            return _verify_eddsa(jwk, signing_input, signature)
    except InvalidSignature:
        return False
    except Exception:  # noqa: BLE001 — unusable key / malformed jwk => reject
        return False
    return False


def _verify_rsa(
    alg: str, jwk: dict[str, Any], signing_input: bytes, signature: bytes
) -> bool:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    n = int.from_bytes(_jwt_b64url_decode(str(jwk["n"])), "big")
    e = int.from_bytes(_jwt_b64url_decode(str(jwk["e"])), "big")
    public_key = rsa.RSAPublicNumbers(e, n).public_key()
    hash_alg = {"RS256": hashes.SHA256, "RS384": hashes.SHA384, "RS512": hashes.SHA512}.get(
        alg, hashes.SHA256
    )()
    pad = (
        padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.DIGEST_LENGTH)
        if alg == "PS256"
        else padding.PKCS1v15()
    )
    public_key.verify(signature, signing_input, pad, hash_alg)
    return True


def _verify_ec(
    alg: str, jwk: dict[str, Any], signing_input: bytes, signature: bytes
) -> bool:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    curve, hash_alg, coord = {
        "ES256": (ec.SECP256R1(), hashes.SHA256(), 32),
        "ES384": (ec.SECP384R1(), hashes.SHA384(), 48),
        "ES512": (ec.SECP521R1(), hashes.SHA512(), 66),
    }[alg]
    x = int.from_bytes(_jwt_b64url_decode(str(jwk["x"])), "big")
    y = int.from_bytes(_jwt_b64url_decode(str(jwk["y"])), "big")
    public_key = ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    # JWS ES* signatures are raw R||S, not DER — convert before verify.
    if len(signature) != 2 * coord:
        return False
    r = int.from_bytes(signature[:coord], "big")
    s = int.from_bytes(signature[coord:], "big")
    public_key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hash_alg))
    return True


def _verify_eddsa(jwk: dict[str, Any], signing_input: bytes, signature: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if jwk.get("crv") != "Ed25519":
        return False
    public_key = Ed25519PublicKey.from_public_bytes(_jwt_b64url_decode(str(jwk["x"])))
    public_key.verify(signature, signing_input)
    return True
