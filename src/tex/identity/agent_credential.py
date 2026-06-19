"""
Attested agent identity — verify a signed identity credential at decision time.

The brain↔body gate (Phase 0) and the externally-anchored receipt (Phase 1)
prove WHAT was decided and WHEN, but the agent_id in the receipt is whatever the
caller declared — the exact weakness research flagged in comparable shipping
products. This binds an enforcement decision to a CRYPTOGRAPHICALLY ATTESTED
identity: the agent presents an Ed25519-signed identity credential (an A2A
AgentCard / SPIFFE-SVID-style object), and we verify it OFFLINE against an
allow-listed issuer key before the attested identity is sealed into the
enforcement fact.

This implements the SAME verification scheme as the discovery-side
``EvidenceFold`` (``discovery/conduit/evidence_fold.py``): EdDSA (Ed25519) over
the JCS-canonical payload (RFC 8785-style: sorted keys, compact), verified
against an allow-listed issuer. It is kept as an independent, self-contained
primitive so the enforcement path never imports from discovery; a future
refactor may unify the two onto one shared verifier.

Honesty: a VERIFIED credential attests *who* the agent is; it does NOT raise
trust or lower risk on its own. An unsigned / tampered / untrusted-issuer /
oversize credential is ``verified=False`` with the reason in ``status`` — the
caller decides what to do (e.g. fail closed). Nothing here proves the agent is
benign, only that it is who an allow-listed issuer says it is.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse


class CredentialVerification(StrEnum):
    VERIFIED = "verified"
    UNSIGNED = "unsigned"
    TAMPERED = "tampered"
    UNTRUSTED_ISSUER = "untrusted_issuer"
    OVERSIZE = "oversize"
    EGRESS_BLOCKED = "egress_blocked"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    AUDIENCE_MISMATCH = "audience_mismatch"
    STALE_NO_EXPIRY = "stale_no_expiry"


def _jcs(payload: Any) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _check_freshness_audience(
    payload: Any,
    *,
    now: float | None,
    expected_audience: str | None,
    require_expiry: bool,
) -> CredentialVerification:
    """Enforce the SIGNED temporal + audience claims of a verified card.

    Returns ``VERIFIED`` only when the (signature-valid) payload is within its
    ``exp``/``nbf`` window and, when an audience is expected, names it. This is
    what turns a credential from a non-expiring, anywhere-valid bearer token into
    a short-lived, audience-scoped one — captured credentials stop working at
    ``exp`` and outside their ``aud``. Fail-closed: an unparseable ``exp``/``nbf``
    is treated as out-of-window. ``require_expiry`` rejects a card with no ``exp``
    at all (use in deployments that mandate freshness)."""
    import time as _time

    clock = now if now is not None else _time.time()
    claims = payload if isinstance(payload, dict) else {}

    exp = claims.get("exp")
    if exp is not None:
        try:
            if float(exp) < clock:
                return CredentialVerification.EXPIRED
        except (TypeError, ValueError):
            return CredentialVerification.EXPIRED
    elif require_expiry:
        return CredentialVerification.STALE_NO_EXPIRY

    nbf = claims.get("nbf")
    if nbf is not None:
        try:
            if float(nbf) > clock:
                return CredentialVerification.NOT_YET_VALID
        except (TypeError, ValueError):
            return CredentialVerification.NOT_YET_VALID

    if expected_audience is not None and claims.get("aud") != expected_audience:
        return CredentialVerification.AUDIENCE_MISMATCH

    return CredentialVerification.VERIFIED


def verify_signed_card(
    signed_card: dict[str, Any],
    *,
    trusted_issuers: dict[str, str],
    egress_allowlist: set[str] | None = None,
    max_bytes: int = 64 * 1024,
    source_url: str | None = None,
    now: float | None = None,
    expected_audience: str | None = None,
    require_expiry: bool = False,
) -> CredentialVerification:
    """Verify an Ed25519-signed identity card OFFLINE. Fail-closed: any defect
    returns a non-VERIFIED status. ``trusted_issuers`` maps issuer id -> base64
    raw-32-byte Ed25519 public key. ``source_url`` (if given) must be on the
    ``egress_allowlist``; omit it when the credential is presented directly.

    Freshness (anti-replay): a signature-valid card is additionally rejected when
    it is outside its signed ``exp``/``nbf`` window or, when ``expected_audience``
    is given, does not carry that ``aud`` — so a captured credential is not a
    forever-valid, anywhere-valid bearer token."""
    if source_url is not None:
        host = urlparse(source_url).hostname or ""
        if host not in (egress_allowlist or set()):
            return CredentialVerification.EGRESS_BLOCKED
    try:
        raw = _jcs(signed_card)
    except (TypeError, ValueError):
        return CredentialVerification.TAMPERED
    if len(raw) > max_bytes:
        return CredentialVerification.OVERSIZE
    payload = signed_card.get("payload")
    issuer = signed_card.get("issuer")
    sig_b64 = signed_card.get("signature_b64")
    if not sig_b64 or payload is None:
        return CredentialVerification.UNSIGNED
    issuer_key = trusted_issuers.get(str(issuer))
    if issuer_key is None:
        return CredentialVerification.UNTRUSTED_ISSUER
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pub = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(issuer_key.encode("ascii"))
        )
        pub.verify(base64.b64decode(str(sig_b64).encode("ascii")), _jcs(payload))
    except Exception:  # noqa: BLE001 — any verify failure is tampered, fail-closed
        return CredentialVerification.TAMPERED
    # Signature valid. Enforce freshness (exp/nbf) + audience on the SIGNED payload
    # so a captured credential is not a non-expiring, anywhere-valid bearer token.
    return _check_freshness_audience(
        payload,
        now=now,
        expected_audience=expected_audience,
        require_expiry=require_expiry,
    )


@dataclass(frozen=True, slots=True)
class AttestedIdentity:
    """The result of verifying an agent's identity credential."""

    verified: bool
    status: str  # a CredentialVerification value
    issuer: str | None
    claimed_agent_id: str | None
    method: str = "ed25519_agent_card"

    def to_detail(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "status": self.status,
            "issuer": self.issuer,
            "claimed_agent_id": self.claimed_agent_id,
            "method": self.method,
        }


def verify_agent_credential(
    signed_card: dict[str, Any],
    *,
    trusted_issuers: dict[str, str],
    egress_allowlist: set[str] | None = None,
    max_bytes: int = 64 * 1024,
    source_url: str | None = None,
    method: str = "ed25519_agent_card",
    now: float | None = None,
    expected_audience: str | None = None,
    require_expiry: bool = False,
) -> AttestedIdentity:
    """Verify a signed identity credential and return the attested identity.
    ``verified`` is True iff the signature checked out against an allow-listed
    issuer AND the card is within its ``exp``/``nbf`` window and (when
    ``expected_audience`` is given) names that audience; otherwise ``status``
    carries the fail-closed reason."""
    status = verify_signed_card(
        signed_card,
        trusted_issuers=trusted_issuers,
        egress_allowlist=egress_allowlist,
        max_bytes=max_bytes,
        source_url=source_url,
        now=now,
        expected_audience=expected_audience,
        require_expiry=require_expiry,
    )
    payload = signed_card.get("payload") if isinstance(signed_card, dict) else None
    claimed = payload.get("agent_id") if isinstance(payload, dict) else None
    issuer = signed_card.get("issuer") if isinstance(signed_card, dict) else None
    return AttestedIdentity(
        verified=(status is CredentialVerification.VERIFIED),
        status=status.value,
        issuer=str(issuer) if issuer else None,
        claimed_agent_id=str(claimed) if claimed else None,
        method=method,
    )
