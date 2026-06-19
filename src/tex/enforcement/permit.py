"""
The permit signer — the missing cryptographic mint/verify for Tex action permits.

``tex.memory.permit_store`` persists permits but explicitly does NOT produce them:
its docstring points here ("the actual cryptographic mint and signature live in
``tex.enforcement.permit``") for the nonce + signature. This module is that seam.

A *permit* is a short-lived, single-use authorization that the PDP released a
specific action. It is an HMAC-SHA256 over a canonical claim set with a shared
secret (``TEX_PERMIT_SIGNING_SECRET``); a verifier in any process trusts only
permits it can re-derive. The claims bind the permit to the *exact* action, so a
permit minted for one call cannot authorize another:

    pid   permit id (uuid)            aud   audience / recipient host
    did   PDP decision id (uuid)      act   action_type (the tool / verb)
    tn    tenant                      cd    content digest (sha256 of the
    aid   agent id (the principal)          committed argument bytes)
    nonce one-time-use token          exp   expiry (epoch seconds)

The content digest is what closes the check-vs-commit gap: the forwarder verifies
the permit against a fresh digest of the bytes it is about to send, so a permit
approved for content X cannot be replayed to send content Y.

Fail-closed posture, mirroring ``tex.gateway.grant`` / ``tex.api.auth``:
  * production-like env (``TEX_APP_ENV`` not in the dev set, or
    ``TEX_REQUIRE_AUTH=1``) with no ``TEX_PERMIT_SIGNING_SECRET`` set -> ``mint``
    returns None and ``verify`` returns not-ok. No guessable default ever signs a
    real permit.
  * dev with no secret -> a clearly-logged ephemeral per-process secret (loopback
    only; not cross-process stable).

Honesty — what a permit proves and what it does NOT:
  * It proves the PDP released THIS action (principal + audience + action +
    content), unforgeably, within its TTL. Single-use (double-spend) is enforced
    by the store's UNIQUE(nonce) constraint, not by this stateless module.
  * It does NOT make a third-party resource enforce it. A permit is Tex's own
    egress authority inside Tex's trust boundary — an external API will ignore the
    ``X-Tex-Permit`` header until taught to demand it. Universal enforcement is
    the credential-broker endgame, not a property this module grants on its own.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

__all__ = [
    "permit_secret",
    "is_production_like",
    "content_digest",
    "new_nonce",
    "MintedPermit",
    "PermitVerification",
    "mint",
    "verify",
]

_logger = logging.getLogger(__name__)

_PERMIT_VERSION = 1
_DEV_ENVS = frozenset({"dev", "development", "test", "testing", "local"})

# One ephemeral dev secret per process (only used when no real secret is set in a
# non-production env). Stable within a process so mint/verify agree.
_EPHEMERAL_DEV_SECRET = secrets.token_hex(32)


# --------------------------------------------------------------------------- #
# Secret resolution (fail-closed, identical rule to tex.gateway.grant)         #
# --------------------------------------------------------------------------- #


def is_production_like() -> bool:
    """True when signing must fail closed — same rule as ``tex.api.auth``."""
    if os.environ.get("TEX_REQUIRE_AUTH") == "1":
        return True
    env = (os.environ.get("TEX_APP_ENV") or "development").strip().casefold()
    return env not in _DEV_ENVS


def permit_secret() -> str | None:
    """The signing secret, or None when production requires one and none is set."""
    configured = os.environ.get("TEX_PERMIT_SIGNING_SECRET")
    if configured:
        return configured
    if is_production_like():
        return None  # fail closed: no guessable default signs a real permit
    _logger.warning(
        "TEX_PERMIT_SIGNING_SECRET unset in a non-production env — using an "
        "ephemeral per-process dev secret for permit HMAC (loopback only)."
    )
    return _EPHEMERAL_DEV_SECRET


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def content_digest(content: str | bytes | None) -> str | None:
    """SHA-256 hex of the action's committed argument bytes (or None)."""
    if content is None:
        return None
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def new_nonce() -> str:
    """A fresh one-time-use nonce (URL-safe)."""
    return secrets.token_urlsafe(18)


def _sign(secret: str, body: str) -> str:
    return _b64url(hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest())


def _canonical(claims: dict) -> str:
    """Deterministic claim serialization -> b64url body the signature covers."""
    return _b64url(
        json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


# --------------------------------------------------------------------------- #
# Mint                                                                         #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class MintedPermit:
    """A freshly minted permit, ready to attach to a request and persist."""

    token: str  # compact "body.sig" — goes in the X-Tex-Permit header
    signature: str  # the bare HMAC (the PermitStore.signature column)
    nonce: str
    permit_id: UUID
    decision_id: UUID
    expiry: datetime  # tz-aware UTC (what PermitStore.issue wants)
    claims: dict = field(default_factory=dict)

    @property
    def metadata(self) -> dict:
        """Binding claims for the store's metadata column (audit trail)."""
        return {
            "permit_id": str(self.permit_id),
            "agent_id": self.claims.get("aid"),
            "audience": self.claims.get("aud"),
            "action_type": self.claims.get("act"),
            "content_digest": self.claims.get("cd"),
        }


def mint(
    *,
    decision_id: UUID | str,
    tenant: str,
    action_type: str,
    agent_id: str | None = None,
    recipient: str | None = None,
    content: str | bytes | None = None,
    content_sha256: str | None = None,
    ttl_seconds: int = 30,
    permit_id: UUID | None = None,
    nonce: str | None = None,
    now: float | None = None,
) -> MintedPermit | None:
    """Mint a permit binding the release to this exact action.

    Returns None (fail-closed) when production requires a secret and none is set.
    Pass either ``content`` (it will be digested) or a precomputed
    ``content_sha256``; the digest binds the permit to the committed argument.
    """
    secret = permit_secret()
    if secret is None:
        return None

    pid = permit_id or uuid4()
    did = decision_id if isinstance(decision_id, UUID) else UUID(str(decision_id))
    nonce = nonce or new_nonce()
    issued = int(now if now is not None else time.time())
    exp = issued + int(ttl_seconds)
    cd = content_sha256 if content_sha256 is not None else content_digest(content)

    claims = {
        "v": _PERMIT_VERSION,
        "pid": str(pid),
        "did": str(did),
        "tn": tenant,
        "aid": agent_id,
        "aud": recipient,
        "act": action_type,
        "cd": cd,
        "nonce": nonce,
        "exp": exp,
    }
    body = _canonical(claims)
    sig = _sign(secret, body)
    return MintedPermit(
        token=f"{body}.{sig}",
        signature=sig,
        nonce=nonce,
        permit_id=pid,
        decision_id=did,
        expiry=datetime.fromtimestamp(exp, tz=UTC),
        claims=claims,
    )


# --------------------------------------------------------------------------- #
# Verify                                                                       #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class PermitVerification:
    ok: bool
    reason: str
    claims: dict | None = None


def verify(
    token: str | None,
    *,
    now: float | None = None,
    expected_content_digest: str | None = None,
    expected_audience: str | None = None,
    expected_action_type: str | None = None,
    expected_tenant: str | None = None,
    expected_agent_id: str | None = None,
) -> PermitVerification:
    """Verify a permit token. Never raises; any defect is a not-ok verdict.

    The optional ``expected_*`` checks bind the verification to the action the
    caller is *about to perform* — pass a fresh digest of the bytes you are about
    to forward to close the check-vs-commit (TOCTOU) gap.
    """
    secret = permit_secret()
    if secret is None:
        return PermitVerification(False, "no signing secret (fail-closed)")
    if not token or "." not in token:
        return PermitVerification(False, "malformed permit")

    body, _, sig = token.partition(".")
    expected_sig = _sign(secret, body)
    if not hmac.compare_digest(sig, expected_sig):
        return PermitVerification(False, "bad signature")

    try:
        claims = json.loads(_b64url_decode(body))
    except (ValueError, json.JSONDecodeError):
        return PermitVerification(False, "unparseable claims")

    if not isinstance(claims, dict) or claims.get("v") != _PERMIT_VERSION:
        return PermitVerification(False, "unsupported permit version")

    clock = now if now is not None else time.time()
    if int(claims.get("exp", 0)) < int(clock):
        return PermitVerification(False, "expired", claims)

    if expected_content_digest is not None and not hmac.compare_digest(
        str(claims.get("cd") or ""), expected_content_digest
    ):
        return PermitVerification(False, "content digest mismatch", claims)

    if expected_audience is not None and claims.get("aud") != expected_audience:
        return PermitVerification(False, "audience mismatch", claims)

    if expected_action_type is not None and claims.get("act") != expected_action_type:
        return PermitVerification(False, "action_type mismatch", claims)

    if expected_tenant is not None and claims.get("tn") != expected_tenant:
        return PermitVerification(False, "tenant mismatch", claims)

    if expected_agent_id is not None and claims.get("aid") != expected_agent_id:
        return PermitVerification(False, "agent mismatch", claims)

    return PermitVerification(True, "ok", claims)
