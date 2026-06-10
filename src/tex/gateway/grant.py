"""
[Architecture: Voice infrastructure] — the short-lived recognizer grant.

``GET /v1/voice/token`` mints a token here; the gateway verifies it on connect.
The token is an HMAC-SHA256 over ``{tenant, exp}`` with a shared secret
(``TEX_VOICE_GATEWAY_SECRET``) — no long-lived secret ever reaches the browser
bundle, and the gateway trusts only tokens it can re-derive.

Fail-closed posture, mirroring ``tex.api.auth``:
  * In a production-like environment (``TEX_APP_ENV`` not in the dev set, or
    ``TEX_REQUIRE_AUTH=1``) with NO secret configured, minting and verification
    both refuse — the caller surfaces 503 / closes the socket. The voice loop is
    OFF rather than protected by a guessable default.
  * In dev with no secret, a clearly-labelled ephemeral per-process dev secret
    is used so the loopback works locally; tokens are still real HMACs, just not
    cross-process-stable. This is logged, not silent.
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

__all__ = ["voice_secret", "make_token", "verify_token", "is_production_like"]

_logger = logging.getLogger(__name__)

_DEV_ENVS = frozenset({"dev", "development", "test", "testing", "local"})

# One ephemeral dev secret per process (only used when no real secret is set in
# a non-production env). Stable within a process so mint/verify agree.
_EPHEMERAL_DEV_SECRET = secrets.token_hex(32)


def is_production_like() -> bool:
    """True when auth must fail closed — same rule as ``tex.api.auth``."""
    if os.environ.get("TEX_REQUIRE_AUTH") == "1":
        return True
    env = (os.environ.get("TEX_APP_ENV") or "development").strip().casefold()
    return env not in _DEV_ENVS


def voice_secret() -> str | None:
    """The signing secret, or None when production requires one and none is set."""
    configured = os.environ.get("TEX_VOICE_GATEWAY_SECRET")
    if configured:
        return configured
    if is_production_like():
        return None  # fail closed: no guessable default in production
    _logger.warning(
        "TEX_VOICE_GATEWAY_SECRET unset in a non-production env — using an "
        "ephemeral per-process dev secret for voice-token HMAC (loopback only)."
    )
    return _EPHEMERAL_DEV_SECRET


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def make_token(tenant: str | None, *, ttl_seconds: int = 120) -> tuple[str, int] | None:
    """Return ``(token, expires_at_epoch)`` or None when no secret is available."""
    secret = voice_secret()
    if secret is None:
        return None
    exp = int(time.time()) + int(ttl_seconds)
    body = _b64url(json.dumps({"tenant": tenant, "exp": exp}, separators=(",", ":")).encode("utf-8"))
    sig = _b64url(hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest())
    return f"{body}.{sig}", exp


def verify_token(token: str | None) -> tuple[bool, str | None]:
    """Return ``(ok, tenant)``. ok is False on any malformation, bad signature,
    or expiry. Never raises."""
    secret = voice_secret()
    if secret is None or not token or "." not in token:
        return False, None
    body, _, sig = token.partition(".")
    expected = _b64url(hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        return False, None
    try:
        claims = json.loads(_b64url_decode(body))
    except (ValueError, json.JSONDecodeError):
        return False, None
    if int(claims.get("exp", 0)) < int(time.time()):
        return False, None
    return True, claims.get("tenant")
