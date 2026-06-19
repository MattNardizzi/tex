"""Load the PEP's trusted-issuer key map from the environment (G6).

``verify_agent_credential`` (``agent_credential.py``) checks an agent's signed
identity card against a map ``{issuer_id: base64 raw-32-byte Ed25519 pubkey}``.
This module is the ONE place that builds that map from operator configuration so
a bad key fails at BOOT, not silently per-request.

Resolution (fail-closed, file preferred over inline):
  * ``TEX_PEP_TRUSTED_ISSUERS_FILE`` — path to a JSON object
    ``{issuer_id: base64_ed25519_pubkey}``. Preferred.
  * ``TEX_PEP_TRUSTED_ISSUERS`` — the SAME JSON object inline (used only when
    the file var is unset).
  * Neither set -> ``{}`` (the unchanged default: no issuer trusted, so no
    credential verifies; with ``require_identity`` False this degrades to the
    documented header-trust gap — see ``proxy._verify_identity``).

Any defect — unreadable file, malformed JSON, a non-object shape, a value that
is not a string, a base64 that does not decode, or a key that is not a valid
32-byte Ed25519 public key — raises :class:`IssuerKeyError`. The caller
(``pep/__main__.build_app``) does not catch it, so the proxy REFUSES TO BOOT on a
misconfigured key rather than starting and rejecting every credential at runtime
with an opaque ``untrusted_issuer``.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping

__all__ = ["IssuerKeyError", "load_trusted_issuers"]

_FILE_VAR = "TEX_PEP_TRUSTED_ISSUERS_FILE"
_INLINE_VAR = "TEX_PEP_TRUSTED_ISSUERS"


class IssuerKeyError(ValueError):
    """A trusted-issuer key map could not be loaded or validated at boot."""


def load_trusted_issuers(env: Mapping[str, str]) -> dict[str, str]:
    """Build ``{issuer_id: base64_ed25519_pubkey}`` from ``env`` (fail-closed).

    Returns ``{}`` when neither env var is set (the unchanged default). Raises
    :class:`IssuerKeyError` on any malformed input so misconfiguration is caught
    at boot, never silently swallowed into a runtime "untrusted_issuer" for every
    request.
    """
    raw = _read_source(env)
    if raw is None:
        return {}

    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise IssuerKeyError(f"trusted-issuers JSON is malformed: {exc}") from exc
    if not isinstance(parsed, dict):
        raise IssuerKeyError(
            "trusted-issuers must be a JSON object {issuer_id: base64_pubkey}"
        )

    issuers: dict[str, str] = {}
    for issuer, key_b64 in parsed.items():
        if not isinstance(issuer, str) or not issuer:
            raise IssuerKeyError(f"trusted-issuers issuer id must be a non-empty string: {issuer!r}")
        if not isinstance(key_b64, str) or not key_b64:
            raise IssuerKeyError(
                f"trusted-issuers key for {issuer!r} must be a non-empty base64 string"
            )
        _validate_ed25519_pubkey(issuer, key_b64)
        issuers[issuer] = key_b64
    return issuers


def _read_source(env: Mapping[str, str]) -> str | None:
    """Return the raw JSON text from the file var (preferred) or the inline var,
    or ``None`` when neither is set. A configured-but-unreadable file is a boot
    error, not a silent fall-through to the inline var."""
    file_path = (env.get(_FILE_VAR) or "").strip()
    if file_path:
        try:
            with open(file_path, encoding="utf-8") as fh:
                return fh.read()
        except OSError as exc:
            raise IssuerKeyError(
                f"cannot read {_FILE_VAR}={file_path!r}: {exc}"
            ) from exc
    inline = (env.get(_INLINE_VAR) or "").strip()
    return inline or None


def _validate_ed25519_pubkey(issuer: str, key_b64: str) -> None:
    """Decode and load the key so an invalid one fails at boot, not per-request.

    Mirrors exactly what ``verify_signed_card`` does at verify time
    (``Ed25519PublicKey.from_public_bytes(base64.b64decode(...))``) so a key that
    boots here is a key that will verify there."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        raw_key = base64.b64decode(key_b64.encode("ascii"), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise IssuerKeyError(
            f"trusted-issuers key for {issuer!r} is not valid base64: {exc}"
        ) from exc
    if len(raw_key) != 32:
        raise IssuerKeyError(
            f"trusted-issuers key for {issuer!r} is {len(raw_key)} bytes, "
            "expected 32 (raw Ed25519 public key)"
        )
    try:
        Ed25519PublicKey.from_public_bytes(raw_key)
    except Exception as exc:  # noqa: BLE001 — any load failure is a boot-time reject
        raise IssuerKeyError(
            f"trusted-issuers key for {issuer!r} is not a valid Ed25519 public key: {exc}"
        ) from exc
