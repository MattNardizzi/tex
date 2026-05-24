"""
Intel TDX (Trust Domain Extensions) attestation evidence collector.

Production path
---------------
When ``TEX_TEE_MODE=1`` and the Python bindings for Intel's
``trustauthority-client-for-python`` are installed AND the host runs an
Intel TDX-capable kernel (Ubuntu 24.04 LTS, kernel >= 6.8 per ITA
requirements), this module imports
``inteltrustauthorityclient.tdx.intel`` and collects a real TD Quote.

Dev-mode fallback
-----------------
When the SDK is unavailable or the host is not TDX-capable, this module
returns a deterministic stub evidence blob clearly marked as
non-production (``is_dev_mode=True``). Every consumer downstream
(``composite.compose_attestation``, the verifier, the evidence
recorder) propagates this flag; auditors must reject ``is_dev_mode``
records when reasoning about production claims.

References
----------
* Intel Trust Authority Python Client:
  https://github.com/intel/trustauthority-client-for-python
* ITA composite attestation spec:
  https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-gpu-attestation.html
* arxiv 2605.03213 §VII (May 7 2026): identifies "partial TEE shielding"
  as a 2026 attack surface. Tex therefore records ``tdx_is_debuggable``
  and the verifier treats debuggable=True as fail-closed.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from dataclasses import dataclass

_logger = logging.getLogger(__name__)


__all__ = [
    "TdxEvidence",
    "collect_tdx_evidence",
    "is_tdx_capable",
    "fresh_user_data",
]


@dataclass(frozen=True, slots=True)
class TdxEvidence:
    """Raw TDX evidence ready for ITA submission."""

    quote: bytes
    user_data: bytes
    is_dev_mode: bool
    platform: str


def is_tdx_capable() -> bool:
    """Return True iff the host has a TDX-capable kernel AND the Intel
    Trust Authority Python client is importable."""
    try:
        import importlib

        importlib.import_module("inteltrustauthorityclient.tdx.intel")
    except ImportError:
        return False
    except Exception:  # noqa: BLE001
        return False

    candidate_paths = (
        "/sys/kernel/config/tsm/report",
        "/dev/tdx_guest",
    )
    return any(os.path.exists(p) for p in candidate_paths)


def collect_tdx_evidence(*, user_data: bytes | None = None) -> TdxEvidence:
    """Collect a TD Quote bound to ``user_data``.

    On TDX-capable hosts: real TD Quote via Intel Trust Authority Python
    client. Otherwise: deterministic dev-mode stub marked
    ``is_dev_mode=True``.
    """
    ud = user_data if user_data is not None else b""

    if is_tdx_capable():
        try:
            from inteltrustauthorityclient.tdx.intel.intel_tdx_adapter import (  # type: ignore[import-not-found]
                IntelTDXAdapter,
            )

            adapter = IntelTDXAdapter(user_data=ud)
            evidence = adapter.collect_evidence(nonce=ud)
            quote_bytes = getattr(evidence, "quote", None) or getattr(
                evidence, "evidence", b""
            )
            if not isinstance(quote_bytes, (bytes, bytearray)):
                raise RuntimeError(
                    "Intel TDX adapter returned non-bytes evidence"
                )
            return TdxEvidence(
                quote=bytes(quote_bytes),
                user_data=ud,
                is_dev_mode=False,
                platform="tdx-baremetal",
            )
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"TDX evidence collection failed on capable host: {exc}"
            ) from exc

    seed = hashlib.sha256(b"tex-tdx-dev-stub" + ud).digest()
    quote_stub = (seed * 16)[:512]
    return TdxEvidence(
        quote=quote_stub,
        user_data=ud,
        is_dev_mode=True,
        platform="dev-stub",
    )


def fresh_user_data(seed: str = "") -> bytes:
    """Generate 64 bytes of user-data suitable for binding to a TD Quote.

    Per ITA convention the lower 32 bytes of report_data MUST be a
    SHA-256 of the user data; the upper 32 bytes are caller-defined.
    """
    upper = hashlib.sha256(
        seed.encode("utf-8") if seed else secrets.token_bytes(32)
    ).digest()
    lower = hashlib.sha256(upper).digest()
    return upper + lower
