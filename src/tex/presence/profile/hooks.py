"""Orchestrator wiring hooks for presence PROFILE memory.

The ONLY surface the orchestrator touches. The live voice path
(``main.py`` / ``voice/voice_ask.py``) is never edited by this session; at
integration the orchestrator constructs these and hangs them off ``app.state``
(e.g. ``app.state.presence_profile``), exactly as it already does for
``app.state.presence_memory``.

INTEGRATION CONTRACT (for the orchestrator owner)
-------------------------------------------------
  * ``build_profile_memory(durable=..., sign=...)`` → a
    :class:`~tex.presence.profile.store.SealedProfileMemory` implementing the
    :class:`~tex.presence.profile.types.ProfileMemory` protocol. ``durable=True``
    enables the Postgres mirror (no-op unless ``DATABASE_URL`` is set). A signer is
    attached only when sealing is on (``sign=True`` or ``TEX_SEAL_DECISIONS=1``);
    we never mint a key when sealing is off.
  * Wire it onto ``app.state.presence_profile`` and register the confirm/correct
    router via ``tex.api.presence_profile_routes.build_presence_profile_router``.
  * In the presence run (``run_presence``), insert ONE line between the gate call
    and ``build_envelope``:
        ``detailed = apply_profile_corrections(tenant=tenant, evaluations=detailed,
        profile=app.state.presence_profile)``
"""

from __future__ import annotations

import logging
import os
from typing import Any

from tex.presence.profile.durable import ProfileDurableMirror
from tex.presence.profile.store import SealedProfileMemory

_logger = logging.getLogger(__name__)

__all__ = ["build_profile_memory"]


def _sealing_enabled(sign: bool | None) -> bool:
    if sign is not None:
        return sign
    return os.environ.get("TEX_SEAL_DECISIONS") == "1"


def build_profile_memory(
    *,
    durable: bool = False,
    sign: bool | None = None,
    signer: Any | None = None,
) -> SealedProfileMemory:
    """Build the profile-memory store the orchestrator wires onto app.state.

    ``durable`` — attach the Postgres mirror (a no-op when ``DATABASE_URL`` is
    unset). ``sign`` — force-enable/disable signing; ``None`` follows
    ``TEX_SEAL_DECISIONS``. ``signer`` — inject a pre-built signer; otherwise a
    default evidence-chain signer is built lazily ONLY when sealing is enabled.
    """
    mirror = ProfileDurableMirror() if durable else None

    resolved_signer = signer
    if resolved_signer is None and _sealing_enabled(sign):
        try:
            from tex.evidence.seal import build_evidence_chain_signer

            resolved_signer = build_evidence_chain_signer()
            algo = getattr(getattr(resolved_signer, "algorithm", None), "value", "?")
            _logger.info(
                "presence profile: sealing ENABLED — signer algorithm=%s "
                "(post-quantum only if an ML-DSA backend is present; else honestly "
                "classical ecdsa-p256)",
                algo,
            )
        except Exception:
            _logger.exception(
                "presence profile: could not build a signer; sealing degrades to "
                "content-anchor-only (facts still carry a recomputable hash, no "
                "authorship signature)"
            )
            resolved_signer = None

    return SealedProfileMemory(mirror=mirror, signer=resolved_signer)
