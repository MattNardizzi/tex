"""Orchestrator wiring hooks for presence memory.

This is the ONLY surface the orchestrator touches. The live voice path
(``main.py`` / ``voice/voice_ask.py``) is never edited by this session; at
integration the orchestrator constructs these and hangs them off ``app.state``
(e.g. ``app.state.presence_memory``), exactly as it already does for
``app.state.presence_brain``.

INTEGRATION CONTRACT (for the orchestrator owner)
-------------------------------------------------
  * ``build_presence_memory(durable=..., sign=...)`` → a
    :class:`~tex.presence.memory.store.SealedPresenceMemory` implementing the
    contract's ``PresenceMemory`` protocol. Pass ``durable=True`` to enable the
    Postgres mirror (no-op unless ``DATABASE_URL`` is set). A signer is attached
    only when sealing is on (``sign=True`` or ``TEX_SEAL_DECISIONS=1``).
  * ``build_calibration_feed()`` → a
    :class:`~tex.presence.memory.calibration.PresenceCalibrationFeed`. Wire it in
    the ``/decisions/{id}/seal`` handler: AFTER ``recorder.record_human_resolution``
    for a presence-tagged hold, call
    ``feed.record_resolution(tenant=..., decision=decision, human_verdict=body.verdict)``.
    Around the DERIVED gate call, wrap with
    ``tenant_calibration_env(feed, tenant)`` so the gate reads the tenant's file
    (and concurrent tenants serialize on the process-global env var).
"""

from __future__ import annotations

import logging
import os
from typing import Any

from tex.presence.memory.calibration import PresenceCalibrationFeed
from tex.presence.memory.durable import PresenceDurableMirror
from tex.presence.memory.store import SealedPresenceMemory

_logger = logging.getLogger(__name__)

__all__ = ["build_presence_memory", "build_calibration_feed"]


def _sealing_enabled(sign: bool | None) -> bool:
    if sign is not None:
        return sign
    return os.environ.get("TEX_SEAL_DECISIONS") == "1"


def build_presence_memory(
    *,
    durable: bool = False,
    sign: bool | None = None,
    signer: Any | None = None,
) -> SealedPresenceMemory:
    """Build the presence-memory store the orchestrator wires onto app.state.

    ``durable`` — attach the Postgres mirror (a no-op when ``DATABASE_URL`` is
    unset, so this is safe to default-on in prod and harmless in tests).
    ``sign`` — force-enable/disable signing; ``None`` follows
    ``TEX_SEAL_DECISIONS``. ``signer`` — inject a pre-built signer (e.g. an
    HSM/KMS-backed one); otherwise a default evidence-chain signer is built lazily
    when sealing is enabled. We never mint a key when sealing is off.
    """
    mirror = PresenceDurableMirror() if durable else None

    resolved_signer = signer
    if resolved_signer is None and _sealing_enabled(sign):
        try:
            from tex.evidence.seal import build_evidence_chain_signer

            resolved_signer = build_evidence_chain_signer()
            algo = getattr(getattr(resolved_signer, "algorithm", None), "value", "?")
            _logger.info(
                "presence memory: sealing ENABLED — signer algorithm=%s "
                "(post-quantum only if an ML-DSA backend is present; else "
                "honestly classical ecdsa-p256)",
                algo,
            )
        except Exception:
            # Sealing must degrade to content-anchor-only, never break startup.
            _logger.exception(
                "presence memory: could not build a signer; sealing degrades to "
                "content-anchor-only (records still carry a recomputable hash, no "
                "authorship signature)"
            )
            resolved_signer = None

    return SealedPresenceMemory(mirror=mirror, signer=resolved_signer)


def build_calibration_feed(*, base_dir: str | None = None) -> PresenceCalibrationFeed:
    """Build the per-tenant conformal calibration feed (the learning flywheel)."""
    return PresenceCalibrationFeed(base_dir=base_dir)
