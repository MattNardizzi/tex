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
  * RECORDING (the flywheel's fuel) — wire ONE call into the
    ``/decisions/{id}/seal`` handler, AFTER ``recorder.record_human_resolution``
    for a presence-tagged hold::

        from tex.presence.memory import (
            record_resolution_for_calibration, CalibrationResolution,
        )
        record_resolution_for_calibration(
            tenant,  # the AUTHENTICATED request tenant — Decision carries no tenant
            CalibrationResolution(
                decision=decision,            # the SERVER-LOOKED-UP Decision
                human_verdict=body.verdict,   # "approved" | "held" | "refused"
            ),
        )

    Only a ``refused`` resolution records a label; it never raises into the seal
    flow (best-effort, like ``outcome_autoseal``). ``resolution`` may also be a
    plain dict ``{"decision": ..., "human_verdict": ...}`` — it is duck-typed.

  * READING (L1 — the gate self-selects per tenant). DO **NOT** wrap the gate call
    in ``tenant_calibration_env`` any more: the DERIVED gate now points at the
    tenant's calibration file itself (``tex.presence.gate.conformal``), so a
    forgotten wrap can't silently defeat the flywheel, and double-wrapping can't
    deadlock (the env lock is re-entrant). Just pass the ``tenant`` into the gate
    as it already does.

  * PATH AGREEMENT (do not get this wrong, or the flywheel silently no-ops). The
    seal hook's writer and the gate's reader must resolve to the SAME directory for
    a tenant. Both ``record_resolution_for_calibration`` (no explicit feed) and the
    gate use ``default_calibration_feed()``, which reads ``TEX_PRESENCE_CALIBRATION_DIR``
    (default ``./data/presence_calibration``). So the safe wiring is: **set
    ``TEX_PRESENCE_CALIBRATION_DIR`` once at startup and pass NO custom ``base_dir``
    anywhere.** If you must inject a feed with a custom ``base_dir`` into the hook,
    you MUST also point the gate at the same dir (set the env to it) — otherwise the
    writer fills one directory while the reader watches another and nothing ever
    calibrates.
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
