"""Tex Presence — mnemonic sovereignty (Session 5).

Sealed, per-tenant, write-gated, FORGETTABLE memory where presence facts live —
NEVER in model weights. One deterministic truth-gate's verdicts are sealed here as
content-anchored records the brain/gate can later recall and ground against, and
that any tenant can have forgotten.

The package implements the frozen ``PresenceMemory`` protocol
(:mod:`tex.presence.contract`) and feeds the learning flywheel: sealed human
resolutions of held decisions become a per-tenant conformal calibration set, so
confirmed resolutions accrue real labels that move Session 2's DERIVED floor from
transductive (approximate) toward a calibrated — selection-conditional — floor.

Public surface (the orchestrator wires these in; the live voice path is untouched):

    from tex.presence.memory import build_presence_memory, build_calibration_feed
    from tex.presence.memory import SealedPresenceMemory, PresenceCalibrationFeed
    from tex.presence.memory import tenant_calibration_env

HONEST EDGES (baked in; cited from this session's design survey — never overclaimed)
-----------------------------------------------------------------------------------
  * Forgetting is sound BY AVOIDANCE — presence facts are only ever written to
    this store, never trained into weights, so there is nothing parametric to
    unlearn. "Delete from the external retrieval store, not the weights" is a
    named technique for closed-source models (arXiv:2410.15267). ``forget``
    governs THIS store only; it makes NO claim over a vendor model's KV-cache or
    prompt-logging of a prior ``recall`` result, nor over any ref already copied
    out. It is an architecture argument, NOT certified machine-unlearning, and its
    ``True`` is scoped to one store instance.
  * Per-tenant isolation is application-layer ONLY (in-memory dict outer key +
    ``WHERE tenant_id``). NO Postgres RLS, no schema partitioning, no
    encryption-at-rest — the literature's *weak* isolation tier (OWASP LLM08:2025).
  * STRICT per-tenant: no cross-customer learning. The calibration feed is
    per-tenant; there is no global calibration file. It forwards a refused
    resolution's own ``Decision.final_score`` unmodified (never invents one) and
    trusts its caller to pass the server-looked-up ``Decision``, not a request value.
  * The conformal floor this feed earns is SELECTION-CONDITIONAL, per-tenant — NOT
    i.i.d. split-conformal marginal coverage (held resolutions are a selected,
    non-exchangeable tail; arXiv:2403.03868). The ``MIN_CALIBRATION_N`` floor is a
    WRITER-side convention (the feed withholds the scores file below it); the
    conformal consumer enforces no n-check, so the floor holds only while this feed
    is the sole producer of a tenant's calibration path.
  * A record's ``record_hash`` is a CONTENT ANCHOR (recomputable sha256), not a
    chain-membership proof (``prior_link_witness`` is always ``None``). The
    optional ``pq_signature`` is post-quantum only when an ML-DSA backend is
    present (else honestly ``ecdsa-p256``), and present only when
    ``TEX_SEAL_DECISIONS=1``.
"""

from tex.presence.memory.calibration import (
    MIN_CALIBRATION_N,
    PRESENCE_ORIGIN_DIMENSION,
    CalibrationResolution,
    PresenceCalibrationFeed,
    calibration_available,
    calibration_disabled_env,
    default_calibration_feed,
    forget_resolution_for_calibration,
    is_presence_origin_decision,
    record_resolution_for_calibration,
    tenant_calibration_env,
)
from tex.presence.memory.durable import PresenceDurableMirror
from tex.presence.memory.hooks import build_calibration_feed, build_presence_memory
from tex.presence.memory.records import (
    SealedPresenceRecord,
    presence_record_hash,
)
from tex.presence.memory.store import SealedPresenceMemory

__all__ = [
    "SealedPresenceMemory",
    "SealedPresenceRecord",
    "PresenceDurableMirror",
    "PresenceCalibrationFeed",
    "CalibrationResolution",
    "presence_record_hash",
    "tenant_calibration_env",
    "calibration_disabled_env",
    "calibration_available",
    "default_calibration_feed",
    "is_presence_origin_decision",
    "record_resolution_for_calibration",
    "forget_resolution_for_calibration",
    "build_presence_memory",
    "build_calibration_feed",
    "MIN_CALIBRATION_N",
    "PRESENCE_ORIGIN_DIMENSION",
]
