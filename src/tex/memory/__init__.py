"""
Tex memory system — public API.

The memory layer is the system of record for every durable artifact
Tex produces: decisions, inputs, policy snapshots, permits, verifications,
and the evidence chain. Every consumer should import from this package
and never reach into the individual store modules — the layout below is
load-bearing for the locked spec.

Usage::

    from tex.memory import MemorySystem

    memory = MemorySystem(
        tenant_id="default",
        evidence_path="./data/evidence.jsonl",
    )

    memory.record_decision(
        decision=decision,
        full_input=request_payload,
    )

    health = memory.health()
    assert health.durable

    # Replay
    from tex.memory import MemoryReplayEngine
    engine = MemoryReplayEngine(
        decisions=memory.decisions,
        inputs=memory.inputs,
        policies=memory.policies,
        evaluator=my_evaluator,
    )
    result = engine.replay(decision.decision_id)
    assert result.is_clean
"""

from tex.memory.decision_input_store import (
    DecisionInputStore,
    StoredDecisionInput,
)
from tex.memory.decision_store import DurableDecisionStore
from tex.memory.evidence_store import (
    DurableEvidenceStore,
    StoredEvidenceRecord,
)
from tex.memory.permit_store import (
    PermitNotFoundError,
    PermitStore,
    StoredPermit,
)
from tex.memory.policy_snapshot_store import DurablePolicyStore
from tex.memory.replay import (
    MemoryReplayEngine,
    ReplayDivergence,
    ReplayMissingArtifactError,
    ReplayResult,
)
from tex.memory.system import MemoryHealth, MemorySystem
from tex.memory.verification_store import (
    StoredVerification,
    VerificationResult,
    VerificationStore,
)

__all__ = [
    # Orchestrator
    "MemorySystem",
    "MemoryHealth",
    # Decision aggregate
    "DurableDecisionStore",
    "DecisionInputStore",
    "StoredDecisionInput",
    # Policy aggregate
    "DurablePolicyStore",
    # Permits + verifications
    "PermitStore",
    "StoredPermit",
    "PermitNotFoundError",
    "VerificationStore",
    "StoredVerification",
    "VerificationResult",
    # Evidence
    "DurableEvidenceStore",
    "StoredEvidenceRecord",
    # Replay
    "MemoryReplayEngine",
    "ReplayResult",
    "ReplayDivergence",
    "ReplayMissingArtifactError",
]
