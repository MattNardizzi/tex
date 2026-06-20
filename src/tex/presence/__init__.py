"""Tex Presence — the sovereign, proof-carrying voice layer.

This package is the substrate around an off-the-shelf reasoning model (NOT a
custom LLM). Facts never live in model weights; honesty is external and
deterministic. One deterministic truth-gate emits ONE monotone verdict per
claim — ``{SEALED | DERIVED | ABSTAIN}`` — and that single verdict drives three
bound channels: the spoken WORDS, the cryptographic PROOF, and the VOICE
prosody.

The frozen cross-session contract lives in :mod:`tex.presence.contract`. Every
build session (brain, gate, attest, voice, memory, UI) imports from there and
nowhere else for shared shapes, so the sessions can build in parallel without
drifting.

Sub-packages (created by their owning session, all under ``tex.presence``):
    brain/    — grounded reasoning + read-tools over sealed stores (Session 1)
    gate/     — truth-gate + abstain + conformal floor (Session 2, the heart)
    attest/   — proof-carrying speech / grounding attestation (Session 3)
    prosody/  — epistemic prosody voice mapping (Session 4)
    memory/   — mnemonic sovereignty (sealed, per-tenant, forgettable) (Session 5)
"""

from tex.presence.contract import (
    CONTRACT_VERSION,
    Attestation,
    AnswerEnvelope,
    ClaimKind,
    DEFAULT_PROSODY,
    EvidenceRef,
    GroundedBrain,
    NULL_BRAIN,
    NULL_GATE,
    NULL_MEMORY,
    PresenceAttestor,
    PresenceClaim,
    PresenceMemory,
    PresenceTier,
    PresenceVerdict,
    ProsodyMapper,
    ProsodyPlan,
    ReadTool,
    TruthGate,
    tighten,
)

__all__ = [
    "CONTRACT_VERSION",
    "Attestation",
    "AnswerEnvelope",
    "ClaimKind",
    "DEFAULT_PROSODY",
    "EvidenceRef",
    "GroundedBrain",
    "NULL_BRAIN",
    "NULL_GATE",
    "NULL_MEMORY",
    "PresenceAttestor",
    "PresenceClaim",
    "PresenceMemory",
    "PresenceTier",
    "PresenceVerdict",
    "ProsodyMapper",
    "ProsodyPlan",
    "ReadTool",
    "TruthGate",
    "tighten",
]
