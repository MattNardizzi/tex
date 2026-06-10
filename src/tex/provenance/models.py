"""
Provenance domain models — the sealed records and resolutions.

These are the things that get written, returned, and verified. A
``ProvenanceRecord`` is one sealed event in the transparency log. A
``ProvenanceResolution`` is the engine's graded answer to "who is this?"
A ``BehavioralBirthCertificate`` is the verifiable origin document for an
agent, anchored to its attested identity and behavioural signature.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from tex.domain.evidence import CombinedEvidence, EvidenceMaturity
from tex.domain.signal_trust import SignalTrustTier


class ProvenanceEventKind(StrEnum):
    """
    What a sealed provenance record represents. Past tense: by the time
    it lands in the log, the event has happened and is being witnessed.
    """

    BIRTH = "birth"  # first time an actor is witnessed; certificate sealed
    SIGHTING = "sighting"  # re-witnessed, identity confirmed, no change
    REIDENTIFIED = "reidentified"  # same actor recognized under a new name/key
    DRIFT = "drift"  # known agent's behaviour diverged from its baseline
    SLEPT = "slept"  # dormant agent put to sleep (reversible) on Tex's authority
    WOKE = "woke"  # sleeping agent woken by a sealed human act


class ProvenanceMatch(BaseModel):
    """One candidate identity match with its graded confidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: UUID
    confidence: float = Field(ge=0.0, le=1.0)
    signature_hash: str
    shared_anchors: int = Field(ge=0)


class ProvenanceResolution(BaseModel):
    """
    The engine's answer to "who is this actor?" — graded, never asserted.

    ``best_match`` is the strongest candidate (or None for a new actor).
    ``confidence`` is Tex's calibrated belief that the observed signature
    is ``best_match``. ``requires_human`` flags the case where the
    resolution is consequential and ambiguous enough that a person must
    decide (a possible merge or a drift past threshold) — that is the
    held-decision path, the only thing that earns the voice.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    observed_signature_hash: str
    event_kind: ProvenanceEventKind
    best_match: ProvenanceMatch | None = None
    alternatives: tuple[ProvenanceMatch, ...] = ()
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    warm: bool = False
    requires_human: bool = False
    note: str | None = None


class ProvenanceRecord(BaseModel):
    """
    One sealed, hash-chained, signed entry in the behavioural provenance
    transparency log. This is the Certificate-Transparency-for-agents
    record: anyone holding the public key can verify the chain and the
    signature without trusting Tex.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    sequence: int = Field(ge=0)
    event_kind: ProvenanceEventKind
    agent_id: UUID
    signature_hash: str

    # The graded belief, sealed alongside the fact — never a bare claim.
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    # The admissibility grade of the signal this rests on.
    signal_tier: int = Field(default=int(SignalTrustTier.NETWORK_OBSERVED))
    observation_count: int = Field(ge=0, default=0)

    # When REIDENTIFIED: the prior identity this actor was recognized as.
    linked_agent_id: UUID | None = None

    detail: dict[str, Any] = Field(default_factory=dict)
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Chain + signature fields (filled by the ledger on append).
    payload_sha256: str = ""
    previous_hash: str | None = None
    record_hash: str = ""
    signature_b64: str = ""
    signing_key_id: str = ""


class BehavioralBirthCertificate(BaseModel):
    """
    The verifiable origin document for an agent.

    Unlike a self-declared Agent Card, this is issued by Tex as a third-
    party witness and anchored to the agent's *attested* identity (its
    stable behavioural anchors) plus the sealed log sequence where its
    birth was witnessed. It is the thing a client hands an auditor — or
    another organization — to prove an agent's continuous identity across
    credential rotations and renames, offline, without trusting Tex.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    certificate_id: UUID = Field(default_factory=uuid4)
    agent_id: UUID
    signature_hash: str
    signal_tier: int
    signal_tier_label: str

    system_prompt_hash: str | None = None
    tool_manifest_hash: str | None = None
    memory_hash: str | None = None

    born_at: datetime
    born_at_sequence: int = Field(ge=0)
    last_seen_at: datetime
    observation_count: int = Field(ge=0)

    # The agent's *declared* purpose, sealed at birth (from a self-declared
    # card, a connector description, an operator note). Monitoring later
    # measures observed behaviour against this sealed declaration; the
    # drift is a signal nobody else has, because nobody else sealed the
    # original. ``None`` when the agent declared nothing.
    declared_intent: str | None = None

    # The sealed record hash of the BIRTH event — the anchor into the log.
    birth_record_hash: str
    signing_key_id: str


class CoverageBoundary(BaseModel):
    """
    The sealed edge of Tex's sight for one agent — a grade, not a graph.

    "Miss nothing" is asymptotic. A witness does not claim total coverage;
    it states which planes confirmed an agent, the strongest admissibility
    it can defend, and — honestly — what it cannot see. This is the
    coverage boundary surfaced *as a grade*: the inventory entry carries
    its own provenance, so a relying party reads not just "this agent
    exists" but "this is how well we can prove it, and here is the edge."
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: UUID
    # Strongest admissibility tier that has confirmed this agent.
    signal_tier: int
    signal_tier_label: str
    admissibility: str  # proven | observed | platform_attested | claimed

    # The planes (sources/tiers) that have actually confirmed this agent.
    confirmed_tiers: tuple[str, ...] = ()

    # Whether the confirming signal is one the workload cannot forge.
    tamper_resistant: bool = False

    # The honest edge, in one sealed sentence.
    edge_of_sight: str = ""

    observation_count: int = Field(ge=0, default=0)
    warm: bool = False


# ===========================================================================
# SealedFact — the typed, proof-carrying truth object (PCVR)
# ===========================================================================
#
# ``ProvenanceRecord`` above seals one *behavioural-identity* event. A
# ``SealedFact`` generalizes that to any governance action Tex must be able to
# prove later: a verdict, an enforcement, a drift alarm, a blame attribution,
# an identity event, a spoken answer. It is the "sealed truth object" — one
# canonical, typed record per action, and (this is the point) it can *carry its
# own proof*: an optional ``CombinedEvidence`` e-value scalar with its honest
# validity labels.
#
# Sealed into the hash-chained, signed ``SealedFactLedger`` (provenance/
# ledger.py), each fact becomes a Proof-Carrying Verdict Record (PCVR): the
# claim, the proof, and the cryptographic linkage, verifiable offline by anyone
# holding the public key. ``BehavioralProvenanceLedger`` is now one
# domain-specific instance of the same construction, kept intact.
#
# Honest limit: ``claim`` and ``maturity`` are producer-asserted descriptive
# fields; the ledger proves the fact was sealed unaltered and authored by Tex,
# and ``evidence`` (when present) carries its own machine-checkable validity —
# but the type does not verify that the prose ``claim`` matches the ``evidence``.
# The seal records both so an auditor checks the linkage.


class SealedFactKind(StrEnum):
    """What a sealed truth object asserts. The six governance actions Tex must
    be able to prove after the fact (ROADMAP §D)."""

    DECISION = "decision"        # a verdict was produced (PERMIT/ABSTAIN/FORBID)
    ENFORCEMENT = "enforcement"  # an action was allowed/blocked at the PEP
    DRIFT = "drift"              # a drift e-process crossed / was observed
    BLAME = "blame"              # responsibility/attribution was assigned
    IDENTITY = "identity"        # an agent identity event (birth / re-id)
    ANSWER = "answer"            # a grounded/spoken answer was sealed


class SealedFact(BaseModel):
    """One typed, sealable governance fact — optionally proof-carrying.

    Frozen + ``extra="forbid"`` like every sealed model. ``evidence`` is the
    proof-carrying part: a ``CombinedEvidence`` scalar (from the e-value spine)
    whose own ``is_true_e_value`` / ``anytime_valid`` labels say exactly what is
    proven. A fact with no e-value (e.g. an IDENTITY birth) simply omits it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    fact_id: UUID = Field(default_factory=uuid4)
    kind: SealedFactKind
    # What this fact concerns: a decision_id / agent_id / request_id, as a
    # string so the fact is agnostic to the subject's id type. None when the
    # subject is implicit.
    subject_id: str | None = Field(default=None, max_length=200)
    # The human-readable assertion being sealed (descriptive; the proof is
    # ``evidence``).
    claim: str = Field(min_length=1, max_length=2000)
    # The proof-carrying e-value, when the fact rests on one.
    evidence: CombinedEvidence | None = None
    # Honesty tag for the whole fact.
    maturity: EvidenceMaturity
    # Structured, JSON-native supporting detail.
    detail: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def canonical_payload(self) -> dict[str, Any]:
        """The ordered, JSON-safe dict the ledger seals. Embeds the evidence's
        own canonical payload so the proof is sealed inside the fact."""
        return {
            "fact_id": str(self.fact_id),
            "kind": self.kind.value,
            "subject_id": self.subject_id,
            "claim": self.claim,
            "evidence": self.evidence.canonical_payload() if self.evidence else None,
            "maturity": self.maturity.value,
            "detail": self.detail,
            "created_at": self.created_at.isoformat(),
        }


class SealedFactRecord(BaseModel):
    """One sealed, hash-chained, signed entry in the ``SealedFactLedger`` — the
    PCVR. Anyone holding the public key can verify the chain and the signature
    offline; the wrapped ``fact`` (with its embedded proof) is what was sealed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    sequence: int = Field(ge=0)
    fact: SealedFact

    payload_sha256: str
    previous_hash: str | None = None
    record_hash: str
    signature_b64: str
    signing_key_id: str
    sealed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
