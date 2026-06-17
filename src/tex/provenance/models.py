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


# ===========================================================================
# Crypto-agile seal envelope — the post-quantum dual-signature primitive
# ===========================================================================
#
# A sealed record's ``record_hash`` is signed once per algorithm. Today that is
# ECDSA-P256 (for every verifier shipping now) PLUS ML-DSA-65 (FIPS 204, the
# post-quantum authorship signature). The set of signatures is carried in a
# ``SealEnvelope`` with an explicit ``seal_version`` so a future migration can
# add or retire an algorithm *without touching the hash chain*: every signature
# covers the same ``record_hash`` the chain already commits to, so adding the
# envelope changes neither ``payload_sha256`` nor ``record_hash``.
#
# Backward compatibility is structural: a legacy ECDSA-only record carries
# ``seal_envelope = None`` and is verified through its ``signature_b64`` exactly
# as before. The envelope is purely additive.


class SealSignature(BaseModel):
    """One algorithm's signature over a record's ``record_hash``.

    ``algorithm`` is a :class:`~tex.pqcrypto.algorithm_agility.SignatureAlgorithm`
    *value* (a plain string, e.g. ``"ecdsa-p256"`` / ``"ml-dsa-65"``), not the
    enum — so a record sealed under an algorithm a future reader does not know
    still deserializes and is honestly reported as "unverifiable", never a crash.
    The signed message is the same ``record_hash`` bytes the legacy
    ``signature_b64`` covers, which is what keeps the hash chain unchanged.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    algorithm: str = Field(min_length=1, max_length=64)
    key_id: str = Field(min_length=1, max_length=200)
    signature_b64: str = Field(min_length=1)


class SealEnvelope(BaseModel):
    """A crypto-agile set of signatures over one record's ``record_hash``.

    The migration-friendly seal: an explicit ``seal_version`` plus one
    :class:`SealSignature` per algorithm. ``is_dual`` is the post-quantum
    property — at least two distinct algorithms (a classical one for today's
    verifiers and a post-quantum one). A future migration adds/retires an
    algorithm here and bumps ``seal_version`` without disturbing ``record_hash``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    seal_version: str = Field(min_length=1, max_length=16)
    signatures: tuple[SealSignature, ...] = Field(min_length=1)

    def algorithms(self) -> tuple[str, ...]:
        """The algorithm tags present, in envelope order (primary first)."""
        return tuple(s.algorithm for s in self.signatures)

    def signature_for(self, algorithm: str) -> "SealSignature | None":
        """The signature tagged ``algorithm``, or ``None`` if absent."""
        for sig in self.signatures:
            if sig.algorithm == algorithm:
                return sig
        return None

    @property
    def is_dual(self) -> bool:
        """True when the envelope binds two or more distinct algorithms."""
        return len({s.algorithm for s in self.signatures}) >= 2


class SealPublicKey(BaseModel):
    """A public key a verifier needs to check one algorithm's seal signature.

    Carried in the offline bundle next to the records. It is **not** a basis of
    trust on its own: the verifier checks signatures against a *pinned* key and
    flags any substitution (see ``provenance/bundle.py``). ECDSA keys are PEM
    bytes; ML-DSA keys are the raw FIPS 204 §5.3 public-key encoding.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    algorithm: str = Field(min_length=1, max_length=64)
    key_id: str = Field(min_length=1, max_length=200)
    public_key_b64: str = Field(min_length=1)


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

    # Crypto-agile dual signature over ``record_hash``. ``None`` for a legacy
    # ECDSA-only record (verified via ``signature_b64``); a ``SealEnvelope`` with
    # ECDSA-P256 + ML-DSA-65 once the post-quantum signer is active. Additive: it
    # never enters ``payload_sha256`` / ``record_hash``, so the chain is unchanged.
    seal_envelope: SealEnvelope | None = None


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
    """What a sealed truth object asserts. The seven governance actions Tex
    must be able to prove after the fact (ROADMAP §D; ATTEMPT is the Wave-2
    attempt-hook addition — pre-verdict by definition, so L3's count
    conservation derives from sealed facts instead of trust-me inputs)."""

    ATTEMPT = "attempt"          # an evaluation was begun (pre-verdict, evaluate() entry)
    DECISION = "decision"        # a verdict was produced (PERMIT/ABSTAIN/FORBID)
    ENFORCEMENT = "enforcement"  # an action was allowed/blocked at the PEP
    DRIFT = "drift"              # a drift e-process crossed / was observed
    BLAME = "blame"              # responsibility/attribution was assigned
    IDENTITY = "identity"        # an agent identity event (birth / re-id)
    ANSWER = "answer"            # a grounded/spoken answer was sealed
    # The canonical execution transcript + monotonicity witness for one verdict
    # (engine/verdict_transcript.py). A DISTINCT kind on purpose: it is neither a
    # verdict (DECISION) nor a pre-verdict marker (ATTEMPT), so L1's seal-binding
    # and L3's count-conservation — both keyed on DECISION — never see it.
    VERDICT_TRANSCRIPT = "verdict_transcript"


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

    # Crypto-agile dual signature over ``record_hash`` (ECDSA-P256 + ML-DSA-65).
    # ``None`` for a legacy ECDSA-only PCVR — verified via ``signature_b64``, the
    # backward-compatible path. Additive: never part of the sealed payload or the
    # chain, so a dual-signed bundle and a legacy bundle share identical chains.
    seal_envelope: SealEnvelope | None = None

    sealed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
