"""The frozen Presence contract — ONE verdict, three channels.

Every presence build session imports the shapes below and nothing else for the
shared seam. Pin first, freeze, then fan out. Refining a field here is a
breaking change that touches every session, so changes are deliberate and
versioned (:data:`CONTRACT_VERSION`).

WHY A SEPARATE VERDICT TYPE
---------------------------
``tex.domain.verdict.Verdict`` (``PERMIT | ABSTAIN | FORBID``) already exists and
is load-bearing: it is the GOVERNANCE verdict — *may this action be released?*
The presence layer answers a different question — *is this spoken claim
credible, and against what sealed evidence?* That is a separate axis, so it gets
a separate type (:class:`PresenceTier` / :class:`PresenceVerdict`). The two
layers share one human-escalation substrate: a presence ABSTAIN raises a
``HeldDecision`` tagged ``dimension="presence"`` into the existing
``HeldDecisionSink`` — no new vigil route is needed (the vigil provider already
reads ``dimension`` from the hold detail).

WHERE THIS PLUGS IN (the seam the orchestrator owns)
----------------------------------------------------
``src/tex/voice/voice_ask.py::answer_question`` is the live, deterministic,
zero-LLM path. The presence layer WRAPS it — it never replaces the sealed-fact
floor or the exact-match ``VoiceGate``:

  * line 202  ``_FACTS_EXPLAINER.explain(...)`` → the fact-fetch seam. The
    :class:`GroundedBrain` proposes a phrasing and candidate :class:`PresenceClaim`
    s from these *same* sealed facts (it never invents facts).
  * line 217-224 ``_GATE.evaluate(...)`` → the gating seam. The :class:`TruthGate`
    runs in PARALLEL to ``VoiceGate``: VoiceGate guards exact-match
    faithfulness of the templated answer; TruthGate assigns a per-claim
    :class:`PresenceTier` and recomputes aggregates. If the brain's phrasing
    asserts anything the verdicts don't support, it is stripped or the whole
    answer abstains and the deterministic templated answer is spoken instead.
  * ``AskOutcome`` (voice_ask.py:58) gains, at integration time, an optional
    ``presence: AnswerEnvelope | None`` field. The contract documents the shape;
    Session 2 adds the field when it wires the gate in. The legacy fields
    (``verdict``/``proof_ref``/``gate``) are untouched, so the existing UI and
    attestation chain keep working unchanged.

HONEST EDGES — baked in so no session can quietly overclaim
-----------------------------------------------------------
  * "Cannot lie" == "honest abstention with a provable correctness floor under
    stated assumptions" — marginal coverage, needs calibration + exchangeability,
    degrades under distribution shift. NOT absolute. See
    :attr:`PresenceVerdict.correctness_floor` / :attr:`PresenceVerdict.coverage_mode`.
  * Aggregates are RECOMPUTED by the gate from rows
    (:attr:`PresenceVerdict.recomputed_value`); the model never counts.
  * Attestation carries the ACTUAL signing algorithm
    (:attr:`Attestation.algorithm` / :attr:`Attestation.is_post_quantum`); it is
    post-quantum only when the ML-DSA backend is present, else honestly
    classical. Sealing is OFF unless ``TEX_SEAL_DECISIONS=1``.
  * Prosody is a PURE FUNCTION of the tier (:meth:`ProsodyPlan.from_tier`) —
    perceived confidence, derived from the gate's real verdict, never from model
    "vibe". The voice physically cannot bluff up because the tier is monotone.
  * Verifiable forgetting is sound BY AVOIDANCE (facts never touch weights), an
    architecture argument — not solved machine-unlearning.
  * Strict per-tenant isolation; no cross-customer learning.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from tex.domain.verdict import Verdict  # governance verdict, cross-referenced only

CONTRACT_VERSION = "1.0.0"

__all__ = [
    "CONTRACT_VERSION",
    "ClaimKind",
    "PresenceTier",
    "EvidenceRef",
    "PresenceClaim",
    "Attestation",
    "PresenceVerdict",
    "ProsodyPlan",
    "AnswerEnvelope",
    "tighten",
    "DEFAULT_PROSODY",
    "ReadTool",
    "GroundedBrain",
    "TruthGate",
    "PresenceAttestor",
    "ProsodyMapper",
    "PresenceMemory",
    "NULL_BRAIN",
    "NULL_GATE",
    "NULL_MEMORY",
]


# ─────────────────────────────────────────────────────────────────────────────
# Answer taxonomy — Tex always tells you the KIND of answer it is giving.
# Each kind is grounded differently (see the per-kind notes).
# ─────────────────────────────────────────────────────────────────────────────
class ClaimKind(StrEnum):
    """How a single claim is grounded."""

    ENTITY = "entity"
    """A named sealed object ("bring up agent X"). Grounded by direct record
    lookup (e.g. ``decision_store.get``/``agent_registry.get``)."""

    EVENT = "event"
    """Something that happened ("any recent shadow agents?"). Grounded by a row
    that exists in an append-only ledger (discovery_ledger / action_ledger)."""

    AGGREGATE = "aggregate"
    """A count or rate ("how many forbids?"). The GATE recomputes the value from
    rows and binds it to :attr:`PresenceVerdict.recomputed_value`; the model's
    number is never trusted."""

    DERIVED = "derived"
    """Forward-looking or computed-from-limits ("how many agents can I run?").
    Either computed from real limits, or a clearly-labelled calibrated estimate
    with a :attr:`PresenceVerdict.correctness_floor`, or ABSTAIN."""


class PresenceTier(StrEnum):
    """The credibility verdict for a claim. MONOTONE: a verdict may only move
    toward ABSTAIN, never inflate. Ordering (confident → cautious):
    ``SEALED > DERIVED > ABSTAIN``."""

    SEALED = "sealed"
    """Backed by sealed evidence the claim was checked against, byte-for-byte."""

    DERIVED = "derived"
    """A computed/estimated answer with a stated correctness floor; honest about
    being an estimate, not a sealed fact."""

    ABSTAIN = "abstain"
    """Cannot ground it. Tex says so out loud and (optionally) raises a hold."""


_TIER_RANK = {PresenceTier.SEALED: 2, PresenceTier.DERIVED: 1, PresenceTier.ABSTAIN: 0}


def tighten(a: PresenceTier, b: PresenceTier) -> PresenceTier:
    """Return the MORE CAUTIOUS of two tiers. Composition of checks may only
    lower a tier (monotonicity). This is the only sanctioned way to combine
    tiers — never a max()."""

    return a if _TIER_RANK[a] <= _TIER_RANK[b] else b


# ─────────────────────────────────────────────────────────────────────────────
# Evidence reference — points into the REAL sealed records.
# Mirrors tex.domain.evidence.EvidenceRecord (evidence_id / record_hash / chain)
# and the existing voice ProofRef ({kind,id,sha256,seq}).
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """A tamper-evident pointer to one sealed record the claim was checked
    against. ``record_id`` + ``record_hash`` are the load-bearing fields and are
    sufficient to fetch and re-verify the record offline."""

    record_id: str
    """Stable id of the record (str of EvidenceRecord.evidence_id / Decision
    .decision_id / DiscoveryLedgerEntry sequence, etc.)."""

    record_hash: str
    """64-char hex SHA-256 anchor (EvidenceRecord.record_hash). The offline
    verifier recomputes and compares this."""

    store: str
    """Which store/ledger the record lives in, e.g. "decision_store",
    "discovery_ledger", "evidence_jsonl", "sealed_fact_ledger"."""

    field: str | None = None
    """Optional: the specific field inside the record the claim quotes
    (e.g. "verdict", "scores", "registered_count")."""

    prior_link_witness: str | None = None
    """Optional: the predecessor record_hash, for single-record / slice
    inclusion proofs (verify_evidence_chain_slice)."""


@dataclass(frozen=True, slots=True)
class PresenceClaim:
    """One atomic assertion inside a spoken answer, tied to the exact span of
    text that asserts it. The gate emits one :class:`PresenceVerdict` per claim."""

    claim_id: str
    text_span: str
    """The exact substring of ``AnswerEnvelope.spoken_text`` this claim covers.
    Used to STRIP unsupported spans before speaking."""
    kind: ClaimKind


@dataclass(frozen=True, slots=True)
class Attestation:
    """A signed binding of (claim → evidence → tier). Honest about its own
    strength: ``algorithm`` is always the algorithm ACTUALLY used. Present only
    when sealing is enabled (``TEX_SEAL_DECISIONS=1``) and a signer is
    configured; otherwise ``None`` on the verdict."""

    algorithm: str
    """e.g. "composite-ml-dsa-65-ed25519" (post-quantum) or "ecdsa-p256"
    (classical fallback when the ML-DSA backend is absent). Never assume PQ —
    read this field."""
    signed_digest_sha256: str
    signature_b64: str
    is_post_quantum: bool
    key_id: str | None = None
    public_key_b64: str | None = None
    signed_at: str | None = None  # ISO-8601 UTC; stamped by the signer, not here


@dataclass(frozen=True, slots=True)
class PresenceVerdict:
    """The deterministic truth-gate's verdict for ONE claim. This is the single
    object that drives all three channels (words/proof/voice)."""

    claim_id: str
    tier: PresenceTier
    evidence: tuple[EvidenceRef, ...] = ()
    """The sealed records this claim was checked against. Empty iff ABSTAIN."""

    recomputed_value: Any | None = None
    """For AGGREGATE/DERIVED: the value the GATE computed from rows. The spoken
    answer must use THIS, not the model's number."""

    correctness_floor: float | None = None
    """For DERIVED estimates: the conformal lower bound on correctness
    (1 - alpha) from ConformalPredictionSet. None for SEALED facts (a sealed
    fact needs no statistical floor)."""

    coverage_mode: str | None = None
    """"calibrated" (formal marginal coverage, needs a calibration set) or
    "transductive" (approximate). Honest: a floor without "calibrated" mode is
    not a formal guarantee."""

    governance_verdict: Verdict | None = None
    """Optional cross-reference when the claim concerns a governed action
    (PERMIT/FORBID/ABSTAIN). Distinct from ``tier`` — different axis."""

    attestation: Attestation | None = None
    reason: str = ""
    """Human-readable, surfaced in the UI and in the abstain explanation."""

    def supports_speech(self) -> bool:
        """A claim may be spoken as asserted only if its tier is not ABSTAIN."""
        return self.tier is not PresenceTier.ABSTAIN


# ─────────────────────────────────────────────────────────────────────────────
# Prosody — a PURE FUNCTION of the tier. The mapping lives here (not in the TTS
# layer) precisely so prosody can never be sourced from model "vibe". Session 4
# wires these knobs into the backend; it does not get to invent the mapping.
# Evidence base: certain/honest speech == faster rate + falling terminal pitch
# (Goupil & Aucouturier, Nature Comms 12:861, 2021); uncertain == rising/level
# + filled pause (Swerts, Risk Analysis 44(10), 2024).
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class ProsodyPlan:
    """Deterministic prosody knobs derived from a single tier."""

    tier: PresenceTier
    style_label: str
    rate: float          # speech-rate multiplier (1.0 == neutral)
    terminal_pitch: str  # "falling" | "level" | "rising"
    lead_pause_ms: int   # a pause before speaking reads as deliberation, not lag

    @classmethod
    def from_tier(cls, tier: PresenceTier) -> "ProsodyPlan":
        if tier is PresenceTier.SEALED:
            return cls(tier, "assured", rate=1.05, terminal_pitch="falling", lead_pause_ms=0)
        if tier is PresenceTier.DERIVED:
            return cls(tier, "measured", rate=0.98, terminal_pitch="level", lead_pause_ms=120)
        return cls(tier, "uncertain", rate=0.9, terminal_pitch="rising", lead_pause_ms=280)


DEFAULT_PROSODY = ProsodyPlan.from_tier(PresenceTier.ABSTAIN)


@dataclass(frozen=True, slots=True)
class AnswerEnvelope:
    """The full presence answer: words + claims + verdicts + prosody, bound
    together. Carried on ``AskOutcome.presence``."""

    spoken_text: str
    claims: tuple[PresenceClaim, ...] = ()
    verdicts: tuple[PresenceVerdict, ...] = ()
    prosody_plan: ProsodyPlan = DEFAULT_PROSODY
    surface_object: dict[str, Any] | None = None
    """Optional structured object for the UI surface (hold-to-see)."""

    @property
    def overall_tier(self) -> PresenceTier:
        """The most cautious tier across all claims (monotone fold). An empty
        answer is ABSTAIN."""
        tier = PresenceTier.SEALED
        if not self.verdicts:
            return PresenceTier.ABSTAIN
        for v in self.verdicts:
            tier = tighten(tier, v.tier)
        return tier

    def assert_supported(self) -> None:
        """Enforce the core rule: every claim must have a verdict, and the
        envelope's prosody must match its overall tier. Raises ``ValueError`` on
        violation — call this in the integration seam BEFORE speaking; on
        failure, fall back to the deterministic templated answer + ABSTAIN.

        Note: this checks structural integrity (claim↔verdict pairing, prosody
        binding). STRIPPING unsupported spans from ``spoken_text`` is the gate's
        job (Session 2) and happens before this is constructed."""
        verdict_ids = {v.claim_id for v in self.verdicts}
        for c in self.claims:
            if c.claim_id not in verdict_ids:
                raise ValueError(f"claim {c.claim_id!r} has no verdict")
        if self.prosody_plan.tier is not self.overall_tier:
            raise ValueError(
                f"prosody tier {self.prosody_plan.tier} != overall tier "
                f"{self.overall_tier} — prosody must be a pure function of the verdict"
            )

    def with_bound_prosody(self) -> "AnswerEnvelope":
        """Return a copy whose prosody is the pure function of the overall tier.
        The sanctioned way to set prosody — never set it from any other source."""
        return replace(self, prosody_plan=ProsodyPlan.from_tier(self.overall_tier))


# ─────────────────────────────────────────────────────────────────────────────
# Seam protocols — the interfaces each session implements. The orchestrator
# wires concrete implementations in; until a session lands, the NULL_* no-ops
# keep the live deterministic voice path working untouched.
# ─────────────────────────────────────────────────────────────────────────────
@runtime_checkable
class ReadTool(Protocol):
    """Session 1: a deterministic read over sealed app.state stores. Returns the
    aggregate value AND the source refs so a caller can re-verify by iterating
    rows. No inference, no caching of estimates, no model."""

    name: str

    def __call__(self, request: Any, *, tenant: str | None, **kwargs: Any) -> tuple[Any, tuple[EvidenceRef, ...]]:
        ...


@runtime_checkable
class GroundedBrain(Protocol):
    """Session 1: an off-the-shelf, SWAPPABLE reasoning model (e.g. Claude via a
    new ``StructuredSemanticProvider``). It proposes a phrasing and candidate
    claims FROM the sealed facts it is handed; it never sources facts itself and
    its output is never load-bearing until the gate verifies it."""

    def propose(
        self, *, question: str, tenant: str | None, facts: Any, tools: tuple[ReadTool, ...]
    ) -> tuple[str, tuple[PresenceClaim, ...]]:
        """Return (draft spoken_text, candidate claims). Pure proposal."""
        ...


@runtime_checkable
class TruthGate(Protocol):
    """Session 2 (the heart): the deterministic, external truth-gate. For each
    candidate claim it returns a monotone :class:`PresenceVerdict`, recomputing
    aggregates from rows and binding evidence. Hostile text in the draft can
    never flip a verdict — the gate checks against sealed evidence, not the
    draft's assertions."""

    def evaluate(
        self,
        *,
        request: Any,
        tenant: str | None,
        draft: str,
        claims: tuple[PresenceClaim, ...],
        facts: Any,
    ) -> tuple[PresenceVerdict, ...]:
        ...


@runtime_checkable
class PresenceAttestor(Protocol):
    """Session 3: binds (claim → evidence → tier) into a signed
    :class:`Attestation`. Honest about algorithm strength; returns ``None`` when
    sealing is disabled."""

    def attest(self, *, claim: PresenceClaim, verdict: PresenceVerdict) -> Attestation | None:
        ...


@runtime_checkable
class ProsodyMapper(Protocol):
    """Session 4: maps a tier to TTS knobs. The DEFAULT mapping is the pure
    function :meth:`ProsodyPlan.from_tier`; Session 4 translates it to backend
    parameters but may not derive prosody from anything other than the tier."""

    def plan(self, tier: PresenceTier) -> ProsodyPlan:
        ...


@runtime_checkable
class PresenceMemory(Protocol):
    """Session 5: sealed, per-tenant, write-gated, FORGETTABLE memory. Facts
    live only here, never in weights. ``forget`` is sound by avoidance."""

    def recall(self, *, tenant: str, query: str) -> tuple[EvidenceRef, ...]:
        ...

    def seal(self, *, tenant: str, claim: PresenceClaim, verdict: PresenceVerdict) -> EvidenceRef:
        ...

    def forget(self, *, tenant: str, record_id: str) -> bool:
        """Return True iff the record was present and is now unrecoverable from
        this store. (Vendor-model caching is outside Tex's boundary — disclose,
        do not claim to control.)"""
        ...


# ─────────────────────────────────────────────────────────────────────────────
# NULL implementations — the live voice path keeps working before sessions land.
# A null brain proposes nothing; a null gate abstains on everything; null memory
# remembers nothing. The orchestrator's default is "presence not engaged" →
# fall back to the existing deterministic templated answer.
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class _NullBrain:
    def propose(self, *, question, tenant, facts, tools):  # noqa: ANN001
        return ("", ())


@dataclass(frozen=True, slots=True)
class _NullGate:
    def evaluate(self, *, request, tenant, draft, claims, facts):  # noqa: ANN001
        return tuple(
            PresenceVerdict(claim_id=c.claim_id, tier=PresenceTier.ABSTAIN, reason="presence-not-engaged")
            for c in claims
        )


@dataclass(frozen=True, slots=True)
class _NullMemory:
    def recall(self, *, tenant, query):  # noqa: ANN001
        return ()

    def seal(self, *, tenant, claim, verdict):  # noqa: ANN001
        raise NotImplementedError("null memory does not seal")

    def forget(self, *, tenant, record_id):  # noqa: ANN001
        return False


NULL_BRAIN: GroundedBrain = _NullBrain()
NULL_GATE: TruthGate = _NullGate()
NULL_MEMORY: PresenceMemory = _NullMemory()
