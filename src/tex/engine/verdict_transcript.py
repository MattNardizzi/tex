"""
Canonical verdict transcript + monotonicity witness.

[Architecture: Layer 0 (Evidence / self-certification substrate)]

What this is
------------
Tex's verdict pipeline (``engine/pdp.py``) is DETERMINISTIC: recognizers →
retrieval → agent governance → judges → behavioral/path contracts → STRUCTURAL
FORBID FLOOR → routing/fusion → monotone-lowering holds → CRC gate → seal. No
LLM sits in the verdict path. This module turns that run into a *canonical,
deterministic, hashable execution TRANSCRIPT* — an ordered record of each
pipeline stage with ``{stage, signal_id, score-before, score-after, direction}``
— and derives a MONOTONICITY WITNESS asserting the engine's two load-bearing
invariants actually held on this run:

  1. **Signals only lower a verdict toward caution.** No stage moved the verdict
     toward PERMIT (every transforming step is non-decreasing in *caution* —
     PERMIT → ABSTAIN → FORBID — and never decreases the risk score). This is
     the runtime contract the router (``engine/router.py``) and the CRC gate
     (``engine/crc_gate.py``, RCPS one-sided bound) are built to honor.
  2. **The structural floor forces FORBID, regardless of model scores.** When a
     deterministic structural deny fired (PCAS / CaMeL / IFC / ARGUS proof,
     Rule-of-Two trifecta, RV4 permanent path, action-class FORBID cell, a
     behavioral-contract hard violation, or a path-policy ``block``), the verdict
     is FORBID with risk 1.0 — the short-circuit at ``pdp.py`` (``final_score =
     1.0``), not a fused inference.

Why it is built this way
------------------------
This transcript is the SUBSTRATE for three things Tex does not have yet and is
deliberately leaving room for:

  * **zk-Verdict** — a future zk proof that *some* sealed transcript with this
    hash satisfies the monotonicity witness, without revealing the private
    per-stream scores. The transcript hash is the public commitment; the witness
    is the relation. NOTHING here is a zk proof today: this module emits a plain
    SHA-256 commitment over the canonical transcript (``hashlib`` below) — no
    succinct-argument backend exists, so the maturity of the zk story is
    ``speculative``. Keeping the schema canonical + versioned + byte-stable is
    only what makes a future circuit *possible*; it does not claim one.
  * **Proof-carrying verdicts** — a verdict that travels with its own replayable
    execution trace + witness, sealed into the ledger, verifiable offline by
    anyone holding Tex's public key.
  * **The self-certifying checker** — an offline checker (the ``night/offline-
    checker`` thread) that RECOMPUTES the witness from the transcript and
    confirms it matches the sealed one. ``verify_transcript_witness`` is its
    entry point; this module imports only ``Verdict`` + pydantic + stdlib so the
    checker need not pull the whole engine.

Honesty (what the witness does and does NOT prove)
--------------------------------------------------
The witness proves a STRUCTURAL property of *the recorded trace*: that, as
recorded, no stage relaxed the verdict and the floor forced FORBID. It does NOT
prove the verdict is the *correct* output of the policy (that is L1 / zkPDP), and
it does NOT by itself prove the trace faithfully reflects the live run — the seal
(``provenance/transcript_seal.py``, ECDSA-P256 + hash chain) proves authorship +
integrity of the recorded transcript, never its semantic correctness. The
endpoints the witness rests on (router base verdict, final verdict, structural
floor) are captured from the live ``RoutingResult`` objects; the per-hold
attribution inside the aggregate ``monotone_holds`` stage is reconstructed from
the durable outcome flags and is labelled as such — see ``build_verdict_transcript``.

Schema stability contract (read before changing anything)
---------------------------------------------------------
``TRANSCRIPT_SCHEMA_VERSION`` / ``WITNESS_SCHEMA_VERSION`` are bumped on ANY
change to ``canonical_payload`` shape or field semantics. Identical inputs MUST
produce a byte-identical ``canonical_json`` — no timestamps, no insertion-order
dict iteration, no unrounded floats. All scores are rounded to
``_SCORE_NDIGITS`` so the serialization is platform-stable.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from tex.domain.verdict import Verdict

if TYPE_CHECKING:  # hints only — keep runtime imports light for the offline checker
    from tex.deterministic.gate import DeterministicGateResult
    from tex.domain.agent_signal import AgentEvaluationBundle
    from tex.engine.contract_bridge import ContractEvaluationOutcome
    from tex.engine.path_policy_bridge import PathPolicyOutcome
    from tex.engine.router import RoutingResult
    from tex.semantic.schema import SemanticAnalysis
    from tex.specialists.base import SpecialistBundle
    from tex.specialists.structural_floor import StructuralFloorResult


# Bumped on any change to canonical_payload shape or field semantics.
TRANSCRIPT_SCHEMA_VERSION = "vtx-1"
WITNESS_SCHEMA_VERSION = "vtw-1"

# All risk / signal scores are rounded to this precision before serialization so
# the canonical JSON is byte-identical across platforms and float reprs.
_SCORE_NDIGITS = 6
# Float comparison tolerance for the monotonicity / continuity checks. Scores are
# rounded to 6 digits, so anything tighter than this is serialization noise.
_EPS = 1e-9

# Caution ordering. The whole monotonicity invariant is: this rank is
# NON-DECREASING across the transforming stages (the verdict never moves toward
# PERMIT). Higher rank = more caution.
_CAUTION_RANK: dict[Verdict, int] = {
    Verdict.PERMIT: 0,
    Verdict.ABSTAIN: 1,
    Verdict.FORBID: 2,
}


class StageDirection(StrEnum):
    """Which way a pipeline stage moved the running verdict.

    ``TOWARD_PERMIT`` is the ONLY value that is an invariant violation — it means
    a stage relaxed the verdict (raised permissiveness / lowered the risk score
    / lowered the caution rank). ``EVIDENCE`` marks a non-transforming stage that
    produced a signal feeding fusion but did not itself move the running verdict.
    """

    EVIDENCE = "evidence"          # produced a signal; did not transform the verdict
    HELD = "held"                  # ran, but verdict + risk unchanged
    TOWARD_CAUTION = "toward_caution"  # lowered the verdict (PERMIT→ABSTAIN→FORBID) / raised risk
    TOWARD_PERMIT = "toward_permit"    # raised the verdict toward PERMIT — A VIOLATION


def _round_score(value: float) -> float:
    """Clamp to [0, 1] and round so the canonical form is byte-stable."""
    return round(min(1.0, max(0.0, float(value))), _SCORE_NDIGITS)


class TranscriptStage(BaseModel):
    """One ordered pipeline stage in a canonical verdict transcript.

    ``risk_before`` / ``risk_after`` are the engine-oriented *caution* score
    (∈ [0, 1], higher = more caution / toward FORBID; the structural FORBID floor
    sets it to 1.0). They mirror ``RoutingResult.final_score``. ``signal_score``
    is the stage's own risk contribution for an EVIDENCE stage (e.g. the
    specialist max-risk that fed fusion), ``None`` for a transforming stage.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    index: int = Field(ge=0)
    stage: str = Field(min_length=1, max_length=80)
    signal_id: str = Field(min_length=1, max_length=200)

    verdict_before: Verdict
    verdict_after: Verdict
    risk_before: float = Field(ge=0.0, le=1.0)
    risk_after: float = Field(ge=0.0, le=1.0)

    direction: StageDirection
    applied: bool = False
    signal_score: float | None = Field(default=None, ge=0.0, le=1.0)
    detail: dict[str, Any] = Field(default_factory=dict)

    def canonical_payload(self) -> dict[str, Any]:
        """Ordered, JSON-safe dict — the unit the transcript hash commits to."""
        return {
            "index": self.index,
            "stage": self.stage,
            "signal_id": self.signal_id,
            "verdict_before": self.verdict_before.value,
            "verdict_after": self.verdict_after.value,
            "risk_before": self.risk_before,
            "risk_after": self.risk_after,
            "direction": self.direction.value,
            "applied": self.applied,
            "signal_score": self.signal_score,
            "detail": self.detail,
        }


class VerdictTranscript(BaseModel):
    """The canonical, deterministic, hashable execution transcript for one verdict.

    Byte-identical inputs produce a byte-identical ``canonical_json`` — there is
    no timestamp here on purpose (the ledger envelope carries time, the trace
    does not). ``transcript_hash`` is the public commitment a zk circuit or an
    offline checker attests.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = TRANSCRIPT_SCHEMA_VERSION

    request_id: str = Field(min_length=1, max_length=200)
    policy_id: str = Field(min_length=1, max_length=200)
    policy_version: str = Field(min_length=1, max_length=200)
    content_sha256: str = Field(min_length=1, max_length=200)
    determinism_fingerprint: str = Field(min_length=1, max_length=200)

    final_verdict: Verdict
    final_risk_score: float = Field(ge=0.0, le=1.0)
    structural_floor_fired: bool
    hard_violation: bool

    stages: tuple[TranscriptStage, ...] = Field(default_factory=tuple)

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "content_sha256": self.content_sha256,
            "determinism_fingerprint": self.determinism_fingerprint,
            "final_verdict": self.final_verdict.value,
            "final_risk_score": self.final_risk_score,
            "structural_floor_fired": self.structural_floor_fired,
            "hard_violation": self.hard_violation,
            "stages": [stage.canonical_payload() for stage in self.stages],
        }

    def canonical_json(self) -> str:
        """Stable serialization — sorted keys, tight separators, no ASCII escape.
        Same idiom as ``domain/evidence.py`` and ``provenance/ledger.py`` so a
        transcript sealed into the ledger re-serializes byte-identically."""
        return json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def transcript_hash(self) -> str:
        """SHA-256 hex of ``canonical_json`` — the commitment the seal + witness
        bind to, and the public input a future zk-Verdict circuit attests."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


class WitnessViolation(BaseModel):
    """One place the monotonicity invariant was violated on the recorded trace."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    stage_index: int = Field(ge=0)
    stage: str
    kind: str  # verdict_raised_toward_permit | risk_score_decreased | continuity_break | floor_not_forbid | final_mismatch
    detail: str
    verdict_before: Verdict
    verdict_after: Verdict
    risk_before: float = Field(ge=0.0, le=1.0)
    risk_after: float = Field(ge=0.0, le=1.0)

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "stage_index": self.stage_index,
            "stage": self.stage,
            "kind": self.kind,
            "detail": self.detail,
            "verdict_before": self.verdict_before.value,
            "verdict_after": self.verdict_after.value,
            "risk_before": self.risk_before,
            "risk_after": self.risk_after,
        }


class MonotonicityWitness(BaseModel):
    """The derived assertion that the verdict invariants held on a transcript.

    ``holds`` is True iff (a) no transforming stage moved the verdict toward
    PERMIT, (b) the running verdict + risk thread continuously through the stages,
    (c) the structural floor, when it fired, forced FORBID at risk 1.0, and
    (d) the recorded endpoint matches ``final_verdict`` / ``final_risk_score``.
    ``transcript_hash`` binds this witness to the exact transcript it was derived
    from — an offline checker re-derives and compares (``verify_transcript_witness``).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = WITNESS_SCHEMA_VERSION
    transcript_hash: str = Field(min_length=1, max_length=200)

    holds: bool
    final_verdict: Verdict
    n_stages: int = Field(ge=0)
    n_transforming_stages: int = Field(ge=0)

    structural_floor_fired: bool
    structural_floor_forced_forbid: bool

    violations: tuple[WitnessViolation, ...] = Field(default_factory=tuple)
    checked_invariants: tuple[str, ...] = Field(default_factory=tuple)

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "transcript_hash": self.transcript_hash,
            "holds": self.holds,
            "final_verdict": self.final_verdict.value,
            "n_stages": self.n_stages,
            "n_transforming_stages": self.n_transforming_stages,
            "structural_floor_fired": self.structural_floor_fired,
            "structural_floor_forced_forbid": self.structural_floor_forced_forbid,
            "violations": [v.canonical_payload() for v in self.violations],
            "checked_invariants": list(self.checked_invariants),
        }

    def canonical_json(self) -> str:
        return json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def witness_hash(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


# ===========================================================================
# Witness derivation + verification — the pure, offline-checkable core
# ===========================================================================


def _caution_increased(
    verdict_before: Verdict,
    risk_before: float,
    verdict_after: Verdict,
    risk_after: float,
) -> bool:
    """True iff this step moved STRICTLY toward caution (rank up, or rank equal
    and risk up)."""
    rank_before = _CAUTION_RANK[verdict_before]
    rank_after = _CAUTION_RANK[verdict_after]
    if rank_after != rank_before:
        return rank_after > rank_before
    return risk_after > risk_before + _EPS


def _classify_direction(
    verdict_before: Verdict,
    risk_before: float,
    verdict_after: Verdict,
    risk_after: float,
) -> StageDirection:
    """Direction of a transforming step from its endpoints."""
    rank_before = _CAUTION_RANK[verdict_before]
    rank_after = _CAUTION_RANK[verdict_after]
    if rank_after < rank_before:
        return StageDirection.TOWARD_PERMIT
    if rank_after > rank_before:
        return StageDirection.TOWARD_CAUTION
    # Equal rank — tie-break on the risk score.
    if risk_after > risk_before + _EPS:
        return StageDirection.TOWARD_CAUTION
    if risk_after < risk_before - _EPS:
        return StageDirection.TOWARD_PERMIT
    return StageDirection.HELD


_FLOOR_STAGE = "structural_forbid_floor"


def derive_monotonicity_witness(transcript: VerdictTranscript) -> MonotonicityWitness:
    """Derive the monotonicity witness from a transcript — the PURE relation.

    Walks the ordered stages, threading a running ``(verdict, risk)`` state, and
    records a violation for any transforming stage that (a) breaks continuity
    with the running state, (b) moves the verdict toward PERMIT, or (c) decreases
    the risk score. Then it checks the structural-floor-forces-FORBID invariant
    and the final-endpoint consistency. ``EVIDENCE``-direction stages are signals
    only and are skipped by the transforming-stage checks.

    This is what a zk circuit encodes and what the offline checker recomputes; it
    reads only the transcript, never the live engine.
    """
    violations: list[WitnessViolation] = []
    checked: list[str] = [
        "monotone_lowering:no_stage_raises_verdict_toward_permit",
        "monotone_lowering:risk_score_non_decreasing",
        "continuity:running_state_threads_through_stages",
        "structural_floor:fired_implies_forbid_at_risk_one",
        "endpoint:last_state_matches_final_verdict",
    ]

    n_transforming = 0
    structural_floor_forced_forbid = False

    # Running state starts at the most-permissive prior; the first stage must be
    # continuous with it (the builder emits a pipeline_entry anchor at PERMIT/0).
    running_verdict = Verdict.PERMIT
    running_risk = 0.0
    have_running = False

    for stage in transcript.stages:
        if stage.direction is StageDirection.EVIDENCE:
            # A signal-only stage. It must not pretend to transform the verdict.
            if (
                stage.verdict_before is not stage.verdict_after
                or abs(stage.risk_after - stage.risk_before) > _EPS
            ):
                violations.append(
                    _violation(
                        stage,
                        "continuity_break",
                        "an EVIDENCE stage changed the running verdict/risk; "
                        "evidence stages must be non-transforming",
                    )
                )
            continue

        n_transforming += 1

        # (b) Continuity: the stage must start where the pipeline currently is.
        if have_running and (
            stage.verdict_before is not running_verdict
            or abs(stage.risk_before - running_risk) > _EPS
        ):
            violations.append(
                _violation(
                    stage,
                    "continuity_break",
                    f"stage starts at ({stage.verdict_before.value}, "
                    f"{stage.risk_before}) but the running state is "
                    f"({running_verdict.value}, {running_risk})",
                )
            )

        # (c) Monotonicity: never toward PERMIT, never a risk decrease.
        if _CAUTION_RANK[stage.verdict_after] < _CAUTION_RANK[stage.verdict_before]:
            violations.append(
                _violation(
                    stage,
                    "verdict_raised_toward_permit",
                    f"verdict moved {stage.verdict_before.value} → "
                    f"{stage.verdict_after.value} (toward PERMIT)",
                )
            )
        if stage.risk_after < stage.risk_before - _EPS:
            violations.append(
                _violation(
                    stage,
                    "risk_score_decreased",
                    f"risk score dropped {stage.risk_before} → {stage.risk_after} "
                    "(relaxed toward PERMIT)",
                )
            )

        # The structural FORBID floor: when it applies it must force FORBID@1.0.
        if stage.stage == _FLOOR_STAGE and stage.applied:
            if stage.verdict_after is Verdict.FORBID and stage.risk_after >= 1.0 - _EPS:
                structural_floor_forced_forbid = True
            else:
                violations.append(
                    _violation(
                        stage,
                        "floor_not_forbid",
                        "structural floor applied but did not force FORBID@1.0 "
                        f"(got {stage.verdict_after.value}@{stage.risk_after})",
                    )
                )

        running_verdict = stage.verdict_after
        running_risk = stage.risk_after
        have_running = True

    # (d) Endpoint consistency: the recorded trace must land on the final verdict.
    if have_running and (
        running_verdict is not transcript.final_verdict
        or abs(running_risk - transcript.final_risk_score) > _EPS
    ):
        violations.append(
            WitnessViolation(
                stage_index=len(transcript.stages),
                stage="<final>",
                kind="final_mismatch",
                detail=(
                    f"trace ends at ({running_verdict.value}, {running_risk}) but "
                    f"transcript.final = ({transcript.final_verdict.value}, "
                    f"{transcript.final_risk_score})"
                ),
                verdict_before=running_verdict,
                verdict_after=transcript.final_verdict,
                risk_before=_round_score(running_risk),
                risk_after=transcript.final_risk_score,
            )
        )

    # If the floor is recorded as fired, it MUST have forced FORBID somewhere.
    if transcript.structural_floor_fired and not structural_floor_forced_forbid:
        violations.append(
            WitnessViolation(
                stage_index=len(transcript.stages),
                stage=_FLOOR_STAGE,
                kind="floor_not_forbid",
                detail=(
                    "transcript marks the structural floor fired, but no applied "
                    "floor stage forced FORBID@1.0"
                ),
                verdict_before=Verdict.PERMIT,
                verdict_after=transcript.final_verdict,
                risk_before=0.0,
                risk_after=transcript.final_risk_score,
            )
        )

    return MonotonicityWitness(
        transcript_hash=transcript.transcript_hash(),
        holds=not violations,
        final_verdict=transcript.final_verdict,
        n_stages=len(transcript.stages),
        n_transforming_stages=n_transforming,
        structural_floor_fired=transcript.structural_floor_fired,
        structural_floor_forced_forbid=structural_floor_forced_forbid,
        violations=tuple(violations),
        checked_invariants=tuple(checked),
    )


def _violation(stage: TranscriptStage, kind: str, detail: str) -> WitnessViolation:
    return WitnessViolation(
        stage_index=stage.index,
        stage=stage.stage,
        kind=kind,
        detail=detail,
        verdict_before=stage.verdict_before,
        verdict_after=stage.verdict_after,
        risk_before=stage.risk_before,
        risk_after=stage.risk_after,
    )


def recompute_witness(transcript: VerdictTranscript) -> MonotonicityWitness:
    """Alias for ``derive_monotonicity_witness`` — the name the offline checker
    reads as "recompute, do not trust the sealed one"."""
    return derive_monotonicity_witness(transcript)


def verify_transcript_witness(
    transcript: VerdictTranscript,
    witness: MonotonicityWitness,
) -> bool:
    """Self-certifying check: does ``witness`` match what ``transcript`` implies?

    The offline checker's entry point. Recomputes the witness from the transcript
    and confirms (a) the witness binds to THIS transcript by hash, (b) the
    recomputed verdict/violations/holds match the supplied witness byte-for-byte.
    Returns True only when the supplied witness is exactly the one this transcript
    derives — a tampered transcript, a swapped witness, or a forged "holds=True"
    all fail here.
    """
    if witness.transcript_hash != transcript.transcript_hash():
        return False
    recomputed = derive_monotonicity_witness(transcript)
    # Compare on the canonical bytes so every material field is covered at once.
    return recomputed.canonical_json() == witness.canonical_json()


# ===========================================================================
# Builder — reconstruct the canonical transcript from the live pipeline run
# ===========================================================================
#
# The builder is the only impure-ish part (it reads the engine's artifacts), but
# it is a pure function of them — no I/O, no clock. It is duck-typed on the
# artifact attributes so importing the SCHEMA + WITNESS + VERIFY above never
# pulls the engine; only a caller that actually builds (the PDP) imports those
# types. Stage order mirrors ``pdp.py``'s documented ``evaluation_order``.


def _deterministic_signal_score(deterministic_result: "DeterministicGateResult") -> float:
    """Coarse, deterministic risk for the recognizer stage (a blocked gate is a
    structural max; otherwise grade by the worst finding severity). Mirrors the
    spirit of ``router._deterministic_score`` without importing it."""
    if getattr(deterministic_result, "blocked", False):
        return 1.0
    findings = tuple(getattr(deterministic_result, "findings", ()) or ())
    if not findings:
        return 0.0
    severity_scores = {"CRITICAL": 1.0, "WARNING": 0.55, "INFO": 0.20}
    worst = 0.0
    for finding in findings:
        sev = getattr(getattr(finding, "severity", None), "value", None)
        worst = max(worst, severity_scores.get(sev, 0.0))
    return worst


def _evidence_stage(
    index: int,
    stage: str,
    signal_id: str,
    signal_score: float | None,
    detail: dict[str, Any],
) -> TranscriptStage:
    """A non-transforming signal stage: verdict + risk held at the permissive
    prior (PERMIT / 0.0); the signal it produced is recorded in ``signal_score``
    + ``detail`` for the record and for a future circuit, but it does not move
    the running verdict (fusion does)."""
    return TranscriptStage(
        index=index,
        stage=stage,
        signal_id=signal_id,
        verdict_before=Verdict.PERMIT,
        verdict_after=Verdict.PERMIT,
        risk_before=0.0,
        risk_after=0.0,
        direction=StageDirection.EVIDENCE,
        applied=False,
        signal_score=None if signal_score is None else _round_score(signal_score),
        detail=detail,
    )


def build_verdict_transcript(
    *,
    request: Any,
    policy: Any,
    content_sha256: str,
    determinism_fingerprint: str,
    deterministic_result: "DeterministicGateResult",
    specialist_bundle: "SpecialistBundle",
    semantic_analysis: "SemanticAnalysis",
    agent_bundle: "AgentEvaluationBundle",
    contract_outcome: "ContractEvaluationOutcome",
    path_outcome: "PathPolicyOutcome",
    structural_floor: "StructuralFloorResult",
    routed_base: "RoutingResult | None",
    routing_result: "RoutingResult",
) -> VerdictTranscript:
    """Reconstruct the canonical transcript for one verdict from its artifacts.

    Faithfulness contract
    ----------------------
    The verdict-carrying endpoints are CAPTURED from the live objects, never
    guessed: the structural floor (``structural_floor`` + the contract/path hard
    flags), the router's base verdict (``routed_base``, ``None`` only when the
    floor short-circuited the router), and the final verdict (``routing_result``,
    after every monotone-lowering hold + the CRC gate). The aggregate
    ``monotone_holds`` stage therefore has exact endpoints (``routed_base`` →
    ``routing_result``); the per-layer attribution inside its ``detail`` (which of
    soft-contract / path-warn / predictive / spine / PQ / CRC contributed) is
    reconstructed from the durable outcome flags and is labelled "checked", since
    once the verdict reaches ABSTAIN the later holds are verdict no-ops and exact
    ordering is unobservable from the finalized result — the constitution's
    "prove or label" applied to attribution.

    Stage order mirrors ``pdp.py``'s ``evaluation_order``: evidence stages first
    (deterministic → agent → specialists → semantic → contracts → path), then the
    transforming stages (structural floor → routing/fusion → monotone holds).
    """
    hard_contract = bool(getattr(contract_outcome, "has_hard_violation", False))
    path_block = bool(getattr(path_outcome, "has_block", False))
    floor_fired = bool(getattr(structural_floor, "fired", False))
    hard_violation = hard_contract or path_block or floor_fired

    final_verdict: Verdict = routing_result.verdict
    final_risk = _round_score(routing_result.final_score)

    stages: list[TranscriptStage] = []
    idx = 0

    def add(stage: TranscriptStage) -> None:
        nonlocal idx
        stages.append(stage)
        idx += 1

    # ── Anchor: the most-permissive prior the pipeline starts from ──
    add(
        TranscriptStage(
            index=idx,
            stage="pipeline_entry",
            signal_id="pipeline_entry",
            verdict_before=Verdict.PERMIT,
            verdict_after=Verdict.PERMIT,
            risk_before=0.0,
            risk_after=0.0,
            direction=StageDirection.HELD,
            applied=False,
            detail={"note": "permissive prior; only signals may lower from here"},
        )
    )

    # ── Evidence stages (non-transforming; they feed fusion) ──
    add(
        _evidence_stage(
            idx,
            "deterministic_recognizers",
            "deterministic_recognizers",
            _deterministic_signal_score(deterministic_result),
            {
                "blocked": bool(getattr(deterministic_result, "blocked", False)),
                "finding_count": len(
                    tuple(getattr(deterministic_result, "findings", ()) or ())
                ),
                "enabled_recognizers": list(
                    getattr(deterministic_result, "enabled_recognizers", ()) or ()
                ),
            },
        )
    )

    agent_present = bool(getattr(agent_bundle, "agent_present", False))
    add(
        _evidence_stage(
            idx,
            "agent_governance",
            "agent_governance_streams",
            (
                _round_score(getattr(agent_bundle, "aggregate_risk_score", 0.0))
                if agent_present
                else None
            ),
            {"agent_present": agent_present},
        )
    )

    add(
        _evidence_stage(
            idx,
            "specialist_judges",
            "specialist_judges",
            _round_score(getattr(specialist_bundle, "max_risk_score", 0.0) or 0.0),
            {
                "judge_count": len(tuple(getattr(specialist_bundle, "results", ()) or ())),
                "max_risk_score": _round_score(
                    getattr(specialist_bundle, "max_risk_score", 0.0) or 0.0
                ),
            },
        )
    )

    semantic_recommended = getattr(
        getattr(semantic_analysis, "recommended_verdict", None), "verdict", None
    )
    add(
        _evidence_stage(
            idx,
            "semantic_judge",
            "semantic_judge",
            _round_score(getattr(semantic_analysis, "max_dimension_score", 0.0) or 0.0),
            {
                "recommended_verdict": (
                    semantic_recommended.value
                    if isinstance(semantic_recommended, Verdict)
                    else None
                ),
            },
        )
    )

    add(
        _evidence_stage(
            idx,
            "behavioral_contracts",
            "behavioral_contracts",
            None,
            {
                "has_hard_violation": hard_contract,
                "has_soft_violation": bool(
                    getattr(contract_outcome, "has_soft_violation", False)
                ),
            },
        )
    )

    add(
        _evidence_stage(
            idx,
            "path_policies",
            "path_policies",
            None,
            {
                "checked": bool(getattr(path_outcome, "checked", False)),
                "has_block": path_block,
                "has_soft_violation": bool(
                    getattr(path_outcome, "has_soft_violation", False)
                ),
            },
        )
    )

    # ── Transforming stage 1: the structural FORBID floor ──
    # Fires (and short-circuits the router) on any hard violation: a structural
    # deny, a behavioral-contract hard violation, or a path-policy block. When it
    # fires it forces FORBID @ risk 1.0 — never a fused inference.
    if hard_violation:
        denying = list(getattr(structural_floor, "denying_specialists", ()) or ())
        add(
            TranscriptStage(
                index=idx,
                stage=_FLOOR_STAGE,
                signal_id="structural_floor",
                verdict_before=Verdict.PERMIT,
                verdict_after=Verdict.FORBID,
                risk_before=0.0,
                risk_after=1.0,
                direction=StageDirection.TOWARD_CAUTION,
                applied=True,
                detail={
                    "structural_deny_fired": floor_fired,
                    "denying_specialists": denying,
                    "contract_hard_violation": hard_contract,
                    "path_block": path_block,
                    "reasons": list(getattr(structural_floor, "reasons", ()) or ()),
                },
            )
        )
        # Router + holds did not run; record them as skipped (held at FORBID@1.0)
        # so the canonical stage list is stable across both paths.
        add(_held_stage(idx, "routing_fusion", "routing_fusion", Verdict.FORBID, 1.0,
                        {"skipped": True, "reason": "short-circuited by structural floor"}))
        add(_held_stage(idx, "monotone_holds", "monotone_holds", Verdict.FORBID, 1.0,
                        {"skipped": True, "reason": "short-circuited by structural floor"}))
    else:
        # Floor checked, did not fire.
        add(_held_stage(idx, _FLOOR_STAGE, "structural_floor", Verdict.PERMIT, 0.0,
                        {"structural_deny_fired": False}))

        # ── Transforming stage 2: routing / fusion (the base verdict) ──
        base_verdict: Verdict = (
            routed_base.verdict if routed_base is not None else routing_result.verdict
        )
        base_risk = _round_score(
            routed_base.final_score if routed_base is not None else routing_result.final_score
        )
        add(
            TranscriptStage(
                index=idx,
                stage="routing_fusion",
                signal_id="routing_fusion",
                verdict_before=Verdict.PERMIT,
                verdict_after=base_verdict,
                risk_before=0.0,
                risk_after=base_risk,
                direction=_classify_direction(Verdict.PERMIT, 0.0, base_verdict, base_risk),
                applied=True,
                detail={
                    "scores": {
                        k: _round_score(v)
                        for k, v in sorted(
                            (getattr(routed_base, "scores", None) or {}).items()
                        )
                        if not k.startswith("conf_stream:")
                    },
                    "routed_base_captured": routed_base is not None,
                },
            )
        )

        # ── Transforming stage 3: the monotone-lowering holds (aggregate) ──
        # Exact endpoints (base → final). Per-layer attribution is reconstructed
        # from durable flags and labelled — see the builder docstring.
        active_layers = _active_monotone_layers(
            base_verdict=base_verdict,
            final_verdict=final_verdict,
            contract_outcome=contract_outcome,
            path_outcome=path_outcome,
            request=request,
        )
        add(
            TranscriptStage(
                index=idx,
                stage="monotone_holds",
                signal_id="monotone_holds",
                verdict_before=base_verdict,
                verdict_after=final_verdict,
                risk_before=base_risk,
                risk_after=final_risk,
                direction=_classify_direction(
                    base_verdict, base_risk, final_verdict, final_risk
                ),
                applied=(base_verdict is not final_verdict)
                or (abs(final_risk - base_risk) > _EPS),
                detail={
                    "layers": "soft_contract,path_warn,predictive_holds,risk_spine,"
                    "pq_durability,crc_gate",
                    "attribution": "endpoints captured; per-layer flags below are "
                    "which layers were active, not an exact ordering",
                    "active": active_layers,
                },
            )
        )

    return VerdictTranscript(
        request_id=str(getattr(request, "request_id", "")),
        policy_id=str(getattr(policy, "policy_id", "")),
        policy_version=str(getattr(policy, "version", "")),
        content_sha256=content_sha256,
        determinism_fingerprint=determinism_fingerprint,
        final_verdict=final_verdict,
        final_risk_score=final_risk,
        structural_floor_fired=floor_fired,
        hard_violation=hard_violation,
        stages=tuple(stages),
    )


def _held_stage(
    index: int,
    stage: str,
    signal_id: str,
    verdict: Verdict,
    risk: float,
    detail: dict[str, Any],
) -> TranscriptStage:
    """A transforming-class stage that ran but changed nothing (or was skipped)."""
    risk_r = _round_score(risk)
    return TranscriptStage(
        index=index,
        stage=stage,
        signal_id=signal_id,
        verdict_before=verdict,
        verdict_after=verdict,
        risk_before=risk_r,
        risk_after=risk_r,
        direction=StageDirection.HELD,
        applied=False,
        detail=detail,
    )


def _active_monotone_layers(
    *,
    base_verdict: Verdict,
    final_verdict: Verdict,
    contract_outcome: Any,
    path_outcome: Any,
    request: Any,
) -> dict[str, Any]:
    """Best-effort, honestly-labelled enumeration of which lowering layers were
    active between the router base verdict and the final verdict. Reads only
    durable flags + request opt-in metadata — never re-runs a hold."""
    metadata = getattr(request, "metadata", None) or {}
    return {
        "soft_contract": bool(getattr(contract_outcome, "has_soft_violation", False)),
        "path_warn": bool(getattr(path_outcome, "has_soft_violation", False)),
        "predictive_holds_opt_in": "systemic_lookahead" in metadata
        or "rv4_path_policies" in metadata,
        "pq_non_repudiation_opt_in": "pq_non_repudiation" in metadata,
        "verdict_lowered": base_verdict is not final_verdict,
    }


__all__ = [
    "TRANSCRIPT_SCHEMA_VERSION",
    "WITNESS_SCHEMA_VERSION",
    "StageDirection",
    "TranscriptStage",
    "VerdictTranscript",
    "WitnessViolation",
    "MonotonicityWitness",
    "build_verdict_transcript",
    "derive_monotonicity_witness",
    "recompute_witness",
    "verify_transcript_witness",
]
