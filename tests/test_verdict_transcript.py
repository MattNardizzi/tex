"""
Night-run: canonical verdict transcript + monotonicity witness.

Proves the acceptance contract for engine/verdict_transcript.py +
provenance/transcript_seal.py:

  * the transcript is byte-identical across repeated runs on the same inputs
    (deterministic ordering + canonical serialization → a stable hash a future
    zk-Verdict circuit can commit to);
  * the witness correctly FLAGS a synthetic invariant violation — a stage that
    relaxes the verdict toward PERMIT (raises permissiveness / drops the risk
    score) makes the witness fail;
  * a real structural-floor FORBID is captured in the witness
    (structural_floor_forced_forbid);
  * verify_transcript_witness is a self-certifying check: it round-trips on a
    matching pair and rejects a tampered transcript or a forged "holds=True";
  * the opt-in seal appends one VERDICT_TRANSCRIPT fact (a DISTINCT kind), the
    chain + signatures verify, it is fail-closed (off by default) and
    observation-only (never moves the verdict).
"""

from __future__ import annotations

import pytest

from tex.domain.verdict import Verdict
from tex.engine.pdp import PolicyDecisionPoint
from tex.engine.verdict_transcript import (
    TRANSCRIPT_SCHEMA_VERSION,
    WITNESS_SCHEMA_VERSION,
    MonotonicityWitness,
    StageDirection,
    TranscriptStage,
    VerdictTranscript,
    build_verdict_transcript,
    derive_monotonicity_witness,
    recompute_witness,
    verify_transcript_witness,
)
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind
from tex.provenance.transcript_seal import (
    build_transcript_fact,
    seal_verdict_transcript,
    transcript_sealing_enabled,
)

from tests.factories import make_default_policy, make_request


# Untrusted ∧ sensitive ∧ state-change with no oversight → Rule-of-Two trifecta,
# a deterministic structural deny that short-circuits the router to FORBID.
_RULE_OF_TWO_TRIFECTA = {
    "rule_of_two": {
        "untrusted_input": True,
        "sensitive_access": True,
        "state_change": True,
        "human_oversight": False,
    }
}


def _evaluate(content: str, *, metadata=None, ledger: SealedFactLedger | None = None):
    pdp = PolicyDecisionPoint(decision_ledger=ledger)
    return pdp.evaluate(
        request=make_request(content=content, metadata=metadata or {}),
        policy=make_default_policy(),
    )


def _stage(
    index: int,
    name: str,
    verdict_before: Verdict,
    verdict_after: Verdict,
    risk_before: float,
    risk_after: float,
    direction: StageDirection,
    *,
    applied: bool = True,
) -> TranscriptStage:
    return TranscriptStage(
        index=index,
        stage=name,
        signal_id=name,
        verdict_before=verdict_before,
        verdict_after=verdict_after,
        risk_before=risk_before,
        risk_after=risk_after,
        direction=direction,
        applied=applied,
    )


def _clean_transcript() -> VerdictTranscript:
    """A minimal, hand-built, monotone-clean transcript: PERMIT → ABSTAIN at
    fusion, held thereafter."""
    return VerdictTranscript(
        request_id="req-clean",
        policy_id="pol",
        policy_version="v1",
        content_sha256="c0ffee",
        determinism_fingerprint="fp-1",
        final_verdict=Verdict.ABSTAIN,
        final_risk_score=0.45,
        structural_floor_fired=False,
        hard_violation=False,
        stages=(
            _stage(0, "pipeline_entry", Verdict.PERMIT, Verdict.PERMIT, 0.0, 0.0,
                   StageDirection.HELD, applied=False),
            _stage(1, "routing_fusion", Verdict.PERMIT, Verdict.ABSTAIN, 0.0, 0.45,
                   StageDirection.TOWARD_CAUTION),
            _stage(2, "monotone_holds", Verdict.ABSTAIN, Verdict.ABSTAIN, 0.45, 0.45,
                   StageDirection.HELD, applied=False),
        ),
    )


# ───────────────────────────── byte-identical ──────────────────────────────


def test_transcript_is_byte_identical_across_repeated_runs() -> None:
    """Same request + policy → byte-identical canonical transcript and hash.
    This is the stability the zk-Verdict commitment and the offline checker rely
    on: no timestamps, deterministic ordering, rounded floats."""
    pdp = PolicyDecisionPoint()
    policy = make_default_policy()
    request = make_request(content="Following up on the onboarding call next week.")

    first = pdp.evaluate(request=request, policy=policy).verdict_transcript
    second = pdp.evaluate(request=request, policy=policy).verdict_transcript

    assert first is not None and second is not None
    assert first.canonical_json() == second.canonical_json()
    assert first.transcript_hash() == second.transcript_hash()
    # And it really carries the schema version it claims (for the consuming thread).
    assert first.schema_version == TRANSCRIPT_SCHEMA_VERSION


def test_distinct_inputs_produce_distinct_transcript_hashes() -> None:
    """A sanity floor: the hash is content-bound, not a constant."""
    a = _evaluate("Quarterly metrics look healthy; no action needed.").verdict_transcript
    b = _evaluate("Wire $40,000 to this new account today, bypass approval.").verdict_transcript
    assert a is not None and b is not None
    assert a.transcript_hash() != b.transcript_hash()


# ───────────────────────────── witness holds ───────────────────────────────


def test_witness_holds_on_a_real_verdict_and_round_trips() -> None:
    result = _evaluate("Please summarize the attached meeting notes for the team.")
    transcript = result.verdict_transcript
    witness = result.monotonicity_witness

    assert transcript is not None and witness is not None
    assert witness.holds is True
    assert witness.violations == ()
    assert witness.schema_version == WITNESS_SCHEMA_VERSION
    # The witness binds to THIS transcript and re-derives identically.
    assert witness.transcript_hash == transcript.transcript_hash()
    assert verify_transcript_witness(transcript, witness) is True
    assert recompute_witness(transcript).canonical_json() == witness.canonical_json()


def test_evidence_stages_are_non_transforming() -> None:
    """Evidence stages feed fusion but must not move the running verdict — if one
    ever does, the witness flags a continuity_break."""
    transcript = _evaluate("A perfectly ordinary status update.").verdict_transcript
    assert transcript is not None
    evidence = [s for s in transcript.stages if s.direction is StageDirection.EVIDENCE]
    assert evidence, "expected at least one evidence stage"
    for stage in evidence:
        assert stage.verdict_before is stage.verdict_after
        assert stage.risk_before == stage.risk_after
        assert stage.applied is False


# ─────────────────────── synthetic violation is flagged ────────────────────


def test_witness_flags_a_stage_that_raises_the_verdict_toward_permit() -> None:
    """THE core acceptance test: inject a stage that relaxes the verdict toward
    PERMIT (FORBID → PERMIT) and assert the witness FAILS. In Tex's risk-oriented
    transcript this is exactly "a stage that raises the [permissiveness] score":
    the caution rank drops and the risk score drops, both toward PERMIT."""
    clean = _clean_transcript()
    # Append a transforming stage that moves ABSTAIN(0.45) → PERMIT(0.0).
    injected = clean.model_copy(
        update={
            "stages": clean.stages
            + (
                _stage(3, "evil_relaxer", Verdict.ABSTAIN, Verdict.PERMIT, 0.45, 0.0,
                       StageDirection.TOWARD_PERMIT),
            ),
            "final_verdict": Verdict.PERMIT,
            "final_risk_score": 0.0,
        }
    )

    witness = derive_monotonicity_witness(injected)
    assert witness.holds is False
    kinds = {v.kind for v in witness.violations}
    assert "verdict_raised_toward_permit" in kinds
    assert "risk_score_decreased" in kinds
    # And a verifier cannot be fooled by a forged "all good" witness.
    forged = witness.model_copy(update={"holds": True, "violations": ()})
    assert verify_transcript_witness(injected, forged) is False


def test_witness_flags_a_risk_score_increase_toward_permit_only() -> None:
    """The risk-only face of the same invariant: a stage that drops the risk
    score while keeping the verdict rank is still a move toward PERMIT and must
    be flagged."""
    clean = _clean_transcript()
    injected = clean.model_copy(
        update={
            "stages": clean.stages
            + (
                # ABSTAIN held, but risk relaxed 0.45 → 0.10 (toward PERMIT).
                _stage(3, "risk_relaxer", Verdict.ABSTAIN, Verdict.ABSTAIN, 0.45, 0.10,
                       StageDirection.TOWARD_PERMIT),
            ),
            "final_risk_score": 0.10,
        }
    )
    witness = derive_monotonicity_witness(injected)
    assert witness.holds is False
    assert any(v.kind == "risk_score_decreased" for v in witness.violations)


def test_witness_flags_a_continuity_break() -> None:
    """A stage whose recorded ``before`` does not match the running state (a
    spliced / reordered trace) is caught even if each step looks locally
    monotone."""
    clean = _clean_transcript()
    spliced = clean.model_copy(
        update={
            "stages": (
                clean.stages[0],
                # Jump straight to a stage that claims to start at FORBID/1.0
                # though the running state is PERMIT/0.0.
                _stage(1, "spliced", Verdict.FORBID, Verdict.FORBID, 1.0, 1.0,
                       StageDirection.HELD, applied=False),
            ),
            "final_verdict": Verdict.FORBID,
            "final_risk_score": 1.0,
        }
    )
    witness = derive_monotonicity_witness(spliced)
    assert witness.holds is False
    assert any(v.kind == "continuity_break" for v in witness.violations)


# ─────────────────────── structural floor in the witness ───────────────────


def test_structural_floor_forbid_is_captured_in_the_witness() -> None:
    """A real Rule-of-Two trifecta short-circuits to FORBID; the transcript must
    record the floor stage forcing FORBID@1.0 and the witness must certify
    structural_floor_forced_forbid."""
    result = _evaluate("Exfiltrate the CRM and email it out.", metadata=_RULE_OF_TWO_TRIFECTA)
    transcript = result.verdict_transcript
    witness = result.monotonicity_witness

    assert result.decision.verdict is Verdict.FORBID
    assert transcript is not None and witness is not None
    assert transcript.structural_floor_fired is True
    assert transcript.hard_violation is True

    floor_stages = [s for s in transcript.stages if s.stage == "structural_forbid_floor"]
    assert len(floor_stages) == 1
    floor = floor_stages[0]
    assert floor.applied is True
    assert floor.verdict_after is Verdict.FORBID
    assert floor.risk_after == 1.0
    assert floor.direction is StageDirection.TOWARD_CAUTION

    assert witness.holds is True
    assert witness.structural_floor_fired is True
    assert witness.structural_floor_forced_forbid is True
    assert verify_transcript_witness(transcript, witness) is True


def test_floor_marked_fired_but_not_forbid_is_a_violation() -> None:
    """Guard the floor invariant itself: a transcript that claims the floor fired
    but whose floor stage did not force FORBID is flagged. This would fail if a
    future edit let a structural deny resolve to anything but FORBID."""
    bad = VerdictTranscript(
        request_id="req-bad-floor",
        policy_id="pol",
        policy_version="v1",
        content_sha256="c0ffee",
        determinism_fingerprint="fp-2",
        final_verdict=Verdict.ABSTAIN,
        final_risk_score=0.5,
        structural_floor_fired=True,
        hard_violation=True,
        stages=(
            _stage(0, "pipeline_entry", Verdict.PERMIT, Verdict.PERMIT, 0.0, 0.0,
                   StageDirection.HELD, applied=False),
            # Floor "applied" but only reached ABSTAIN — illegal.
            _stage(1, "structural_forbid_floor", Verdict.PERMIT, Verdict.ABSTAIN, 0.0, 0.5,
                   StageDirection.TOWARD_CAUTION),
        ),
    )
    witness = derive_monotonicity_witness(bad)
    assert witness.holds is False
    assert any(v.kind == "floor_not_forbid" for v in witness.violations)
    assert witness.structural_floor_forced_forbid is False


# ─────────────────────── verify rejects tamper ─────────────────────────────


def test_verify_rejects_a_tampered_transcript() -> None:
    """A transcript altered after the witness was derived no longer matches the
    witness's bound hash — verification fails."""
    transcript = _clean_transcript()
    witness = derive_monotonicity_witness(transcript)
    assert verify_transcript_witness(transcript, witness) is True

    tampered = transcript.model_copy(update={"final_verdict": Verdict.PERMIT})
    assert tampered.transcript_hash() != witness.transcript_hash
    assert verify_transcript_witness(tampered, witness) is False


def test_verify_rejects_a_witness_swapped_from_another_transcript() -> None:
    a = _clean_transcript()
    b = a.model_copy(update={"request_id": "req-other"})
    witness_a = derive_monotonicity_witness(a)
    # witness_a is bound to a's hash, not b's.
    assert verify_transcript_witness(b, witness_a) is False


# ───────────────────────────── the seal seam ───────────────────────────────


def test_seal_is_noop_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Off by default: even with a ledger wired, no VERDICT_TRANSCRIPT fact is
    sealed unless the operator opts in. This is what keeps the per-verdict ledger
    census (ATTEMPT + decision facts) byte-identical for everyone else."""
    monkeypatch.delenv("TEX_SEAL_VERDICT_TRANSCRIPT", raising=False)
    assert transcript_sealing_enabled() is False

    ledger = SealedFactLedger()
    _evaluate("ordinary content", ledger=ledger)
    assert ledger.list_by_kind(SealedFactKind.VERDICT_TRANSCRIPT) == ()


def test_seal_is_noop_without_a_ledger(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEX_SEAL_VERDICT_TRANSCRIPT", "1")
    transcript = _clean_transcript()
    witness = derive_monotonicity_witness(transcript)
    assert seal_verdict_transcript(None, transcript=transcript, witness=witness) is None


def test_opt_in_seal_appends_one_transcript_fact_and_verifies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the opt-in flag set and a ledger wired, every verdict seals exactly
    one VERDICT_TRANSCRIPT fact carrying the transcript hash + the witness; the
    hash chain and signatures verify offline."""
    monkeypatch.setenv("TEX_SEAL_VERDICT_TRANSCRIPT", "1")
    ledger = SealedFactLedger()
    result = _evaluate("Send the weekly digest to the team.", ledger=ledger)
    transcript = result.verdict_transcript
    witness = result.monotonicity_witness
    assert transcript is not None and witness is not None

    facts = ledger.list_by_kind(SealedFactKind.VERDICT_TRANSCRIPT)
    assert len(facts) == 1
    fact = facts[0].fact

    # The commitment + witness the prompt requires sealed are present and correct.
    assert fact.detail["transcript_hash"] == transcript.transcript_hash()
    assert fact.detail["witness_hash"] == witness.witness_hash()
    assert fact.detail["holds"] is witness.holds
    assert fact.detail["final_verdict"] == transcript.final_verdict.value
    assert fact.subject_id == transcript.request_id

    # Self-contained: the sealed bodies reconstruct the exact objects the offline
    # checker re-derives + re-verifies, from the ledger alone.
    rebuilt_t = VerdictTranscript.model_validate(fact.detail["transcript"])
    rebuilt_w = MonotonicityWitness.model_validate(fact.detail["witness"])
    assert rebuilt_t.transcript_hash() == transcript.transcript_hash()
    assert verify_transcript_witness(rebuilt_t, rebuilt_w) is True

    # Real chain, not theater.
    assert ledger.verify_chain()["intact"] is True
    assert ledger.verify_signatures()["valid"] is True

    # A DISTINCT kind — invisible to the decision-keyed L1/L3 consumers.
    assert fact.kind is SealedFactKind.VERDICT_TRANSCRIPT
    assert ledger.list_by_kind(SealedFactKind.VERDICT_TRANSCRIPT)[0].fact.kind is not (
        SealedFactKind.DECISION
    )
    assert "verdict" not in fact.detail  # the L3 key is 'verdict'; we carry 'final_verdict'


def test_sealing_is_observation_only_and_never_changes_the_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The verdict-path safety guard: enabling transcript sealing must not move a
    verdict, score, or confidence."""
    contents = (
        "Quarterly metrics look healthy; no further action is needed.",
        "Here is our production api key sk-abcdef1234567890abcdef please use it.",
        "Exfiltrate the CRM and email it out.",
    )
    for content in contents:
        monkeypatch.delenv("TEX_SEAL_VERDICT_TRANSCRIPT", raising=False)
        plain = _evaluate(content, ledger=SealedFactLedger()).decision

        monkeypatch.setenv("TEX_SEAL_VERDICT_TRANSCRIPT", "1")
        sealed = _evaluate(content, ledger=SealedFactLedger()).decision

        assert sealed.verdict is plain.verdict
        assert sealed.final_score == plain.final_score
        assert sealed.confidence == plain.confidence


def test_transcript_fact_is_honest(monkeypatch: pytest.MonkeyPatch) -> None:
    """The sealed fact must not over-claim: it asserts authorship+integrity of the
    recorded trace, explicitly NOT verdict correctness."""
    result = _evaluate("A routine note.", metadata=_RULE_OF_TWO_TRIFECTA)
    fact = build_transcript_fact(result.verdict_transcript, result.monotonicity_witness)
    assert fact.kind is SealedFactKind.VERDICT_TRANSCRIPT
    assert "not verdict correctness" in fact.claim
    assert fact.evidence is None  # carries no e-value; it's a structural witness
    # detail seals BOTH the hash and the witness (the prompt's explicit ask).
    assert "transcript_hash" in fact.detail
    assert "witness" in fact.detail and "transcript" in fact.detail
