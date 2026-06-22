"""The STABLE correction key — a correction must cap the SAME subject across
re-asks, even when the brain emits a different ``claim_id`` (or the rows change
underneath the question).

THE VERIFIED TRAP (``grounded_brain.py:179``): a claim's ``claim_id`` is the LLM's
emitted string OR a positional ``claim-{index}`` fallback — NOT stable across
re-asks. A correction keyed on it caps a claim within ONE answer but SILENTLY fails
to cap the same thing asked again. The obvious "fix" — key on the verdict's
grounded evidence ``record_id``s — is *also* unstable: an AGGREGATE binds a witness
SET capped at 64 that grows as rows arrive (``queries.py`` ``_count_decisions`` /
``EVIDENCE_CAP``) and a discovery/event claim binds the moving LATEST sequence
(``evidence.py`` ``ref_for_discovery_entry``). The one handle that is stable across
re-asks AND as rows change is the gate's ROUTING identity (``query.key`` + target).

Nothing here is mocked: the truth-gate routes + recomputes against the REAL
in-memory stores in ``populated_state`` (parent ``tests/presence/conftest.py``).
"""

from __future__ import annotations

from tex.domain.verdict import Verdict
from tex.presence.contract import ClaimKind, PresenceClaim, PresenceTier
from tex.presence.gate.gate import PresenceTruthGate
from tex.presence.profile import SealedProfileMemory, apply_profile_corrections
from tex.presence.profile.influence import stable_subject_key

from ..conftest import make_decision  # real Decision rows (parent gate conftest)


def _eval_one(gate, state, claim, *, tenant="acme"):
    return gate.evaluate_detailed(
        request=state, tenant=tenant, draft=claim.text_span, claims=(claim,), facts=None,
    )[0]


class _StubBrain:
    """A deterministic proposer that emits one fixed claim — enough to drive
    ``run_presence`` end-to-end without a model on the path."""

    def __init__(self, claim: PresenceClaim) -> None:
        self._claim = claim

    def propose(self, *, question, tenant, facts, tools):  # noqa: ANN001
        return (self._claim.text_span, (self._claim,))


# ───────────────────────────────────────────── the derivation is stable (red→green)
def test_same_entity_question_yields_identical_subject_key_across_reasks(populated_state):
    gate = PresenceTruthGate()
    agent_id = populated_state.agent_a.agent_id

    # Ask 1: the brain emits a KEYED claim_id carrying the target.
    c1 = PresenceClaim(
        claim_id=f"agent_status:{agent_id}",
        text_span=f"what is the status of agent {agent_id}",
        kind=ClaimKind.ENTITY,
    )
    # Ask 2: the SAME question; the brain emits a positional fallback claim_id and
    # the UUID lives only in the span. This is exactly the re-ask drift of the trap.
    c2 = PresenceClaim(
        claim_id="claim-0",
        text_span=f"status of agent {agent_id}",
        kind=ClaimKind.ENTITY,
    )

    e1 = _eval_one(gate, populated_state, c1)
    e2 = _eval_one(gate, populated_state, c2)

    # Precondition: the brain claim_ids genuinely DIFFER (else the test is vacuous —
    # it must be the keying, not luck, that makes the subject stable).
    assert e1.claim.claim_id != e2.claim.claim_id
    assert e1.verdict.tier is PresenceTier.SEALED and e2.verdict.tier is PresenceTier.SEALED

    # THE FIX: the stable subject is identical across the two re-asks …
    assert stable_subject_key(e1) == stable_subject_key(e2)
    # … and it is the meaningful routing identity, never the volatile claim_id.
    assert stable_subject_key(e1) != e1.claim.claim_id.strip().casefold()
    assert "agent_status" in stable_subject_key(e1)
    assert str(agent_id).casefold() in stable_subject_key(e1)


# ───────────────────────────────────────── the trap, then the fix (side by side)
def test_legacy_claim_id_correction_silently_fails_across_reask_but_stable_key_holds(populated_state):
    gate = PresenceTruthGate()

    c1 = PresenceClaim("forbid_count", "how many forbids", ClaimKind.AGGREGATE)
    e1 = _eval_one(gate, populated_state, c1)
    assert e1.verdict.tier is PresenceTier.SEALED

    # Re-ask the SAME question; the brain emits a DIFFERENT claim_id (the drift).
    c2 = PresenceClaim("claim-0", "how many forbids", ClaimKind.AGGREGATE)
    e2 = _eval_one(gate, populated_state, c2)
    assert e2.verdict.tier is PresenceTier.SEALED
    assert e2.claim.claim_id != e1.claim.claim_id

    # ---- THE TRAP: a correction keyed on the volatile claim_id ----
    legacy = SealedProfileMemory(mirror=None)
    legacy.apply_correction(
        tenant="acme", claim_id=e1.claim.claim_id,
        corrected_tier=PresenceTier.ABSTAIN, operator="op@acme.com",
    )
    out_legacy = apply_profile_corrections(tenant="acme", evaluations=(e2,), profile=legacy)
    assert out_legacy[0].verdict.tier is PresenceTier.SEALED  # SILENTLY not capped

    # ---- THE FIX: the same correction keyed on the STABLE subject ----
    stable = SealedProfileMemory(mirror=None)
    stable.apply_correction(
        tenant="acme", claim_id=e1.claim.claim_id, subject_key=stable_subject_key(e1),
        corrected_tier=PresenceTier.ABSTAIN, operator="op@acme.com",
    )
    out_stable = apply_profile_corrections(tenant="acme", evaluations=(e2,), profile=stable)
    assert out_stable[0].verdict.tier is PresenceTier.ABSTAIN  # STILL capped


# ────────────────────────── stable across a ROW change (where evidence-keying dies)
def test_correction_caps_same_aggregate_even_as_the_grounded_rows_change(populated_state):
    gate = PresenceTruthGate()
    profile = SealedProfileMemory(mirror=None)

    c1 = PresenceClaim("forbid_count", "how many forbids", ClaimKind.AGGREGATE)
    e1 = _eval_one(gate, populated_state, c1)
    assert e1.verdict.recomputed_value == populated_state.forbid_count == 3

    profile.apply_correction(
        tenant="acme", claim_id="forbid_count", subject_key=stable_subject_key(e1),
        corrected_tier=PresenceTier.ABSTAIN, operator="ceo@acme.com",
    )

    # A new FORBID lands → the grounded evidence record-id SET changes (3 → 4).
    # Keying on evidence record_ids would now MISS; the routing identity does not.
    populated_state.decision_store.save(make_decision(Verdict.FORBID, n=99))

    c2 = PresenceClaim("claim-7", "how many forbids were blocked", ClaimKind.AGGREGATE)
    e2 = _eval_one(gate, populated_state, c2)
    assert e2.verdict.recomputed_value == 4  # uncorrected it is now SEALED=4
    assert e2.verdict.tier is PresenceTier.SEALED

    out = apply_profile_corrections(tenant="acme", evaluations=(e2,), profile=profile)
    assert out[0].verdict.tier is PresenceTier.ABSTAIN  # capped despite claim_id + row change


# ─────────────────────────────────── paraphrase robustness (no embeddings/similarity)
def test_correction_still_caps_under_paraphrase(populated_state):
    gate = PresenceTruthGate()
    profile = SealedProfileMemory(mirror=None)

    c1 = PresenceClaim("forbid_count", "how many forbids", ClaimKind.AGGREGATE)
    e1 = _eval_one(gate, populated_state, c1)
    profile.apply_correction(
        tenant="acme", claim_id="forbid_count", subject_key=stable_subject_key(e1),
        corrected_tier=PresenceTier.ABSTAIN, operator="ceo@acme.com",
    )

    # Heavily paraphrased re-ask, different claim_id; routes via the "blocked" alias.
    c2 = PresenceClaim("zz", "tell me the number of blocked actions on record", ClaimKind.AGGREGATE)
    e2 = _eval_one(gate, populated_state, c2)
    assert e2.verdict.tier is PresenceTier.SEALED  # routes to the same query
    out = apply_profile_corrections(tenant="acme", evaluations=(e2,), profile=profile)
    assert out[0].verdict.tier is PresenceTier.ABSTAIN


# ───────────────────────────────── adversarial: a correction can NEVER raise a tier
def test_a_correction_can_never_raise_a_tier_through_the_apply_path(populated_state):
    # Even if a (write-refused) higher ceiling were somehow stored, the apply path
    # folds with ``tighten`` — there is no code path that raises a tier.
    gate = PresenceTruthGate()
    profile = SealedProfileMemory(mirror=None)
    c1 = PresenceClaim("forbid_count", "how many forbids", ClaimKind.AGGREGATE)
    e1 = _eval_one(gate, populated_state, c1)
    # The strongest legal correction (ABSTAIN) on this subject.
    profile.apply_correction(
        tenant="acme", claim_id="forbid_count", subject_key=stable_subject_key(e1),
        corrected_tier=PresenceTier.ABSTAIN, operator="op@acme.com",
    )
    out = apply_profile_corrections(tenant="acme", evaluations=(e1,), profile=profile)
    # SEALED → ABSTAIN is a lowering; it can never come back up.
    assert out[0].verdict.tier is PresenceTier.ABSTAIN
    # The write-gate itself refuses an upward (inflating) correction outright.
    import pytest

    with pytest.raises(ValueError):
        profile.apply_correction(
            tenant="acme", claim_id="forbid_count", subject_key="q:aggregate:forbid_count",
            corrected_tier=PresenceTier.SEALED, operator="op@acme.com",
        )


# ───────────────────────── over-suppression telemetry (the watch metric) via run_presence
def test_over_suppression_telemetry_counts_corrected_answers(populated_state):
    from tex.presence.gate.compose import run_presence
    from tex.presence.gate.telemetry import PresenceTelemetry

    gate = PresenceTruthGate()
    profile = SealedProfileMemory(mirror=None)
    claim = PresenceClaim("forbid_count", "how many forbids", ClaimKind.AGGREGATE)

    # A control answer FIRST (no correction yet) → no over-suppression.
    tel = PresenceTelemetry()
    env0 = run_presence(
        gate=gate, request=populated_state, tenant="acme", brain=_StubBrain(claim),
        transcript="how many forbids", facts=None, templated_abstain="I can't ground that.",
        telemetry=tel, profile=profile,
    )
    assert env0 is not None and "3" in env0.spoken_text  # spoke the sealed count
    assert tel.snapshot()["answers_corrected_down"] == 0
    assert tel.over_suppression_rate == 0.0

    # Operator corrects the subject → cap at ABSTAIN.
    e = _eval_one(gate, populated_state, claim)
    profile.apply_correction(
        tenant="acme", claim_id="forbid_count", subject_key=stable_subject_key(e),
        corrected_tier=PresenceTier.ABSTAIN, operator="ceo@acme.com",
    )

    # Same question again → the correction lowers the claim; the answer is suppressed.
    env1 = run_presence(
        gate=gate, request=populated_state, tenant="acme", brain=_StubBrain(claim),
        transcript="how many forbids", facts=None, templated_abstain="I can't ground that.",
        telemetry=tel, profile=profile,
    )
    assert env1 is not None and env1.spoken_text == "I can't ground that."  # stripped → templated abstain
    snap = tel.snapshot()
    assert snap["answers_corrected_down"] == 1   # exactly the one corrected answer
    assert snap["claims_corrected_down"] == 1
    assert snap["over_suppression_rate"] == 0.5  # 1 of 2 answers
    # There is NO inflation counter — inflation is structurally impossible.
    assert "answers_inflated" not in snap
