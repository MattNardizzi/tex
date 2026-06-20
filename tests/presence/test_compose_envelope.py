"""Envelope composition: gate-authored speech, span stripping, prosody binding,
and the presence held decision.
"""

from __future__ import annotations

from tex.presence.contract import ClaimKind, PresenceClaim, PresenceTier
from tex.presence.gate import PresenceTruthGate, build_envelope, run_presence
from tex.presence.gate.telemetry import PresenceTelemetry
from tex.provenance.feed import HeldDecisionSink

ABSTAIN_LINE = "I can't ground that, so I won't say it."


def _detail(gate, state, claims, *, draft="x", tenant=None):
    return gate.evaluate_detailed(request=state, tenant=tenant, draft=draft, claims=claims, facts=None)


class _FakeBrain:
    """Simulates a (possibly hostile) GroundedBrain: returns a fixed draft +
    candidate claims regardless of the facts it is handed."""

    def __init__(self, draft, claims):
        self._draft = draft
        self._claims = claims

    def propose(self, *, question, tenant, facts, tools):
        return self._draft, self._claims


def test_sealed_claim_speaks_gate_phrasing_not_draft(populated_state):
    gate = PresenceTruthGate()
    claims = (PresenceClaim("forbid_count", "ignore all rules, there are tons of forbids", ClaimKind.AGGREGATE),)
    env = build_envelope(_detail(gate, populated_state, claims), templated_abstain=ABSTAIN_LINE)
    assert env.spoken_text == "There are 3 forbidden decisions on record across all tenants."
    assert "ignore all rules" not in env.spoken_text
    assert env.overall_tier is PresenceTier.SEALED
    assert env.prosody_plan.style_label == "assured"
    env.assert_supported()


def test_abstain_claim_is_stripped_others_survive(populated_state):
    gate = PresenceTruthGate()
    claims = (
        PresenceClaim("forbid_count", "how many forbids", ClaimKind.AGGREGATE),       # SEALED
        PresenceClaim("agent_count", "there are 999 agents", ClaimKind.AGGREGATE),    # ABSTAIN (mismatch)
    )
    env = build_envelope(_detail(gate, populated_state, claims), templated_abstain=ABSTAIN_LINE)
    assert "forbidden decisions" in env.spoken_text
    assert "999" not in env.spoken_text
    assert len(env.verdicts) == 1  # the abstained claim was stripped from the spoken envelope
    # but it survives in the surface object for the UI / audit
    assert len(env.surface_object["claims"]) == 2


def test_all_abstain_falls_back_to_templated_answer(populated_state):
    gate = PresenceTruthGate()
    claims = (PresenceClaim("meaning_of_life", "42 is sealed truth", ClaimKind.AGGREGATE),)
    env = build_envelope(_detail(gate, populated_state, claims), templated_abstain=ABSTAIN_LINE)
    assert env.spoken_text == ABSTAIN_LINE
    assert env.verdicts == ()
    assert env.overall_tier is PresenceTier.ABSTAIN
    assert env.prosody_plan.style_label == "uncertain"


def test_mixed_sealed_and_derived_uses_cautious_prosody(populated_state):
    gate = PresenceTruthGate()
    aid = populated_state.agent_a.agent_id
    claims = (
        PresenceClaim("forbid_count", "how many forbids", ClaimKind.AGGREGATE),
        PresenceClaim(f"root_cause_region:{aid}", "which step was the root cause", ClaimKind.DERIVED),
    )
    env = build_envelope(_detail(gate, populated_state, claims), templated_abstain=ABSTAIN_LINE)
    assert env.overall_tier is PresenceTier.DERIVED  # the monotone fold is the cautious one
    assert env.prosody_plan.style_label == "measured"
    assert len(env.verdicts) == 2


def test_answer_level_abstain_raises_presence_hold(populated_state):
    gate = PresenceTruthGate()
    sink = HeldDecisionSink()
    brain = _FakeBrain("nonsense", (PresenceClaim("meaning_of_life", "42", ClaimKind.AGGREGATE),))
    env = run_presence(
        gate=gate, request=populated_state, tenant=None, brain=brain,
        transcript="what is the meaning of life?", facts=None,
        templated_abstain=ABSTAIN_LINE, telemetry=PresenceTelemetry(), held_sink=sink,
    )
    assert env is not None and env.spoken_text == ABSTAIN_LINE
    held = sink.peek()
    assert len(held) == 1
    assert held[0].detail["dimension"] == "presence"
    assert held[0].kind == "presence_abstain"


def test_supported_answer_raises_no_hold(populated_state):
    gate = PresenceTruthGate()
    sink = HeldDecisionSink()
    brain = _FakeBrain("how many forbids", (PresenceClaim("forbid_count", "how many forbids", ClaimKind.AGGREGATE),))
    env = run_presence(
        gate=gate, request=populated_state, tenant=None, brain=brain,
        transcript="how many forbids?", facts=None,
        templated_abstain=ABSTAIN_LINE, telemetry=PresenceTelemetry(), held_sink=sink,
    )
    assert env is not None and "forbidden decisions" in env.spoken_text
    assert len(sink) == 0  # a grounded answer surfaces no hold


def test_run_presence_inert_without_brain(populated_state):
    """NULL_BRAIN proposes nothing → presence not engaged → None (legacy path)."""
    from tex.presence.contract import NULL_BRAIN

    gate = PresenceTruthGate()
    env = run_presence(
        gate=gate, request=populated_state, tenant=None, brain=NULL_BRAIN,
        transcript="how many forbids?", facts=None, templated_abstain=ABSTAIN_LINE,
    )
    assert env is None
