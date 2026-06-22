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


def test_profile_correction_tightens_through_run_presence(populated_state):
    """L2 wire: a tenant's active correction caps the verdict to ABSTAIN THROUGH
    run_presence — proving the post-gate monotone fold is actually engaged on the
    spoken path (it was unit-tested in isolation but had no caller until wired)."""
    from tex.presence.profile import SealedProfileMemory

    gate = PresenceTruthGate()
    claims = (PresenceClaim("forbid_count", "how many forbids", ClaimKind.AGGREGATE),)

    def _ask(profile):
        return run_presence(
            gate=gate, request=populated_state, tenant="acme",
            brain=_FakeBrain("how many forbids", claims),
            transcript="how many forbids?", facts=None,
            templated_abstain=ABSTAIN_LINE, telemetry=PresenceTelemetry(),
            held_sink=HeldDecisionSink(), profile=profile,
        )

    # Control: no profile correction → the SEALED count is spoken as usual.
    env_uncorrected = _ask(None)
    assert "forbidden decisions" in env_uncorrected.spoken_text

    # Treatment: the tenant corrected this subject down to ABSTAIN. The fold caps
    # the verdict (monotone, never raises), so the only claim is suppressed and the
    # answer falls back to the templated abstain — a correction changed the speech.
    profile = SealedProfileMemory(mirror=None)
    profile.apply_correction(
        tenant="acme", claim_id="forbid_count",
        corrected_tier=PresenceTier.ABSTAIN, operator="ceo@acme.com",
    )
    env_corrected = _ask(profile)
    assert env_corrected.spoken_text == ABSTAIN_LINE
    assert env_corrected.verdicts == ()


# ── Grounding the brain (build_grounded_facts → brain_facts → SEALED) ──────────
class _GroundedFakeBrain:
    """A well-behaved grounded brain: drafts the canonical phrasing of one named
    recomputable fact and keys the claim by its claim_id — exactly what the real
    prompt now asks the model to do. Proves the grounded sheet reaches the brain
    and a brain that uses it produces a SEALING claim."""

    def __init__(self, key):
        self._key = key

    def propose(self, *, question, tenant, facts, tools):
        rows = (facts or {}).get("recomputable_facts", []) if isinstance(facts, dict) else []
        fact = next((f for f in rows if f.get("claim_id") == self._key), None)
        if fact is None:
            return ("", ())
        draft = fact["phrase"]
        return (draft, (PresenceClaim(self._key, draft, ClaimKind.AGGREGATE),))


def test_grounded_brain_facts_seal_agent_count_end_to_end(populated_state):
    """The slice-1 fix: with the gate's own agent_count handed to the brain as
    brain_facts, a keyed claim SEALs and the voice speaks the real count (2),
    instead of abstaining on a guessed number."""
    from tex.presence.brain.grounded_facts import build_grounded_facts

    gate = PresenceTruthGate()
    brain_facts = build_grounded_facts(
        populated_state, tenant="acme", dimension_facts={"dim": "identity"}
    )
    env = run_presence(
        gate=gate, request=populated_state, tenant="acme",
        brain=_GroundedFakeBrain("agent_count"),
        transcript="how many agents are in my directory?",
        facts={"dim": "identity"}, templated_abstain=ABSTAIN_LINE,
        brain_facts=brain_facts, telemetry=PresenceTelemetry(), held_sink=HeldDecisionSink(),
    )
    assert env is not None
    assert env.overall_tier is PresenceTier.SEALED
    assert env.spoken_text == "There are 2 registered agents."


def test_gate_still_rejects_a_guessed_number(populated_state):
    """The gate stays authoritative: even a confident draft stating the WRONG
    number (the old 441-style guess) abstains via draft-value-mismatch."""
    gate = PresenceTruthGate()
    brain = _FakeBrain(
        "There are 441 registered agents.",
        (PresenceClaim("agent_count", "There are 441 registered agents.", ClaimKind.AGGREGATE),),
    )
    env = run_presence(
        gate=gate, request=populated_state, tenant="acme", brain=brain,
        transcript="how many agents?", facts={"dim": "x"}, templated_abstain=ABSTAIN_LINE,
        telemetry=PresenceTelemetry(), held_sink=HeldDecisionSink(),
    )
    assert env is not None and env.spoken_text == ABSTAIN_LINE
    assert env.overall_tier is PresenceTier.ABSTAIN


def test_run_presence_hands_brain_facts_to_brain_else_legacy():
    """brain_facts is what the brain reads when present; it falls back to the
    legacy facts when absent (keeps every existing caller byte-identical)."""
    gate = PresenceTruthGate()
    seen = {}

    class _Capture:
        def propose(self, *, question, tenant, facts, tools):
            seen["facts"] = facts
            return ("", ())

    run_presence(
        gate=gate, request=None, tenant=None, brain=_Capture(),
        transcript="q", facts={"legacy": 1}, templated_abstain=ABSTAIN_LINE,
        brain_facts={"recomputable_facts": [], "x": 2},
    )
    assert seen["facts"] == {"recomputable_facts": [], "x": 2}

    seen.clear()
    run_presence(
        gate=gate, request=None, tenant=None, brain=_Capture(),
        transcript="q", facts={"legacy": 1}, templated_abstain=ABSTAIN_LINE,
    )
    assert seen["facts"] == {"legacy": 1}
