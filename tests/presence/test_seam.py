"""Integration at the voice_ask seam.

Proves: (1) presence is INERT with the default NULL_BRAIN — the live answer is
unchanged; (2) when a GroundedBrain is configured on ``app.state.presence_brain``,
the dimension branch attaches a presence envelope ALONGSIDE (never replacing) the
deterministic verdict/answer.
"""

from __future__ import annotations

from types import SimpleNamespace

from tex.presence.contract import ClaimKind, PresenceClaim
from tex.voice import answer_forms, voice_ask


class _FakeBrain:
    def __init__(self, draft, claims):
        self._draft, self._claims = draft, claims

    def propose(self, *, question, tenant, facts, tools):
        return self._draft, self._claims


def _request(state) -> SimpleNamespace:
    return SimpleNamespace(app=SimpleNamespace(state=state))


def test_inert_with_null_brain_does_not_change_live_answer():
    out = voice_ask.answer_question(
        _request(SimpleNamespace()), transcript="qwerty zxcvb asdfg", tenant=None
    )
    assert out.presence is None
    assert out.verdict.value == "ABSTAIN"
    assert out.attestation_anchor  # the legacy attestation chain still seals


def test_askoutcome_has_optional_presence_field():
    fields = voice_ask.AskOutcome.__dataclass_fields__
    assert "presence" in fields
    # default is None so every existing construction keeps working
    assert fields["presence"].default is None


def test_dimension_branch_attaches_presence_without_replacing(monkeypatch, populated_state):
    # Force the deterministic dimension path into a known shape: non-empty facts,
    # no fillable template (so the legacy answer is the templated ABSTAIN). The
    # presence channel runs in parallel off the same facts.
    fake_facts = SimpleNamespace(is_empty=lambda: False)
    fake_explanation = SimpleNamespace(facts=fake_facts)

    def _fake_explain(request, *, dimension, tenant, claim_text):
        return fake_explanation

    monkeypatch.setattr(voice_ask, "_FACTS_EXPLAINER", SimpleNamespace(explain=_fake_explain))
    monkeypatch.setattr(answer_forms, "build_dimension_answer", lambda *a, **k: None)

    populated_state.presence_brain = _FakeBrain(
        "how many forbids",
        (PresenceClaim("forbid_count", "how many forbids", ClaimKind.AGGREGATE),),
    )

    out = voice_ask.answer_question(
        _request(populated_state), transcript="how many forbidden actions were there", tenant=None
    )

    # Legacy path untouched: deterministic ABSTAIN answer + verdict.
    assert out.verdict.value == "ABSTAIN"
    assert out.answer == answer_forms.ABSTAIN_NO_FACT
    # Presence attached in parallel, grounded from the SAME sealed rows.
    assert out.presence is not None
    assert out.presence.spoken_text == "There are 3 forbidden decisions on record."
    assert out.presence.overall_tier.value == "sealed"


def test_seam_telemetry_accumulates(monkeypatch, populated_state):
    tel_before = voice_ask.get_presence_telemetry().snapshot()["answers_total"]

    fake_facts = SimpleNamespace(is_empty=lambda: False)
    monkeypatch.setattr(
        voice_ask, "_FACTS_EXPLAINER",
        SimpleNamespace(explain=lambda r, *, dimension, tenant, claim_text: SimpleNamespace(facts=fake_facts)),
    )
    monkeypatch.setattr(answer_forms, "build_dimension_answer", lambda *a, **k: None)
    populated_state.presence_brain = _FakeBrain(
        "how many forbids",
        (PresenceClaim("forbid_count", "how many forbids", ClaimKind.AGGREGATE),),
    )
    voice_ask.answer_question(_request(populated_state), transcript="how many forbidden actions were there", tenant=None)

    tel_after = voice_ask.get_presence_telemetry().snapshot()["answers_total"]
    assert tel_after == tel_before + 1
