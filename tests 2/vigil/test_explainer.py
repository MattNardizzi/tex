"""
The explanation layer must stay fenced: it narrates sealed facts, falls back
deterministically, never advises, and never sees unsealed input. These tests
pin all four.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from tex.domain.decision import Decision
from tex.domain.verdict import Verdict
from tex.main import create_app
from tex.vigil.explainer import Explainer, ExplanationMode


class _FakeReq:
    """Minimal request exposing app.state for the explainer to read."""

    def __init__(self, app) -> None:
        self.app = app


class _StubProvider:
    """Records the prompts it is handed; optionally fails."""

    def __init__(self, text: str = "Tex narration.", fail: bool = False) -> None:
        self.text = text
        self.fail = fail
        self.calls = 0
        self.system_prompt: str | None = None
        self.user_prompt: str | None = None

    def complete(self, *, system_prompt: str, user_prompt: str) -> str:
        self.calls += 1
        self.system_prompt = system_prompt
        self.user_prompt = user_prompt
        if self.fail:
            raise RuntimeError("provider down")
        return self.text


def _mk(verdict, eh, action="wire_transfer", channel="api", flags=None):
    return Decision(
        request_id=uuid4(),
        verdict=verdict,
        confidence=0.9,
        final_score=0.9,
        action_type=action,
        channel=channel,
        environment="production",
        content_excerpt="x",
        content_sha256="a" * 64,
        policy_version="v1",
        uncertainty_flags=(flags or []),
        evidence_hash=eh,
        decided_at=datetime.now(UTC),
    )


@pytest.fixture()
def seeded_request():
    app = create_app()
    ds = app.state.decision_store
    for i in range(14):
        ds.save(_mk(Verdict.FORBID, f"{i:064x}", action="wire_transfer"))
    for i in range(4):
        ds.save(_mk(Verdict.FORBID, f"{i+50:064x}", action="data_export", channel="slack"))
    for i in range(3):
        ds.save(_mk(Verdict.ABSTAIN, f"{i+100:064x}", flags=["conflicting_signals"]))
    return _FakeReq(app)


def test_deterministic_floor_when_no_provider(seeded_request) -> None:
    exp = Explainer(provider=None)
    out = exp.explain(seeded_request, dimension="execution", tenant=None,
                      claim_text="I held back 18 actions tonight.")
    assert out.mode is ExplanationMode.DEFAULT_FALLBACK
    assert out.generator == "deterministic"
    assert out.grounded is True
    # Restates the sealed facts and cites an anchor.
    assert "18 actions were forbidden" in out.explanation
    assert "wire_transfer" in out.explanation
    assert out.facts.anchors and out.facts.anchors[0].sha256


def test_provider_narration_is_used_and_facts_travel(seeded_request) -> None:
    stub = _StubProvider(text="Overnight you forbade 18 actions, mostly wire transfers.")
    exp = Explainer(provider=stub, provider_name="stub")
    out = exp.explain(seeded_request, dimension="execution", tenant=None,
                      claim_text="I held back 18 actions tonight.")
    assert out.mode is ExplanationMode.PRIMARY_PROVIDER
    assert out.generator == "stub"
    assert out.explanation == stub.text
    # The sealed facts ALWAYS travel back with the prose.
    assert out.grounded is True
    assert out.facts.headline.startswith("18 actions were forbidden")
    assert out.facts.anchors


def test_provider_only_ever_sees_sealed_facts(seeded_request) -> None:
    stub = _StubProvider()
    exp = Explainer(provider=stub)
    exp.explain(seeded_request, dimension="execution", tenant=None,
                claim_text="I held back 18 actions tonight.")
    # The model's input is the sealed fact sheet, not raw agent text.
    assert "18" in stub.user_prompt
    assert "wire_transfer" in stub.user_prompt
    # The system prompt forbids advice and forbids inventing facts.
    assert "NEVER give advice" in stub.system_prompt
    assert "Use ONLY the facts" in stub.system_prompt


def test_provider_failure_falls_back_deterministically(seeded_request) -> None:
    stub = _StubProvider(fail=True)
    exp = Explainer(provider=stub, allow_fallback=True)
    out = exp.explain(seeded_request, dimension="execution", tenant=None)
    assert out.mode is ExplanationMode.FAILURE_FALLBACK
    assert out.generator == "deterministic"
    assert "18 actions were forbidden" in out.explanation


def test_provider_failure_raises_when_fallback_disabled(seeded_request) -> None:
    stub = _StubProvider(fail=True)
    exp = Explainer(provider=stub, allow_fallback=False)
    with pytest.raises(RuntimeError):
        exp.explain(seeded_request, dimension="execution", tenant=None)


def test_empty_dimension_never_calls_provider(seeded_request) -> None:
    stub = _StubProvider()
    exp = Explainer(provider=stub)
    out = exp.explain(seeded_request, dimension="does_not_exist", tenant=None)
    assert stub.calls == 0  # no model call on an empty sheet
    assert out.mode is ExplanationMode.DEFAULT_FALLBACK
    assert "nothing sealed to explain" in out.explanation.lower()


def test_deterministic_floor_does_not_advise(seeded_request) -> None:
    exp = Explainer(provider=None)
    out = exp.explain(seeded_request, dimension="human_decision", tenant=None)
    lowered = out.explanation.lower()
    for advice_word in ("you should", "recommend", "we suggest", "you ought"):
        assert advice_word not in lowered
