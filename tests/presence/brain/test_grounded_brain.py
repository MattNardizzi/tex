"""GroundedReasoner: proposes only from a provider, parses safely, abstains when
uncertain. The provider is faked — no network, no SDK needed."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from tex.presence.brain import GroundedReasoner, build_grounded_brain, build_read_tools
from tex.presence.brain.prompts import build_brain_system_prompt
from tex.presence.contract import ClaimKind, GroundedBrain, PresenceClaim


@dataclass
class _FakeProvider:
    """A StructuredSemanticProvider stand-in returning a canned payload (or raising)."""

    payload: Any = None
    error: Exception | None = None
    seen: dict = None  # captured prompts

    def analyze(self, *, system_prompt: str, user_prompt: str):
        if self.seen is not None:
            self.seen["system"] = system_prompt
            self.seen["user"] = user_prompt
        if self.error is not None:
            raise self.error
        return self.payload


def _brain(payload=None, error=None, seen=None):
    return GroundedReasoner(provider=_FakeProvider(payload=payload, error=error, seen=seen))


def test_conforms_to_groundedbrain_protocol():
    assert isinstance(GroundedReasoner(), GroundedBrain)
    assert isinstance(build_grounded_brain(), GroundedBrain)


def test_no_provider_is_deterministic_noop():
    brain = build_grounded_brain(provider=None)
    draft, claims = brain.propose(question="how many forbids?", tenant="acme", facts={}, tools=())
    assert draft == ""
    assert claims == ()


def test_parses_grounded_claims_and_maps_kinds():
    draft = "There is 1 forbid and agent alpha is active."
    payload = {
        "draft": draft,
        "claims": [
            {"text_span": "1 forbid", "kind": "aggregate"},
            {"text_span": "agent alpha is active", "kind": "entity"},
        ],
    }
    got_draft, claims = _brain(payload).propose(question="status?", tenant="acme", facts={}, tools=())
    assert got_draft == draft
    assert [c.kind for c in claims] == [ClaimKind.AGGREGATE, ClaimKind.ENTITY]
    assert all(isinstance(c, PresenceClaim) for c in claims)
    assert all(c.text_span in draft for c in claims)
    assert len({c.claim_id for c in claims}) == 2  # unique ids


def test_drops_claim_whose_span_is_not_in_draft():
    brain = _brain({
        "draft": "Two agents are active.",
        "claims": [
            {"text_span": "Two agents are active", "kind": "aggregate"},
            {"text_span": "five forbids last week", "kind": "aggregate"},  # hallucinated span
        ],
    })
    draft, claims = brain.propose(question="?", tenant=None, facts={}, tools=())
    assert len(claims) == 1
    assert brain.last_drops.get("span_not_in_draft") == 1


def test_drops_claim_with_unknown_kind_never_guesses():
    brain = _brain({
        "draft": "Agent alpha exists.",
        "claims": [{"text_span": "Agent alpha exists", "kind": "prophecy"}],
    })
    draft, claims = brain.propose(question="?", tenant=None, facts={}, tools=())
    assert claims == ()
    assert brain.last_drops.get("bad_or_missing_kind") == 1


def test_empty_draft_proposes_nothing():
    draft, claims = _brain({"draft": "   ", "claims": []}).propose(
        question="?", tenant=None, facts={}, tools=()
    )
    assert draft == ""
    assert claims == ()


def test_provider_refusal_or_error_proposes_nothing():
    brain = _brain(error=RuntimeError("refused"))
    draft, claims = brain.propose(question="?", tenant=None, facts={}, tools=())
    assert (draft, claims) == ("", ())


def test_wrong_shape_payload_proposes_nothing():
    # A SemanticAnalysis-like object (no 'draft') must not be coerced into a guess.
    class _Analysis:
        def model_dump(self):
            return {"primary_risk": "phishing", "confidence": 0.9}

    draft, claims = _brain(_Analysis()).propose(question="?", tenant=None, facts={}, tools=())
    assert (draft, claims) == ("", ())


def test_string_json_payload_is_parsed():
    import json

    payload = json.dumps({"draft": "Alpha is active.", "claims": [{"text_span": "Alpha is active", "kind": "entity"}]})
    draft, claims = _brain(payload).propose(question="?", tenant=None, facts={}, tools=())
    assert draft == "Alpha is active."
    assert claims[0].kind is ClaimKind.ENTITY


def test_facts_are_handed_in_prompt_not_sourced(populated_state):
    seen: dict = {}
    brain = _brain({"draft": "", "claims": []}, seen=seen)
    tools = build_read_tools(populated_state)
    facts = {"human_decision.verdict_count": {"count": 1, "verdict": "FORBID"}}
    brain.propose(question="how many forbids?", tenant="acme", facts=facts, tools=tools)
    # The provider only ever sees the facts via the prompt — never sources them.
    assert "FORBID" in seen["user"]
    assert "how many forbids?" in seen["user"]
    # System prompt names the read-tools and the grounding rules.
    assert "propose_presence_answer" in seen["system"]
    assert "ONLY the sealed facts" in seen["system"]


def test_over_max_claims_is_reported_not_silent():
    draft = "x " * 5  # span "x" is in draft
    payload = {"draft": draft, "claims": [{"text_span": "x", "kind": "entity"} for _ in range(10)]}
    brain = GroundedReasoner(provider=_FakeProvider(payload=payload), max_claims=3)
    _, claims = brain.propose(question="?", tenant=None, facts={}, tools=())
    assert len(claims) == 3
    assert brain.last_drops.get("over_max_claims") == 7


def test_system_prompt_lists_tool_names(populated_state):
    tools = build_read_tools(populated_state)
    prompt = build_brain_system_prompt([t.name for t in tools])
    assert "execution.recent_actions" in prompt
    assert "discovery.chain_head" in prompt
