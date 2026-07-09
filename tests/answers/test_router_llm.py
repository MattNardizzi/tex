"""
The LLM seam — Claude routes and drafts, and can never fabricate or mute.

Three layers under test, none touching the network:

  * ``AnswerLLM`` unit tests over a fake SDK client — the routing call's
    shape (schema-constrained, system-prompted, prior exchange threaded),
    the re-validation on receipt, and the fail-open law: ANY fault returns
    None, never raises.
  * ``_intent_from_route`` mapping law — "none" falls back (the LLM path is
    a strict SUPERSET of the regex parse), "unsupported" windows are
    decisive abstains, UUIDs stay regex-extracted so a hallucinated id is
    structurally impossible.
  * Route-level assembly over the REAL exhibit/drafter/gate seam with a fake
    seam injected via ``build_answer_router(llm_seam=...)`` — an
    understanding upgrade the regexes miss, the regex fallback when the seam
    goes quiet, the latest-record ask, and the drafter flooring when the
    seam's draft callable dies mid-flight.

Plus the two honesty additions in the exhibit layer: "recent" is bounded to
seven local days, and ``get_decision_record(store, None, tenant)`` resolves
"the last recorded" to the newest tenant-visible row.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tex.answers import exhibits
from tex.answers.router_llm import (
    ROUTE_TOOLS,
    ROUTE_VERDICTS,
    ROUTE_WINDOWS,
    AnswerLLM,
    build_seam_from_env,
)
from tex.api.answer_routes import _intent_from_route, build_answer_router
from tex.api.auth import TexPrincipal, authenticate_request
from tex.domain.decision import Decision
from tex.domain.verdict import Verdict
from tex.stores.decision_store import InMemoryDecisionStore


# --------------------------------------------------------------------------- #
# Builders (the sibling suites' idiom, verbatim)                              #
# --------------------------------------------------------------------------- #


def _decision(
    *,
    verdict: Verdict,
    tenant: str,
    decided_at: datetime,
    action_type: str = "send_email",
) -> Decision:
    uncertainty_flags = ["requires_human_review"] if verdict is Verdict.ABSTAIN else []
    return Decision(
        request_id=uuid4(),
        verdict=verdict,
        confidence=0.9,
        final_score=0.9,
        action_type=action_type,
        channel="api",
        environment="prod",
        content_excerpt="audit excerpt",
        content_sha256="a" * 64,
        policy_version="v1",
        uncertainty_flags=uncertainty_flags,
        metadata={"tenant_id": tenant},
        decided_at=decided_at,
    )


def _scoped(tenant: str) -> TexPrincipal:
    return TexPrincipal(
        api_key_fingerprint="test",
        tenant=tenant,
        scopes=frozenset({"decision:read"}),
    )


def _seam_client(
    store: InMemoryDecisionStore, principal: TexPrincipal, seam
) -> TestClient:
    app = FastAPI()
    app.include_router(build_answer_router(llm_seam=seam))
    app.state.decision_store = store
    app.dependency_overrides[authenticate_request] = lambda: principal
    return TestClient(app)


def _now_utc() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- #
# Fakes                                                                       #
# --------------------------------------------------------------------------- #


class _FakeSDKClient:
    """Duck-types the two SDK surfaces the seam touches: with_options + create."""

    def __init__(self, reply, stop_reason: str = "end_turn") -> None:
        self.reply = reply  # str payload, or an Exception to raise
        self.stop_reason = stop_reason
        self.create_calls: list[dict] = []
        self.option_calls: list[dict] = []
        self.messages = SimpleNamespace(create=self._create)

    def with_options(self, **kwargs):
        self.option_calls.append(kwargs)
        return self

    def _create(self, **kwargs):
        self.create_calls.append(kwargs)
        if isinstance(self.reply, Exception):
            raise self.reply
        return SimpleNamespace(
            stop_reason=self.stop_reason,
            content=[SimpleNamespace(type="text", text=self.reply)],
        )


class _FakeSeam:
    """The route handler's view of the seam: route() decides.

    ``draft`` is a REGRESSION GUARD, not a used method — the answer route must
    never call an LLM drafter (truth-safety: the gate byte-verifies digits,
    not the prose frame). If a future edit re-wires LLM drafting, this fires
    and the ``test_route_never_calls_the_llm_drafter`` test breaks loudly.
    """

    def __init__(self, decision) -> None:
        self.decision = decision
        self.seen: tuple | None = None

    def route(self, question, prior_question=None, prior_answer=None):
        self.seen = (question, prior_question, prior_answer)
        return self.decision

    def draft(self, prompt: str) -> str:
        raise AssertionError(
            "the answer route must not call an LLM drafter — drafting stays "
            "the deterministic floor (gate verifies digits, not prose)"
        )


# --------------------------------------------------------------------------- #
# AnswerLLM.route — the wire contract                                         #
# --------------------------------------------------------------------------- #


def test_route_happy_path_returns_validated_decision() -> None:
    payload = json.dumps({"tool": "count", "verdict": "FORBID", "window": "today"})
    client = _FakeSDKClient(payload)
    seam = AnswerLLM(client, model="claude-opus-4-8", route_timeout=6.0)

    decision = seam.route("how many did you stop today?")

    assert decision == {"tool": "count", "verdict": "FORBID", "window": "today"}
    call = client.create_calls[0]
    # The decision is schema-constrained at the API layer, not parsed prose.
    fmt = call["output_config"]["format"]
    assert fmt["type"] == "json_schema"
    assert set(fmt["schema"]["properties"]) == {"tool", "verdict", "window"}
    assert "QUESTION: how many did you stop today?" in call["messages"][0]["content"]
    assert "sealed" in call["system"].lower()
    # Routing runs with a hard timeout and no SDK retries — the regex parse
    # IS the retry.
    assert client.option_calls[0]["max_retries"] == 0


def test_route_threads_the_prior_exchange() -> None:
    payload = json.dumps({"tool": "count", "verdict": "FORBID", "window": "yesterday"})
    client = _FakeSDKClient(payload)
    seam = AnswerLLM(client)

    seam.route(
        "what about yesterday?",
        prior_question="how many were forbidden today?",
        prior_answer="three decisions were forbidden today.",
    )

    content = client.create_calls[0]["messages"][0]["content"]
    assert "PRIOR QUESTION: how many were forbidden today?" in content
    assert "PRIOR ANSWER: three decisions were forbidden today." in content
    assert content.rstrip().endswith("QUESTION: what about yesterday?")


def test_route_fails_open_on_wire_fault() -> None:
    seam = AnswerLLM(_FakeSDKClient(RuntimeError("api down")))
    assert seam.route("how many today?") is None


def test_route_fails_open_on_refusal() -> None:
    payload = json.dumps({"tool": "count", "verdict": "ANY", "window": "today"})
    seam = AnswerLLM(_FakeSDKClient(payload, stop_reason="refusal"))
    assert seam.route("how many today?") is None


def test_route_fails_open_on_off_menu_reply() -> None:
    # Unreachable through the schema constraint, but the seam re-validates —
    # it never trusts the wire more than once.
    payload = json.dumps({"tool": "drop_tables", "verdict": "ANY", "window": "today"})
    seam = AnswerLLM(_FakeSDKClient(payload))
    assert seam.route("how many today?") is None


def test_route_fails_open_on_malformed_json() -> None:
    seam = AnswerLLM(_FakeSDKClient("count of forbids please"))
    assert seam.route("how many today?") is None


def test_seam_exposes_routing_only_never_a_drafter() -> None:
    # Truth-safety invariant: the seam must not carry a drafting method — the
    # gate byte-verifies digits, not the prose FRAME, so an LLM-authored frame
    # could seal a fabricated verdict/window/name. Routing is the only role.
    seam = AnswerLLM(_FakeSDKClient("{}"))
    assert not hasattr(seam, "draft")
    assert not hasattr(seam, "draft_callable")


# --------------------------------------------------------------------------- #
# build_seam_from_env — fail-open construction                                #
# --------------------------------------------------------------------------- #


def test_seam_is_none_without_a_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert build_seam_from_env() is None


def test_seam_is_none_when_opted_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("TEX_ANSWER_LLM", "0")
    assert build_seam_from_env() is None


def test_seam_builds_with_key_and_honors_model_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.delenv("TEX_ANSWER_LLM", raising=False)
    monkeypatch.setenv("TEX_ANSWER_MODEL", "claude-haiku-4-5")
    seam = build_seam_from_env()
    assert isinstance(seam, AnswerLLM)
    assert seam._model == "claude-haiku-4-5"  # noqa: SLF001 — white-box, sibling-suite idiom


# --------------------------------------------------------------------------- #
# _intent_from_route — the mapping law                                        #
# --------------------------------------------------------------------------- #


def test_none_tool_falls_back_to_regex() -> None:
    routed = {"tool": "none", "verdict": "ANY", "window": "recent"}
    assert _intent_from_route(routed, "philosophy question") is None
    assert _intent_from_route(None, "anything") is None


def test_unsupported_window_is_a_decisive_abstain() -> None:
    routed = {"tool": "count", "verdict": "FORBID", "window": "unsupported"}
    intent = _intent_from_route(routed, "how many were forbidden last week?")
    assert intent is not None and intent.kind == "unsupported_window"


def test_any_verdict_maps_to_none_and_agents_strip_verdicts() -> None:
    intent = _intent_from_route(
        {"tool": "count", "verdict": "ANY", "window": "today"}, "how many today?"
    )
    assert intent.kind == "count" and intent.verdict is None

    roster = _intent_from_route(
        {"tool": "agents_list", "verdict": "FORBID", "window": "recent"},
        "name my agents",
    )
    assert roster.kind == "agents_list" and roster.verdict is None


def test_record_id_is_regex_extracted_never_model_authored() -> None:
    uid = str(uuid4())
    with_id = _intent_from_route(
        {"tool": "record", "verdict": "ANY", "window": "recent"},
        f"show me the record for {uid}",
    )
    assert with_id.kind == "record" and with_id.decision_id == uid

    latest = _intent_from_route(
        {"tool": "record", "verdict": "ANY", "window": "recent"},
        "show me the last recorded",
    )
    assert latest.kind == "record" and latest.decision_id is None


def test_held_waiting_tools_map_and_ignore_window_and_verdict() -> None:
    # The router can name the waiting tools directly; the mapping forces the
    # present, held-only reading and drops any stray window/verdict.
    for tool in ("held_waiting_count", "held_waiting_list"):
        intent = _intent_from_route(
            {"tool": tool, "verdict": "ANY", "window": "recent"}, "what needs me now"
        )
        assert intent.kind == tool
        assert intent.verdict == "HELD"
        assert intent.window_label is None
    # A stray 'unsupported' window can never mute a "what needs me now" ask —
    # the waiting mapping is checked before the unsupported-window rule.
    intent = _intent_from_route(
        {"tool": "held_waiting_count", "verdict": "ANY", "window": "unsupported"}, "q"
    )
    assert intent.kind == "held_waiting_count"


def test_held_qualified_last_record_never_returns_permit() -> None:
    # THE BUG: the router routes "last held action" to record + ANY (the held
    # qualifier dropped). The FLOOR must still filter to ABSTAIN so a PERMIT can
    # never be sealed for a held question — enforced in the exhibit floor, not
    # the router prompt.
    store = InMemoryDecisionStore()
    now = _now_utc()
    held = _decision(
        verdict=Verdict.ABSTAIN,
        tenant="acme",
        decided_at=now - timedelta(hours=2),
        action_type="wire_transfer",
    )
    permit = _decision(
        verdict=Verdict.PERMIT, tenant="acme", decided_at=now, action_type="file_write"
    )
    store.save(held)
    store.save(permit)

    seam = _FakeSeam({"tool": "record", "verdict": "ANY", "window": "recent"})
    client = _seam_client(store, _scoped("acme"), seam)
    r = client.post("/v1/answer", json={"question": "what was the last held action?"})

    assert r.status_code == 200, r.text
    body = r.json()
    exhibit = body["exhibits"][0]
    assert exhibit["kind"] == "record"
    pairs = dict(exhibit["value"])
    # The newest ABSTAIN, never the newer PERMIT.
    assert pairs["verdict"] == "ABSTAIN"
    assert pairs["decision_id"] == str(held.decision_id)
    assert "PERMIT" not in body["spoken_text"]


# --------------------------------------------------------------------------- #
# Route-level assembly with an injected seam                                  #
# --------------------------------------------------------------------------- #


def test_seam_routes_a_phrasing_the_regexes_miss() -> None:
    store = InMemoryDecisionStore()
    now = _now_utc()
    for _ in range(3):
        store.save(_decision(verdict=Verdict.FORBID, tenant="acme", decided_at=now))

    seam = _FakeSeam({"tool": "count", "verdict": "FORBID", "window": "today"})
    client = _seam_client(store, _scoped("acme"), seam)
    # No count/list/verdict regex matches this phrasing — keyless Tex abstains.
    r = client.post("/v1/answer", json={"question": "how did the estate do today?"})

    assert r.status_code == 200
    body = r.json()
    assert body["overall_tier"] == "SEALED"
    assert body["abstain_reason"] is None
    assert body["exhibits"][0]["query"]["tool"] == "count_decisions"
    assert body["exhibits"][0]["query"]["verdict"] == "FORBID"
    assert body["exhibits"][0]["value"] == 3
    # The DETERMINISTIC FLOOR authored the prose (the seam has no drafter) —
    # phrasing that is exhibit-consistent by construction, verb from the
    # exhibit's own verdict.
    assert "three" in body["spoken_text"]
    assert "forbidden" in body["spoken_text"]


def test_route_never_calls_the_llm_drafter() -> None:
    # The whole truth-safety fix in one assertion: even with a live seam whose
    # draft() would raise AssertionError, a full answer succeeds — proving the
    # route wires drafter.draft(llm=None) and never lets the model write prose.
    store = InMemoryDecisionStore()
    store.save(_decision(verdict=Verdict.FORBID, tenant="acme", decided_at=_now_utc()))

    seam = _FakeSeam({"tool": "count", "verdict": "FORBID", "window": "today"})
    client = _seam_client(store, _scoped("acme"), seam)
    r = client.post("/v1/answer", json={"question": "rundown on blocks today"})

    assert r.status_code == 200  # no AssertionError leaked from a draft() call
    assert r.json()["overall_tier"] == "SEALED"


def test_quiet_seam_falls_back_to_the_regex_parse() -> None:
    store = InMemoryDecisionStore()
    store.save(_decision(verdict=Verdict.FORBID, tenant="acme", decided_at=_now_utc()))

    seam = _FakeSeam(None)  # wire fault posture
    client = _seam_client(store, _scoped("acme"), seam)
    r = client.post(
        "/v1/answer", json={"question": "how many decisions were forbidden today?"}
    )

    assert r.status_code == 200
    assert r.json()["overall_tier"] == "SEALED"
    assert "one" in r.json()["spoken_text"]


def test_none_tool_still_answers_what_regexes_can() -> None:
    # The SUPERSET law: the model saying "none" can never mute a question the
    # deterministic parse already answers.
    store = InMemoryDecisionStore()
    store.save(_decision(verdict=Verdict.FORBID, tenant="acme", decided_at=_now_utc()))

    seam = _FakeSeam({"tool": "none", "verdict": "ANY", "window": "recent"})
    client = _seam_client(store, _scoped("acme"), seam)
    r = client.post(
        "/v1/answer", json={"question": "how many decisions were forbidden today?"}
    )

    assert r.status_code == 200
    assert r.json()["overall_tier"] == "SEALED"


def test_seam_unsupported_window_abstains_honestly() -> None:
    store = InMemoryDecisionStore()
    store.save(_decision(verdict=Verdict.FORBID, tenant="acme", decided_at=_now_utc()))

    seam = _FakeSeam({"tool": "count", "verdict": "FORBID", "window": "unsupported"})
    client = _seam_client(store, _scoped("acme"), seam)
    r = client.post(
        "/v1/answer", json={"question": "how many were forbidden last friday?"}
    )

    assert r.status_code == 200
    assert r.json()["abstain_reason"] == "unsupported_window"


def test_prior_exchange_rides_the_dto_into_the_seam() -> None:
    store = InMemoryDecisionStore()
    store.save(_decision(verdict=Verdict.FORBID, tenant="acme", decided_at=_now_utc()))

    seam = _FakeSeam({"tool": "count", "verdict": "FORBID", "window": "today"})
    client = _seam_client(store, _scoped("acme"), seam)
    r = client.post(
        "/v1/answer",
        json={
            "question": "and what about today?",
            "prior_question": "how many were forbidden yesterday?",
            "prior_answer": "two decisions were forbidden yesterday.",
        },
    )

    assert r.status_code == 200
    assert seam.seen == (
        "and what about today?",
        "how many were forbidden yesterday?",
        "two decisions were forbidden yesterday.",
    )


def test_latest_record_ask_speaks_the_newest_row() -> None:
    store = InMemoryDecisionStore()
    now = _now_utc()
    store.save(
        _decision(
            verdict=Verdict.FORBID,
            tenant="acme",
            decided_at=now - timedelta(hours=3),
            action_type="wire_transfer",
        )
    )
    newest = _decision(
        verdict=Verdict.PERMIT,
        tenant="acme",
        decided_at=now,
        action_type="file_write",
    )
    store.save(newest)

    seam = _FakeSeam({"tool": "record", "verdict": "ANY", "window": "recent"})
    client = _seam_client(store, _scoped("acme"), seam)
    r = client.post("/v1/answer", json={"question": "show me the last recorded"})

    assert r.status_code == 200
    body = r.json()
    assert body["abstain_reason"] is None
    exhibit = body["exhibits"][0]
    assert exhibit["kind"] == "record"
    pairs = dict(exhibit["value"])
    assert pairs["decision_id"] == str(newest.decision_id)
    assert pairs["action_type"] == "file_write"


# --------------------------------------------------------------------------- #
# Exhibit honesty additions                                                   #
# --------------------------------------------------------------------------- #


def test_recent_window_is_bounded_to_seven_days() -> None:
    store = InMemoryDecisionStore()
    now = _now_utc()
    store.save(
        _decision(verdict=Verdict.ABSTAIN, tenant="acme", decided_at=now - timedelta(days=2))
    )
    store.save(
        _decision(verdict=Verdict.ABSTAIN, tenant="acme", decided_at=now - timedelta(days=30))
    )

    count = exhibits.count_decisions(
        store, "acme", "HELD", window_label="recent"
    )
    # "recently" now MEANS the last seven days — the 30-day-old hold is
    # honestly outside it (it still counts under "in total").
    assert count["value"] == 1
    total = exhibits.count_decisions(store, "acme", "HELD", window_label="in total")
    assert total["value"] == 2


def test_latest_record_respects_tenant_walls_and_empty_stores() -> None:
    store = InMemoryDecisionStore()
    now = _now_utc()
    mine = _decision(
        verdict=Verdict.FORBID, tenant="acme", decided_at=now - timedelta(hours=1)
    )
    store.save(mine)
    # A NEWER row behind another tenant's wall must not be "the latest".
    store.save(_decision(verdict=Verdict.PERMIT, tenant="rival", decided_at=now))

    record = exhibits.get_decision_record(store, None, "acme")
    assert dict(record["value"])["decision_id"] == str(mine.decision_id)

    with pytest.raises(KeyError):
        exhibits.get_decision_record(InMemoryDecisionStore(), None, "acme")
