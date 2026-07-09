"""
POST /v1/answer — pipeline assembly, end to end over the REAL exhibit +
drafter + gate seam.

These tests wire a bare FastAPI app mounting ``build_answer_router()`` against
a real ``InMemoryDecisionStore`` seeded with real ``Decision`` rows, so the
exhibit primitives compute real values from real rows — nothing about the
numbers is faked. Auth is faked exactly like the sibling route tests: the
``authenticate_request`` dependency is overridden to return a controlled
``TexPrincipal`` (anonymous for the happy paths, scoped for the isolation and
collision cases), which is the seam ``RequireScope("decision:read")`` runs on.

What is proven:

  * forbid-today happy path → a single SEALED span whose digits came from the
    store, correct response shape,
  * held-recent → the HELD word maps to the store's ABSTAIN verdict and seals,
  * a measured ZERO count is a SEALED answer, never an ABSTAIN,
  * an unsupported intent abstains with the exact contract line + reason,
  * cross-tenant isolation: tenant B's rows are invisible to tenant A,
  * key-tenant / query-tenant collision → 403 before any row is read,
  * the ping liveness endpoint.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tex.api.answer_routes import ABSTAIN_LINE, build_answer_router
from tex.api.auth import TexPrincipal, authenticate_request
from tex.domain.decision import Decision
from tex.domain.verdict import Verdict
from tex.stores.decision_store import InMemoryDecisionStore


# --------------------------------------------------------------------------- #
# Row + app builders                                                          #
# --------------------------------------------------------------------------- #


def _decision(
    *,
    verdict: Verdict,
    tenant: str,
    decided_at: datetime,
    action_type: str = "send_email",
) -> Decision:
    """A minimal-but-real Decision row stamped for one tenant at one instant."""
    # An ABSTAIN row must carry at least one uncertainty flag (the domain model
    # enforces it) — that IS the held/awaiting-human marker the HELD word reads.
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


def _anonymous() -> TexPrincipal:
    # Anonymous == every scope; the keyless dev posture the UI runs against.
    return TexPrincipal(api_key_fingerprint="", tenant="default", scopes=frozenset())


def _scoped(tenant: str) -> TexPrincipal:
    return TexPrincipal(
        api_key_fingerprint="test",
        tenant=tenant,
        scopes=frozenset({"decision:read"}),
    )


def _client(store: InMemoryDecisionStore, principal: TexPrincipal) -> TestClient:
    app = FastAPI()
    app.include_router(build_answer_router())
    app.state.decision_store = store
    app.dependency_overrides[authenticate_request] = lambda: principal
    return TestClient(app)


def _now_utc() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- #
# Liveness                                                                    #
# --------------------------------------------------------------------------- #


def test_ping_is_live() -> None:
    client = _client(InMemoryDecisionStore(), _anonymous())
    r = client.get("/v1/answer/ping")
    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True}


# --------------------------------------------------------------------------- #
# Happy path: forbid today                                                    #
# --------------------------------------------------------------------------- #


def test_forbid_today_seals_a_single_span() -> None:
    store = InMemoryDecisionStore()
    # Three FORBIDs today for acme, one PERMIT today (must not be counted),
    # and one FORBID a week ago (outside the window).
    now = _now_utc()
    for _ in range(3):
        store.save(_decision(verdict=Verdict.FORBID, tenant="acme", decided_at=now))
    store.save(_decision(verdict=Verdict.PERMIT, tenant="acme", decided_at=now))
    store.save(
        _decision(
            verdict=Verdict.FORBID, tenant="acme", decided_at=now - timedelta(days=7)
        )
    )

    client = _client(store, _scoped("acme"))
    r = client.post("/v1/answer", json={"question": "how many did you forbid today?"})
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["tenant_id"] == "acme"
    assert body["overall_tier"] == "SEALED"
    assert body["abstain_reason"] is None
    assert len(body["spans"]) >= 1
    span = body["spans"][0]
    assert span["verdict"] == "SEALED"
    assert span["prosody"] == "sealed"
    assert span["anchor_sha256"]  # a real seal was minted

    # The exhibit is a count of exactly the three windowed FORBIDs — a value
    # computed by deterministic code, humanized to "three".
    assert len(body["exhibits"]) == 1
    exhibit = body["exhibits"][0]
    assert exhibit["kind"] == "count"
    assert exhibit["value"] == 3
    assert exhibit["spoken"] == "three"
    assert exhibit["query"]["verdict"] == "FORBID"
    assert exhibit["query"]["window_label"] == "today"

    # The spoken text carries the number-word, never a digit, and is the span
    # concatenation.
    assert "three" in body["spoken_text"]
    assert body["spoken_text"] == " ".join(s["text"] for s in body["spans"])


# --------------------------------------------------------------------------- #
# Held, recent window                                                         #
# --------------------------------------------------------------------------- #


def test_held_recent_maps_to_abstain_verdict_and_seals() -> None:
    store = InMemoryDecisionStore()
    now = _now_utc()
    # HELD in the operator's mouth == ABSTAIN in the store.
    for _ in range(2):
        store.save(_decision(verdict=Verdict.ABSTAIN, tenant="acme", decided_at=now))
    store.save(_decision(verdict=Verdict.FORBID, tenant="acme", decided_at=now))

    client = _client(store, _scoped("acme"))
    r = client.post(
        "/v1/answer", json={"question": "how many are you holding right now?"}
    )
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["overall_tier"] == "SEALED"
    exhibit = body["exhibits"][0]
    assert exhibit["value"] == 2
    assert exhibit["spoken"] == "two"
    # The query discloses the honest sealed verdict the HELD word normalized to.
    assert exhibit["query"]["verdict"] == "ABSTAIN"
    assert "two" in body["spoken_text"]


# --------------------------------------------------------------------------- #
# Zero is a sealed truth, never an abstention                                 #
# --------------------------------------------------------------------------- #


def test_zero_count_is_sealed_not_abstain() -> None:
    store = InMemoryDecisionStore()
    # A permit today, but ZERO forbids — the answer to "how many forbidden" is
    # a sealed zero.
    store.save(_decision(verdict=Verdict.PERMIT, tenant="acme", decided_at=_now_utc()))

    client = _client(store, _scoped("acme"))
    r = client.post("/v1/answer", json={"question": "how many were forbidden today?"})
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["overall_tier"] == "SEALED"
    assert body["abstain_reason"] is None
    assert body["spans"][0]["verdict"] == "SEALED"
    exhibit = body["exhibits"][0]
    assert exhibit["value"] == 0
    assert exhibit["spoken"] == "zero"
    # The line the caller hears is the calm sealed zero — the "No ..."
    # phrasing the is_zero provenance flag unlocks — never the ABSTAIN line.
    assert body["spoken_text"] != ABSTAIN_LINE
    assert body["spoken_text"] == "No decisions were forbidden today."


# --------------------------------------------------------------------------- #
# Unsupported intent abstains                                                 #
# --------------------------------------------------------------------------- #


def test_unsupported_intent_abstains() -> None:
    store = InMemoryDecisionStore()
    store.save(_decision(verdict=Verdict.FORBID, tenant="acme", decided_at=_now_utc()))

    client = _client(store, _scoped("acme"))
    r = client.post(
        "/v1/answer", json={"question": "what is the meaning of governance?"}
    )
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["overall_tier"] == "ABSTAIN"
    assert body["abstain_reason"] == "unsupported_intent"
    assert len(body["spans"]) == 1
    span = body["spans"][0]
    assert span["verdict"] == "ABSTAIN"
    assert span["prosody"] == "abstain"
    assert span["text"] == ABSTAIN_LINE
    assert body["spoken_text"] == ABSTAIN_LINE
    assert body["exhibits"] == []


# --------------------------------------------------------------------------- #
# Cross-tenant isolation                                                      #
# --------------------------------------------------------------------------- #


def test_cross_tenant_rows_are_invisible() -> None:
    store = InMemoryDecisionStore()
    now = _now_utc()
    # Two FORBIDs for globex (tenant B). acme (tenant A) has none.
    for _ in range(2):
        store.save(_decision(verdict=Verdict.FORBID, tenant="globex", decided_at=now))

    # Anonymous would see all tenants; use a scoped acme principal so the box
    # is real. The route pins the effective tenant to acme.
    client = _client(store, _scoped("acme"))
    r = client.post("/v1/answer", json={"question": "how many did you forbid today?"})
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["tenant_id"] == "acme"
    # acme sees a sealed ZERO — globex's two rows are invisible.
    assert body["overall_tier"] == "SEALED"
    assert body["exhibits"][0]["value"] == 0
    assert body["exhibits"][0]["spoken"] == "zero"


# --------------------------------------------------------------------------- #
# Key-tenant / query-tenant collision                                         #
# --------------------------------------------------------------------------- #


def test_key_query_tenant_collision_is_403() -> None:
    store = InMemoryDecisionStore()
    store.save(_decision(verdict=Verdict.FORBID, tenant="globex", decided_at=_now_utc()))

    # A key scoped to acme asking about globex is rejected before any row read.
    client = _client(store, _scoped("acme"))
    r = client.post(
        "/v1/answer",
        json={"question": "how many did you forbid today?", "tenant_id": "globex"},
    )
    assert r.status_code == 403, r.text


def test_scoped_key_may_query_its_own_tenant_explicitly() -> None:
    store = InMemoryDecisionStore()
    store.save(_decision(verdict=Verdict.FORBID, tenant="acme", decided_at=_now_utc()))

    client = _client(store, _scoped("acme"))
    r = client.post(
        "/v1/answer",
        json={"question": "how many did you forbid today?", "tenant_id": "acme"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["tenant_id"] == "acme"
    assert r.json()["exhibits"][0]["value"] == 1


# --------------------------------------------------------------------------- #
# Record miss abstains                                                        #
# --------------------------------------------------------------------------- #


def test_missing_record_abstains() -> None:
    store = InMemoryDecisionStore()
    client = _client(store, _scoped("acme"))
    # A record ask for a decision id that does not exist.
    missing = "11111111-1111-4111-8111-111111111111"
    r = client.post(
        "/v1/answer",
        json={"question": f"show me the record for decision {missing}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["overall_tier"] == "ABSTAIN"
    assert body["abstain_reason"] == "no_scoped_tool"
    assert body["spoken_text"] == ABSTAIN_LINE


# --------------------------------------------------------------------------- #
# The reviewer's regression pack: list and record answers must be SPEECH,
# never a serialized structure. These are the two breaches that shipped
# green because nothing asserted the actual spoken text.
# --------------------------------------------------------------------------- #


def _assert_speakable(spoken_text: str) -> None:
    """No structural characters and no naked digits may reach the voice."""
    for ch in "[]{}<>":
        assert ch not in spoken_text, spoken_text
    assert not any(c.isnumeric() for c in spoken_text), spoken_text
    assert "None" not in spoken_text, spoken_text


def test_list_answer_speaks_names_not_structures() -> None:
    store = InMemoryDecisionStore()
    for _ in range(5):
        store.save(_decision(verdict=Verdict.FORBID, tenant="acme", decided_at=_now_utc()))

    client = _client(store, _scoped("acme"))
    r = client.post("/v1/answer", json={"question": "list what you forbade"})
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["overall_tier"] == "SEALED"
    _assert_speakable(body["spoken_text"])
    # The ear hears agent names (this fixture has no agent -> the honest
    # fallback), plus a humanized remainder — never a repr of rows.
    assert "an unnamed agent" in body["spoken_text"]
    assert "more" in body["spoken_text"]  # five rows, three named, "two more"
    assert "decision_id" not in body["spoken_text"]


def test_record_answer_speaks_a_clean_sentence() -> None:
    store = InMemoryDecisionStore()
    d = _decision(verdict=Verdict.FORBID, tenant="acme", decided_at=_now_utc())
    store.save(d)

    client = _client(store, _scoped("acme"))
    r = client.post(
        "/v1/answer",
        json={"question": f"show me the record for decision {d.decision_id}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["overall_tier"] == "SEALED"
    # The record speaks its verdict/action/agent fragment — ids, hashes and
    # timestamps stay in the exhibit for the eye, never in the voice. The
    # sentence carries the record's own words, which may legitimately name
    # the action type — but never brackets, digits, or Python literals.
    spoken = body["spoken_text"]
    for ch in "[]{}<>":
        assert ch not in spoken, spoken
    assert "None" not in spoken, spoken
    assert "FORBID" in spoken
    assert "send_email" in spoken
    # The exhibit still carries the full record + real anchor for the PROOF chip.
    exhibit = body["exhibits"][0]
    assert exhibit["anchor_sha256"] == d.content_sha256


# --------------------------------------------------------------------------- #
# Window vocabulary v2: yesterday / in total / unsupported windows, and the
# agents-roster buttons. Each new button gets the same law as the originals:
# true numbers at the asked altitude, or an honest abstain — never the nearest
# window Tex happens to know.
# --------------------------------------------------------------------------- #

from tex.domain.agent import AgentIdentity  # noqa: E402
from tex.stores.agent_registry import InMemoryAgentRegistry  # noqa: E402


def test_yesterday_window_is_bounded() -> None:
    store = InMemoryDecisionStore()
    now = _now_utc()
    # One forbid right now (today), one 26h ago (yesterday, most zones).
    store.save(_decision(verdict=Verdict.FORBID, tenant="acme", decided_at=now))
    store.save(
        _decision(
            verdict=Verdict.FORBID, tenant="acme", decided_at=now - timedelta(hours=30)
        )
    )
    client = _client(store, _scoped("acme"))
    r = client.post("/v1/answer", json={"question": "how many forbid actions yesterday"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["overall_tier"] == "SEALED"
    assert body["exhibits"][0]["query"]["window_label"] == "yesterday"
    # Bounded window: today's forbid must NOT be counted.
    assert body["exhibits"][0]["value"] <= 1
    assert "yesterday" in body["spoken_text"]


def test_total_window_counts_everything_and_says_so() -> None:
    store = InMemoryDecisionStore()
    now = _now_utc()
    for age_days in (0, 3, 40):
        store.save(
            _decision(
                verdict=Verdict.FORBID,
                tenant="acme",
                decided_at=now - timedelta(days=age_days),
            )
        )
    client = _client(store, _scoped("acme"))
    r = client.post("/v1/answer", json={"question": "how many forbid actions total"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["exhibits"][0]["value"] == 3
    assert "in total" in body["spoken_text"]
    assert "recently" not in body["spoken_text"]


def test_unsupported_window_abstains_never_misaims() -> None:
    store = InMemoryDecisionStore()
    store.save(_decision(verdict=Verdict.FORBID, tenant="acme", decided_at=_now_utc()))
    client = _client(store, _scoped("acme"))
    r = client.post("/v1/answer", json={"question": "how many forbid actions last week"})
    assert r.status_code == 200, r.text
    body = r.json()
    # A true number at the wrong altitude is the sin — Tex abstains instead.
    assert body["overall_tier"] == "ABSTAIN"
    assert body["abstain_reason"] == "unsupported_window"
    assert body["spoken_text"] == ABSTAIN_LINE


def _registry_with(names_and_status) -> InMemoryAgentRegistry:
    reg = InMemoryAgentRegistry()
    for name, status, tenant in names_and_status:
        ident = AgentIdentity(
            name=name, owner="ops", tenant_id=tenant, lifecycle_status=status
        )
        reg.save(ident)
    return reg


def _client_with_registry(store, registry, principal) -> TestClient:
    app = FastAPI()
    app.include_router(build_answer_router())
    app.state.decision_store = store
    app.state.agent_registry = registry
    app.dependency_overrides[authenticate_request] = lambda: principal
    return TestClient(app)


def test_agents_roster_is_named_and_scoped() -> None:
    from tex.domain.agent import AgentLifecycleStatus

    reg = _registry_with(
        [
            ("GridArb", AgentLifecycleStatus.ACTIVE, "acme"),
            ("ForgeMaster", AgentLifecycleStatus.ACTIVE, "acme"),
            ("SleeperCell", AgentLifecycleStatus.SLEEPING, "acme"),
            ("ForeignBot", AgentLifecycleStatus.ACTIVE, "globex"),
        ]
    )
    client = _client_with_registry(InMemoryDecisionStore(), reg, _scoped("acme"))

    r = client.post("/v1/answer", json={"question": "name a few of the agents i have"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["overall_tier"] == "SEALED"
    assert "GridArb" in body["spoken_text"] and "ForgeMaster" in body["spoken_text"]
    # Sleeping and foreign-tenant agents never speak.
    assert "SleeperCell" not in body["spoken_text"]
    assert "ForeignBot" not in body["spoken_text"]

    r2 = client.post("/v1/answer", json={"question": "how many agents do i have"})
    body2 = r2.json()
    assert body2["exhibits"][0]["value"] == 2
    assert body2["spoken_text"] == "two agents are running."


def test_agents_ask_without_registry_abstains() -> None:
    client = _client(InMemoryDecisionStore(), _scoped("acme"))  # no registry on state
    r = client.post("/v1/answer", json={"question": "how many agents"})
    body = r.json()
    assert body["overall_tier"] == "ABSTAIN"


def test_agents_mention_without_provable_framing_abstains() -> None:
    from tex.domain.agent import AgentLifecycleStatus

    reg = _registry_with([("GridArb", AgentLifecycleStatus.ACTIVE, "acme")])
    client = _client_with_registry(InMemoryDecisionStore(), reg, _scoped("acme"))
    r = client.post("/v1/answer", json={"question": "who owns the most agents"})
    body = r.json()
    # Ownership is not in the vocabulary — the roster count would be a true
    # number answering a different question. Abstain.
    assert body["overall_tier"] == "ABSTAIN"
    assert body["abstain_reason"] == "unsupported_intent"


# --------------------------------------------------------------------------- #
# The unresolved-held truth path: "needs my attention RIGHT NOW" counts only    #
# the holds still waiting on a human — resolved holds and Tex's settled          #
# abstains are excluded — and is distinct from a HISTORICAL held tally.          #
# --------------------------------------------------------------------------- #

from tex.api.answer_routes import _normalize_waiting, _parse_intent  # noqa: E402
from tex.evidence.recorder import EvidenceRecorder  # noqa: E402


def _client_with_recorder(store, recorder, principal) -> TestClient:
    app = FastAPI()
    app.include_router(build_answer_router())
    app.state.decision_store = store
    app.state.evidence_recorder = recorder
    app.dependency_overrides[authenticate_request] = lambda: principal
    return TestClient(app)


def test_needs_attention_routes_to_waiting_and_excludes_resolved(tmp_path) -> None:
    store = InMemoryDecisionStore()
    now = _now_utc()
    held = [
        _decision(verdict=Verdict.ABSTAIN, tenant="acme", decided_at=now) for _ in range(3)
    ]
    for d in held:
        store.save(d)
    recorder = EvidenceRecorder(tmp_path / "evidence.jsonl")
    # A named human act resolves ONE of the three holds — it must stop counting.
    recorder.record_human_resolution(held[0], verdict="approved", resolved_by="ops@acme")

    client = _client_with_recorder(store, recorder, _scoped("acme"))
    r = client.post(
        "/v1/answer",
        json={
            "question": "are there any held decisions right now that need my attention?"
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["overall_tier"] == "SEALED"
    exhibit = body["exhibits"][0]
    assert exhibit["query"]["tool"] == "count_held_waiting"
    assert exhibit["value"] == 2  # three held minus the one resolved
    assert "two" in body["spoken_text"]
    assert "waiting for your attention" in body["spoken_text"]


def test_needs_attention_list_carries_walkable_rows(tmp_path) -> None:
    store = InMemoryDecisionStore()
    now = _now_utc()
    for _ in range(2):
        store.save(_decision(verdict=Verdict.ABSTAIN, tenant="acme", decided_at=now))
    recorder = EvidenceRecorder(tmp_path / "e.jsonl")
    client = _client_with_recorder(store, recorder, _scoped("acme"))
    r = client.post(
        "/v1/answer",
        json={"question": "show me the holds still waiting on me right now"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["overall_tier"] == "SEALED"
    exhibit = body["exhibits"][0]
    assert exhibit["query"]["tool"] == "list_held_waiting"
    # The act-able queue rides through to the JSON response, beside the voice.
    assert len(exhibit["rows"]) == 2
    assert set(exhibit["rows"][0].keys()) == {
        "decision_id",
        "agent",
        "action_type",
        "content_excerpt",
        "at",
    }
    assert "Waiting for your attention" in body["spoken_text"]
    _assert_speakable(body["spoken_text"])


def test_held_today_stays_a_historical_tally_not_waiting() -> None:
    store = InMemoryDecisionStore()
    store.save(_decision(verdict=Verdict.ABSTAIN, tenant="acme", decided_at=_now_utc()))
    client = _client(store, _scoped("acme"))
    r = client.post("/v1/answer", json={"question": "how many did you hold today?"})
    assert r.status_code == 200, r.text
    exhibit = r.json()["exhibits"][0]
    # A past-tense, windowed held question stays on the historical count tool.
    assert exhibit["query"]["tool"] == "count_decisions"
    assert exhibit["query"]["window_label"] == "today"


def test_normalize_waiting_rewrites_attention_cue_held() -> None:
    q = "are there any held decisions right now that need my attention?"
    assert _normalize_waiting(_parse_intent(q), q).kind == "held_waiting_count"
    q2 = "list the decisions still waiting on a human"
    assert _normalize_waiting(_parse_intent(q2), q2).kind == "held_waiting_list"


def test_normalize_waiting_leaves_history_and_other_verdicts_alone() -> None:
    hist = "how many did you hold this week?"
    got = _normalize_waiting(_parse_intent(hist), hist)
    assert got.kind == "count" and got.window_label == "this week"

    # A FORBID question with a cue must not be hijacked into the held queue.
    forbid = "how many did you forbid right now?"
    got2 = _normalize_waiting(_parse_intent(forbid), forbid)
    assert got2.kind == "count" and got2.verdict == "FORBID"
