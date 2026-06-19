"""Activation tests — the emission gate (Approach B) FIRES on the live proxy
request path (``TexEnforcementProxy.handle``).

These prove the wiring documented in ``src/tex/emission/PROXY_INTEGRATION.md`` is
now active, off the SAME sealed ``CapabilitySurface`` the discovery filter
(``_filter_tools_list``) reads:

  * a forbidden tool is stripped end-to-end before the request egresses;
  * a non-provider request is forwarded byte-identical (no silent mis-rewrite);
  * the constraint is sealed (proof-carrying) when a ledger is wired.

Maturity: ``provider-trusted`` (Approach B) — Tex controls the request the
provider decodes, not the sampler. True un-emittability is Approach A
(``tex.emission.vllm_mapping``), which needs a Tex-hosted endpoint.
"""

from __future__ import annotations

import json
from uuid import uuid4

from tex.domain.agent import CapabilitySurface
from tex.pep.decision_client import Decision, DecisionClient, DecisionResult
from tex.pep.proxy import ProxyConfig, TexEnforcementProxy, UpstreamResponse


# --------------------------------------------------------------------------- #
# Fakes                                                                        #
# --------------------------------------------------------------------------- #


class _RecordingForwarder:
    def __init__(self):
        self.calls: list[dict] = []

    def send(self, method, url, headers, body):
        self.calls.append(
            {"method": method, "url": url, "headers": headers, "body": body}
        )
        return UpstreamResponse(
            status=200, headers={"content-type": "application/json"}, body=b"{}"
        )


class _StaticClient(DecisionClient):
    def __init__(self, result: DecisionResult):
        self._result = result
        self.last: Decision | None = None

    def decide(self, decision: Decision) -> DecisionResult:
        self.last = decision
        return self._result


class _AgentWithSurface:
    def __init__(self, surface):
        self.capability_surface = surface


class _SurfaceGov:
    """Minimal stand-in for the in-process governor: resolves any principal to
    one agent carrying ``surface`` (the proxy only reads ``capability_surface``)."""

    def __init__(self, surface):
        self._surface = surface

    def _resolve_agent(self, tenant, agent_id, agent_external_id):  # noqa: D401
        return _AgentWithSurface(self._surface)


def _permit() -> DecisionResult:
    return DecisionResult(
        released=True, verdict="PERMIT", reason="ok", decision_id=str(uuid4())
    )


def _openai_two_tool_body() -> dict:
    return {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "do it"}],
        "tools": [
            {"type": "function", "function": {"name": "get_weather", "parameters": {}}},
            {
                "type": "function",
                "function": {"name": "delete_database", "parameters": {}},
            },
        ],
        "tool_choice": "auto",
    }


def _proxy(surface, *, forwarder=None, seal_ledger=None) -> TexEnforcementProxy:
    # No origdst -> the header-fallback path; X-Tex-Upstream resolves the recipient.
    return TexEnforcementProxy(
        decision_client=_StaticClient(_permit()),
        forwarder=forwarder or _RecordingForwarder(),
        governance=_SurfaceGov(surface),
        seal_ledger=seal_ledger,
        config=ProxyConfig(),
    )


# --------------------------------------------------------------------------- #
# Task 1 — emission gate fires on the forward path                            #
# --------------------------------------------------------------------------- #


def test_forbidden_tool_stripped_end_to_end():
    # Surface permits only get_weather; the agent's request also offers
    # delete_database. The bytes that egress must carry ONLY get_weather.
    surface = CapabilitySurface(allowed_tools=("get_weather",))
    fwd = _RecordingForwarder()
    proxy = _proxy(surface, forwarder=fwd)

    resp = proxy.handle(
        method="POST",
        path="/v1/chat/completions",
        headers={"X-Tex-Upstream": "https://api.openai.com"},
        body=json.dumps(_openai_two_tool_body()).encode("utf-8"),
        peer=("1.2.3.4", 5),
    )
    assert resp.status == 200
    assert len(fwd.calls) == 1
    sent = json.loads(fwd.calls[0]["body"])
    names = [t["function"]["name"] for t in sent["tools"]]
    assert names == ["get_weather"]  # delete_database stripped before egress
    # content-length was reset to the rewritten size.
    assert fwd.calls[0]["headers"]["content-length"] == str(len(fwd.calls[0]["body"]))


def test_anthropic_forbidden_tool_stripped_end_to_end():
    # The wiring is provider-agnostic: an Anthropic Messages request is rewritten
    # too (detect_provider/rewrite_provider_request handle both dialects).
    surface = CapabilitySurface(allowed_tools=("get_weather",))
    fwd = _RecordingForwarder()
    proxy = _proxy(surface, forwarder=fwd)
    body = {
        "model": "claude-opus-4-8",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": "do it"}],
        "tools": [
            {"name": "get_weather", "input_schema": {"type": "object"}},
            {"name": "delete_database", "input_schema": {"type": "object"}},
        ],
    }
    proxy.handle(
        method="POST",
        path="/v1/messages",
        headers={"X-Tex-Upstream": "https://api.anthropic.com"},
        body=json.dumps(body).encode("utf-8"),
        peer=("1.2.3.4", 5),
    )
    sent = json.loads(fwd.calls[0]["body"])
    assert [t["name"] for t in sent["tools"]] == ["get_weather"]


def test_forbidden_specific_tool_choice_downgraded():
    # A request that FORCES the forbidden tool is fail-closed to "no tool",
    # not merely stripped from the menu.
    surface = CapabilitySurface(allowed_tools=("get_weather",))
    fwd = _RecordingForwarder()
    proxy = _proxy(surface, forwarder=fwd)
    body = _openai_two_tool_body()
    body["tool_choice"] = {"type": "function", "function": {"name": "delete_database"}}

    proxy.handle(
        method="POST",
        path="/v1/chat/completions",
        headers={"X-Tex-Upstream": "https://api.openai.com"},
        body=json.dumps(body).encode("utf-8"),
        peer=("1.2.3.4", 5),
    )
    sent = json.loads(fwd.calls[0]["body"])
    assert sent["tool_choice"] == "none"
    assert [t["function"]["name"] for t in sent["tools"]] == ["get_weather"]


def test_non_provider_request_untouched():
    # A body that is not a recognizable provider chat request egresses
    # byte-identical — the gate never mis-rewrites a dialect it cannot reason on.
    surface = CapabilitySurface(allowed_tools=("get_weather",))
    fwd = _RecordingForwarder()
    proxy = _proxy(surface, forwarder=fwd)
    raw = json.dumps({"hello": "world", "n": 1}).encode("utf-8")

    proxy.handle(
        method="POST",
        path="/v1/data",
        headers={"X-Tex-Upstream": "https://api.example"},
        body=raw,
        peer=("1.2.3.4", 5),
    )
    assert fwd.calls[0]["body"] == raw  # untouched, byte-for-byte


def test_no_surface_leaves_provider_body_untouched():
    # No in-process governor surface (governance=None) => the gate is inert and
    # the provider body egresses unchanged (zero behaviour change for sidecars
    # without a wired governor).
    fwd = _RecordingForwarder()
    proxy = TexEnforcementProxy(
        decision_client=_StaticClient(_permit()),
        forwarder=fwd,
        governance=None,
    )
    raw = json.dumps(_openai_two_tool_body()).encode("utf-8")
    proxy.handle(
        method="POST",
        path="/v1/chat/completions",
        headers={"X-Tex-Upstream": "https://api.openai.com"},
        body=raw,
        peer=("1.2.3.4", 5),
    )
    assert fwd.calls[0]["body"] == raw


def test_unrestricted_surface_keeps_all_tools():
    # An empty surface declares NO tool restriction; the gate must not invent
    # one — both tools survive (honesty: no mask claimed that was not applied).
    surface = CapabilitySurface()  # unrestricted
    fwd = _RecordingForwarder()
    proxy = _proxy(surface, forwarder=fwd)
    proxy.handle(
        method="POST",
        path="/v1/chat/completions",
        headers={"X-Tex-Upstream": "https://api.openai.com"},
        body=json.dumps(_openai_two_tool_body()).encode("utf-8"),
        peer=("1.2.3.4", 5),
    )
    sent = json.loads(fwd.calls[0]["body"])
    assert sorted(t["function"]["name"] for t in sent["tools"]) == [
        "delete_database",
        "get_weather",
    ]


def test_constraint_is_sealed_when_ledger_present():
    from tex.provenance.ledger import SealedFactLedger

    surface = CapabilitySurface(allowed_tools=("get_weather",))
    ledger = SealedFactLedger()
    fwd = _RecordingForwarder()
    proxy = _proxy(surface, forwarder=fwd, seal_ledger=ledger)

    proxy.handle(
        method="POST",
        path="/v1/chat/completions",
        headers={"X-Tex-Upstream": "https://api.openai.com"},
        body=json.dumps(_openai_two_tool_body()).encode("utf-8"),
        peer=("1.2.3.4", 5),
    )
    # The ledger carries an emission-constraint fact (alongside the terminal
    # enforcement-outcome fact); find it by its distinctive detail.
    constraint_facts = [
        r.fact
        for r in ledger.list_all()
        if "constraint_digest" in (r.fact.detail or {})
    ]
    assert len(constraint_facts) == 1
    fact = constraint_facts[0]
    assert fact.detail["approach"] == "provider_trusted"
    assert fact.detail["allowed_tool_names"] == ["get_weather"]
    assert fact.detail["constrains_tool_names"] is True
    assert "emission gate decoded turn under allowlist H=" in fact.claim
    assert ledger.verify_chain()["intact"] is True
    assert ledger.verify_signatures()["valid"] is True


def test_egress_permit_binds_to_rewritten_bytes(monkeypatch):
    # Ordering invariant: the emission rewrite runs BEFORE the G10 permit gate, so
    # the content-bound egress permit binds to the bytes that ACTUALLY egress
    # (the rewritten request), not the agent's original body. If the gate were
    # placed after the permit mint, this verify against the rewritten body would
    # fail — so this test guards that ordering.
    import os
    import tempfile

    from tex.enforcement import permit
    from tex.memory.system import MemorySystem

    monkeypatch.setenv("TEX_PERMIT_SIGNING_SECRET", "s3cret-test")
    d = tempfile.mkdtemp()
    mem = MemorySystem(
        tenant_id="default", evidence_path=os.path.join(d, "ev.jsonl")
    )
    surface = CapabilitySurface(allowed_tools=("get_weather",))
    fwd = _RecordingForwarder()
    proxy = TexEnforcementProxy(
        decision_client=_StaticClient(_permit()),
        forwarder=fwd,
        governance=_SurfaceGov(surface),
        permit_memory=mem,
    )
    original = json.dumps(_openai_two_tool_body()).encode("utf-8")
    resp = proxy.handle(
        method="POST",
        path="/v1/chat/completions",
        headers={"X-Tex-Upstream": "https://api.openai.com"},
        body=original,
        peer=("1.2.3.4", 5),
    )
    assert resp.status == 200
    egressed = fwd.calls[0]["body"]
    assert egressed != original  # the body was rewritten (delete_database stripped)
    token = fwd.calls[0]["headers"]["X-Tex-Permit"]

    # The permit verifies against the REWRITTEN bytes + the verified audience...
    ok = permit.verify(
        token,
        expected_content_digest=permit.content_digest(egressed),
        expected_audience="api.openai.com",
    )
    assert ok.ok
    # ...and NOT against the agent's original (pre-strip) body.
    stale = permit.verify(
        token,
        expected_content_digest=permit.content_digest(original),
        expected_audience="api.openai.com",
    )
    assert not stale.ok


def test_no_seal_ledger_still_rewrites():
    # The seal is observation-only: with no ledger the rewrite still happens.
    surface = CapabilitySurface(allowed_tools=("get_weather",))
    fwd = _RecordingForwarder()
    proxy = _proxy(surface, forwarder=fwd, seal_ledger=None)
    proxy.handle(
        method="POST",
        path="/v1/chat/completions",
        headers={"X-Tex-Upstream": "https://api.openai.com"},
        body=json.dumps(_openai_two_tool_body()).encode("utf-8"),
        peer=("1.2.3.4", 5),
    )
    sent = json.loads(fwd.calls[0]["body"])
    assert [t["function"]["name"] for t in sent["tools"]] == ["get_weather"]
