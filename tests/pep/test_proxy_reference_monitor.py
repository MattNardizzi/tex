"""Reference-monitor wiring tests for ``tex.pep.proxy`` (G7 / G6 / G10).

These exercise the proxy CORE (``handle``) with fakes for the decision client,
forwarder, and orig_dst loader, plus a REAL ``MemorySystem`` for the permit
path. They pin the behaviours that turn the proxy from "asks the PDP and trusts
request headers" into a reference monitor:

  G7 — the proxy decides on, and forwards to, the KERNEL-captured destination,
       not the spoofable Host / X-Tex-Upstream header.
  G6 — a presented identity credential is verified; an attested id that
       disagrees with the ruled-on agent id is FORBIDden.
  G10 — every released action mints a single-use, content-bound permit that is
        verified against the bytes about to egress and consumed exactly once.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from uuid import uuid4

import pytest

from tex.enforcement import permit
from tex.memory.system import MemorySystem
from tex.pep.decision_client import Decision, DecisionClient, DecisionResult
from tex.pep.proxy import (
    OrigDstResolver,
    ProxyConfig,
    ResolvedDst,
    TexEnforcementProxy,
    UpstreamResponse,
    _base_from_dst,
)


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
            status=200, headers={"content-type": "text/plain"}, body=b"OK"
        )


class _StaticClient(DecisionClient):
    def __init__(self, result: DecisionResult):
        self._result = result
        self.last: Decision | None = None

    def decide(self, decision: Decision) -> DecisionResult:
        self.last = decision
        return self._result


class _FakeResolver:
    """Stands in for the UDS OrigDstResolver. Returns a fixed dst (or None)."""

    def __init__(self, dst: ResolvedDst | None):
        self._dst = dst

    def resolve(self, src_ip, src_port):
        return self._dst


def _permit() -> DecisionResult:
    return DecisionResult(
        released=True, verdict="PERMIT", reason="ok", decision_id=str(uuid4())
    )


def _mem():
    d = tempfile.mkdtemp()
    return MemorySystem(tenant_id="default", evidence_path=os.path.join(d, "ev.jsonl"))


def _signed_card(agent_id: str, issuer: str = "issuer-1", **claims):
    """Build an Ed25519-signed identity card + its trusted_issuers map.

    Extra signed claims (e.g. ``exp``, ``nbf``, ``aud``) can be passed as kwargs;
    ``None`` values are dropped so the default card stays exp/aud-free."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    raw_pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    payload = {
        "agent_id": agent_id,
        "name": "demo",
        **{k: v for k, v in claims.items() if v is not None},
    }
    jcs = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    card = {
        "payload": payload,
        "issuer": issuer,
        "signature_b64": base64.b64encode(sk.sign(jcs)).decode("ascii"),
    }
    issuers = {issuer: base64.b64encode(raw_pub).decode("ascii")}
    return card, issuers


def _cred_header(card: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(card).encode("utf-8")).decode("ascii")


# --------------------------------------------------------------------------- #
# G7 — kernel-captured destination                                            #
# --------------------------------------------------------------------------- #


def test_decides_and_forwards_on_kernel_dst_not_spoofed_host():
    fwd = _RecordingForwarder()
    client = _StaticClient(_permit())
    proxy = TexEnforcementProxy(
        decision_client=client,
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.5", 80)),
        # The vhost legitimately lives on the kernel-pinned IP.
        host_resolver=lambda h: {"10.0.0.5"} if h == "allowed-api.example" else set(),
    )
    resp = proxy.handle(
        method="POST",
        path="/v1/data",
        # The agent's X-Tex-Upstream is ignored; the kernel dst pins the IP and
        # the Host (pinned to that IP) is what policy rules on.
        headers={
            "Host": "allowed-api.example",
            "X-Tex-Upstream": "https://elsewhere.example",
        },
        body=b"payload",
        peer=("172.16.0.9", 51111),
    )
    assert resp.status == 200
    # Ruled on the Host pinned to the kernel IP — not the spoofable X-Tex-Upstream.
    assert client.last is not None
    assert client.last.recipient == "allowed-api.example"
    # Forwarded to the kernel dst ip:port; the connection can't be moved.
    assert fwd.calls[0]["url"] == "http://10.0.0.5:80/v1/data"
    assert fwd.calls[0]["headers"].get("Host") == "allowed-api.example"


def test_host_not_resolving_to_kernel_ip_is_forbidden():
    # A Host naming a vhost that does NOT resolve to the kernel-pinned IP is a
    # mismatch — refused before the PDP (closes "claim an allowed name while the
    # IP is elsewhere").
    fwd = _RecordingForwarder()
    client = _StaticClient(_permit())
    proxy = TexEnforcementProxy(
        decision_client=client,
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.5", 443)),
        host_resolver=lambda h: {"203.0.113.9"},  # resolves elsewhere
    )
    resp = proxy.handle(
        method="POST",
        path="/p",
        headers={"Host": "claimed.example"},
        body=b"x",
        peer=("1.2.3.4", 5),
    )
    assert resp.status == 403
    assert b"mismatch" in resp.body
    assert fwd.calls == []
    assert client.last is None  # blocked before the PDP


def test_forbidden_vhost_on_allowed_ip_is_ruled_by_name():
    # THE bypass: forbidden.example is co-located on the allowed IP. It pins to
    # the IP (DNS ok), but the PDP now rules on the NAME and FORBIDs it.
    class _HostForbidClient(DecisionClient):
        def __init__(self):
            self.last = None

        def decide(self, decision):
            self.last = decision
            ok = decision.recipient != "forbidden.example"
            return DecisionResult(
                released=ok, verdict="PERMIT" if ok else "FORBID", reason="x"
            )

    fwd = _RecordingForwarder()
    client = _HostForbidClient()
    proxy = TexEnforcementProxy(
        decision_client=client,
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.5", 443)),
        host_resolver=lambda h: {"10.0.0.5"},  # both vhosts share the allowed IP
    )
    resp = proxy.handle(
        method="POST",
        path="/p",
        headers={"Host": "forbidden.example"},
        body=b"x",
        peer=("1.2.3.4", 5),
    )
    assert resp.status == 403  # caught by NAME, though the IP was allowed
    assert client.last.recipient == "forbidden.example"
    assert fwd.calls == []


def test_no_host_header_rules_on_kernel_ip():
    # No Host => no vhost to bind => rule on the kernel IP, as before.
    fwd = _RecordingForwarder()
    client = _StaticClient(_permit())
    proxy = TexEnforcementProxy(
        decision_client=client,
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.5", 80)),
    )
    resp = proxy.handle(
        method="GET", path="/p", headers={}, body=b"", peer=("1.2.3.4", 5)
    )
    assert resp.status == 200
    assert client.last.recipient == "10.0.0.5"


def test_header_fallback_when_no_verified_dst_is_untrusted_but_works():
    fwd = _RecordingForwarder()
    client = _StaticClient(_permit())
    proxy = TexEnforcementProxy(
        decision_client=client, forwarder=fwd, origdst=_FakeResolver(None)
    )
    resp = proxy.handle(
        method="GET",
        path="/p",
        headers={"Host": "h.example", "X-Tex-Upstream": "https://up.example"},
        body=b"",
        peer=("1.2.3.4", 5),
    )
    assert resp.status == 200
    assert client.last.recipient == "up.example"  # header used (untrusted)
    assert fwd.calls[0]["url"] == "https://up.example/p"


def test_require_verified_dst_forbids_on_miss():
    fwd = _RecordingForwarder()
    client = _StaticClient(_permit())
    proxy = TexEnforcementProxy(
        decision_client=client,
        forwarder=fwd,
        origdst=_FakeResolver(None),
        config=ProxyConfig(require_verified_dst=True),
    )
    resp = proxy.handle(
        method="GET", path="/p", headers={"Host": "h"}, body=b"", peer=("1.2.3.4", 5)
    )
    assert resp.status == 403
    assert fwd.calls == []  # never forwarded


def test_origdst_resolver_unreachable_socket_returns_none():
    # A real resolver pointed at a non-existent socket fails soft (no raise).
    resolver = OrigDstResolver("/run/tex/does-not-exist.sock", timeout=0.2)
    assert resolver.resolve("1.2.3.4", 5555) is None


# --------------------------------------------------------------------------- #
# G6 — attested identity                                                       #
# --------------------------------------------------------------------------- #


def test_identity_mismatch_forbids_before_forwarding():
    declared = str(uuid4())
    card, issuers = _signed_card(agent_id="some-other-id")  # != declared
    fwd = _RecordingForwarder()
    client = _StaticClient(_permit())
    proxy = TexEnforcementProxy(
        decision_client=client,
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.1", 80)),
        config=ProxyConfig(trusted_issuers=issuers),
    )
    resp = proxy.handle(
        method="POST",
        path="/p",
        headers={
            "X-Tex-Agent-Id": declared,
            "X-Tex-Agent-Credential": _cred_header(card),
        },
        body=b"x",
        peer=("1.2.3.4", 5),
    )
    assert resp.status == 403
    assert b"mismatch" in resp.body
    assert fwd.calls == []  # blocked before the PDP and the forward
    assert client.last is None  # never even decided


def test_identity_match_allows():
    agent_id = str(uuid4())
    card, issuers = _signed_card(agent_id=agent_id)
    fwd = _RecordingForwarder()
    client = _StaticClient(_permit())
    proxy = TexEnforcementProxy(
        decision_client=client,
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.1", 80)),
        config=ProxyConfig(trusted_issuers=issuers),
    )
    resp = proxy.handle(
        method="POST",
        path="/p",
        headers={
            "X-Tex-Agent-Id": agent_id,
            "X-Tex-Agent-Credential": _cred_header(card),
        },
        body=b"x",
        peer=("1.2.3.4", 5),
    )
    assert resp.status == 200
    assert fwd.calls  # forwarded


def test_bad_credential_forbids_even_without_require_identity():
    card, issuers = _signed_card(agent_id="a")
    card["payload"]["agent_id"] = "tampered"  # signature now stale
    fwd = _RecordingForwarder()
    client = _StaticClient(_permit())
    proxy = TexEnforcementProxy(
        decision_client=client,
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.1", 80)),
        config=ProxyConfig(trusted_issuers=issuers),  # require_identity False
    )
    resp = proxy.handle(
        method="POST",
        path="/p",
        headers={
            "X-Tex-Agent-Id": "a",
            "X-Tex-Agent-Credential": _cred_header(card),
        },
        body=b"x",
        peer=("1.2.3.4", 5),
    )
    assert resp.status == 403
    assert fwd.calls == []


def test_require_identity_with_no_credential_forbids():
    fwd = _RecordingForwarder()
    client = _StaticClient(_permit())
    proxy = TexEnforcementProxy(
        decision_client=client,
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.1", 80)),
        config=ProxyConfig(require_identity=True),
    )
    resp = proxy.handle(
        method="POST",
        path="/p",
        headers={"X-Tex-Agent-Id": str(uuid4())},
        body=b"x",
        peer=("1.2.3.4", 5),
    )
    assert resp.status == 403
    assert fwd.calls == []


def test_no_credential_proceeds_by_default_documented_gap():
    # Default deployment (no issuer wired): we proceed on the unverified header.
    fwd = _RecordingForwarder()
    client = _StaticClient(_permit())
    proxy = TexEnforcementProxy(
        decision_client=client,
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.1", 80)),
    )
    resp = proxy.handle(
        method="POST",
        path="/p",
        headers={"X-Tex-Agent-Id": str(uuid4())},
        body=b"x",
        peer=("1.2.3.4", 5),
    )
    assert resp.status == 200
    assert fwd.calls


def test_proxy_seals_executed_receipt_with_per_request_attested_identity():
    # End-to-end: the proxy verifies the credential (G6) AND seals a TERMINAL
    # receipt (G4) carrying that exact attested identity, outcome=executed.
    from tex.provenance.ledger import SealedFactLedger

    agent_id = str(uuid4())
    card, issuers = _signed_card(agent_id=agent_id)
    ledger = SealedFactLedger()
    fwd = _RecordingForwarder()
    proxy = TexEnforcementProxy(
        decision_client=_StaticClient(_permit()),
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.1", 80)),
        config=ProxyConfig(trusted_issuers=issuers),
        seal_ledger=ledger,
    )
    resp = proxy.handle(
        method="POST",
        path="/p",
        headers={
            "X-Tex-Agent-Id": agent_id,
            "X-Tex-Agent-Credential": _cred_header(card),
        },
        body=b"x",
        peer=("1.2.3.4", 5),
    )
    assert resp.status == 200
    assert len(proxy.seal_records) == 1
    detail = proxy.seal_records[0].fact.detail
    assert detail["outcome"] == "executed"  # forwarded => executed
    attestation = detail["identity_attestation"]
    assert attestation["verified"] is True
    assert attestation["claimed_agent_id"] == agent_id
    assert ledger.verify_chain()["intact"] is True


def test_permit_block_seals_blocked_not_executed(monkeypatch):
    # Receipt-inversion fix: a released action the permit gate REFUSES must seal
    # outcome=blocked — never a false "executed". (No signing secret in a
    # production-like env makes the permit gate fail closed on a released action.)
    monkeypatch.delenv("TEX_PERMIT_SIGNING_SECRET", raising=False)
    monkeypatch.setenv("TEX_REQUIRE_AUTH", "1")
    from tex.provenance.ledger import SealedFactLedger

    ledger = SealedFactLedger()
    fwd = _RecordingForwarder()
    proxy = TexEnforcementProxy(
        decision_client=_StaticClient(_permit()),  # PDP RELEASED
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.7", 80)),
        permit_memory=_mem(),
        seal_ledger=ledger,
    )
    resp = proxy.handle(
        method="POST", path="/x", headers={}, body=b"b", peer=("1.2.3.4", 5)
    )
    assert resp.status == 403  # permit gate refused
    assert fwd.calls == []  # never forwarded
    assert len(proxy.seal_records) == 1
    detail = proxy.seal_records[0].fact.detail
    assert detail["outcome"] == "blocked"  # the TRUTH, not "executed"
    assert detail["allowed"] is False
    assert detail["verdict"] == "PERMIT"  # PDP released, but the PEP blocked it
    assert ledger.verify_chain()["intact"] is True


def test_forbidden_decision_seals_blocked():
    from tex.provenance.ledger import SealedFactLedger

    ledger = SealedFactLedger()
    fwd = _RecordingForwarder()
    forbid = DecisionResult(released=False, verdict="FORBID", reason="nope")
    proxy = TexEnforcementProxy(
        decision_client=_StaticClient(forbid),
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.1", 80)),
        seal_ledger=ledger,
    )
    resp = proxy.handle(
        method="POST", path="/x", headers={}, body=b"b", peer=("1.2.3.4", 5)
    )
    assert resp.status == 403
    assert len(proxy.seal_records) == 1
    detail = proxy.seal_records[0].fact.detail
    assert detail["outcome"] == "blocked"
    assert detail["verdict"] == "FORBID"


def test_verified_credential_fills_in_absent_principal():
    # No agent header at all, but a verified credential carries the id: we rule
    # on the attested id rather than an anonymous request.
    agent_id = "did:tex:agent-77"
    card, issuers = _signed_card(agent_id=agent_id)
    fwd = _RecordingForwarder()
    client = _StaticClient(_permit())
    proxy = TexEnforcementProxy(
        decision_client=client,
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.1", 80)),
        config=ProxyConfig(trusted_issuers=issuers),
    )
    resp = proxy.handle(
        method="POST",
        path="/p",
        headers={"X-Tex-Agent-Credential": _cred_header(card)},
        body=b"x",
        peer=("1.2.3.4", 5),
    )
    assert resp.status == 200
    assert client.last.agent_external_id == agent_id


def test_expired_credential_forbids_at_proxy():
    # Anti-replay: a signature-valid but EXPIRED credential is refused even
    # without require_identity (exp=1000 is decades in the past vs the real clock).
    agent_id = str(uuid4())
    card, issuers = _signed_card(agent_id=agent_id, exp=1000)
    fwd = _RecordingForwarder()
    client = _StaticClient(_permit())
    proxy = TexEnforcementProxy(
        decision_client=client,
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.1", 80)),
        config=ProxyConfig(trusted_issuers=issuers),
    )
    resp = proxy.handle(
        method="POST",
        path="/p",
        headers={
            "X-Tex-Agent-Id": agent_id,
            "X-Tex-Agent-Credential": _cred_header(card),
        },
        body=b"x",
        peer=("1.2.3.4", 5),
    )
    assert resp.status == 403
    assert fwd.calls == []  # captured/expired credential never forwards


def test_credential_audience_mismatch_forbids_at_proxy():
    # A credential minted for another PEP (aud) is refused at this one.
    agent_id = str(uuid4())
    card, issuers = _signed_card(agent_id=agent_id, aud="pep-other")
    fwd = _RecordingForwarder()
    client = _StaticClient(_permit())
    proxy = TexEnforcementProxy(
        decision_client=client,
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.1", 80)),
        config=ProxyConfig(trusted_issuers=issuers, pep_audience="pep-this"),
    )
    resp = proxy.handle(
        method="POST",
        path="/p",
        headers={
            "X-Tex-Agent-Id": agent_id,
            "X-Tex-Agent-Credential": _cred_header(card),
        },
        body=b"x",
        peer=("1.2.3.4", 5),
    )
    assert resp.status == 403
    assert fwd.calls == []


# --------------------------------------------------------------------------- #
# G10 — single-use content-bound permit                                        #
# --------------------------------------------------------------------------- #


def test_mints_attaches_and_consumes_permit(monkeypatch):
    monkeypatch.setenv("TEX_PERMIT_SIGNING_SECRET", "s3cret-test")
    mem = _mem()
    fwd = _RecordingForwarder()
    client = _StaticClient(_permit())
    proxy = TexEnforcementProxy(
        decision_client=client,
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.7", 80)),
        permit_memory=mem,
    )
    resp = proxy.handle(
        method="POST",
        path="/pay",
        headers={},
        body=b"transfer 100",
        peer=("1.2.3.4", 5),
    )
    assert resp.status == 200

    token = fwd.calls[0]["headers"]["X-Tex-Permit"]
    assert token  # the egress proof is attached to the forwarded request

    # The permit is bound to the EXACT bytes that egressed + the verified audience.
    v = permit.verify(
        token,
        expected_content_digest=permit.content_digest(b"transfer 100"),
        expected_audience="10.0.0.7",
    )
    assert v.ok

    # It was consumed exactly once (single-use) and recorded VALID.
    stored = mem.permits.get_by_nonce(v.claims["nonce"])
    assert stored is not None and stored.consumed_at is not None
    assert not stored.is_active
    assert any(r.result.value == "VALID" for r in mem.verifications.list_recent())


def test_permit_minted_for_wrong_audience_would_fail_verify(monkeypatch):
    # The permit the proxy attaches verifies against the dst it forwarded to,
    # NOT a host an attacker might claim — proving the audience binding is live.
    monkeypatch.setenv("TEX_PERMIT_SIGNING_SECRET", "s3cret-test")
    mem = _mem()
    fwd = _RecordingForwarder()
    proxy = TexEnforcementProxy(
        decision_client=_StaticClient(_permit()),
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.7", 80)),
        permit_memory=mem,
    )
    proxy.handle(method="POST", path="/x", headers={}, body=b"b", peer=("1.2.3.4", 5))
    token = fwd.calls[0]["headers"]["X-Tex-Permit"]
    bad = permit.verify(
        token,
        expected_content_digest=permit.content_digest(b"b"),
        expected_audience="evil.example",
    )
    assert not bad.ok and "audience" in bad.reason


def test_permit_no_signing_secret_in_production_forbids(monkeypatch):
    monkeypatch.delenv("TEX_PERMIT_SIGNING_SECRET", raising=False)
    monkeypatch.setenv("TEX_REQUIRE_AUTH", "1")  # production-like
    mem = _mem()
    fwd = _RecordingForwarder()
    proxy = TexEnforcementProxy(
        decision_client=_StaticClient(_permit()),
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.7", 80)),
        permit_memory=mem,
    )
    resp = proxy.handle(
        method="POST", path="/x", headers={}, body=b"b", peer=("1.2.3.4", 5)
    )
    # Released by the PDP, but no signing secret => no egress proof => fail closed.
    assert resp.status == 403
    assert fwd.calls == []


def test_forbidden_decision_mints_no_permit(monkeypatch):
    monkeypatch.setenv("TEX_PERMIT_SIGNING_SECRET", "s3cret-test")
    mem = _mem()
    fwd = _RecordingForwarder()
    forbid = DecisionResult(released=False, verdict="FORBID", reason="nope")
    proxy = TexEnforcementProxy(
        decision_client=_StaticClient(forbid),
        forwarder=fwd,
        origdst=_FakeResolver(ResolvedDst("10.0.0.7", 80)),
        permit_memory=mem,
    )
    resp = proxy.handle(
        method="POST", path="/x", headers={}, body=b"b", peer=("1.2.3.4", 5)
    )
    assert resp.status == 403
    assert fwd.calls == []
    assert mem.verifications.list_recent() == ()  # no permit lifecycle at all


# --------------------------------------------------------------------------- #
# G9 — https_opaque marker + rule_opaque + upstream-scheme fix                 #
# --------------------------------------------------------------------------- #


def test_to_decision_opaque_marks_https_opaque_not_silent_http():
    # The first slice: an opaque/TLS-unreadable body becomes an explicit
    # `https_opaque` action on the (pinned) recipient — NOT a silent `http_<method>`
    # default the PDP would tend to PERMIT.
    proxy = TexEnforcementProxy(decision_client=_StaticClient(_permit()))
    decision, mcp = proxy._to_decision(
        method="CONNECT",
        path="",
        body=b"\x16\x03\x01garbage-ciphertext",  # looks like a TLS record, unreadable
        tenant="default",
        recipient="api.openai.com",
        agent_id=None,
        agent_external_id=None,
        session_id=None,
        opaque=True,
    )
    assert decision.action_type == "https_opaque"
    assert decision.recipient == "api.openai.com"
    assert decision.channel == "network"
    assert "not inspectable" in decision.content
    assert mcp is None
    # The non-opaque default is unchanged (regression guard for the silent path).
    plain, _ = proxy._to_decision(
        method="GET", path="/p", body=b"", tenant="default", recipient="h",
        agent_id=None, agent_external_id=None, session_id=None,
    )
    assert plain.action_type == "http_get"


def test_rule_opaque_permit_releases_and_seals_executed():
    from tex.provenance.ledger import SealedFactLedger

    ledger = SealedFactLedger()
    proxy = TexEnforcementProxy(
        decision_client=_StaticClient(_permit()), seal_ledger=ledger,
        config=ProxyConfig(default_agent_external_id="sidecar-agent"),
    )
    result = proxy.rule_opaque(recipient="api.example")
    assert result.released is True
    # Ruled as https_opaque (the PDP saw an opaque action, not a forged http_get).
    assert proxy._decide.last.action_type == "https_opaque"
    assert proxy._decide.last.recipient == "api.example"
    assert proxy._decide.last.agent_external_id == "sidecar-agent"
    detail = proxy.seal_records[0].fact.detail
    assert detail["outcome"] == "executed"  # committed to splice
    assert ledger.verify_chain()["intact"] is True


def test_rule_opaque_non_permit_does_not_release_and_seals_blocked():
    from tex.provenance.ledger import SealedFactLedger

    ledger = SealedFactLedger()
    abstain = DecisionResult(released=False, verdict="ABSTAIN", reason="opaque content")
    proxy = TexEnforcementProxy(
        decision_client=_StaticClient(abstain), seal_ledger=ledger
    )
    result = proxy.rule_opaque(recipient="unknown.example")
    assert result.released is False
    assert result.verdict == "ABSTAIN"
    detail = proxy.seal_records[0].fact.detail
    assert detail["outcome"] == "blocked"  # never spliced -> fail-closed


def test_base_from_dst_does_not_downgrade_unknown_ports_to_http():
    # The fix: only port 80 is treated as plaintext; 443 AND unknown ports default
    # to https (no silent downgrade). An explicit tls flag overrides the guess.
    assert _base_from_dst(ResolvedDst("10.0.0.1", 80)) == "http://10.0.0.1:80"
    assert _base_from_dst(ResolvedDst("10.0.0.1", 443)) == "https://10.0.0.1:443"
    assert _base_from_dst(ResolvedDst("10.0.0.1", 8443)) == "https://10.0.0.1:8443"
    assert _base_from_dst(ResolvedDst("10.0.0.1", 9999)) == "https://10.0.0.1:9999"
    # explicit transport hint wins both ways
    assert _base_from_dst(ResolvedDst("10.0.0.1", 8080, tls=False)) == "http://10.0.0.1:8080"
    assert _base_from_dst(ResolvedDst("10.0.0.1", 80, tls=True)) == "https://10.0.0.1:80"
