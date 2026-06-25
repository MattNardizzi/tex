"""LocalForbidSource + the live-decide() local-action FORBID feed (S2).

Proves the verdict that warms the in-kernel LOCAL deny set flows from the REAL
StandingGovernance.decide() path — not a stub — and that it is inert by default
(no sink wired) so the change is byte-for-byte safe.
"""

from __future__ import annotations

import pytest

from tex.governance.local_forbid_source import LocalForbidSource, is_local_action_type
from tex.governance.standing import StandingGovernance
from tex.domain.verdict import Verdict


class _EmptyRegistry:
    """Empty registry => every agent is unsealed => decide() FORBIDs (Tier-1 floor)."""

    def get(self, _uid):
        return None

    def list_all(self):
        return []


def _gov(local_sink=None):
    return StandingGovernance(agent_registry=_EmptyRegistry(), local_forbid_sink=local_sink)


# ---- the source in isolation ----------------------------------------------

def test_add_revoke_epoch():
    src = LocalForbidSource()
    assert src.add("atlas", "/data/payroll.db") is True
    e1 = src.epoch
    assert src.response_set("acme")["forbid"] == [{"agent_id": "atlas", "path": "/data/payroll.db"}]
    assert src.revoke("atlas", "/data/payroll.db") == 1
    assert src.epoch > e1
    assert src.response_set("acme")["forbid"] == []


def test_blank_is_fail_closed_not_permit():
    src = LocalForbidSource()
    assert src.add("", "/x") is False
    assert src.add("a", "") is False
    assert src.response_set(None)["forbid"] == []


def test_ttl_expiry_is_revoke_not_permit():
    t = {"now": 1000.0}
    src = LocalForbidSource(clock=lambda: t["now"], default_ttl_seconds=10.0)
    src.add("a", "/p")
    assert len(src.response_set(None)["forbid"]) == 1
    t["now"] = 1011.0  # past TTL
    assert src.response_set(None)["forbid"] == []  # self-pruned, never a permit


def test_feed_only_fires_on_local_action_types():
    src = LocalForbidSource()
    # network/non-local action type -> no local warm
    assert src.feed_from_decision(action_type="http_post", recipient="evil.com:443",
                                  agent_id="a", tenant="acme") == 0
    # local action type -> warm
    assert src.feed_from_decision(action_type="delete", recipient="/data/x",
                                  agent_id="a", tenant="acme") == 1
    assert is_local_action_type("execute") and not is_local_action_type("send_email")


def test_signed_response_verifies_and_tamper_fails_closed():
    src = LocalForbidSource()
    src.add("atlas", "/data/payroll.db", tenant="acme")
    env = src.signed_response("acme", secret="topsecret")
    parsed = LocalForbidSource.verify_signed(env, secret="topsecret")
    assert parsed is not None
    assert {"agent_id": "atlas", "path": "/data/payroll.db"} in parsed["forbid"]
    # wrong secret -> None
    assert LocalForbidSource.verify_signed(env, secret="other") is None
    # tamper: strip the entry from the canonical string but keep the old sig -> fails closed
    env["set_canonical"] = env["set_canonical"].replace("/data/payroll.db", "")
    assert LocalForbidSource.verify_signed(env, secret="topsecret") is None


def test_from_env_seeds_permanent(monkeypatch):
    monkeypatch.setenv("TEX_LOCAL_FORBID_SET", "atlas=/data/payroll.db scribe=/etc/secrets")
    src = LocalForbidSource()
    assert src.from_env(tenant="acme") == 2
    paths = {f["path"] for f in src.response_set("acme")["forbid"]}
    assert paths == {"/data/payroll.db", "/etc/secrets"}


# ---- the binding to the LIVE decide() path --------------------------------

def test_live_decide_forbid_warms_local_set():
    """A real FORBID from the live StandingGovernance.decide() path warms the
    local set when the sink is wired (TEX_LOCAL_PEP). This is the verdict->
    enforcement binding the kernel loader consumes."""
    src = LocalForbidSource()
    gov = _gov(local_sink=src.feed_from_decision)
    outcome = gov.decide(
        tenant="acme",
        action_type="delete",
        content="rm -rf /data/payroll.db",
        recipient="/data/payroll.db",
        agent_id="ghost-agent",
    )
    assert outcome.verdict is Verdict.FORBID  # REAL verdict from the live path
    assert outcome.released is False
    forbid = src.response_set("acme")["forbid"]
    assert {"agent_id": "ghost-agent", "path": "/data/payroll.db"} in forbid


def test_default_off_is_byte_for_byte_inert():
    """With NO local sink wired (default), the identical FORBID warms nothing —
    proving the change is inert until TEX_LOCAL_PEP wires the sink."""
    src = LocalForbidSource()
    gov = _gov(local_sink=None)  # default
    outcome = gov.decide(
        tenant="acme",
        action_type="delete",
        content="rm -rf /data/payroll.db",
        recipient="/data/payroll.db",
        agent_id="ghost-agent",
    )
    assert outcome.verdict is Verdict.FORBID
    assert src.response_set("acme")["forbid"] == []  # nothing warmed


def test_network_action_forbid_does_not_warm_local_set():
    """A non-local (network) FORBID must not warm the LOCAL set even with the sink
    wired — the two planes stay separate (no policy cross-contamination)."""
    src = LocalForbidSource()
    gov = _gov(local_sink=src.feed_from_decision)
    outcome = gov.decide(
        tenant="acme",
        action_type="http_post",
        content="exfiltrate",
        recipient="evil.example.com:443",
        agent_id="ghost-agent",
    )
    assert outcome.verdict is Verdict.FORBID
    assert src.response_set("acme")["forbid"] == []  # local set untouched
