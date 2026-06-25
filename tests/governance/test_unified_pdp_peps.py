"""One verdict, many PEPs — the reference-monitor unification.

A single StandingGovernance.decide() path feeds BOTH the network-egress kernel
PEP (forbid_sink -> the eBPF connect/sendmsg floor) AND the local-action kernel
PEP (local_forbid_sink -> the BPF-LSM file/exec floor). This proves the two
enforcement legs are bound to ONE verdict source and each is fed only for its
own action class — the agent must defeat the SAME decision to evade either.

HONEST SCOPE: this is PARITY with the reference-monitor architecture ("one
verdict, many PEPs"), not a beyond-frontier claim. The deeper unification — ONE
signed capability artifact every PEP (including the kernel) cryptographically
verifies — is a further step coupled to the paused exec-sota capability token and
is NOT built here. The network feed remains epoch-anti-rollback'd; the local feed
is HMAC-signed; they are not yet one artifact.
"""

from __future__ import annotations

from tex.governance.forbid_source import ForbidSource
from tex.governance.local_forbid_source import LocalForbidSource
from tex.governance.standing import StandingGovernance
from tex.domain.verdict import Verdict


class _EmptyRegistry:
    """Unsealed agents => decide() FORBIDs at the Tier-1 floor."""

    def get(self, _uid):
        return None

    def list_all(self):
        return []


def _resolver(host: str) -> list[str]:
    return ["203.0.113.7"]  # deterministic, no real DNS


def _gov_with_both_peps():
    net = ForbidSource(resolver=_resolver)
    loc = LocalForbidSource()
    gov = StandingGovernance(
        agent_registry=_EmptyRegistry(),
        forbid_sink=net.feed_from_decision,
        local_forbid_sink=loc.feed_from_decision,
    )
    return gov, net, loc


def test_local_forbid_feeds_only_the_local_pep():
    # One verdict source, both PEPs wired. A LOCAL-action FORBID warms the local
    # kernel PEP and leaves the network PEP untouched (a delete has no network
    # destination) — the right body is fed from the one brain.
    gov, net, loc = _gov_with_both_peps()
    outcome = gov.decide(
        tenant="acme",
        action_type="delete",
        content="rm -rf /data/payroll.db",
        recipient="/data/payroll.db",
        agent_id="ghost-agent",
    )
    assert outcome.verdict is Verdict.FORBID
    assert {"agent_id": "ghost-agent", "path": "/data/payroll.db"} in loc.response_set("acme")["forbid"]
    assert net.for_tenant("acme") == []  # network PEP correctly NOT fed by a local action


def test_one_decision_path_carries_both_sinks_without_crosstalk():
    # The same gov, a second LOCAL FORBID: still only the local PEP grows; the
    # network PEP stays empty. No sink fires outside its action class.
    gov, net, loc = _gov_with_both_peps()
    for path in ("/etc/secrets.env", "/srv/ledger.db"):
        out = gov.decide(
            tenant="acme",
            action_type="overwrite",
            content="clobber",
            recipient=path,
            agent_id="ghost-agent",
        )
        assert out.verdict is Verdict.FORBID
    local_paths = {e["path"] for e in loc.response_set("acme")["forbid"]}
    assert local_paths == {"/etc/secrets.env", "/srv/ledger.db"}
    assert net.for_tenant("acme") == []


def test_both_peps_inert_by_default():
    # With neither sink wired (the default deploy), the identical FORBIDs warm
    # nothing — both legs are byte-for-byte inert until explicitly activated.
    net = ForbidSource(resolver=_resolver)
    loc = LocalForbidSource()
    gov = StandingGovernance(agent_registry=_EmptyRegistry())  # no sinks
    gov.decide(
        tenant="acme",
        action_type="delete",
        content="rm",
        recipient="/data/x",
        agent_id="ghost-agent",
    )
    assert loc.response_set("acme")["forbid"] == []
    assert net.for_tenant("acme") == []
