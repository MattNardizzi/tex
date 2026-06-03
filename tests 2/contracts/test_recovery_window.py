"""
Tests for soft-violation recovery window semantics.

Coverage focuses on the bounded-eventually F<=k operator unrolled into
the per-(agent, contract, formula) deadline counter:

  * k = 0 — must recover at the same step (essentially impossible by
    construction since detection IS the failed step)
  * k = 1 — one step of grace, then escalate
  * large k — recovery far in the future still discharges
  * multi-soft contracts — independent counters per (contract, formula)
  * recovery is not retroactive: a constraint that recovers AFTER
    deadline expiry produces an escalation record + a fresh
    discharge cycle if it fails again
"""

from __future__ import annotations

from tex.contracts import BehavioralContract, ContractEnforcer
from tests.contracts.conftest import make_event, make_state


def _tone_contract(*, k: int, contract_id: str = "c-tone") -> BehavioralContract:
    return BehavioralContract.make(
        contract_id=contract_id,
        agent_id="alice",
        description="tone soft",
        soft_invariants_ltl=("G (field:tone==good)",),
        recovery_window_k=k,
    )


def _step(e: ContractEnforcer, *, tone: str) -> None:
    e.check_pre(
        agent_id="alice",
        proposed_event=make_event(payload={"tone": tone}),
        current_state=make_state(),
    )


class TestRecoveryWindowK:
    def test_k_zero_window_is_extremely_tight(self) -> None:
        """k=0 means the deadline is the SAME step as detection."""
        c = _tone_contract(k=0)
        e = ContractEnforcer(contracts=(c,))
        # Step 1: violation; deadline = 1+0 = 1
        _step(e, tone="bad")
        # Step 2: sweep sees deadline=1 is past -> escalation fires.
        _step(e, tone="good")
        # We expect: 1 soft warn + 1 escalation block.
        severities = [v.severity for v in e.violations]
        assert "warn" in severities
        assert "block" in severities

    def test_k_one_just_in_time_recovery(self) -> None:
        """k=1: violation at step 1, deadline=2, recovery at step 2 succeeds."""
        c = _tone_contract(k=1)
        e = ContractEnforcer(contracts=(c,))
        _step(e, tone="bad")  # step 1
        _step(e, tone="good")  # step 2 (deadline)
        recovered = [v for v in e.violations if v.recovered_at_step is not None]
        assert len(recovered) == 1
        assert recovered[0].recovered_at_step == 2
        # No escalation should have fired.
        assert all(v.severity != "block" for v in e.violations)

    def test_k_one_late_recovery_escalates(self) -> None:
        """Recovery one step too late -> escalation."""
        c = _tone_contract(k=1)
        e = ContractEnforcer(contracts=(c,))
        _step(e, tone="bad")  # step 1, deadline 2
        _step(e, tone="bad")  # step 2, still bad
        _step(e, tone="good")  # step 3, deadline already expired
        block_violations = [v for v in e.violations if v.severity == "block"]
        assert len(block_violations) >= 1

    def test_large_k_allows_distant_recovery(self) -> None:
        c = _tone_contract(k=20)
        e = ContractEnforcer(contracts=(c,))
        _step(e, tone="bad")  # step 1
        for _ in range(15):
            _step(e, tone="bad")
        _step(e, tone="good")  # step 17 — well within window
        recovered = [v for v in e.violations if v.recovered_at_step is not None]
        assert len(recovered) == 1
        assert recovered[0].recovered_at_step == 17

    def test_multiple_soft_contracts_independent_counters(self) -> None:
        """Two soft contracts run independent recovery deadlines."""
        c_tone = _tone_contract(k=2, contract_id="c-tone")
        c_latency = BehavioralContract.make(
            contract_id="c-latency",
            agent_id="alice",
            description="latency soft",
            soft_governance_ltl=("G (field:latency_ms<500)",),
            recovery_window_k=4,
        )
        e = ContractEnforcer(contracts=(c_tone, c_latency))
        # Step 1: tone bad (deadline=3), latency bad (deadline=5)
        e.check_pre(
            agent_id="alice",
            proposed_event=make_event(
                payload={"tone": "bad", "latency_ms": 1500}
            ),
            current_state=make_state(),
        )
        # Step 2: tone recovers, latency still bad
        e.check_pre(
            agent_id="alice",
            proposed_event=make_event(
                payload={"tone": "good", "latency_ms": 1500}
            ),
            current_state=make_state(),
        )
        # Step 3: latency also recovers
        e.check_pre(
            agent_id="alice",
            proposed_event=make_event(
                payload={"tone": "good", "latency_ms": 100}
            ),
            current_state=make_state(),
        )
        # Both recoveries should have fired, no escalations.
        recovered = [v for v in e.violations if v.recovered_at_step is not None]
        assert len(recovered) == 2
        assert all(v.severity != "block" for v in e.violations)

    def test_recovery_then_re_violation_creates_fresh_cycle(self) -> None:
        c = _tone_contract(k=2)
        e = ContractEnforcer(contracts=(c,))
        # First cycle: violate at 1, recover at 2.
        _step(e, tone="bad")
        _step(e, tone="good")
        # Second cycle: violate at 3, recover at 4.
        _step(e, tone="bad")
        _step(e, tone="good")
        recovered = [v for v in e.violations if v.recovered_at_step is not None]
        assert len(recovered) == 2

    def test_pending_count_updates_correctly(self) -> None:
        c = _tone_contract(k=5)
        e = ContractEnforcer(contracts=(c,))
        assert e.pending_soft_recoveries == 0
        _step(e, tone="bad")
        assert e.pending_soft_recoveries == 1
        # Another step still in violation does NOT add a new pending
        # entry (obligation token semantics).
        _step(e, tone="bad")
        assert e.pending_soft_recoveries == 1
        _step(e, tone="good")
        assert e.pending_soft_recoveries == 0
