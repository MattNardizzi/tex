"""
Tests for ContractEnforcer ↔ events ledger integration.

Each detected violation must:
  - emit a POLICY_DECISION event into the ledger
  - flow through algorithm-agility CryptoProvenance (no hardcoded crypto)
  - preserve chain integrity (verify_chain still passes after emission)
  - bind ledger_event_id back onto the in-memory ContractViolation
  - carry contract_id, severity, step_index in the typed payload

Mirrors the structure of tests/drift/test_ledger_emission.py.
"""

from __future__ import annotations

# tex.contracts is force-imported first by conftest.py to break the
# tex.events ↔ tex.ecosystem circular dance.
from tex.contracts import BehavioralContract, ContractEnforcer
from tex.ontology.event_types import EventKind
from tests.contracts.conftest import (
    ledger_with_provenance,
    make_event,
    make_state,
)


# ---------------------------------------------------------------------
# Ledger emission core
# ---------------------------------------------------------------------


class TestLedgerEmission:
    def test_violation_appears_as_policy_decision_event(self) -> None:
        ledger, provenance = ledger_with_provenance()
        c = BehavioralContract.make(
            contract_id="c-pii",
            agent_id="alice",
            description="no PII",
            hard_invariants_ltl=("G (field:output.pii==false)",),
            severity_on_violation="block",
        )
        e = ContractEnforcer(
            contracts=(c,), ledger=ledger, provenance=provenance
        )
        e.check_pre(
            agent_id="alice",
            proposed_event=make_event(payload={"output": {"pii": True}}),
            current_state=make_state(),
        )
        # The ledger should now have one POLICY_DECISION event.
        all_events = list(ledger.stream_after(0))
        policy_events = [
            ev for ev in all_events if ev.kind == EventKind.POLICY_DECISION.value
        ]
        assert len(policy_events) == 1
        ev = policy_events[0]
        assert ev.payload["decision_kind"] == "contract_violation"
        assert ev.payload["contract_id"] == "c-pii"
        assert ev.payload["severity"] == "block"
        assert ev.payload["violated_clause"] == "hard_invariant"
        assert ev.payload["step_index"] == 1

    def test_ledger_event_id_bound_back_on_violation(self) -> None:
        ledger, provenance = ledger_with_provenance()
        c = BehavioralContract.make(
            contract_id="c-pii",
            agent_id="alice",
            description="x",
            hard_invariants_ltl=("G (field:output.pii==false)",),
        )
        e = ContractEnforcer(
            contracts=(c,), ledger=ledger, provenance=provenance
        )
        e.check_pre(
            agent_id="alice",
            proposed_event=make_event(payload={"output": {"pii": True}}),
            current_state=make_state(),
        )
        violation = e.violations[0]
        assert violation.ledger_event_id is not None
        # Round-trip: the ledger has an event with the bound id.
        ev = ledger.get(violation.ledger_event_id)
        assert ev is not None
        assert ev.kind == EventKind.POLICY_DECISION.value
        assert ev.payload["violation_id"] == violation.violation_id

    def test_chain_integrity_after_emission(self) -> None:
        ledger, provenance = ledger_with_provenance()
        c = BehavioralContract.make(
            contract_id="c-pii",
            agent_id="alice",
            description="x",
            hard_invariants_ltl=("G (field:output.pii==false)",),
        )
        e = ContractEnforcer(
            contracts=(c,), ledger=ledger, provenance=provenance
        )
        # Fire several violations.
        for _ in range(3):
            e.check_pre(
                agent_id="alice",
                proposed_event=make_event(payload={"output": {"pii": True}}),
                current_state=make_state(),
            )
        # Each violation produced a ledger event; the chain still
        # verifies end-to-end.
        assert ledger.verify_chain(from_sequence=1, to_sequence=len(ledger))

    def test_no_emission_when_telemetry_only(self) -> None:
        # No ledger wired -> violations are still recorded internally
        # but ledger_event_id stays None and no append is attempted.
        c = BehavioralContract.make(
            contract_id="c-pii",
            agent_id="alice",
            description="x",
            hard_invariants_ltl=("G (field:output.pii==false)",),
        )
        e = ContractEnforcer(contracts=(c,))
        e.check_pre(
            agent_id="alice",
            proposed_event=make_event(payload={"output": {"pii": True}}),
            current_state=make_state(),
        )
        v = e.violations[0]
        assert v.ledger_event_id is None

    def test_algorithm_agility_uses_pq_signature_algorithm_field(self) -> None:
        # A ledger emission should set the canonical signing algorithm
        # field on the Event — for ECDSA-P256 today that's "ecdsa-p256".
        # This is what the institutional layer checks when validating
        # provenance, and confirms we're not hardcoded to any one alg.
        ledger, provenance = ledger_with_provenance()
        c = BehavioralContract.make(
            contract_id="c-pii",
            agent_id="alice",
            description="x",
            hard_invariants_ltl=("G (field:output.pii==false)",),
        )
        e = ContractEnforcer(
            contracts=(c,), ledger=ledger, provenance=provenance
        )
        e.check_pre(
            agent_id="alice",
            proposed_event=make_event(payload={"output": {"pii": True}}),
            current_state=make_state(),
        )
        v = e.violations[0]
        assert v.ledger_event_id is not None
        ev = ledger.get(v.ledger_event_id)
        assert ev is not None
        assert ev.pq_signature_algorithm == "ecdsa-p256"

    def test_milli_unit_coercion_on_compliance_gap(self) -> None:
        # ABC §3.6 compliance_gap is a float in [0, 1]; we coerce to
        # milli-units in the payload for byte-stable canonicalisation.
        ledger, provenance = ledger_with_provenance()
        c = BehavioralContract.make(
            contract_id="c-pii",
            agent_id="alice",
            description="x",
            # Two hard invariants -> compliance_gap = 1/2 = 0.5 -> 500
            hard_invariants_ltl=(
                "G (field:output.pii==false)",
                "G (field:output.toxic==false)",
            ),
        )
        e = ContractEnforcer(
            contracts=(c,), ledger=ledger, provenance=provenance
        )
        e.check_pre(
            agent_id="alice",
            proposed_event=make_event(
                payload={"output": {"pii": True, "toxic": False}}
            ),
            current_state=make_state(),
        )
        v = e.violations[0]
        ev = ledger.get(v.ledger_event_id)  # type: ignore[arg-type]
        assert ev is not None
        assert ev.payload["compliance_gap_milli"] == 500
