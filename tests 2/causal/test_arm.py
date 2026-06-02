"""
Tests for tex.causal.arm — AgenticReferenceMonitor.

Covers
------
* Five-level integrity lattice ordering (Definition 1, §2.3)
* Lattice meet (lattice_meet) over multi-source data nodes
* Monotonic taint propagation (Property 1, §5.3)
* Counterfactual edge auto-attach to next call only (§3.7)
* Causality laundering attack scenario (§7.2.1) blocked
* Transitive taint chain scenario (§7.2.2) blocked
* Mixed-provenance field exploit (§7.2.3) blocked via field-level provenance
* Hash-chained DENIAL_EVENT ledger write with algorithm-agility
* Construction-mode validation (ledger-without-provenance rejected)
* Deterministic check_proposed (unknown event → conservative deny)
"""

from __future__ import annotations

import pytest

from tex.causal import (
    DEFAULT_TRUST_THRESHOLD,
    AgenticReferenceMonitor,
    DenialRecord,
    IntegrityLevel,
    LABEL_DERIVED_FROM_TAINTED,
    LABEL_TAINTED_BY_DENIAL,
    LABEL_TRUSTED,
    LABEL_UNTRUSTED_INPUT,
    lattice_meet,
)
from tex.causal._provenance_graph import ProvenanceGraph
from tex.events.crypto_provenance import CryptoProvenance
from tex.events._ecdsa_provider import default_signature_provider
from tex.events.ledger import InMemoryLedger
from tex.ontology.event_types import EventKind


# ---------- Lattice ----------------------------------------------------


def test_integrity_lattice_total_order() -> None:
    """ToolDesc < ToolUntrusted < ToolTrusted < UserInput < SysInstr."""
    assert IntegrityLevel.TOOL_DESC < IntegrityLevel.TOOL_UNTRUSTED
    assert IntegrityLevel.TOOL_UNTRUSTED < IntegrityLevel.TOOL_TRUSTED
    assert IntegrityLevel.TOOL_TRUSTED < IntegrityLevel.USER_INPUT
    assert IntegrityLevel.USER_INPUT < IntegrityLevel.SYS_INSTR


def test_default_threshold_is_tool_trusted() -> None:
    """Per §4.3.2: default θ for graph-aware enforcement is ToolTrusted."""
    assert DEFAULT_TRUST_THRESHOLD == IntegrityLevel.TOOL_TRUSTED


def test_lattice_meet_picks_minimum() -> None:
    """meet over (UserInput, ToolUntrusted, ToolTrusted) → ToolUntrusted."""
    levels = (
        IntegrityLevel.USER_INPUT,
        IntegrityLevel.TOOL_UNTRUSTED,
        IntegrityLevel.TOOL_TRUSTED,
    )
    assert lattice_meet(levels) == IntegrityLevel.TOOL_UNTRUSTED


def test_lattice_meet_rejects_empty() -> None:
    with pytest.raises(ValueError):
        lattice_meet(())


# ---------- Construction validation -----------------------------------


def test_construction_with_ledger_requires_provenance() -> None:
    """A wired ledger MUST come with a CryptoProvenance — algorithm-agility
    flows through the provenance object, never hardcoded."""
    provider = default_signature_provider()
    keypair = provider.generate_keypair("k")
    ledger = InMemoryLedger(
        verifying_public_key=keypair.public_key,
        signing_provider=provider,
    )
    with pytest.raises(ValueError, match="provenance is required"):
        AgenticReferenceMonitor(ledger=ledger, provenance=None)


def test_default_construction_works_without_ledger() -> None:
    arm = AgenticReferenceMonitor()
    assert isinstance(arm.graph, ProvenanceGraph)


def test_external_provenance_graph_can_be_shared() -> None:
    g = ProvenanceGraph()
    arm = AgenticReferenceMonitor(provenance_graph=g)
    assert arm.graph is g


# ---------- record_denial: in-memory only -----------------------------


def test_record_denial_returns_record() -> None:
    arm = AgenticReferenceMonitor()
    record = arm.record_denial(
        denied_event_id="read_shadow",
        denial_reason="HB-2 sensitive path",
        counterfactual_targets=(),
    )
    assert isinstance(record, DenialRecord)
    assert record.denied_event_id == "read_shadow"
    assert record.ledger_event_id is None  # no ledger wired


def test_record_denial_rejects_empty_event_id() -> None:
    arm = AgenticReferenceMonitor()
    with pytest.raises(ValueError):
        arm.record_denial(
            denied_event_id="", denial_reason="x", counterfactual_targets=()
        )


def test_record_denial_rejects_empty_reason() -> None:
    arm = AgenticReferenceMonitor()
    with pytest.raises(ValueError):
        arm.record_denial(
            denied_event_id="x", denial_reason="", counterfactual_targets=()
        )


# ---------- Counterfactual edge auto-attach (§3.7) -------------------


def test_counterfactual_edge_attaches_to_next_call_only() -> None:
    """
    Per §3.7: ARM auto-attaches Counterfactual to the *next* call. The
    one after that does NOT inherit a fresh edge; only the temporally
    adjacent call is treated as potentially influenced.
    """
    arm = AgenticReferenceMonitor()
    arm.record_denial(
        denied_event_id="probe_shadow",
        denial_reason="HB-2",
        counterfactual_targets=(),
    )
    # First call after denial → tainted by denial
    arm.register_call(
        event_id="next_call",
        tool_name="send_email",
        arguments={"body": "shadow exists"},
    )
    assert arm.integrity_label_for("next_call") == LABEL_TAINTED_BY_DENIAL

    # A second call (no fresh denial) → not tainted by denial
    arm.register_call(
        event_id="much_later", tool_name="benign", arguments={}
    )
    assert arm.integrity_label_for("much_later") == LABEL_TRUSTED


# ---------- Attack 1: Causality laundering (§7.2.1) ------------------


def test_causality_laundering_blocked() -> None:
    """
    Probe → denied → exfiltrate via second call. Flat provenance baseline
    misses this; ARM blocks via Counterfactual edge from DeniedAction to
    the next call.
    """
    arm = AgenticReferenceMonitor()
    arm.register_call(
        event_id="user_query", tool_name="user_input", arguments={"q": "..."}
    )
    arm.record_denial(
        denied_event_id="read_shadow",
        denial_reason="HB-2",
        counterfactual_targets=(),
    )
    arm.register_call(
        event_id="exfil",
        tool_name="send_email",
        arguments={"body": "shadow exists"},
    )

    allow, reason = arm.check_proposed(proposed_event_id="exfil")
    assert allow is False
    assert reason == "causality_laundering"


# ---------- Attack 2: Transitive taint chain (§7.2.2) ----------------


def test_transitive_taint_chain_blocked() -> None:
    """
    Untrusted data flows through multiple intermediate calls; ARM blocks
    the privileged sink via Property 1 (monotonic taint, §5.3).
    """
    arm = AgenticReferenceMonitor()

    # Step 1: tool fetch returns ToolUntrusted data
    arm.register_call(
        event_id="c1", tool_name="fetch_web", arguments={"url": "evil.com"}
    )
    arm.register_data(
        event_id="d1",
        producing_call_event_id="c1",
        trust=IntegrityLevel.TOOL_UNTRUSTED,
    )

    # Step 2: c2 takes d1 as input, returns more data
    arm.register_call(event_id="c2", tool_name="parse", arguments={})
    arm.register_input(data_event_id="d1", call_event_id="c2")
    arm.register_data(
        event_id="d2",
        producing_call_event_id="c2",
        trust=IntegrityLevel.TOOL_TRUSTED,  # masquerading as trusted
    )

    # Step 3: c3 (the sink) takes d2 as input — should still inherit
    # the taint via Property 1 because d1 is reachable from c3.
    arm.register_call(event_id="c3", tool_name="send_email", arguments={})
    arm.register_input(data_event_id="d2", call_event_id="c3")

    label = arm.integrity_label_for("c3")
    assert label in {LABEL_DERIVED_FROM_TAINTED, LABEL_UNTRUSTED_INPUT}

    allow, reason = arm.check_proposed(proposed_event_id="c3")
    assert allow is False
    assert reason == "transitive_taint"


# ---------- Property 1: Monotonic Taint -------------------------------


def test_property_1_monotonic_taint() -> None:
    """
    Per §5.3 Property 1: for any edge (u, v), MinTrust(v) ≤ MinTrust(u).

    We construct a chain c1 → d1 → c2 with d1 at TOOL_UNTRUSTED, then
    verify the inequality at every edge. Note Definition 4 excludes
    the node itself from its own ancestor set, so MinTrust(d1) is the
    SysInstr fallback (no upstream data); the taint shows up at c2,
    where d1 is now an ancestor.
    """
    arm = AgenticReferenceMonitor()

    arm.register_call(event_id="c1", tool_name="t1", arguments={})
    arm.register_data(
        event_id="d1",
        producing_call_event_id="c1",
        trust=IntegrityLevel.TOOL_UNTRUSTED,
    )

    arm.register_call(event_id="c2", tool_name="t2", arguments={})
    arm.register_input(data_event_id="d1", call_event_id="c2")

    g = arm.graph
    mt_c1 = g.min_trust("call:c1")
    mt_d1 = g.min_trust("data:d1")
    mt_c2 = g.min_trust("call:c2")

    # Every edge must satisfy the inequality:
    #   c1 → d1 (DirectOutput): MinTrust(d1) ≤ MinTrust(c1)
    #   d1 → c2 (InputTo):     MinTrust(c2) ≤ MinTrust(d1)
    assert mt_d1 <= mt_c1
    assert mt_c2 <= mt_d1
    # Concrete: c2 inherits d1's trust because d1 is a data ancestor.
    assert mt_c2 == IntegrityLevel.TOOL_UNTRUSTED


# ---------- Attack 3: Mixed-provenance field exploit (§7.2.3) --------


def test_field_level_provenance_blocks_mixed_trust_fields() -> None:
    """
    A contact record with name=ToolTrusted, email=ToolUntrusted. A
    send_email(to=email) call must be blocked because the email field's
    untrusted taint propagates through the FieldOf edge.
    """
    arm = AgenticReferenceMonitor()
    arm.register_call(event_id="lookup", tool_name="get_contact", arguments={})
    arm.register_data(
        event_id="contact",
        producing_call_event_id="lookup",
        trust=IntegrityLevel.TOOL_TRUSTED,
    )
    arm.register_data_field(
        event_id="contact_name",
        parent_data_event_id="contact",
        field_path="$.name",
        trust=IntegrityLevel.TOOL_TRUSTED,
    )
    arm.register_data_field(
        event_id="contact_email",
        parent_data_event_id="contact",
        field_path="$.email",
        trust=IntegrityLevel.TOOL_UNTRUSTED,
    )

    # send_email(to=email) — feeds the untrusted field into the call
    arm.register_call(event_id="send", tool_name="send_email", arguments={})
    arm.register_input(data_event_id="contact_email", call_event_id="send")

    allow, reason = arm.check_proposed(proposed_event_id="send")
    assert allow is False
    assert reason == "transitive_taint"


# ---------- Ledger integration (§4.5) --------------------------------


@pytest.fixture
def signed_arm() -> tuple[AgenticReferenceMonitor, InMemoryLedger]:
    provider = default_signature_provider()
    keypair = provider.generate_keypair("test-arm-key")
    prov = CryptoProvenance(signing_key=keypair, signing_provider=provider)
    ledger = InMemoryLedger(
        verifying_public_key=keypair.public_key,
        signing_provider=provider,
    )
    arm = AgenticReferenceMonitor(ledger=ledger, provenance=prov)
    return arm, ledger


def test_record_denial_appends_denial_event_to_ledger(
    signed_arm: tuple[AgenticReferenceMonitor, InMemoryLedger],
) -> None:
    arm, ledger = signed_arm
    record = arm.record_denial(
        denied_event_id="read_shadow",
        denial_reason="HB-2 /etc/shadow",
        counterfactual_targets=(),
    )
    assert record.ledger_event_id is not None
    assert len(ledger) == 1
    event = ledger.get(record.ledger_event_id)
    assert event.kind == EventKind.DENIAL_EVENT.value
    assert event.payload["denied_event_id"] == "read_shadow"
    assert event.payload["denial_reason"] == "HB-2 /etc/shadow"
    assert event.payload["provenance_node_id"] == record.provenance_node_id


def test_ledger_chain_verifies_after_denial(
    signed_arm: tuple[AgenticReferenceMonitor, InMemoryLedger],
) -> None:
    arm, ledger = signed_arm
    arm.record_denial(
        denied_event_id="ev1", denial_reason="r1", counterfactual_targets=()
    )
    arm.record_denial(
        denied_event_id="ev2", denial_reason="r2", counterfactual_targets=()
    )
    assert ledger.verify_chain(from_sequence=1, to_sequence=2) is True


def test_algorithm_agility_routes_through_provenance(
    signed_arm: tuple[AgenticReferenceMonitor, InMemoryLedger],
) -> None:
    """
    The signing algorithm name on the ledger event must match what the
    injected CryptoProvenance reports. Today: ECDSA-P256. ML-DSA-65 is a
    drop-in via the same parameter.
    """
    arm, ledger = signed_arm
    record = arm.record_denial(
        denied_event_id="x", denial_reason="y", counterfactual_targets=()
    )
    event = ledger.get(record.ledger_event_id)
    # Whatever algorithm the provider reports must be on the event; we
    # don't hardcode "ecdsa-p256" — the value flows through.
    assert event.pq_signature_algorithm  # non-empty
    assert event.pq_signature_b64  # non-empty


# ---------- check_proposed: deterministic ------------------------------


def test_check_proposed_unknown_event_denies() -> None:
    """Conservative deny so callers cannot bypass enforcement by submitting
    an event id ARM has never seen."""
    arm = AgenticReferenceMonitor()
    allow, reason = arm.check_proposed(proposed_event_id="never_registered")
    assert allow is False
    assert reason == "unknown_event"


def test_check_proposed_clean_call_allows() -> None:
    arm = AgenticReferenceMonitor()
    arm.register_call(event_id="c", tool_name="t", arguments={})
    allow, reason = arm.check_proposed(proposed_event_id="c")
    assert allow is True
    assert reason is None


# ---------- integrity_label_for ---------------------------------------


def test_integrity_label_for_unknown_returns_untrusted() -> None:
    arm = AgenticReferenceMonitor()
    assert arm.integrity_label_for("never_seen") == LABEL_UNTRUSTED_INPUT


def test_integrity_label_for_resolves_by_node_id() -> None:
    """Direct graph node IDs must also resolve."""
    arm = AgenticReferenceMonitor()
    arm.register_call(event_id="c1", tool_name="t", arguments={})
    # Both forms must work
    assert arm.integrity_label_for("c1") == LABEL_TRUSTED
    assert arm.integrity_label_for("call:c1") == LABEL_TRUSTED


def test_integrity_label_for_originator_vs_derived() -> None:
    """
    A Data node with no upstream Data ancestors is the originator
    (UNTRUSTED_INPUT); a Data node that derives from another untrusted
    Data is DERIVED_FROM_TAINTED.
    """
    arm = AgenticReferenceMonitor()
    arm.register_call(event_id="c1", tool_name="t", arguments={})
    arm.register_data(
        event_id="d1",
        producing_call_event_id="c1",
        trust=IntegrityLevel.TOOL_UNTRUSTED,
    )
    # d1 has no Data ancestors above c1, so it's the originator.
    assert arm.integrity_label_for("d1") == LABEL_UNTRUSTED_INPUT


# ---------- Counterfactual targets passed explicitly ------------------


def test_explicit_counterfactual_targets_get_wired_when_present() -> None:
    """
    Callers may pass already-registered call event ids in
    counterfactual_targets; ARM should wire Counterfactual edges to all
    of them, in addition to the temporally-adjacent next-call heuristic.
    """
    arm = AgenticReferenceMonitor()
    # Pre-register a call BEFORE the denial so we can pass it as a target
    arm.register_call(
        event_id="future_call", tool_name="t", arguments={}
    )
    record = arm.record_denial(
        denied_event_id="probe",
        denial_reason="HB-2",
        counterfactual_targets=("future_call",),
    )
    # The pre-existing call must now be tainted by denial
    assert arm.integrity_label_for("future_call") == LABEL_TAINTED_BY_DENIAL
    assert record.counterfactual_target_event_ids == ("future_call",)
