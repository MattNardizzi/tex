"""Tests for tex.events.ledger (InMemoryLedger + EventLedger Protocol)."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest

from tex.ecosystem.proposed_event import ProposedEvent
from tex.events import (
    ChainLinkError,
    CryptoProvenance,
    Event,
    EventLedger,
    InMemoryLedger,
    MissingUpstreamError,
    PayloadHashMismatchError,
    RecordHashMismatchError,
    SequenceGapError,
    SignatureVerificationError,
    genesis_ledger_hash,
)
from tex.events._ecdsa_provider import EcdsaP256Provider
from tex.ontology.validator import EventLookup


# --- fixtures ---


@pytest.fixture
def provider() -> EcdsaP256Provider:
    return EcdsaP256Provider()


@pytest.fixture
def keypair(provider: EcdsaP256Provider):
    return provider.generate_keypair("ledger-test")


@pytest.fixture
def provenance(provider, keypair) -> CryptoProvenance:
    return CryptoProvenance(signing_key=keypair, signing_provider=provider)


@pytest.fixture
def ledger(provider, keypair) -> InMemoryLedger:
    return InMemoryLedger(
        verifying_public_key=keypair.public_key,
        signing_provider=provider,
    )


def _make_proposed(**overrides) -> ProposedEvent:
    base = {
        "event_kind": "agent_invokes_tool",
        "actor_entity_id": "agent_1",
        "payload": {"tool_id": "search_v1"},
        "proposed_at": datetime(2026, 5, 7, 12, 0, 0, tzinfo=UTC),
    }
    base.update(overrides)
    return ProposedEvent(**base)


# --- Protocol conformance ---


def test_ledger_satisfies_event_ledger_protocol(ledger: InMemoryLedger) -> None:
    assert isinstance(ledger, EventLedger)


def test_ledger_satisfies_event_lookup_protocol(ledger: InMemoryLedger) -> None:
    """Thread 1's OntologyValidator(event_lookup=ledger) must work."""
    assert isinstance(ledger, EventLookup)


# --- happy path ---


def test_append_proposed_first_event(ledger: InMemoryLedger, provenance) -> None:
    proposed = _make_proposed()
    event = ledger.append_proposed(proposed, provenance=provenance)
    assert event.sequence_number == 1
    assert event.previous_ledger_hash == genesis_ledger_hash()
    assert len(ledger) == 1


def test_append_proposed_chains_correctly(ledger: InMemoryLedger, provenance) -> None:
    p1 = _make_proposed()
    p2 = _make_proposed(event_kind="agent_emits_output", payload={"response": "ok"})
    e1 = ledger.append_proposed(p1, provenance=provenance)
    e2 = ledger.append_proposed(p2, provenance=provenance)
    assert e2.sequence_number == 2
    assert e2.previous_ledger_hash == e1.record_hash


def test_append_proposed_with_upstream(ledger: InMemoryLedger, provenance) -> None:
    e1 = ledger.append_proposed(_make_proposed(), provenance=provenance)
    p2 = _make_proposed(
        event_kind="agent_emits_output",
        payload={"response": "ok"},
        upstream_event_ids=(e1.event_id,),
    )
    e2 = ledger.append_proposed(p2, provenance=provenance)
    assert e2.upstream_event_ids == (e1.event_id,)


def test_get_returns_appended_event(ledger: InMemoryLedger, provenance) -> None:
    e = ledger.append_proposed(_make_proposed(), provenance=provenance)
    assert ledger.get(e.event_id) is e


def test_get_returns_none_for_unknown(ledger: InMemoryLedger) -> None:
    assert ledger.get("evt_does_not_exist") is None


def test_exists_protocol_method(ledger: InMemoryLedger, provenance) -> None:
    e = ledger.append_proposed(_make_proposed(), provenance=provenance)
    assert ledger.exists(e.event_id)
    assert not ledger.exists("evt_nope")


def test_stream_after_returns_only_newer(ledger: InMemoryLedger, provenance) -> None:
    e1 = ledger.append_proposed(_make_proposed(), provenance=provenance)
    e2 = ledger.append_proposed(
        _make_proposed(event_kind="agent_emits_output", payload={"r": "ok"}),
        provenance=provenance,
    )
    after_one = ledger.stream_after(1)
    assert len(after_one) == 1
    assert after_one[0].event_id == e2.event_id

    after_zero = ledger.stream_after(0)
    assert len(after_zero) == 2

    # Negative cursor returns everything (operator semantics).
    after_neg = ledger.stream_after(-1)
    assert len(after_neg) == 2


# --- enforcement: sequence + chain ---


def test_append_rejects_out_of_order_sequence(
    ledger: InMemoryLedger, provenance, keypair, provider
) -> None:
    """Bypass append_proposed and feed a hand-built Event with wrong seq."""
    # First event in normally
    e1 = ledger.append_proposed(_make_proposed(), provenance=provenance)
    # Build a second event but lie about the sequence number
    p2 = _make_proposed(payload={"tool_id": "second"})
    bad_event = provenance.attach(
        proposed=p2,
        sequence_number=99,  # wrong
        previous_ledger_hash=e1.record_hash,
    )
    with pytest.raises(SequenceGapError):
        ledger.append(bad_event)


def test_append_rejects_wrong_previous_hash(
    ledger: InMemoryLedger, provenance
) -> None:
    ledger.append_proposed(_make_proposed(), provenance=provenance)
    p2 = _make_proposed(payload={"tool_id": "second"})
    bad_event = provenance.attach(
        proposed=p2,
        sequence_number=2,
        previous_ledger_hash="b" * 64,  # wrong
    )
    with pytest.raises(ChainLinkError):
        ledger.append(bad_event)


def test_append_rejects_missing_upstream(
    ledger: InMemoryLedger, provenance
) -> None:
    p = _make_proposed(upstream_event_ids=("evt_does_not_exist",))
    with pytest.raises(MissingUpstreamError):
        ledger.append_proposed(p, provenance=provenance)


def test_append_rejects_first_event_with_wrong_genesis(
    ledger: InMemoryLedger, provenance
) -> None:
    """First event must declare previous_ledger_hash == genesis sentinel."""
    p = _make_proposed()
    bad_event = provenance.attach(
        proposed=p, sequence_number=1, previous_ledger_hash="c" * 64
    )
    with pytest.raises(ChainLinkError):
        ledger.append(bad_event)


# --- enforcement: tamper detection ---


def test_append_rejects_event_with_tampered_payload_hash(
    ledger: InMemoryLedger, provenance, provider, keypair
) -> None:
    p = _make_proposed()
    good = provenance.attach(
        proposed=p, sequence_number=1, previous_ledger_hash=genesis_ledger_hash()
    )
    tampered = good.model_copy(update={"payload_sha256": "0" * 64})
    with pytest.raises(PayloadHashMismatchError):
        ledger.append(tampered)


def test_append_rejects_event_with_tampered_record_hash(
    ledger: InMemoryLedger, provenance
) -> None:
    p = _make_proposed()
    good = provenance.attach(
        proposed=p, sequence_number=1, previous_ledger_hash=genesis_ledger_hash()
    )
    tampered = good.model_copy(update={"record_hash": "0" * 64})
    # record_hash mismatch surfaces as RecordHashMismatchError because
    # the chain-link check fires first only when prior records exist;
    # for the first event the integrity check runs before signature.
    with pytest.raises((RecordHashMismatchError, SignatureVerificationError)):
        ledger.append(tampered)


def test_append_rejects_event_with_tampered_signature(
    ledger: InMemoryLedger, provenance
) -> None:
    p = _make_proposed()
    good = provenance.attach(
        proposed=p, sequence_number=1, previous_ledger_hash=genesis_ledger_hash()
    )
    bad_sig_b64 = base64.b64encode(b"\x00" * 64).decode("ascii")
    tampered = good.model_copy(update={"pq_signature_b64": bad_sig_b64})
    with pytest.raises(SignatureVerificationError):
        ledger.append(tampered)


def test_append_rejects_event_with_unparseable_signature(
    ledger: InMemoryLedger, provenance
) -> None:
    p = _make_proposed()
    good = provenance.attach(
        proposed=p, sequence_number=1, previous_ledger_hash=genesis_ledger_hash()
    )
    tampered = good.model_copy(update={"pq_signature_b64": "!!!not-base64!!!"})
    with pytest.raises(SignatureVerificationError):
        ledger.append(tampered)


# --- verify_chain ---


def test_verify_chain_full_range_ok(ledger: InMemoryLedger, provenance) -> None:
    for i in range(5):
        ledger.append_proposed(
            _make_proposed(payload={"tool_id": f"t{i}"}),
            provenance=provenance,
        )
    assert ledger.verify_chain(from_sequence=1, to_sequence=5)


def test_verify_chain_partial_slice_ok(ledger: InMemoryLedger, provenance) -> None:
    for i in range(5):
        ledger.append_proposed(
            _make_proposed(payload={"tool_id": f"t{i}"}),
            provenance=provenance,
        )
    # Slice in the middle — uses the predecessor at seq=1 as the boundary
    assert ledger.verify_chain(from_sequence=2, to_sequence=4)


def test_verify_chain_detects_in_place_tamper(
    ledger: InMemoryLedger, provenance
) -> None:
    """Mutate a stored record's payload_sha256 directly — verify_chain must catch it."""
    for i in range(3):
        ledger.append_proposed(
            _make_proposed(payload={"tool_id": f"t{i}"}),
            provenance=provenance,
        )
    # Mutate the internal list in place. Pydantic frozen models block field
    # assignment, so we swap the whole record.
    original = ledger._events[1]
    tampered = original.model_copy(update={"payload_sha256": "0" * 64})
    ledger._events[1] = tampered
    assert not ledger.verify_chain(from_sequence=1, to_sequence=3)


def test_verify_chain_rejects_invalid_range(ledger: InMemoryLedger, provenance) -> None:
    ledger.append_proposed(_make_proposed(), provenance=provenance)
    assert not ledger.verify_chain(from_sequence=0, to_sequence=1)
    assert not ledger.verify_chain(from_sequence=2, to_sequence=1)
    assert not ledger.verify_chain(from_sequence=1, to_sequence=99)


def test_verify_chain_without_provider_raises(provenance) -> None:
    """If the ledger has no verifying key/provider, verify_chain must surface."""
    no_verify_ledger = InMemoryLedger()
    no_verify_ledger.append_proposed(_make_proposed(), provenance=provenance)
    # The append succeeded with a soft-warning telemetry; verify_chain
    # is forced and must report failure rather than silently pass.
    assert not no_verify_ledger.verify_chain(from_sequence=1, to_sequence=1)


# --- behavior with no signature provider configured (soft-warn path) ---


def test_ledger_appends_without_provider_with_soft_warning(provenance) -> None:
    """No verifying key/provider → append succeeds, verify_chain fails closed."""
    no_verify_ledger = InMemoryLedger()
    e = no_verify_ledger.append_proposed(_make_proposed(), provenance=provenance)
    assert e.sequence_number == 1
    assert no_verify_ledger.exists(e.event_id)


# --- ontology validator wiring ---


def test_ledger_works_as_event_lookup_for_ontology_validator(
    ledger: InMemoryLedger, provenance
) -> None:
    """Wire OntologyValidator(event_lookup=ledger) and confirm upstream check resolves."""
    from tex.ontology.entity_types import EntityTypeRegistry
    from tex.ontology.event_types import EventTypeRegistry
    from tex.ontology.validator import OntologyValidator

    e1 = ledger.append_proposed(_make_proposed(), provenance=provenance)

    validator = OntologyValidator(
        entity_registry=EntityTypeRegistry(),
        event_registry=EventTypeRegistry(),
        event_lookup=ledger,
    )
    proposed = _make_proposed(
        event_kind="agent_emits_output",
        payload={"response": "ok"},
        upstream_event_ids=(e1.event_id,),
    )
    ok, errs = validator.validate_event(proposed)
    assert ok, errs

    # And a missing upstream is rejected by the validator using the ledger.
    bad = _make_proposed(
        event_kind="agent_emits_output",
        payload={"response": "ok"},
        upstream_event_ids=("evt_does_not_exist",),
    )
    ok, errs = validator.validate_event(bad)
    assert not ok
    assert any("not found" in e for e in errs)


# --- exception hierarchy ---


def test_all_append_exceptions_subclass_ledger_append_error() -> None:
    from tex.events.exceptions import LedgerAppendError

    for exc_cls in (
        ChainLinkError,
        MissingUpstreamError,
        SequenceGapError,
        SignatureVerificationError,
        PayloadHashMismatchError,
        RecordHashMismatchError,
    ):
        assert issubclass(exc_cls, LedgerAppendError)
