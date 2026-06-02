"""Tests for tex.events.crypto_provenance."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest

from tex.ecosystem.proposed_event import ProposedEvent
from tex.events._canonical import canonical_json, canonical_sha256, sha256_hex
from tex.events._ecdsa_provider import EcdsaP256Provider
from tex.events.crypto_provenance import CryptoProvenance
from tex.events.event import Event, genesis_ledger_hash


@pytest.fixture
def provider() -> EcdsaP256Provider:
    return EcdsaP256Provider()


@pytest.fixture
def keypair(provider: EcdsaP256Provider):
    return provider.generate_keypair("test-key")


@pytest.fixture
def provenance(provider: EcdsaP256Provider, keypair) -> CryptoProvenance:
    return CryptoProvenance(signing_key=keypair, signing_provider=provider)


def _make_proposed(**overrides) -> ProposedEvent:
    base = {
        "event_kind": "agent_invokes_tool",
        "actor_entity_id": "agent_1",
        "payload": {"tool_id": "search_v1"},
        "proposed_at": datetime(2026, 5, 7, 12, 0, 0, tzinfo=UTC),
    }
    base.update(overrides)
    return ProposedEvent(**base)


def test_attach_returns_event_with_all_crypto_fields(provenance: CryptoProvenance) -> None:
    proposed = _make_proposed()
    event = provenance.attach(
        proposed=proposed,
        sequence_number=1,
        previous_ledger_hash=genesis_ledger_hash(),
    )
    assert isinstance(event, Event)
    assert event.event_id.startswith("evt_")
    assert event.kind == "agent_invokes_tool"
    assert event.sequence_number == 1
    assert event.previous_ledger_hash == genesis_ledger_hash()
    assert len(event.payload_sha256) == 64
    assert len(event.record_hash) == 64
    assert event.pq_signature_b64 != ""
    assert event.pq_signing_key_id == "test-key"
    assert event.pq_signature_algorithm == "ecdsa-p256"


def test_attach_payload_sha256_matches_canonical(provenance: CryptoProvenance) -> None:
    payload = {"x": 1, "y": [1, 2, 3], "z": {"nested": True}}
    proposed = _make_proposed(payload=payload)
    event = provenance.attach(
        proposed=proposed, sequence_number=1, previous_ledger_hash=genesis_ledger_hash()
    )
    assert event.payload_sha256 == canonical_sha256(payload)


def test_attach_record_hash_covers_all_lineage_fields(provenance: CryptoProvenance) -> None:
    """record_hash must equal sha256(canonical_json(canonical_record_input()))."""
    proposed = _make_proposed()
    event = provenance.attach(
        proposed=proposed, sequence_number=3, previous_ledger_hash="a" * 64
    )
    expected = sha256_hex(canonical_json(event.canonical_record_input()))
    assert event.record_hash == expected


def test_attach_signature_verifies(provenance: CryptoProvenance) -> None:
    proposed = _make_proposed()
    event = provenance.attach(
        proposed=proposed, sequence_number=1, previous_ledger_hash=genesis_ledger_hash()
    )
    sig = base64.b64decode(event.pq_signature_b64)
    assert provenance.provider.verify(
        event.record_hash.encode("utf-8"),
        sig,
        provenance.public_key,
    )


def test_attach_distinct_sequence_numbers_produce_distinct_record_hashes(
    provenance: CryptoProvenance,
) -> None:
    p = _make_proposed()
    e1 = provenance.attach(
        proposed=p, sequence_number=1, previous_ledger_hash=genesis_ledger_hash()
    )
    e2 = provenance.attach(
        proposed=p, sequence_number=2, previous_ledger_hash=genesis_ledger_hash()
    )
    assert e1.record_hash != e2.record_hash


def test_attach_distinct_prev_hashes_produce_distinct_record_hashes(
    provenance: CryptoProvenance,
) -> None:
    p = _make_proposed()
    e1 = provenance.attach(
        proposed=p, sequence_number=1, previous_ledger_hash=genesis_ledger_hash()
    )
    e2 = provenance.attach(
        proposed=p, sequence_number=1, previous_ledger_hash="a" * 64
    )
    assert e1.record_hash != e2.record_hash


def test_attach_propagates_upstream_event_ids(provenance: CryptoProvenance) -> None:
    proposed = _make_proposed(upstream_event_ids=("evt_a", "evt_b"))
    event = provenance.attach(
        proposed=proposed, sequence_number=1, previous_ledger_hash=genesis_ledger_hash()
    )
    assert event.upstream_event_ids == ("evt_a", "evt_b")


def test_attach_propagates_target_entity_id(provenance: CryptoProvenance) -> None:
    proposed = _make_proposed(target_entity_id="tool_search")
    event = provenance.attach(
        proposed=proposed, sequence_number=1, previous_ledger_hash=genesis_ledger_hash()
    )
    assert event.target_entity_id == "tool_search"


def test_attach_caller_supplied_event_id(provenance: CryptoProvenance) -> None:
    proposed = _make_proposed()
    event = provenance.attach(
        proposed=proposed,
        sequence_number=1,
        previous_ledger_hash=genesis_ledger_hash(),
        event_id="evt_custom_id",
    )
    assert event.event_id == "evt_custom_id"


def test_attach_tool_receipt_id(provenance: CryptoProvenance) -> None:
    proposed = _make_proposed()
    event = provenance.attach(
        proposed=proposed,
        sequence_number=1,
        previous_ledger_hash=genesis_ledger_hash(),
        tool_receipt_id="rcpt_123",
    )
    assert event.tool_receipt_id == "rcpt_123"


def test_provenance_uses_default_provider_when_none_supplied(keypair) -> None:
    """No provider passed → falls back to default ECDSA provider."""
    prov = CryptoProvenance(signing_key=keypair)
    proposed = _make_proposed()
    event = prov.attach(
        proposed=proposed, sequence_number=1, previous_ledger_hash=genesis_ledger_hash()
    )
    assert event.pq_signature_algorithm == "ecdsa-p256"


def test_provenance_event_id_uniqueness(provenance: CryptoProvenance) -> None:
    p = _make_proposed()
    a = provenance.attach(
        proposed=p, sequence_number=1, previous_ledger_hash=genesis_ledger_hash()
    )
    b = provenance.attach(
        proposed=p, sequence_number=2, previous_ledger_hash=a.record_hash
    )
    assert a.event_id != b.event_id


def test_attach_payload_is_copied_not_shared(provenance: CryptoProvenance) -> None:
    """Mutating the source payload after attach must not corrupt the Event."""
    payload = {"tool_id": "search_v1"}
    proposed = _make_proposed(payload=payload)
    event = provenance.attach(
        proposed=proposed, sequence_number=1, previous_ledger_hash=genesis_ledger_hash()
    )
    # ProposedEvent is frozen so we can't mutate its payload, but we can
    # confirm the Event holds its own dict.
    assert event.payload is not proposed.payload
    assert event.payload == proposed.payload


def test_provenance_exposes_signing_key_id(provenance: CryptoProvenance) -> None:
    assert provenance.signing_key_id == "test-key"


def test_provenance_exposes_public_key_and_provider(provenance: CryptoProvenance) -> None:
    assert isinstance(provenance.public_key, bytes)
    assert provenance.public_key.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert provenance.provider is not None
