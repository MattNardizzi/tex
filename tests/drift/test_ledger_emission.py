"""
Tests for ChangePointDetector ↔ events ledger integration.

Each detected change point must:
  - emit a CHANGE_POINT_DETECTED event into the ledger
  - flow through the algorithm-agility CryptoProvenance (no hardcoded crypto)
  - preserve chain integrity (verify_chain still passes after emission)
  - bind ledger_event_id back onto the in-memory ChangePointEvent record
"""

from __future__ import annotations

import logging
import random
from datetime import UTC, datetime

import pytest

from tex.drift import ChangePointDetector
from tex.events._ecdsa_provider import EcdsaP256Provider
from tex.events.crypto_provenance import CryptoProvenance
from tex.events.ledger import InMemoryLedger
from tex.ontology.event_types import EventKind


@pytest.fixture(autouse=True)
def _silence_telemetry():
    logging.getLogger("tex").setLevel(logging.CRITICAL)


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _ledger_with_provenance() -> tuple[InMemoryLedger, CryptoProvenance]:
    """Build a fully-wired ledger + provenance pair."""
    provider = EcdsaP256Provider()
    keypair = provider.generate_keypair("drift-test-key")
    provenance = CryptoProvenance(
        signing_key=keypair, signing_provider=provider
    )
    ledger = InMemoryLedger(
        verifying_public_key=keypair.public_key,
        signing_provider=provider,
    )
    return ledger, provenance


def _shift_stream(seed: int, change_at: int = 200, limit: int = 600):
    rng = random.Random(seed)
    return [
        rng.gauss(0.0, 1.0) if t < change_at else rng.gauss(3.0, 1.0)
        for t in range(limit)
    ]


# ---------------------------------------------------------------------
# Ledger emission
# ---------------------------------------------------------------------


class TestLedgerEmission:
    def test_change_point_appears_in_ledger(self) -> None:
        ledger, provenance = _ledger_with_provenance()
        det = ChangePointDetector(ledger=ledger, provenance=provenance)
        for x in _shift_stream(0):
            det.update(signal_name="s", signal_value=x, at=datetime.now(UTC))
        assert det.detections, "expected at least one detection"
        # Exactly the detected change-points appeared in the ledger.
        ledger_kinds = [
            e.kind for e in ledger.stream_after(0)
        ]
        change_point_events = [
            k for k in ledger_kinds if k == EventKind.CHANGE_POINT_DETECTED.value
        ]
        assert len(change_point_events) == len(det.detections)

    def test_ledger_event_id_bound_back_onto_detection(self) -> None:
        ledger, provenance = _ledger_with_provenance()
        det = ChangePointDetector(ledger=ledger, provenance=provenance)
        for x in _shift_stream(0):
            det.update(signal_name="s", signal_value=x, at=datetime.now(UTC))
        for d in det.detections:
            assert d.ledger_event_id is not None
            # The bound ledger_event_id must resolve via the ledger.
            event = ledger.get(d.ledger_event_id)
            assert event is not None
            assert event.kind == EventKind.CHANGE_POINT_DETECTED.value

    def test_chain_integrity_after_emission(self) -> None:
        ledger, provenance = _ledger_with_provenance()
        det = ChangePointDetector(ledger=ledger, provenance=provenance)
        for x in _shift_stream(0):
            det.update(signal_name="s", signal_value=x, at=datetime.now(UTC))
        n = len(ledger)
        assert n > 0
        assert ledger.verify_chain(from_sequence=1, to_sequence=n) is True

    def test_payload_carries_signal_name_and_score(self) -> None:
        ledger, provenance = _ledger_with_provenance()
        det = ChangePointDetector(ledger=ledger, provenance=provenance)
        for x in _shift_stream(0):
            det.update(
                signal_name="my_signal", signal_value=x, at=datetime.now(UTC)
            )
        assert det.detections
        first_det = det.detections[0]
        assert first_det.ledger_event_id is not None
        ev = ledger.get(first_det.ledger_event_id)
        assert ev is not None
        assert ev.payload["signal_name"] == "my_signal"
        assert "change_point_score_milli" in ev.payload
        assert "detector_kind" in ev.payload
        assert ev.target_entity_id == "my_signal"

    def test_no_emission_without_ledger(self) -> None:
        # Telemetry-only configuration — detections still recorded but
        # ledger_event_id stays None.
        det = ChangePointDetector()
        for x in _shift_stream(0):
            det.update(signal_name="s", signal_value=x, at=datetime.now(UTC))
        assert det.detections
        for d in det.detections:
            assert d.ledger_event_id is None


# ---------------------------------------------------------------------
# Algorithm agility — no hardcoded crypto
# ---------------------------------------------------------------------


class TestAlgorithmAgility:
    def test_signing_algorithm_recorded_on_event(self) -> None:
        """
        The ledger event records pq_signature_algorithm — proving that
        signing flowed through the injected provider, not a hardcoded one.
        Today's default is ECDSA-P256; ML-DSA-65 will swap in cleanly
        once liboqs lands without any change to this code path.
        """
        ledger, provenance = _ledger_with_provenance()
        det = ChangePointDetector(ledger=ledger, provenance=provenance)
        for x in _shift_stream(0):
            det.update(signal_name="s", signal_value=x, at=datetime.now(UTC))
        assert det.detections
        ev = ledger.get(det.detections[0].ledger_event_id)  # type: ignore[arg-type]
        assert ev is not None
        # ECDSA-P256 today; would be ml-dsa-65 with liboqs.
        assert ev.pq_signature_algorithm == "ecdsa-p256"
        assert ev.pq_signing_key_id == "drift-test-key"
