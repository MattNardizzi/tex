"""
Append-only event ledger.

Built on top of the existing tex.evidence.chain SHA-256 hash chain pattern,
adding:
  - upstream-event lineage (every event names its causal predecessors)
  - signature verification at append time + during verify_chain
  - link to tex.receipts tool receipts (P1; opaque ID today)
  - O(1) ``EventLookup.exists`` so the OntologyValidator from Thread 1
    can be wired with ``OntologyValidator(event_lookup=ledger)`` directly

Reference
---------
arxiv 2512.18561 (AAF) section (i) — cryptographically verifiable
interaction provenance with quorum-replicated shards. Storage analysis
(Appendix E): at N=100 agents, h=8 horizon, T=10^6 steps the ledger is
≈492 MB and streams at <80 KB/s — comfortable for in-memory dev/test
fixtures and for the P0 production deployment box.

Quorum replication is P2 — see ``events.quorum_shard``.

Priority: P0.
"""

from __future__ import annotations

import base64
from typing import Protocol, runtime_checkable

from tex.ecosystem.proposed_event import ProposedEvent
from tex.events._canonical import canonical_json, canonical_sha256, sha256_hex
from tex.events.crypto_provenance import CryptoProvenance
from tex.events.event import Event, genesis_ledger_hash
from tex.events.exceptions import (
    ChainLinkError,
    LedgerAppendError,
    MissingUpstreamError,
    PayloadHashMismatchError,
    RecordHashMismatchError,
    SequenceGapError,
    SignatureVerificationError,
)
from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import SignatureProvider


@runtime_checkable
class EventLedger(Protocol):
    """The public ledger surface."""

    def append(self, event: Event) -> None: ...
    def get(self, event_id: str) -> Event | None: ...
    def stream_after(self, sequence_number: int) -> tuple[Event, ...]: ...
    def verify_chain(self, *, from_sequence: int, to_sequence: int) -> bool: ...
    def exists(self, event_id: str) -> bool: ...


class InMemoryLedger:
    """
    In-memory append-only ledger for dev/tests/single-node deployments.

    Satisfies both ``EventLedger`` and the Thread 1
    ``tex.ontology.validator.EventLookup`` Protocol — wire the same
    instance into ``OntologyValidator(event_lookup=ledger)`` and the
    upstream-existence check will resolve against this ledger.

    Verification
    ------------
    Pass a ``verifying_public_key`` and ``signing_provider`` at
    construction so ``append()`` can verify the signature on every event
    before persisting. If neither is provided, signature verification is
    skipped and a single soft-warning telemetry event is emitted on the
    first append (mirrors the ontology validator's no-lookup behavior).
    """

    def __init__(
        self,
        *,
        verifying_public_key: bytes | None = None,
        signing_provider: SignatureProvider | None = None,
    ) -> None:
        self._events: list[Event] = []
        self._index: dict[str, Event] = {}
        self._verifying_public_key = verifying_public_key
        self._provider = signing_provider
        self._warned_no_verification = False

    # --- core append path ---

    def append(self, event: Event) -> None:
        """
        Append an Event to the ledger after enforcing every invariant.

        Invariants checked, in order:
          1. ``sequence_number == len(self) + 1`` — no gaps, no replays
          2. ``previous_ledger_hash`` matches the prior record's record_hash
             (or the genesis sentinel for the first entry)
          3. every ``upstream_event_id`` resolves to an already-stored event
          4. ``payload_sha256`` re-hashes correctly from the stored payload
          5. ``record_hash`` re-hashes correctly from canonical_record_input
          6. signature verifies via the configured provider (if wired)
        """
        expected_sequence = len(self._events) + 1
        if event.sequence_number != expected_sequence:
            raise SequenceGapError(
                f"expected sequence_number={expected_sequence}, "
                f"got {event.sequence_number}"
            )

        expected_prev = (
            self._events[-1].record_hash
            if self._events
            else genesis_ledger_hash()
        )
        if event.previous_ledger_hash != expected_prev:
            raise ChainLinkError(
                "previous_ledger_hash does not match prior record "
                f"(expected={expected_prev[:16]}..., "
                f"got={event.previous_ledger_hash[:16]}...)"
            )

        for upstream_id in event.upstream_event_ids:
            if upstream_id not in self._index:
                raise MissingUpstreamError(
                    f"upstream_event_id {upstream_id!r} not found in ledger"
                )

        self._verify_record_integrity(event)
        self._verify_signature(event)

        self._events.append(event)
        self._index[event.event_id] = event

        emit_event(
            "events.ledger.appended",
            event_id=event.event_id,
            sequence_number=event.sequence_number,
            kind=event.kind,
            upstream_count=len(event.upstream_event_ids),
        )

    def append_proposed(
        self,
        proposed: ProposedEvent,
        *,
        provenance: CryptoProvenance,
        event_id: str | None = None,
        tool_receipt_id: str | None = None,
    ) -> Event:
        """
        Convenience: attach provenance to a ProposedEvent and append in one call.

        The canonical ecosystem-engine path. ``CryptoProvenance.attach`` is
        called with the next sequence number and the current chain head;
        the resulting Event is then appended through the full
        invariant-checking ``append`` path.
        """
        event = provenance.attach(
            proposed=proposed,
            sequence_number=len(self._events) + 1,
            previous_ledger_hash=(
                self._events[-1].record_hash
                if self._events
                else genesis_ledger_hash()
            ),
            event_id=event_id,
            tool_receipt_id=tool_receipt_id,
        )
        self.append(event)
        return event

    # --- read path ---

    def get(self, event_id: str) -> Event | None:
        return self._index.get(event_id)

    def stream_after(self, sequence_number: int) -> tuple[Event, ...]:
        """
        Return all events with ``sequence_number > sequence_number``.

        Cheap O(k) where k is the number of events after the cursor.
        Callers polling this should pass the highest sequence_number they
        have already consumed.
        """
        if sequence_number < 0:
            return tuple(self._events)
        return tuple(e for e in self._events if e.sequence_number > sequence_number)

    def exists(self, event_id: str) -> bool:
        """Satisfies tex.ontology.validator.EventLookup."""
        return event_id in self._index

    def __len__(self) -> int:
        return len(self._events)

    # --- verification path ---

    def verify_chain(self, *, from_sequence: int, to_sequence: int) -> bool:
        """
        Re-verify every record in the inclusive slice [from_sequence, to_sequence].

        Checks per record: payload_sha256, record_hash, previous_ledger_hash
        linkage (to the in-slice predecessor or to the boundary record before
        ``from_sequence``), and signature. Returns False on any mismatch and
        emits ``events.ledger.verify_chain.failed`` with the offending index
        + reason for diagnostics.
        """
        if from_sequence < 1 or to_sequence < from_sequence:
            emit_event(
                "events.ledger.verify_chain.failed",
                reason="invalid_range",
                from_sequence=from_sequence,
                to_sequence=to_sequence,
            )
            return False
        if to_sequence > len(self._events):
            emit_event(
                "events.ledger.verify_chain.failed",
                reason="range_exceeds_ledger",
                from_sequence=from_sequence,
                to_sequence=to_sequence,
                ledger_len=len(self._events),
            )
            return False

        # Establish the predecessor: the record at sequence_number = from_sequence - 1,
        # or the genesis sentinel when from_sequence == 1.
        prior_hash = (
            genesis_ledger_hash()
            if from_sequence == 1
            else self._events[from_sequence - 2].record_hash
        )

        for seq in range(from_sequence, to_sequence + 1):
            event = self._events[seq - 1]
            try:
                self._verify_record_integrity(event)
            except (PayloadHashMismatchError, RecordHashMismatchError) as exc:
                emit_event(
                    "events.ledger.verify_chain.failed",
                    reason=type(exc).__name__,
                    sequence_number=seq,
                    detail=str(exc),
                )
                return False

            if event.previous_ledger_hash != prior_hash:
                emit_event(
                    "events.ledger.verify_chain.failed",
                    reason="ChainLinkError",
                    sequence_number=seq,
                )
                return False

            try:
                self._verify_signature(event, force=True)
            except SignatureVerificationError as exc:
                emit_event(
                    "events.ledger.verify_chain.failed",
                    reason="SignatureVerificationError",
                    sequence_number=seq,
                    detail=str(exc),
                )
                return False

            prior_hash = event.record_hash

        emit_event(
            "events.ledger.verify_chain.ok",
            from_sequence=from_sequence,
            to_sequence=to_sequence,
        )
        return True

    # --- internals ---

    def _verify_record_integrity(self, event: Event) -> None:
        expected_payload_sha256 = canonical_sha256(event.payload)
        if event.payload_sha256 != expected_payload_sha256:
            raise PayloadHashMismatchError(
                f"payload_sha256 mismatch on event {event.event_id!r}"
            )

        expected_record_hash = sha256_hex(
            canonical_json(event.canonical_record_input())
        )
        if event.record_hash != expected_record_hash:
            raise RecordHashMismatchError(
                f"record_hash mismatch on event {event.event_id!r}"
            )

    def _verify_signature(self, event: Event, *, force: bool = False) -> None:
        if self._provider is None or self._verifying_public_key is None:
            if not self._warned_no_verification:
                emit_event(
                    "events.ledger.signature_verification_skipped",
                    reason="no_verifying_key_or_provider_configured",
                )
                self._warned_no_verification = True
            if force:
                # During verify_chain the operator explicitly asked for a
                # full re-verify; missing provider means we cannot fulfill it.
                raise SignatureVerificationError(
                    "verify_chain called but no verifying key/provider configured"
                )
            return

        try:
            signature = base64.b64decode(event.pq_signature_b64.encode("ascii"))
        except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            raise SignatureVerificationError(
                f"could not base64-decode signature on event {event.event_id!r}: {exc}"
            ) from exc

        ok = self._provider.verify(
            event.record_hash.encode("utf-8"),
            signature,
            self._verifying_public_key,
        )
        if not ok:
            raise SignatureVerificationError(
                f"signature did not verify for event {event.event_id!r}"
            )


__all__ = [
    "EventLedger",
    "InMemoryLedger",
    "LedgerAppendError",
    "SequenceGapError",
    "ChainLinkError",
    "MissingUpstreamError",
    "SignatureVerificationError",
    "PayloadHashMismatchError",
    "RecordHashMismatchError",
]
