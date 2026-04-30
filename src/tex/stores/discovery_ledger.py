"""
Append-only hash-chained discovery ledger.

Every reconciliation outcome lands here as a DiscoveryLedgerEntry.
The ledger uses the same SHA-256 chain shape as the evidence
recorder: each entry's `record_hash` covers
`payload_sha256 + previous_hash`, so any reordering, deletion, or
mid-stream tampering is detectable by replaying the chain.

This is the audit story for discovery: not just "we found these
agents," but "we found these agents in this exact order, and here is
the cryptographic proof that nothing was added or removed after the
fact." The same property the evidence chain gives Tex's runtime
decisions, the discovery ledger gives Tex's discovery decisions.

The store is in-memory and thread-safe. Persistence to disk is a
straightforward extension following the EvidenceRecorder pattern;
we ship the in-memory version because discovery runs are typically
operator-initiated, not request-path, and a JSONL persister is a
deployment concern, not a domain concern.
"""

from __future__ import annotations

import hashlib
import json
from threading import RLock
from typing import Any

from tex.domain.discovery import (
    CandidateAgent,
    DiscoveryLedgerEntry,
    ReconciliationOutcome,
)


class InMemoryDiscoveryLedger:
    """
    Thread-safe append-only ledger of discovery outcomes.

    The ledger is the canonical record of "what was discovered, when,
    and what we did about it." It complements the evidence chain
    (which is the canonical record of "what content went out, and
    what verdict we returned"). Together they give an auditor a
    complete picture of agent provenance: how the agent ended up in
    the registry AND what it has done since.
    """

    __slots__ = ("_lock", "_entries", "_by_key", "_by_agent_id")

    def __init__(self) -> None:
        self._lock = RLock()
        self._entries: list[DiscoveryLedgerEntry] = []
        # reconciliation_key -> tuple of sequence numbers, for fast
        # lookup of the history of a specific (source, tenant, ext_id).
        self._by_key: dict[str, list[int]] = {}
        # agent_id (str) -> tuple of sequence numbers. Lets the API
        # answer "show me the discovery history of this registered
        # agent" in one call.
        self._by_agent_id: dict[str, list[int]] = {}

    # ------------------------------------------------------------------ writes

    def append(
        self,
        *,
        candidate: CandidateAgent,
        outcome: ReconciliationOutcome,
    ) -> DiscoveryLedgerEntry:
        """
        Append one outcome to the ledger.

        The chain hash is computed from the canonical JSON of the
        candidate + outcome pair plus the prior record's hash. Any
        change to the candidate evidence, the reconciliation
        decision, or the order of records will break the chain on
        verification.
        """

        with self._lock:
            sequence = len(self._entries)
            previous_hash = self._entries[-1].record_hash if self._entries else None

            payload = {
                "candidate": _to_jsonable(candidate.model_dump(mode="json")),
                "outcome": _to_jsonable(outcome.model_dump(mode="json")),
            }
            payload_json = _stable_json(payload)
            payload_sha256 = _sha256_hex(payload_json)
            record_hash = _sha256_hex(
                _stable_json(
                    {
                        "payload_sha256": payload_sha256,
                        "previous_hash": previous_hash,
                    }
                )
            )

            entry = DiscoveryLedgerEntry(
                sequence=sequence,
                candidate=candidate,
                outcome=outcome,
                payload_sha256=payload_sha256,
                previous_hash=previous_hash,
                record_hash=record_hash,
            )

            self._entries.append(entry)
            self._by_key.setdefault(outcome.reconciliation_key, []).append(sequence)
            if outcome.resulting_agent_id is not None:
                self._by_agent_id.setdefault(
                    str(outcome.resulting_agent_id), []
                ).append(sequence)
            return entry

    # ------------------------------------------------------------------ reads

    def list_all(self) -> tuple[DiscoveryLedgerEntry, ...]:
        with self._lock:
            return tuple(self._entries)

    def list_for_key(self, reconciliation_key: str) -> tuple[DiscoveryLedgerEntry, ...]:
        with self._lock:
            sequences = self._by_key.get(reconciliation_key, [])
            return tuple(self._entries[s] for s in sequences)

    def list_for_agent_id(self, agent_id_str: str) -> tuple[DiscoveryLedgerEntry, ...]:
        with self._lock:
            sequences = self._by_agent_id.get(agent_id_str, [])
            return tuple(self._entries[s] for s in sequences)

    def latest(self) -> DiscoveryLedgerEntry | None:
        with self._lock:
            return self._entries[-1] if self._entries else None

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    # ------------------------------------------------------------------ verify

    def verify_chain(self) -> bool:
        """
        Recompute every record's hash and confirm the chain is
        intact. Returns True if every record's payload hash matches
        its content and every record links to its predecessor.
        """

        with self._lock:
            previous_hash: str | None = None
            for entry in self._entries:
                payload = {
                    "candidate": _to_jsonable(entry.candidate.model_dump(mode="json")),
                    "outcome": _to_jsonable(entry.outcome.model_dump(mode="json")),
                }
                payload_sha256 = _sha256_hex(_stable_json(payload))
                if payload_sha256 != entry.payload_sha256:
                    return False
                expected_record = _sha256_hex(
                    _stable_json(
                        {
                            "payload_sha256": payload_sha256,
                            "previous_hash": previous_hash,
                        }
                    )
                )
                if expected_record != entry.record_hash:
                    return False
                if entry.previous_hash != previous_hash:
                    return False
                previous_hash = entry.record_hash
            return True


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _to_jsonable(value: Any) -> Any:
    """
    Pydantic's `model_dump(mode='json')` already produces JSON-safe
    primitives; this helper exists so the ledger can normalize any
    additional dict-shaped payloads it might be asked to hash later
    without changing the call site.
    """
    return value


def _stable_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
