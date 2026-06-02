"""
Event — the persisted ledger record.

Distinct from ProposedEvent (which is the candidate). Event carries the
crypto provenance and is the canonical immutable form.

The hash chain covers every field that contributes to identity or lineage:
``kind``, ``actor_entity_id``, ``target_entity_id``, ``payload_sha256``,
``timestamp``, ``sequence_number``, ``upstream_event_ids``,
``previous_ledger_hash``, ``tool_receipt_id``. Mutating any of these
breaks ``record_hash`` and is detected by ``EventLedger.verify_chain``.

Reference
---------
arxiv 2512.18561 (AAF) section (i) — "cryptographically verifiable
interaction provenance" — every event in the ledger carries a chained
hash + signature so the post-hoc audit trail is tamper-evident.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# Genesis sentinel for the very first record's previous_ledger_hash.
# Sixty-four zero hex chars — same width as a SHA-256 digest, so the
# previous_ledger_hash field can stay typed as ``str`` (not ``str | None``)
# and the canonical record input has no special-case branch for index 0.
_GENESIS_LEDGER_HASH: str = "0" * 64


def genesis_ledger_hash() -> str:
    """Return the genesis sentinel used for the first ledger record."""
    return _GENESIS_LEDGER_HASH


class Event(BaseModel):
    """An immutable, signed event in the ecosystem ledger."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    kind: str  # one of EventKind values
    actor_entity_id: str
    target_entity_id: str | None = None
    payload: dict[str, Any]
    timestamp: datetime
    sequence_number: int  # monotone within ledger
    upstream_event_ids: tuple[str, ...] = Field(default_factory=tuple)
    previous_ledger_hash: str  # SHA-256 of prior ledger record (or genesis sentinel)
    payload_sha256: str
    record_hash: str  # SHA-256 of canonicalized record
    pq_signature_b64: str  # algorithm-tagged signature (ECDSA today, ML-DSA via Thread 4)
    pq_signing_key_id: str
    pq_signature_algorithm: str = "ecdsa-p256"  # SignatureAlgorithm value
    tool_receipt_id: str | None = None  # link to tex.receipts if applicable

    def canonical_record_input(self) -> dict[str, Any]:
        """
        Return the dict whose stable JSON gets hashed for ``record_hash``.

        The fields included here define the tamper surface: mutating any of
        them must produce a different ``record_hash``. The signature fields
        themselves are excluded because they are computed *over* this dict.
        """
        return {
            "kind": self.kind,
            "actor_entity_id": self.actor_entity_id,
            "target_entity_id": self.target_entity_id,
            "payload_sha256": self.payload_sha256,
            "timestamp": self.timestamp.isoformat(),
            "sequence_number": self.sequence_number,
            "upstream_event_ids": list(self.upstream_event_ids),
            "previous_ledger_hash": self.previous_ledger_hash,
            "tool_receipt_id": self.tool_receipt_id,
        }
