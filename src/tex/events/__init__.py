"""
[Architecture: Layer 5 (Evidence)] — append-only event ledger with ECDSA-P256 signature provenance

See ARCHITECTURE.md for the full six-layer model.

Events Layer — Append-Only Cryptographic Ledger
================================================

The persistent record of every event in the ecosystem. Each event is:
  - immutable
  - chained (links to upstream event IDs and to the prior ledger entry)
  - cryptographically signed (ECDSA-P256 today, ML-DSA via Thread 4)
  - tagged with a HMAC tool receipt where applicable (tex.receipts; opaque ID for now)

Reference
---------
arxiv 2512.18561 (AAF) — cryptographically verifiable interaction provenance
with quorum-replicated shards. Storage analysis: at N=100 agents, h=8 horizon,
T=10^6 steps the ledger is ≈492 MB and streams at <80 KB/s.

Priority
--------
P0 — the ledger is the system of record.

"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.events import __layer__, __layer_kind__`.
__layer__: int | None = 5
__layer_kind__: str = 'evidence'

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
from tex.events.ledger import EventLedger, InMemoryLedger

__all__ = [
    "Event",
    "EventLedger",
    "InMemoryLedger",
    "CryptoProvenance",
    "genesis_ledger_hash",
    # Exceptions
    "LedgerAppendError",
    "ChainLinkError",
    "MissingUpstreamError",
    "PayloadHashMismatchError",
    "RecordHashMismatchError",
    "SequenceGapError",
    "SignatureVerificationError",
]
