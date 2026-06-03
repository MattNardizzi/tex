"""
Exception hierarchy for the events ledger.

All append-time failures are subclasses of ``LedgerAppendError`` so callers
can branch on cause without catching a bare ValueError.

Priority: P0.
"""

from __future__ import annotations


class LedgerAppendError(Exception):
    """Base class for any failure during InMemoryLedger.append()."""


class SequenceGapError(LedgerAppendError):
    """sequence_number does not match the next expected slot in the ledger."""


class ChainLinkError(LedgerAppendError):
    """previous_ledger_hash does not match the prior record's record_hash."""


class MissingUpstreamError(LedgerAppendError):
    """One or more upstream_event_ids do not resolve to stored events."""


class SignatureVerificationError(LedgerAppendError):
    """The ML-DSA / ECDSA signature on the event failed verification."""


class RecordHashMismatchError(LedgerAppendError):
    """The record_hash field does not match the canonical re-computation."""


class PayloadHashMismatchError(LedgerAppendError):
    """The payload_sha256 field does not match the canonical re-computation."""
