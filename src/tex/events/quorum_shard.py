"""
Quorum-replicated ledger shards.

Per AAF (arxiv 2512.18561): the cryptographic ledger is replicated across
multiple shards to ensure availability under node failure / Byzantine
adversaries.

Priority: P2.
"""

from __future__ import annotations


class QuorumShardReplicator:
    """TODO(P2): replicate appended events across N shards with 2f+1 quorum."""
    pass
