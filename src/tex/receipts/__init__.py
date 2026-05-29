"""
[Architecture: Layer 5 (Evidence)] — HMAC tool receipts emitted alongside evidence records

See ARCHITECTURE.md for the full six-layer model.

Tool Execution Receipts (NabaOS-style)
=======================================

HMAC-signed receipts for every tool invocation, classified by epistemic
source per the Nyaya Shastra pramana taxonomy:

  - pratyaksha (direct tool output)
  - anumana (inference)
  - shabda (external testimony)
  - abhava (absence)
  - ungrounded opinion

Reference
---------
arxiv 2603.10060 — "Tool Receipts, Not Zero-Knowledge Proofs: Practical
Hallucination Detection for AI Agents", Abhinaba Basu, 9 Mar 2026.

Threat model
------------
Closes the gap where an LLM fabricates tool calls or misstates output counts.
The LLM does NOT have access to the HMAC signing key, so any claim referencing
a non-existent receipt ID is immediately detectable. Per the paper, this
catches 94.2% of fabricated tool references, 87.6% of count misstatements,
and 91.3% of false absence claims, with <15ms verification overhead.

Priority
--------
P0 — ship in days 15-28. Plugs the hallucination gap that the existing
specialist judges miss (per the Tex Arena live-gameplay finding).

"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.receipts import __layer__, __layer_kind__`.
__layer__: int | None = 5
__layer_kind__: str = 'evidence'

from tex.receipts.epistemic_source import EpistemicSource
from tex.receipts.receipt import ToolExecutionReceipt
from tex.receipts.runtime import ReceiptIssuer, ReceiptVerifier
from tex.receipts.store import InMemoryReceiptStore, ReceiptStore

__all__ = [
    "EpistemicSource",
    "ToolExecutionReceipt",
    "ReceiptIssuer",
    "ReceiptVerifier",
    "InMemoryReceiptStore",
    "ReceiptStore",
]
