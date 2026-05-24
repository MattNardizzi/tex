"""
SAFEFLOW — Transactional agent execution with WAL and rollback.

Implements the transactional-execution discipline from arxiv 2506.07564
(SAFEFLOW: ``Towards Reliable LLM Agents via Transactional Execution
with Write-Ahead Logging and Rollback``, Hu et al., June 2025), adapted
into Tex's evidence-graded chain.

Why this matters
----------------
Most agent frameworks today execute tool calls fire-and-forget. When
a multi-step plan fails midway — a tool errors out, a policy denies a
late-stage step, the model hallucinates a missing field — there is no
reliable way to *undo* the partial work. SAFEFLOW gives agents the
same ACID-style guarantees that databases have had for forty years:

- **Atomicity**: a transaction is all-or-nothing.
- **Crash-consistent recovery**: a write-ahead log records every
  intent before it executes; replay or rollback is deterministic.
- **Snapshot isolation**: concurrent transactions see consistent
  views of state.

Status as of May 2026
---------------------
- SAFEFLOW: paper-only. No reference implementation released.
- Atomix (arxiv 2602.14849, Feb 17 2026): open-source transactional
  tool use, but no integration with policy frontends.
- LogAct (arxiv 2604.07988, Apr 9 2026): agentic WAL for shared
  multi-agent logs; complementary, not competing.

This implementation is the first SAFEFLOW realization wired into a
governance reference monitor. The WAL ties into Tex's existing
SHA-256 hash-chained evidence record so every transaction boundary
becomes an auditable artifact.

Scope of this delivery
----------------------
- Single-agent transactions (no multi-agent conflict resolution yet —
  that's the LogAct extension, deferred).
- Side-effect-free rollback: rollback re-runs the inverse operations
  registered against each step. Tools that cannot register an inverse
  (irreversible: `send_email`, `transfer_funds`) cannot participate
  in a transaction and are rejected at registration.
- WAL persistence is in-memory by default; the file backend writes
  to ``var/safeflow/wal/<txn_id>.log`` in append-only mode.

Components
----------
- ``transaction``    — ``Transaction`` context manager, lifecycle
- ``wal``            — write-ahead-log records, append-only file
- ``rollback``       — inverse-operation registry
- ``executor``       — runs transactions, drives WAL, decides commit /
                       rollback
"""

from tex.safeflow.executor import (
    SafeflowError,
    TransactionalExecutor,
    TransactionOutcome,
)
from tex.safeflow.rollback import (
    InverseOpRegistry,
    register_inverse,
)
from tex.safeflow.transaction import (
    Transaction,
    TransactionState,
    TransactionStep,
)
from tex.safeflow.wal import (
    WAL,
    WALEntry,
    WALEntryKind,
    InMemoryWAL,
    FileWAL,
)

__all__ = [
    "FileWAL",
    "InMemoryWAL",
    "InverseOpRegistry",
    "SafeflowError",
    "Transaction",
    "TransactionalExecutor",
    "TransactionOutcome",
    "TransactionState",
    "TransactionStep",
    "WAL",
    "WALEntry",
    "WALEntryKind",
    "register_inverse",
]
