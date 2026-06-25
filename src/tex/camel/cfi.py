"""
CFI-BUDGET — Control-Flow-Influence pricing for the CaMeL ``Branch`` node.

This module is the *integrity dual* of a confidentiality leakage budget: it
prices the bits of **control-flow influence** an untrusted value exerts when it
steers a ``Branch``, and accumulates those debits in a tamper-evident,
hash-chained ledger. Classic CaMeL forbids untrusted-influenced control flow
outright (a binary floor). CFI-BUDGET converts that floor into a *capacity*:
an untrusted value may steer a branch, but only by spending a measured number
of bits drawn from a finite, declared budget.

Two ingredients price one branch:

- **capacity** of the steering value — ``log2(len(output_domain))`` bits. A
  value drawn from a 2-element typed domain can pick at most 1 bit of the
  downstream control flow; an 8-element domain, 3 bits. An *undeclared*
  (untyped) domain has unbounded capacity and is rejected upstream (the
  interpreter fail-closes rather than pricing infinity).
- **sink weight** of the branch — how much the two arms actually *differ* in
  the side-effecting capability they reach, measured as the size of the
  symmetric difference of the tool scopes reachable in each arm. A branch
  whose arms call the same tools steers nothing dangerous (weight 0, cost 0);
  a branch where one arm reaches ``send_email`` and the other does not has a
  non-trivial sink and a non-trivial price.

``cfi_influence_bits = log2(len(output_domain)) * sink_weight``.

Honest scope (what this does NOT do)
------------------------------------
- It does **not** solve branch steering. It *bounds declared capacity* —
  ``log2|domain| * |scope Δ|`` — which is an upper bound on the bits a value
  *could* inject, not the realized mutual information between the attacker's
  input and the chosen arm. A value that is honestly 2-valued but perfectly
  attacker-correlated still gets priced at exactly 1 bit.
- A single in-budget branch is **not** caught by the budget alone — the budget
  is a cumulative, long-horizon bound, not a per-branch safety check. Catching
  an individual high-leverage branch is the job of the companion CHOKE-X
  certifier (later iteration), not this module.
- The price is only as sound as the honest ``output_domain`` declaration. A
  node that lies about its domain (declares ``("yes","no")`` but can emit
  arbitrary strings) underprices its influence. The interpreter's in-domain
  check (HALT on out-of-domain output) is the runtime enforcement of the
  declaration, but it cannot detect a domain that is honestly-typed yet
  semantically permissive.

References: CaMeL §4.3 (no untrusted control flow); quantitative information
flow / channel capacity (Smith 2009, "On the foundations of quantitative
information flow"); the confidentiality-budget dual in
``tex.governance.private_data_exec`` value-class budgeting.
"""

from __future__ import annotations

import hashlib
import math
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:  # avoid an import cycle (plan imports nothing from cfi)
    from tex.camel.plan import PlanNode


# ---------------------------------------------------------------------------
# Pure pricing functions
# ---------------------------------------------------------------------------


def _reachable_tool_scopes(nodes: "tuple[PlanNode, ...]") -> frozenset[str]:
    """The set of tool names reachable anywhere in ``nodes``, descending into
    nested ``Branch`` arms. This is the side-effect *scope* of an arm — the
    capabilities a value steering toward this arm can cause to fire."""
    # Local import keeps cfi import-light and breaks any construction cycle.
    from tex.camel.plan import Branch, Call

    scopes: set[str] = set()
    for n in nodes:
        if isinstance(n, Call):
            scopes.add(n.tool)
        elif isinstance(n, Branch):
            scopes |= _reachable_tool_scopes(n.then_nodes)
            scopes |= _reachable_tool_scopes(n.else_nodes)
    return frozenset(scopes)


def scope_symmetric_difference(
    then_nodes: "tuple[PlanNode, ...]",
    else_nodes: "tuple[PlanNode, ...]",
) -> int:
    """Sink weight of a branch = size of the symmetric difference of the tool
    scopes reachable in the two arms.

    Tools reachable in *both* arms are not steered by the condition (the value
    causes them regardless), so they contribute 0. Only tools a given arm
    reaches *exclusively* are actually selected by the condition — those are
    the steered sinks. Returns ``len(then_scope △ else_scope)``.
    """
    then_scope = _reachable_tool_scopes(then_nodes)
    else_scope = _reachable_tool_scopes(else_nodes)
    return len(then_scope ^ else_scope)


def cfi_influence_bits(
    output_domain: "tuple[object, ...]",
    sink_weight: int,
) -> float:
    """Control-flow-influence price of a branch, in bits.

    ``log2(len(output_domain)) * sink_weight``.

    - A domain of size 1 is deterministic (``log2(1) = 0``): a constant cannot
      steer, cost 0 regardless of sink weight.
    - A domain of size 2 contributes exactly 1 bit per unit of sink weight.
    - Sink weight 0 (arms with identical reachable tool scopes) costs 0: the
      condition selects nothing side-effecting.

    Raises ``ValueError`` on an empty domain (a value that can take *no* value
    is malformed) or a negative sink weight.
    """
    n = len(output_domain)
    if n < 1:
        raise ValueError("output_domain must be non-empty")
    if sink_weight < 0:
        raise ValueError("sink_weight must be non-negative")
    return math.log2(n) * sink_weight


# ---------------------------------------------------------------------------
# Hash-chained cumulative ledger
# ---------------------------------------------------------------------------

_GENESIS = "cfi-ledger-genesis"


def _hash_entry(prev_hash: str, index: int, debit_bits: float, total_bits: float) -> str:
    """Deterministic entry hash chaining the previous hash with this debit.

    Floats are formatted with ``repr`` so the chain is reproducible bit-for-bit
    across runs (no locale / precision drift)."""
    payload = f"{prev_hash}|{index}|{debit_bits!r}|{total_bits!r}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class CfiLedgerEntry(BaseModel):
    """One immutable, hash-chained debit in the CFI ledger."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    index: int = Field(ge=0)
    debit_bits: float = Field(ge=0.0)
    total_bits: float = Field(ge=0.0)
    prev_hash: str = Field(min_length=1)
    entry_hash: str = Field(min_length=1)


class CfiLedger:
    """A cumulative, tamper-evident ledger of control-flow-influence debits.

    Each ``append`` chains the new entry's hash from the previous entry's hash
    (genesis-rooted), so any retroactive edit to a past debit breaks the chain
    and is detectable via :meth:`verify`. The running ``total_bits`` is the sum
    of all debits so far — the quantity the interpreter compares against its
    hardcoded ``steer_budget``.
    """

    __slots__ = ("_entries",)

    def __init__(self) -> None:
        self._entries: list[CfiLedgerEntry] = []

    @property
    def total_bits(self) -> float:
        """Cumulative control-flow-influence bits debited so far."""
        return self._entries[-1].total_bits if self._entries else 0.0

    @property
    def entries(self) -> tuple[CfiLedgerEntry, ...]:
        return tuple(self._entries)

    @property
    def head_hash(self) -> str:
        return self._entries[-1].entry_hash if self._entries else _GENESIS

    def append(self, debit_bits: float) -> float:
        """Append a debit; return the new cumulative total.

        Raises ``ValueError`` on a negative debit (the price floor is 0)."""
        if debit_bits < 0:
            raise ValueError("debit_bits must be non-negative")
        index = len(self._entries)
        prev_hash = self.head_hash
        total = self.total_bits + debit_bits
        entry_hash = _hash_entry(prev_hash, index, debit_bits, total)
        self._entries.append(
            CfiLedgerEntry(
                index=index,
                debit_bits=debit_bits,
                total_bits=total,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
        )
        return total

    def verify(self) -> bool:
        """Re-derive the whole chain; True iff intact (no entry tampered)."""
        prev = _GENESIS
        running = 0.0
        for i, e in enumerate(self._entries):
            if e.index != i or e.prev_hash != prev:
                return False
            running += e.debit_bits
            if e.total_bits != running:
                return False
            if e.entry_hash != _hash_entry(prev, i, e.debit_bits, e.total_bits):
                return False
            prev = e.entry_hash
        return True


__all__ = [
    "CfiLedger",
    "CfiLedgerEntry",
    "cfi_influence_bits",
    "scope_symmetric_difference",
]
