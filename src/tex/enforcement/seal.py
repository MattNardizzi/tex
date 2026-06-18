"""
Proof-carrying action gating — seal every gate allow/deny into the ledger.

The brain↔body join already exists (``standing_transport.py``):
``StandingGovernanceTransport`` routes a gate check through the full standing
PDP and ``TexGate`` blocks the action on anything but PERMIT. What was missing
is the *proof*: a tamper-evident, offline-verifiable record of **every** gate
allow/deny — including the structural-floor FORBIDs that never reach the deep
evaluator, and the gate's allow/blocked OUTCOME.

This wires that in the codebase's own way: a ``SealingGateObserver`` is handed to
the gate; the gate emits exactly one ``GateEvent`` per gated execution; the
observer seals it as a ``SealedFact(ENFORCEMENT)`` into the same
``SealedFactLedger`` the rest of governance uses (via
``provenance.enforcement_seal.seal_enforcement``). One ledger, one verifier
(``verify_chain``/``verify_signatures`` / ``verifier/check.py``), no new chain.

Honesty (this phase): the seal proves authorship + integrity of "the gate
allowed/blocked this action" — not verdict correctness, and the ledger is not
externally time-anchored yet (RFC-3161 anchoring of the ledger is the next
phase). For FORBID/ABSTAIN the wrapped callable provably did NOT run (the gate
raised before invoking it); for PERMIT the receipt proves authorization and the
gate then runs the action.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tex.enforcement.gate import AbstainPolicy, TexGate
from tex.enforcement.standing_transport import build_standing_gate
from tex.governance.standing import StandingGovernance
from tex.provenance.enforcement_seal import seal_enforcement
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactRecord

if TYPE_CHECKING:
    from tex.enforcement.events import GateEvent

__all__ = ["SealingGateObserver", "build_proof_carrying_gate"]


class SealingGateObserver:
    """A ``GateEventObserver`` that seals one ENFORCEMENT fact per gate decision.

    Satisfies the observer protocol (``__call__(event) -> None``) and, per that
    contract, never raises — a sealing failure is captured in ``last_error`` and
    leaves the ledger unchanged rather than breaking enforcement. Sealed records
    accumulate in ``records`` for inspection; the durable proof lives in the
    ``SealedFactLedger`` (verify it with ``ledger.verify_chain()`` /
    ``ledger.verify_signatures()``).
    """

    __slots__ = ("_ledger", "records", "last_error")

    def __init__(self, ledger: SealedFactLedger) -> None:
        self._ledger = ledger
        self.records: list[SealedFactRecord] = []
        self.last_error: str | None = None

    def __call__(self, event: "GateEvent") -> None:
        try:
            record = seal_enforcement(self._ledger, event)
            if record is not None:
                self.records.append(record)
        except Exception as exc:  # noqa: BLE001 — an observer must never break the gate
            self.last_error = f"{type(exc).__name__}: {exc}"

    @property
    def ledger(self) -> SealedFactLedger:
        return self._ledger


def build_proof_carrying_gate(
    governance: StandingGovernance,
    *,
    ledger: SealedFactLedger | None = None,
    tenant: str | None = None,
    abstain_policy: AbstainPolicy = AbstainPolicy.BLOCK,
    fail_closed: bool = True,
    default_action_type: str = "agent_action",
    default_channel: str = "api",
    default_environment: str = "production",
) -> tuple[TexGate, SealingGateObserver]:
    """A ``TexGate`` that enforces the full standing PDP **and** seals an
    offline-verifiable ENFORCEMENT fact for every allow/deny.

    The brain↔body join (block on non-PERMIT) plus the proof (a per-decision
    sealed record anyone can verify against the ledger's pinned key). Returns
    ``(gate, observer)`` — wrap callables with ``gate``; the durable proof is in
    ``observer.ledger`` (or the ``ledger`` you passed in to share one chain).

        ledger = SealedFactLedger()
        gate, obs = build_proof_carrying_gate(governance, ledger=ledger, tenant="acme")
        send_wire = gate.wrap(raw_send_wire, content_arg="memo",
                              action_type="wire_transfer")
        send_wire(memo="pay vendor")          # FORBID -> raises; an ENFORCEMENT fact is sealed
        assert ledger.verify_chain()["intact"]
    """
    ledger = ledger if ledger is not None else SealedFactLedger()
    observer = SealingGateObserver(ledger)
    gate = build_standing_gate(
        governance,
        tenant=tenant,
        abstain_policy=abstain_policy,
        fail_closed=fail_closed,
        default_action_type=default_action_type,
        default_channel=default_channel,
        default_environment=default_environment,
        observer=observer,
    )
    return gate, observer
