"""
Proof-carrying enforcement at the network PEP.

The in-process gate seals a ``SealedFact(ENFORCEMENT)`` per allow/deny
(``enforcement.seal.SealingGateObserver``). The network PEP (``tex.pep.proxy``)
already decides PERMIT/FORBID via the same standing PDP and obeys ``released`` —
but it produces no receipt. ``SealingDecisionClient`` closes that: it wraps any
``DecisionClient``, asks the inner client to decide, seals the SAME
offline-verifiable enforcement fact for that decision into a ``SealedFactLedger``,
then returns the result UNCHANGED. So a proxy-mediated agent action carries the
identical proof a gated in-process call does — one unified, verifiable receipt
story across both enforcement shapes.

Because it satisfies the ``DecisionClient`` interface, the proxy uses it
transparently (wrap the inner client, hand the proxy the wrapper). Sealing never
changes the decision and never raises into the request path (mirrors the
in-process observer): a seal failure is captured in ``last_error``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tex.pep.decision_client import Decision, DecisionClient, DecisionResult
from tex.provenance.enforcement_seal import seal_enforcement_decision
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactRecord

if TYPE_CHECKING:
    from tex.identity.agent_credential import AttestedIdentity

__all__ = ["SealingDecisionClient"]


class SealingDecisionClient(DecisionClient):
    """A ``DecisionClient`` that seals a proof-carrying receipt for each decision.

    Wraps ``inner`` (an ``InProcessDecisionClient`` / ``HttpDecisionClient``) and
    seals into ``ledger``. ``attested_identity`` (Phase 2), when set, binds every
    sealed fact to a cryptographically attested identity instead of the
    self-declared one. Sealed records also accumulate in ``records`` for
    inspection; the durable proof lives in the ledger.
    """

    __slots__ = ("_inner", "_ledger", "_attested_identity", "records", "last_error")

    def __init__(
        self,
        inner: DecisionClient,
        ledger: SealedFactLedger,
        *,
        attested_identity: "AttestedIdentity | None" = None,
    ) -> None:
        self._inner = inner
        self._ledger = ledger
        self._attested_identity = attested_identity
        self.records: list[SealedFactRecord] = []
        self.last_error: str | None = None

    def decide(self, decision: Decision) -> DecisionResult:
        result = self._inner.decide(decision)
        try:
            record = seal_enforcement_decision(
                self._ledger,
                action_type=decision.action_type,
                channel=decision.channel,
                environment=decision.environment,
                recipient=decision.recipient,
                agent_id=(
                    str(decision.agent_id)
                    if decision.agent_id is not None
                    else (decision.agent_external_id or None)
                ),
                verdict=result.verdict,
                released=result.released,
                decision_id=result.decision_id,
                reason=result.reason,
                tier=result.tier,
                held=result.held,
                attested_identity=self._attested_identity,
            )
            if record is not None:
                self.records.append(record)
        except Exception as exc:  # noqa: BLE001 — sealing must never break the PEP decision
            self.last_error = f"{type(exc).__name__}: {exc}"
        return result
