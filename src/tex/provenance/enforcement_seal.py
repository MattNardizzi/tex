"""
ENFORCEMENT-sealing seam — seal one ``SealedFact(ENFORCEMENT)`` per gated action.

This is the missing leaf in the seal family. ``decision_seal.py`` seals a verdict
(``DECISION``) and ``attempt_seal.py`` seals an evaluation entry (``ATTEMPT``) —
both fire only when the deep PDP runs. But the *enforcement* event — "the gate
allowed/blocked agent action X" — was sealed for nothing in the agent path:

  * a STRUCTURAL FLOOR forbid (unknown/unsealed agent, off-surface action) never
    reaches the deep evaluator (``governance/standing.py`` ``_forbid_floor``), so
    no DECISION fact is ever produced for it; and
  * the gate's allow/blocked OUTCOME (did the wrapped callable actually run, or
    was it stopped?) is a fact about ENFORCEMENT, not about the verdict.

``SealedFactKind.ENFORCEMENT`` already exists and is used by the reflexive
self-governor (``selfgov/governor.py``) for controller mutations. This seam
extends the same kind to the *agent-action* gate, sealing one ENFORCEMENT fact
per gated decision onto the SAME ``SealedFactLedger`` the rest of governance
uses — so a single offline verifier (``verifier/check.py`` / the ledger's own
``verify_chain``/``verify_signatures``) checks it, with no new chain.

Honesty — what the seal proves and what it does NOT:
  * AUTHORSHIP + INTEGRITY of "the gate allowed/blocked this action": the ledger
    is SHA-256 hash-chained and ECDSA-P256 signed (optional post-quantum ML-DSA
    dual-sign). It does NOT prove the verdict was *correct* (that is the PDP /
    zkPDP), and it is NOT externally time-anchored yet — RFC-3161 anchoring of
    this ledger is the next phase. Maturity is ``RESEARCH_SOLID`` accordingly.

Fail-closed, observation-only (mirrors ``decision_seal.seal_decision`` exactly):
  * ``ledger is None`` -> zero-cost no-op, returns ``None``.
  * an append failure is logged and returns ``None`` — it never raises into the
    gate's hot path and never changes what the gate did with the action.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from tex.domain.evidence import EvidenceMaturity
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind, SealedFactRecord

if TYPE_CHECKING:  # avoid an import cycle (enforcement imports provenance, not vice-versa)
    from tex.enforcement.events import GateEvent
    from tex.identity.agent_credential import AttestedIdentity

_logger = logging.getLogger(__name__)

# Real, live ECDSA-P256 + hash-chain crypto (authorship + integrity), newly
# wired and not externally anchored yet, so deliberately NOT ``PRODUCTION`` —
# the same honesty convention as the DECISION and ATTEMPT seals.
_ENFORCEMENT_MATURITY = EvidenceMaturity.RESEARCH_SOLID


def build_enforcement_fact(
    event: "GateEvent", *, attested_identity: "AttestedIdentity | None" = None
) -> SealedFact:
    """Map one gate decision (a ``GateEvent``) to a canonical
    ``SealedFact(ENFORCEMENT)``.

    Pure (no I/O, no mutation). The ``claim`` is deliberately narrow: it asserts
    only that the gate ALLOWED or BLOCKED the action (and, when an identity
    credential was verified, WHO took it) and that authorship + integrity are
    sealed — never that the verdict was correct.

    ``attested_identity`` (Phase 2) is the result of verifying the agent's signed
    identity credential. When present its full result is sealed into the fact, so
    the receipt records a CRYPTOGRAPHICALLY ATTESTED identity rather than a
    self-declared ``agent_id``. ``verified=False`` is recorded honestly (with the
    reason) — the seal never upgrades an unverified identity.
    """
    allowed = event.outcome == "executed"
    word = "allowed" if allowed else "blocked"
    agent = str(event.agent_id) if event.agent_id is not None else "unknown"
    identity_phrase = ""
    if attested_identity is not None:
        identity_phrase = (
            f"; identity ATTESTED (issuer {attested_identity.issuer})"
            if attested_identity.verified
            else f"; identity NOT attested ({attested_identity.status})"
        )
    claim = (
        f"gate {word} action_type={event.action_type!r} for agent={agent} "
        f"(verdict {event.verdict}, outcome {event.outcome}){identity_phrase} "
        f"— authorship+integrity sealed; verdict correctness NOT proven"
    )
    detail = {
        "allowed": allowed,
        "outcome": event.outcome,  # executed | blocked | reviewed
        "verdict": event.verdict,  # PERMIT | ABSTAIN | FORBID | UNAVAILABLE
        "action_type": event.action_type,
        "channel": event.channel,
        "environment": event.environment,
        "recipient": event.recipient,
        "agent_id": str(event.agent_id) if event.agent_id is not None else None,
        "decision_id": str(event.decision_id) if event.decision_id is not None else None,
        "determinism_fingerprint": event.determinism_fingerprint,
        "final_score": event.final_score,
        "confidence": event.confidence,
        "abstain_policy": event.abstain_policy,
        "fail_closed": event.fail_closed,
        "occurred_at": event.occurred_at.isoformat(),
    }
    if attested_identity is not None:
        detail["identity_attestation"] = attested_identity.to_detail()
    return SealedFact(
        kind=SealedFactKind.ENFORCEMENT,
        subject_id=str(event.request_id),
        claim=claim,
        maturity=_ENFORCEMENT_MATURITY,
        detail=detail,
    )


def seal_enforcement(
    ledger: SealedFactLedger | None,
    event: "GateEvent",
    *,
    attested_identity: "AttestedIdentity | None" = None,
) -> SealedFactRecord | None:
    """Seal one ``ENFORCEMENT`` fact into ``ledger`` and return its record.

    Fail-closed and observation-only, mirroring ``seal_decision``:
      * ``ledger is None`` -> no-op, return ``None``.
      * an append failure is logged and returns ``None`` — it never propagates
        into the gate path; the gate's allow/block decision is unaffected.
    """
    if ledger is None:
        return None
    try:
        return ledger.append(
            build_enforcement_fact(event, attested_identity=attested_identity)
        )
    except Exception:  # pragma: no cover - defensive; a seal must never break the gate
        _logger.warning(
            "ENFORCEMENT seal failed for request %s; gate outcome unaffected, fact not sealed",
            getattr(event, "request_id", "?"),
            exc_info=True,
        )
        return None
