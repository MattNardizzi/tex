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
from typing import TYPE_CHECKING, Any

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


def _identity_key_for(
    agent_id: str | None, attested_identity: "AttestedIdentity | None"
) -> str:
    """The stable key an enforcement receipt is sequenced under.

    Prefers the CRYPTOGRAPHICALLY ATTESTED identity, so the sequence binds to a
    verified actor rather than a self-declared ``agent_id``; falls back to the
    declared ``agent_id``, then to a single ``unattested`` bucket. This choice
    decides *whose* receipts must form an unbroken sequence — i.e. whose missing
    receipt reads as a bypass (see ``ledger.verify_no_gaps``). Shared by the
    in-process gate path and the network-PEP path so both sequence identically.
    """
    if attested_identity is not None and attested_identity.verified:
        agent = getattr(attested_identity, "claimed_agent_id", None) or (
            agent_id or "unknown"
        )
        return f"attested:{attested_identity.issuer}:{agent}"
    if agent_id is not None:
        return f"declared:{agent_id}"
    return "unattested:unknown"


def seal_enforcement(
    ledger: SealedFactLedger | None,
    event: "GateEvent",
    *,
    attested_identity: "AttestedIdentity | None" = None,
    action_sequence: int | None = None,
) -> SealedFactRecord | None:
    """Seal one ``ENFORCEMENT`` fact into ``ledger`` and return its record.

    The fact is sealed with a PER-IDENTITY SEQUENCE NUMBER (via
    ``ledger.append_sequenced``) so a *missing* receipt is detectable as a gap —
    the negative-space property that turns "we record what we stopped" into "a
    bypass is visible by the hole it leaves" (``ledger.verify_no_gaps``).
    ``action_sequence`` is the actor's own attested monotonic counter when one is
    available — it makes a true BYPASS detectable, not merely a deletion; when
    ``None`` the ledger assigns the next contiguous number for the identity, which
    still detects deletion/reordering of recorded receipts.

    Fail-closed and observation-only, mirroring ``seal_decision``:
      * ``ledger is None`` -> no-op, return ``None``.
      * an append failure is logged and returns ``None`` — it never propagates
        into the gate path; the gate's allow/block decision is unaffected.
    """
    if ledger is None:
        return None
    try:
        fact = build_enforcement_fact(event, attested_identity=attested_identity)
        agent_id = str(event.agent_id) if event.agent_id is not None else None
        identity_key = _identity_key_for(agent_id, attested_identity)
        return ledger.append_sequenced(
            fact, identity_key=identity_key, claimed_seq=action_sequence
        )
    except Exception:  # pragma: no cover - defensive; a seal must never break the gate
        _logger.warning(
            "ENFORCEMENT seal failed for request %s; gate outcome unaffected, fact not sealed",
            getattr(event, "request_id", "?"),
            exc_info=True,
        )
        return None


def seal_enforcement_decision(
    ledger: SealedFactLedger | None,
    *,
    action_type: str,
    channel: str,
    environment: str,
    recipient: str | None,
    agent_id: str | None,
    verdict: str,
    released: bool,
    decision_id: str | None = None,
    reason: str | None = None,
    tier: str | None = None,
    held: bool = False,
    request_id: str | None = None,
    attested_identity: "AttestedIdentity | None" = None,
    action_sequence: int | None = None,
    source: str = "network_pep",
) -> SealedFactRecord | None:
    """Seal an ENFORCEMENT fact from a PEP decision (no ``GateEvent``).

    The network PEP (``tex.pep``) decides PERMIT/FORBID and obeys ``released``,
    but produces no receipt. This seals the SAME ``SealedFact(ENFORCEMENT)`` the
    in-process gate seals, so a proxy-mediated action carries the identical
    offline-verifiable proof. ``released`` maps to outcome executed/blocked. Same
    fail-closed, observation-only contract as ``seal_enforcement``: ``ledger is
    None`` -> no-op; an append failure is logged and returns ``None`` — it never
    breaks the proxy's decision.
    """
    if ledger is None:
        return None
    from uuid import uuid4

    rid = request_id or str(uuid4())
    allowed = bool(released)
    outcome = "executed" if allowed else "blocked"
    word = "allowed" if allowed else "blocked"
    agent = agent_id or "unknown"
    identity_phrase = ""
    if attested_identity is not None:
        identity_phrase = (
            f"; identity ATTESTED (issuer {attested_identity.issuer})"
            if attested_identity.verified
            else f"; identity NOT attested ({attested_identity.status})"
        )
    claim = (
        f"PEP {word} action_type={action_type!r} for agent={agent} "
        f"(verdict {verdict}, outcome {outcome}){identity_phrase} "
        f"— authorship+integrity sealed; verdict correctness NOT proven"
    )
    detail: dict[str, Any] = {
        "allowed": allowed,
        "outcome": outcome,
        "verdict": verdict,
        "action_type": action_type,
        "channel": channel,
        "environment": environment,
        "recipient": recipient,
        "agent_id": agent_id,
        "decision_id": decision_id,
        "tier": tier,
        "held": held,
        "reason": reason,
        "source": source,
    }
    if attested_identity is not None:
        detail["identity_attestation"] = attested_identity.to_detail()
    try:
        identity_key = _identity_key_for(agent_id, attested_identity)
        return ledger.append_sequenced(
            SealedFact(
                kind=SealedFactKind.ENFORCEMENT,
                subject_id=rid,
                claim=claim,
                maturity=_ENFORCEMENT_MATURITY,
                detail=detail,
            ),
            identity_key=identity_key,
            claimed_seq=action_sequence,
        )
    except Exception:  # pragma: no cover - defensive; a seal must never break the PEP
        _logger.warning(
            "PEP ENFORCEMENT seal failed for request %s; decision unaffected, fact not sealed",
            rid,
            exc_info=True,
        )
        return None
