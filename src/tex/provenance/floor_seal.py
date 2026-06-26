"""
FLOOR-decision sealing seam — seal one ``SealedFact(ENFORCEMENT)`` per
DETERMINISTIC FLOOR ruling (floor FORBID / floor ABSTAIN).

This is the leaf the rest of the seal family left unsealed. ``decision_seal.py``
seals a verdict (``DECISION``) and ``attempt_seal.py`` an evaluation entry
(``ATTEMPT``) — but BOTH fire only when the deep six-layer PDP runs. The
``StandingGovernance`` structural floor (``governance/standing.py``
``_forbid_floor`` / ``_abstain_uninspectable``) rules WITHOUT the deep engine:

  * an unknown / unsealed agent, an agent not in a governable state, an action
    outside its sealed capability surface, or a deep-engine-unavailable/raised
    case -> a deterministic floor FORBID; and
  * un-inspectable egress (a body Tex cannot decode, TLS it could not terminate)
    -> a deterministic floor ABSTAIN (held for a human).

These produce NO ``DECISION`` fact, so until now a large share of real traffic
left no offline-verifiable evidence record at all. This seam closes that: when a
ledger is wired, every floor ruling seals one ``SealedFact(ENFORCEMENT)`` onto
the SAME ``SealedFactLedger`` the deep path uses — one chain, one verifier.

Why ENFORCEMENT and not DECISION (HONESTY — must not be over-read):
  * A floor ruling is what the GATE did deterministically, not a six-layer
    adjudication. ``enforcement_seal.build_enforcement_fact`` already exists
    precisely because "a STRUCTURAL FLOOR forbid ... never reaches the deep
    evaluator ... so no DECISION fact is ever produced for it". ENFORCEMENT is
    the correct, precedented kind.
  * Reusing the deep ``DECISION`` kind would require a full ``Decision`` (final
    score, policy id/version, determinism fingerprint, content hash) the floor
    never computes — fabricating those would dress a deterministic block as a
    deep adjudication, AND would corrupt L1 seal-binding / L3 count-conservation,
    both of which assume an ATTEMPT->DECISION pair from the deep engine.
  * The seal therefore proves AUTHORSHIP + INTEGRITY of a deterministic floor
    block — never that any deep verdict was reached, and never CORRECTNESS. The
    floor IS fully reproducible/inspectable, so sealing it is honest. The
    ``claim`` string says so in words (``DETERMINISTIC`` ... ``NOT a six-layer``).
    Maturity is ``RESEARCH_SOLID``, the same convention as the decision /
    enforcement seals.

Fail-closed, observation-only (mirrors ``seal_decision`` / ``seal_enforcement``):
  * ``ledger is None`` -> zero-cost no-op, returns ``None``. The default deploy
    (TEX_SEAL_DECISIONS unset) builds no ledger, so floor sealing is byte-for-byte
    inert there.
  * an append failure is logged and returns ``None`` — it never raises into the
    ruling path and never changes what the floor decided.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from tex.domain.evidence import EvidenceMaturity
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind, SealedFactRecord

_logger = logging.getLogger(__name__)

# Real, live ECDSA-P256 + hash-chain crypto (authorship + integrity) over a
# deterministic floor ruling, newly wired and not externally anchored — so
# deliberately NOT ``PRODUCTION``, matching the DECISION / ENFORCEMENT seals.
_FLOOR_MATURITY = EvidenceMaturity.RESEARCH_SOLID


def build_floor_decision_fact(
    *,
    verdict: str,
    scope: str | None,
    reason: str | None,
    reason_code: str | None,
    action_type: str | None,
    channel: str | None,
    environment: str | None,
    recipient: str | None,
    tenant: str | None,
    agent_id: str | None,
    decision_id: str,
) -> SealedFact:
    """Map one DETERMINISTIC FLOOR ruling to a canonical ``SealedFact(ENFORCEMENT)``.

    Pure (no I/O, no mutation). Every field is reproducible from the floor inputs;
    the fact carries NO deep-only fields (no final_score / policy_id /
    policy_version / determinism_fingerprint / content_sha256) — sealing a floor
    block as those would fabricate an adjudication that never ran. The ``claim``
    is deliberately narrow and self-limiting so no reader over-reads the record.
    """
    agent = agent_id or "unknown"
    claim = (
        f"floor {verdict} (scope={scope}) for action_type={action_type!r} "
        f"agent={agent} tenant={tenant} — DETERMINISTIC structural floor; "
        f"authorship+integrity sealed; NOT a six-layer adjudication, "
        f"correctness NOT proven"
    )
    detail: dict[str, Any] = {
        "verdict": verdict,  # FORBID | ABSTAIN
        "tier": "floor",
        "forbid_scope": scope,  # identity | lifecycle | surface | deep_error (None for ABSTAIN)
        "reason": reason,
        "reason_code": reason_code,  # uninspectable_request_body | uninspectable_tls_content (ABSTAIN)
        "action_type": action_type,
        "channel": channel,
        "environment": environment,
        "recipient": recipient,
        "tenant": tenant,
        "agent_id": agent_id,
        "released": False,
        "decision_id": decision_id,
        "occurred_at": datetime.now(UTC).isoformat(),
    }
    return SealedFact(
        kind=SealedFactKind.ENFORCEMENT,
        subject_id=decision_id,
        claim=claim,
        maturity=_FLOOR_MATURITY,
        detail=detail,
    )


def seal_floor_decision(
    ledger: SealedFactLedger | None,
    *,
    verdict: str,
    scope: str | None,
    reason: str | None,
    reason_code: str | None,
    action_type: str | None,
    channel: str | None,
    environment: str | None,
    recipient: str | None,
    tenant: str | None,
    agent_id: str | None,
    decision_id: str,
) -> SealedFactRecord | None:
    """Seal one floor ENFORCEMENT fact into ``ledger`` and return its record.

    Fail-closed and observation-only, mirroring ``seal_decision`` /
    ``seal_enforcement`` exactly:
      * ``ledger is None`` -> no-op, return ``None`` (default deploy is inert).
      * an append failure is logged and returns ``None`` — it never propagates
        into the ruling path; the floor's FORBID/ABSTAIN is unaffected.
    """
    if ledger is None:
        return None
    try:
        fact = build_floor_decision_fact(
            verdict=verdict,
            scope=scope,
            reason=reason,
            reason_code=reason_code,
            action_type=action_type,
            channel=channel,
            environment=environment,
            recipient=recipient,
            tenant=tenant,
            agent_id=agent_id,
            decision_id=decision_id,
        )
        return ledger.append(fact)
    except Exception:  # pragma: no cover - defensive; a seal must never break the ruling
        _logger.warning(
            "FLOOR seal failed for decision %s; ruling unaffected, fact not sealed",
            decision_id,
            exc_info=True,
        )
        return None
