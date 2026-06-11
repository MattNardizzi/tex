"""
ATTEMPT-sealing hook (Wave 2 / seam track) — seal one ``SealedFact(ATTEMPT)``
per ``evaluate()`` entry.

This is the upstream half of L3's count-conservation identity
(``attempts == permits + abstains + forbids + errors``). Before this hook,
``n_attempts`` had no sealed source — sealing happened only after a verdict
(the M0 seam), so the identity was UNGATED trust-me. The hook seals the
attempt at the entry of ``PolicyDecisionPoint.evaluate()``, between
``pipeline_start`` and the deterministic-gate call: the ONLY point every
evaluation passes exactly once before anything can raise. The fact derives
from ``request`` + ``policy`` alone — nothing else exists yet.

The declared contract (the two decisions the scoping doc left to this seam,
``negative_knowledge.py`` §ATTEMPT-SEALING HOOK):

* **Count scoping — gate evaluations COUNT.** Every ``evaluate()`` entry
  seals one ATTEMPT: customer traffic and L5 reflexive gate evaluations
  alike (policy ``reflexive-governor``; its fast-paths never call
  ``evaluate()`` and so produce neither fact — consistent on both sides).
  The identity stays global and symmetric: a reflexive evaluation
  contributes 1 attempt and 1 verdict-keyed DECISION fact, so it balances.
  The rejected alternative — filtering by ``action_type`` — would have
  required scoping the verdict side with a byte-identical second filter
  (a divergence trap) and would have made self-governance mutations, the
  facts most worth conserving, invisible to the identity.
* **n_error — derivable and ONE-SIDED.** No error-outcome fact is sealed.
  An "error" is *defined* as an ATTEMPT with no matching verdict-keyed
  DECISION ``subject_id`` in the epoch. The identity therefore catches
  missing or fabricated DECISIONs (the omission attack), but a mid-pipeline
  death is indistinguishable from an omitted DECISION — both surface as
  GATED-BROKEN (fail-closed: a crash raises the alarm, never masks one).
  The rejected alternative — sealing an error fact at the exception
  boundary — exceeds the 1–2-line pdp.py budget AND still would not be
  two-sided: a swallowed DECISION-append failure (decision_seal.py:98-104)
  or a SIGKILL between entry and except produces an uncounted gap anyway.

Disambiguation contract for the shared M0 ledger (the census in
``tests/test_decision_fact_contract.py``): the ATTEMPT fact is a distinct
kind, NOT a detail-typed ``SealedFactKind.DECISION`` — a pre-verdict fact
labelled "a verdict was produced" would be misnamed. Its ``detail`` MUST NOT
carry a ``"verdict"`` key (L3 counts verdict-keyed DECISION facts; L1's
``check_seal_binding`` filters by DECISION kind, so ATTEMPT facts are
invisible to it). For one request the ATTEMPT appends FIRST — before the
optional PQ-durability fact (routing) and the M0 decision seal (finalize).

Honesty — what the seal proves and costs:
  * AUTHORSHIP + INTEGRITY of "an evaluation was begun", never that a verdict
    followed, and never CORRECTNESS of anything. Maturity is
    ``RESEARCH_SOLID``: live ECDSA-P256 + hash-chain crypto, newly wired.
  * An entry hook BOUNDS uncounted work, it does not eliminate it: anything
    that dies before ``evaluate()`` is entered (transport layer, non-PDP
    traffic) remains invisible. The hook turns ``n_attempts`` from trust-me
    into sealed-at-entry; it does not make it total.
  * Ledger growth: under ``TEX_SEAL_DECISIONS=1`` this hook DOUBLES the
    per-request appends (one ATTEMPT + one DECISION) — the very reason
    default-on sealing stays deferred. ATTEMPT facts also enter L6's
    checkpoints (gix covers ALL kinds): ``tree_size`` counts leaves of every
    kind and must never be cited as a decision OR attempt count.

Fail-closed to today's behaviour, observation-only (mirrors
``decision_seal.seal_decision`` exactly):
  * ``ledger is None`` → zero-cost no-op, returns ``None``.
  * An append failure is logged and returns ``None`` — it never raises into
    the request path and never alters the verdict.
"""

from __future__ import annotations

import hashlib
import logging

from tex.domain.evaluation import EvaluationRequest
from tex.domain.evidence import EvidenceMaturity
from tex.domain.policy import PolicySnapshot
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind, SealedFactRecord

_logger = logging.getLogger(__name__)

# Honest maturity tag for an ATTEMPT fact. The seal is real, live ECDSA-P256 +
# hash-chain crypto (authorship + integrity of "an evaluation was begun"), but
# it proves nothing about what happened after entry, so it is deliberately NOT
# ``PRODUCTION``. Same convention as the M0 decision fact.
_ATTEMPT_MATURITY = EvidenceMaturity.RESEARCH_SOLID


def build_attempt_fact(
    request: EvaluationRequest, policy: PolicySnapshot
) -> SealedFact:
    """Map (request, policy) to a canonical ``SealedFact(ATTEMPT)``.

    Pure (no I/O, no mutation). Derives from the only two objects that exist
    at ``evaluate()`` entry. The ``claim`` is deliberately narrow: an
    evaluation was BEGUN — not that a verdict followed, not that anything is
    correct. ``content_sha256`` mirrors the PDP's own hashing
    (``PolicyDecisionPoint._sha256_hex``) so an auditor can link this fact to
    the eventual DECISION beyond the shared ``request_id`` — a fabricated
    DECISION reusing a request_id over different content breaks the link.

    The ``detail`` MUST NOT grow a ``"verdict"`` key — there is no verdict
    yet, and L3's conservation counts verdict-keyed facts
    (tests/test_decision_fact_contract.py pins this contract).
    """
    return SealedFact(
        kind=SealedFactKind.ATTEMPT,
        subject_id=str(request.request_id),
        claim=(
            f"evaluation begun for request {request.request_id} "
            f"under policy {policy.policy_id}@{policy.version} "
            f"— pre-verdict, sealed at evaluate() entry; bounds (never "
            f"totals) uncounted work; says nothing about the outcome"
        ),
        maturity=_ATTEMPT_MATURITY,
        detail={
            "action_type": request.action_type,
            "policy_id": policy.policy_id,
            "policy_version": policy.version,
            "content_sha256": hashlib.sha256(
                request.content.encode("utf-8")
            ).hexdigest(),
        },
    )


def seal_attempt(
    ledger: SealedFactLedger | None,
    *,
    request: EvaluationRequest,
    policy: PolicySnapshot,
) -> SealedFactRecord | None:
    """Seal one ``ATTEMPT`` fact into ``ledger`` and return its record.

    Fail-closed and observation-only, mirroring ``seal_decision``'s contract
    exactly:
      * ``ledger is None`` → no-op, return ``None`` (today's behaviour,
        zero cost).
      * an append failure is logged and returns ``None`` — it never
        propagates into the request path and the eventual verdict is
        unaffected.
    """
    if ledger is None:
        return None
    try:
        return ledger.append(build_attempt_fact(request, policy))
    except Exception:  # pragma: no cover - defensive; a seal must never break a request
        _logger.warning(
            "ATTEMPT seal failed for request %s; evaluation unaffected, fact not sealed",
            getattr(request, "request_id", "?"),
            exc_info=True,
        )
        return None
