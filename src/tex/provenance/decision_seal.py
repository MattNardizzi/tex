"""
DECISION-sealing seam (Wave 2 / M0) — seal one typed ``SealedFact(DECISION)`` per verdict.

This is the Wave-2 enabling seam. Today the :class:`PolicyDecisionPoint` produces
a ``Decision`` (PERMIT / ABSTAIN / FORBID) but seals *nothing*:
:class:`SealedFactLedger` (``provenance/ledger.py``) exists and is tested, yet no
live runtime path appends a ``DECISION`` fact to it. Six Wave-2 leaps — zkPDP
(L1), negative-knowledge (L3), inter-org interchange (L6), adversary-completeness
(L7), the live e-value spine (L9), and the verdict certificate (L12) — all consume
a *sealed decision*, so they were building on a leaf that was never produced. This
module produces it.

Honesty — the seal proves AUTHORSHIP + INTEGRITY, never CORRECTNESS:
  * The ledger is SHA-256 hash-chained and ECDSA-P256 signed (the live signer).
    The hash **chain** proves integrity (no reordering, deletion, or tamper); the
    per-record **signature** proves authorship (Tex wrote it). Appending a
    ``DECISION`` fact therefore proves Tex produced *this* verdict record and that
    it has not been altered.
  * It does **not** prove the verdict is the *correct* output of the policy — that
    is L1 (zkPDP), a separate leap. The ``claim`` string says so in words so no
    reader over-reads the fact.
  * Maturity is ``RESEARCH_SOLID``: the sealing mechanism is real, live crypto, but
    as a governance fact it is newly wired, not yet CI-benchmarked as a production
    default, and carries no e-value proof of correctness. (Same convention the
    drift e-process adapter uses for a real-but-unbenchmarked fact.)

Fail-closed to today's behaviour, observation-only:
  * When no ledger is wired (``ledger is None``) ``seal_decision`` is a zero-cost
    no-op and returns ``None`` — the verdict path is byte-for-byte unchanged.
  * Sealing never alters the verdict (the ``Decision`` is already final) and never
    raises into the request path: an append failure is logged and degrades to
    "not sealed", never to a failed request.
"""

from __future__ import annotations

import logging

from tex.domain.abstention_certificate import AbstentionCertificate
from tex.domain.decision import Decision
from tex.domain.evidence import EvidenceMaturity
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind, SealedFactRecord

_logger = logging.getLogger(__name__)

# Honest maturity tag for a DECISION fact. The seal is real, live ECDSA-P256 +
# hash-chain crypto (authorship + integrity), but the fact carries no proof of
# verdict CORRECTNESS, so it is deliberately NOT ``PRODUCTION``. See the module
# docstring and L1 (zkPDP), which is the leap that would earn a correctness proof.
_DECISION_MATURITY = EvidenceMaturity.RESEARCH_SOLID


def build_decision_fact(
    decision: Decision,
    *,
    abstention_certificate: AbstentionCertificate | None = None,
) -> SealedFact:
    """Map a finalized :class:`Decision` to a canonical ``SealedFact(DECISION)``.

    Pure (no I/O, no mutation). The ``claim`` is deliberately narrow: it asserts
    only that the verdict was *produced* and that authorship + integrity are
    sealed — never that the verdict is correct.

    When ``abstention_certificate`` is supplied (an ABSTAIN verdict), its full
    descriptive payload is folded into the SAME fact's ``detail`` so it is
    hash-chained and signed *alongside the verdict* — one tamper-evident record,
    not a second fact (which would perturb the ATTEMPT→DECISION kind sequence
    consumers depend on). The certificate is descriptive only; sealing it adds
    no correctness claim.
    """
    verdict = decision.verdict.value
    detail = {
        "verdict": verdict,
        "final_score": decision.final_score,
        "confidence": decision.confidence,
        "action_type": decision.action_type,
        "policy_id": decision.policy_id,
        "policy_version": decision.policy_version,
        "content_sha256": decision.content_sha256,
        "determinism_fingerprint": decision.determinism_fingerprint,
    }
    claim = (
        f"verdict {verdict} produced for request {decision.request_id} "
        f"under policy {decision.policy_id}@{decision.policy_version} "
        f"— authorship+integrity sealed; correctness NOT proven (see L1 zkPDP)"
    )
    if abstention_certificate is not None:
        detail["abstention_certificate"] = abstention_certificate.model_dump(mode="json")
        claim += " — abstention certificate (descriptive) sealed alongside"
    return SealedFact(
        kind=SealedFactKind.DECISION,
        subject_id=str(decision.request_id),
        claim=claim,
        maturity=_DECISION_MATURITY,
        detail=detail,
    )


def seal_decision(
    ledger: SealedFactLedger | None,
    decision: Decision,
    *,
    abstention_certificate: AbstentionCertificate | None = None,
) -> SealedFactRecord | None:
    """Seal one ``DECISION`` fact into ``ledger`` and return its PCVR.

    Fail-closed and observation-only:
      * ``ledger is None`` → no-op, return ``None`` (today's behaviour, zero cost).
      * an append failure is logged and returns ``None`` — it never propagates
        into the verdict path (the verdict is already final and is unaffected).

    ``abstention_certificate`` (when the verdict is ABSTAIN) is folded into the
    sealed DECISION fact so the receipt is sealed alongside the verdict.
    """
    if ledger is None:
        return None
    try:
        return ledger.append(
            build_decision_fact(
                decision, abstention_certificate=abstention_certificate
            )
        )
    except Exception:  # pragma: no cover - defensive; a seal must never break a verdict
        _logger.warning(
            "DECISION seal failed for request %s; verdict unaffected, fact not sealed",
            getattr(decision, "request_id", "?"),
            exc_info=True,
        )
        return None
