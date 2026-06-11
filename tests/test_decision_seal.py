"""
Wave 2 / M0 — DECISION-sealing seam tests.

Proves the enabling seam six Wave-2 leaps consume:
  * a finalized verdict is sealed as one canonical SealedFact(DECISION),
  * the seal is fail-closed (no ledger → exact no-op) and OBSERVATION-ONLY
    (wiring a ledger never changes the verdict — the monotone-lowering /
    structural-floor safety guard the constitution requires for verdict-path
    changes), and
  * the chain is real (content-bound, linked, signature-verifiable), not theater.
"""

from __future__ import annotations

from tex.domain.verdict import Verdict
from tex.engine.pdp import PolicyDecisionPoint
from tex.provenance.decision_seal import build_decision_fact, seal_decision
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind
from tex.domain.evidence import EvidenceMaturity

from tests.factories import make_default_policy, make_request


# A spread of contents so the seam is exercised across more than one verdict.
_CONTENTS = (
    "Quarterly metrics look healthy; no further action is needed.",
    "Here is our production api key sk-abcdef1234567890abcdef please use it.",
    "I commit on behalf of the company to a full refund for every customer.",
    "Please summarize the attached meeting notes for the team.",
)


def _decide(content: str, *, ledger: SealedFactLedger | None = None):
    pdp = PolicyDecisionPoint(decision_ledger=ledger)
    return pdp.evaluate(request=make_request(content=content), policy=make_default_policy())


# ----------------------------------------------------------------- mapping ----

def test_build_decision_fact_maps_verdict_and_stays_honest() -> None:
    decision = _decide(_CONTENTS[0]).decision
    fact = build_decision_fact(decision)

    assert fact.kind is SealedFactKind.DECISION
    assert fact.subject_id == str(decision.request_id)
    assert fact.detail["verdict"] == decision.verdict.value
    assert fact.detail["final_score"] == decision.final_score
    assert fact.detail["content_sha256"] == decision.content_sha256
    # The fact carries no proof of correctness and must not imply one.
    assert fact.evidence is None
    assert fact.maturity is EvidenceMaturity.RESEARCH_SOLID
    assert "correctness NOT proven" in fact.claim


# ----------------------------------------------------------- fail-closed ------

def test_seal_decision_with_no_ledger_is_a_noop() -> None:
    decision = _decide(_CONTENTS[0]).decision
    assert seal_decision(None, decision) is None


def test_seal_decision_appends_and_chain_and_signatures_verify() -> None:
    decision = _decide(_CONTENTS[0]).decision
    ledger = SealedFactLedger()

    record = seal_decision(ledger, decision)

    assert record is not None
    assert len(ledger) == 1
    assert record.fact.kind is SealedFactKind.DECISION
    assert ledger.verify_chain()["intact"] is True
    assert ledger.verify_signatures()["valid"] is True


# --------------------------------------------------- PDP integration ----------

def test_pdp_seals_one_decision_per_verdict() -> None:
    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(decision_ledger=ledger)
    policy = make_default_policy()

    sealed_verdicts = []
    for content in _CONTENTS:
        result = pdp.evaluate(request=make_request(content=content), policy=policy)
        sealed_verdicts.append(result.decision.verdict.value)

    # Exactly one DECISION fact per evaluate() call, in order, chain intact.
    # (Total ledger length is 2× since the Wave-2 attempt hook also seals one
    # ATTEMPT fact per evaluate() at entry — recomposed consciously here; the
    # DECISION-kind count is the pin this test owns.)
    records = ledger.list_by_kind(SealedFactKind.DECISION)
    assert len(records) == len(_CONTENTS)
    assert len(ledger) == 2 * len(_CONTENTS)
    assert [r.fact.detail["verdict"] for r in records] == sealed_verdicts
    assert ledger.verify_chain()["intact"] is True
    assert ledger.verify_signatures()["valid"] is True
    # The seam really exercises more than one verdict (not a single-branch test).
    assert {Verdict(v) for v in sealed_verdicts} & {Verdict.FORBID, Verdict.ABSTAIN}


# ------------------------------- observation-only (verdict-path safety) -------

def test_sealing_is_observation_only_and_never_changes_the_verdict() -> None:
    """The monotone-lowering / structural-floor guard: wiring the DECISION
    ledger must not move the verdict. If a future edit made the seal mutate the
    decision (e.g. lowered a verdict as a side effect), this fails."""
    for content in _CONTENTS:
        without = _decide(content, ledger=None).decision
        with_ledger = _decide(content, ledger=SealedFactLedger()).decision
        assert with_ledger.verdict is without.verdict
        assert with_ledger.final_score == without.final_score
        assert with_ledger.confidence == without.confidence


# ------------------------------------------------ real chain, not theater -----

def test_chain_is_content_bound_and_linked() -> None:
    ledger = SealedFactLedger()
    first = seal_decision(ledger, _decide(_CONTENTS[0]).decision)
    second = seal_decision(ledger, _decide(_CONTENTS[1]).decision)

    assert first is not None and second is not None
    # Distinct decisions seal distinct payloads...
    assert first.payload_sha256 != second.payload_sha256
    # ...linked into one chain (the second record commits to the first).
    assert second.previous_hash == first.record_hash
    assert first.previous_hash is None
