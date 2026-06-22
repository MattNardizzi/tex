"""The presence-hold → Decision producer (presence/s9-calibration follow-up).

``raise_presence_hold`` now, when a ``decision_store`` is wired, persists an HONEST
presence-origin ABSTAIN ``Decision`` and stamps its ``decision_id`` onto the
``HeldDecision`` so the ``/held`` card is SEALABLE end-to-end. These unit tests pin
that producer in isolation (real stores, no app):

  * it persists a presence-origin ABSTAIN Decision with NO fabricated risk score
    (``final_score=0.0`` + ``presence_calibration_eligible=False``) and stamps its id;
  * without a store it degrades to the pre-producer behaviour (``decision_id=None``);
  * a store that raises on ``save`` never breaks the hold (voice safety).
"""

from __future__ import annotations

from uuid import UUID

from tex.domain.verdict import Verdict
from tex.presence.contract import ClaimKind, PresenceClaim, PresenceTier, PresenceVerdict
from tex.presence.gate.compose import raise_presence_hold
from tex.presence.gate.gate import ClaimEvaluation, RoutedClaim
from tex.provenance.feed import HeldDecisionSink
from tex.stores.decision_store import InMemoryDecisionStore


def _abstain_detail() -> tuple[ClaimEvaluation, ...]:
    """One ABSTAIN claim evaluation — the answer-level-abstain input to the producer."""
    claim = PresenceClaim("meaning_of_life", "42", ClaimKind.AGGREGATE)
    verdict = PresenceVerdict(
        claim_id="meaning_of_life", tier=PresenceTier.ABSTAIN, reason="no-matching-query"
    )
    return (ClaimEvaluation(claim, verdict, None, RoutedClaim(None, None, "no-matching-query")),)


def test_producer_persists_decision_and_stamps_decision_id():
    sink = HeldDecisionSink()
    store = InMemoryDecisionStore()

    hold = raise_presence_hold(
        sink, _abstain_detail(), transcript="what is the meaning of life?", decision_store=store
    )

    # The hold is stamped → the /held card is sealable.
    assert hold is not None
    assert hold.decision_id is not None
    assert sink.peek()[0].decision_id == hold.decision_id
    assert hold.detail["dimension"] == "presence"  # provenance marker preserved
    assert hold.kind == "presence_abstain"

    # The persisted Decision is an HONEST presence-origin ABSTAIN — no fake score.
    assert len(store) == 1
    d = store.get(UUID(hold.decision_id))
    assert d is not None
    assert d.verdict is Verdict.ABSTAIN
    assert d.final_score == 0.0  # NO fused risk computed
    assert d.confidence == 0.0
    assert d.metadata["dimension"] == "presence"
    assert d.metadata["presence_kind"] == "answer_abstain"
    assert d.metadata["presence_calibration_eligible"] is False
    assert d.metadata["abstained_claim_ids"] == ["meaning_of_life"]
    assert "presence_ungrounded_no_fused_risk" in d.uncertainty_flags


def test_producer_inert_without_store_backward_compat():
    """No decision_store (legacy / bare test double) ⇒ the pre-producer behaviour:
    a single hold with decision_id=None. Nothing about the voice path changes."""
    sink = HeldDecisionSink()

    hold = raise_presence_hold(sink, _abstain_detail(), transcript="q?")

    assert hold is not None
    assert hold.decision_id is None
    assert len(sink) == 1
    assert hold.detail["dimension"] == "presence"


def test_producer_survives_a_failing_store():
    """A store whose ``save`` raises (e.g. Postgres unreachable) must NOT break the
    hold — the producer degrades to an unsealable card, the voice path is unaffected."""

    class _BoomStore:
        def save(self, decision):  # noqa: ARG002
            raise RuntimeError("db down")

    sink = HeldDecisionSink()
    hold = raise_presence_hold(
        sink, _abstain_detail(), transcript="q?", decision_store=_BoomStore()
    )

    assert hold is not None
    assert hold.decision_id is None  # degraded: not sealable, but the hold still surfaced
    assert len(sink) == 1
