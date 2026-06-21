"""Fixtures + builders for the L3 habit tests.

Two deliberate choices to keep these tests honest:

1. **Real S5 store, not a mock.** Where a test needs sealed history, it seals real
   ``PresenceVerdict``s into a real ``SealedPresenceMemory`` and mines THAT — so the
   miner is exercised over the same content_payload shape production produces.

2. **A FAITHFUL L2 spec-stub, clearly labelled.** L2's ``tex.presence.profile`` is
   built in a sibling worktree and is NOT in this tree, so we cannot import the real
   ``SealedProfileMemory``. :class:`FakeProfileMemory` re-implements L2's POSTED
   contract (``PROFILE_INTERFACE.md`` v1.0.0) EXACTLY: ``apply_correction`` refuses a
   ``SEALED`` (inflating) tier and an empty operator; ``recall_profile`` returns
   facts whose ``tier_ceiling`` folds corrections with the FROZEN
   :func:`tex.presence.contract.tighten` (never a ``max``). The monotone math under
   test is therefore the real frozen contract's, not a re-implementation — only the
   storage is a stand-in. When L2 is merged, swap this for
   ``build_profile_memory()`` and the assertions hold unchanged.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import pytest

from tex.presence.contract import (
    ClaimKind,
    EvidenceRef,
    PresenceClaim,
    PresenceTier,
    PresenceVerdict,
    tighten,
)
from tex.presence.habits.types import ObservedOutcome, OutcomeDimension, norm_subject
from tex.presence.memory import SealedPresenceMemory


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---- contract-object builders ----------------------------------------------


def make_evref(seed: str, *, store: str = "decision_store") -> EvidenceRef:
    return EvidenceRef(record_id=f"rec-{seed}", record_hash=_sha(seed), store=store, field="verdict")


def make_obs(
    subject: str,
    outcome: str,
    seed: str,
    *,
    dimension: OutcomeDimension = OutcomeDimension.GOVERNANCE_VERDICT,
    at: str = "2026-06-01T00:00:00+00:00",
) -> ObservedOutcome:
    return ObservedOutcome(
        subject_key=norm_subject(subject),
        dimension=dimension,
        outcome_value=outcome.casefold(),
        evidence=make_evref(seed),
        observed_at=at,
    )


def seal_governed(
    mem: SealedPresenceMemory,
    *,
    tenant: str,
    claim_id: str,
    governance_verdict,
    n: int,
    tier: PresenceTier = PresenceTier.SEALED,
) -> None:
    """Seal ``n`` real presence records for ``claim_id`` carrying ``governance_verdict``.

    Each record is distinct (the ``recomputed_value`` varies) so the content anchors
    differ and the miner sees ``n`` genuine observations, not one re-seal.
    """
    from tex.domain.verdict import Verdict

    gv = governance_verdict if isinstance(governance_verdict, Verdict) else Verdict(governance_verdict)
    for i in range(n):
        claim = PresenceClaim(claim_id=claim_id, text_span=f"about {claim_id} #{i}", kind=ClaimKind.AGGREGATE)
        verdict = PresenceVerdict(
            claim_id=claim_id,
            tier=tier,
            evidence=(make_evref(f"{claim_id}-{i}"),),
            recomputed_value=i,  # vary → distinct content anchor per record
            governance_verdict=gv,
            reason="recomputed-from-rows",
        )
        mem.seal(tenant=tenant, claim=claim, verdict=verdict)


# ---- the faithful L2 ProfileMemory spec-stub --------------------------------


@dataclass(frozen=True, slots=True)
class FakeProfileFact:
    record_id: str
    subject_key: str
    corrected_tier: PresenceTier | None
    statement: str
    operator: str
    decision_id: str | None = None

    def as_ref(self) -> EvidenceRef:
        return EvidenceRef(
            record_id=self.record_id,
            record_hash=self.record_id.removeprefix("pf-") or _sha(self.record_id),
            store="presence_profile",
            field=self.subject_key or None,
            prior_link_witness=None,
        )


@dataclass(frozen=True, slots=True)
class FakeProfileFacts:
    tenant: str
    facts: tuple[FakeProfileFact, ...] = ()

    def refs(self) -> tuple[EvidenceRef, ...]:
        return tuple(f.as_ref() for f in self.facts)

    def corrections(self) -> tuple[FakeProfileFact, ...]:
        return tuple(f for f in self.facts if f.corrected_tier is not None)

    def tier_ceiling(self, claim_id: str) -> PresenceTier | None:
        subject = norm_subject(claim_id)
        ceiling: PresenceTier | None = None
        for f in self.corrections():
            if f.subject_key == subject and f.corrected_tier is not None:
                ceiling = f.corrected_tier if ceiling is None else tighten(ceiling, f.corrected_tier)
        return ceiling


class FakeProfileMemory:
    """Faithful re-implementation of L2's POSTED ProfileMemory contract (storage
    only — the monotone math is the frozen contract's ``tighten``). Records every
    write so tests can assert exactly what L3 sent."""

    def __init__(self) -> None:
        self._by_tenant: dict[str, list[FakeProfileFact]] = {}
        self.correction_calls: list[dict] = []
        self.confirm_calls: list[dict] = []

    def apply_correction(
        self,
        *,
        tenant: str,
        claim_id: str,
        corrected_tier: PresenceTier,
        operator: str,
        statement: str = "",
        original_tier: PresenceTier | None = None,
        decision_id: str | None = None,
        believed_value: str | None = None,
    ) -> EvidenceRef:
        # L2's write-gate, faithfully: refuse inflating tier, refuse empty operator.
        if corrected_tier is PresenceTier.SEALED:
            raise ValueError("apply_correction refuses an inflating (SEALED) correction")
        if not operator or not operator.strip():
            raise ValueError("apply_correction requires an operator (provenance before write)")
        if original_tier is not None and tighten(original_tier, corrected_tier) is not corrected_tier:
            raise ValueError("apply_correction: corrected_tier must be strictly more cautious")
        self.correction_calls.append(
            dict(tenant=tenant, claim_id=claim_id, corrected_tier=corrected_tier,
                 operator=operator, statement=statement, decision_id=decision_id)
        )
        subject = norm_subject(claim_id)
        record_id = "pf-" + _sha(f"{tenant}|{subject}|{corrected_tier.value}|{operator}|{statement}")
        fact = FakeProfileFact(
            record_id=record_id, subject_key=subject, corrected_tier=corrected_tier,
            statement=statement, operator=operator, decision_id=decision_id,
        )
        bucket = self._by_tenant.setdefault(tenant, [])
        if all(f.record_id != fact.record_id for f in bucket):
            bucket.append(fact)
        return fact.as_ref()

    def confirm(self, *, tenant, claim_id, tier, operator, statement="", decision_id=None):  # noqa: ANN001
        if not operator or not operator.strip():
            raise ValueError("confirm requires an operator")
        self.confirm_calls.append(dict(tenant=tenant, claim_id=claim_id, tier=tier, operator=operator))
        record_id = "pf-" + _sha(f"confirm|{tenant}|{norm_subject(claim_id)}|{operator}")
        return EvidenceRef(record_id=record_id, record_hash=_sha(record_id), store="presence_profile")

    def recall_profile(self, *, tenant: str, query: str | None = None) -> FakeProfileFacts:
        return FakeProfileFacts(tenant=tenant, facts=tuple(self._by_tenant.get(tenant, ())))

    def revoke(self, *, tenant: str, record_id: str) -> bool:
        bucket = self._by_tenant.get(tenant, [])
        kept = [f for f in bucket if f.record_id != record_id]
        if len(kept) == len(bucket):
            return False
        self._by_tenant[tenant] = kept
        return True


# ---- fixtures ---------------------------------------------------------------


@pytest.fixture
def mem() -> SealedPresenceMemory:
    return SealedPresenceMemory(mirror=None)


@pytest.fixture
def profile() -> FakeProfileMemory:
    return FakeProfileMemory()
