"""Shared fixtures + builders for the presence PROFILE tests.

Builds real contract objects + a real SealedProfileMemory — never a mock of the
unit under test.
"""

from __future__ import annotations

import hashlib

import pytest

from tex.presence.contract import (
    ClaimKind,
    EvidenceRef,
    PresenceClaim,
    PresenceTier,
    PresenceVerdict,
)
from tex.presence.profile import SealedProfileMemory
from tex.presence.profile.records import SealedProfileFact


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_evref(seed: str) -> EvidenceRef:
    return EvidenceRef(
        record_id=f"rec-{seed}", record_hash=_sha(seed), store="decision_store", field="verdict"
    )


def make_verdict(
    claim_id: str = "forbid_count",
    *,
    tier: PresenceTier = PresenceTier.SEALED,
    value=3,
    n_evidence: int = 1,
    correctness_floor: float | None = None,
    coverage_mode: str | None = None,
    reason: str = "recomputed-from-rows",
) -> PresenceVerdict:
    """A contract PresenceVerdict the gate could have emitted. SEALED/DERIVED carry
    evidence; ABSTAIN carries none (contract: evidence empty iff ABSTAIN)."""
    if tier is PresenceTier.ABSTAIN:
        evidence: tuple[EvidenceRef, ...] = ()
    else:
        evidence = tuple(make_evref(f"{claim_id}-{i}") for i in range(n_evidence))
    return PresenceVerdict(
        claim_id=claim_id,
        tier=tier,
        evidence=evidence,
        recomputed_value=value if tier is not PresenceTier.ABSTAIN else None,
        correctness_floor=correctness_floor if tier is PresenceTier.DERIVED else None,
        coverage_mode=coverage_mode if tier is PresenceTier.DERIVED else None,
        reason=reason,
    )


def make_claim(claim_id: str = "forbid_count", kind: ClaimKind = ClaimKind.AGGREGATE) -> PresenceClaim:
    return PresenceClaim(claim_id=claim_id, text_span=f"how many {claim_id}", kind=kind)


# ---- fake durable mirrors (durability / forget-soundness tests) ------------


class CountingMirror:
    is_durable = True

    def __init__(self, rowcount: int = 1) -> None:
        self._rowcount = rowcount
        self.deletes: list[tuple[str, str]] = []
        self.upserts: list[str] = []

    def list_for_tenant(self, tenant):  # noqa: ANN001
        return ()

    def upsert(self, fact: SealedProfileFact) -> None:
        self.upserts.append(fact.record_id)

    def delete(self, *, tenant: str, record_id: str) -> int:
        self.deletes.append((tenant, record_id))
        return self._rowcount


class RaisingMirror:
    is_durable = True

    def list_for_tenant(self, tenant):  # noqa: ANN001
        return ()

    def upsert(self, fact: SealedProfileFact) -> None:
        pass

    def delete(self, *, tenant: str, record_id: str) -> int:
        raise RuntimeError("postgres unreachable")


# ---- fixtures --------------------------------------------------------------


@pytest.fixture
def profile() -> SealedProfileMemory:
    """A pure in-memory authoritative profile store (no durable mirror)."""
    return SealedProfileMemory(mirror=None)
