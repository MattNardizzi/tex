"""Shared fixtures + builders for the presence-memory tests.

Builds real contract objects (PresenceClaim/PresenceVerdict/EvidenceRef) and a
real SealedPresenceMemory — never a mock of the unit under test.
"""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from uuid import uuid4

import pytest

from tex.domain.decision import Decision
from tex.domain.verdict import Verdict
from tex.presence.contract import (
    ClaimKind,
    EvidenceRef,
    PresenceClaim,
    PresenceTier,
    PresenceVerdict,
)
from tex.presence.memory import (
    PresenceCalibrationFeed,
    SealedPresenceMemory,
)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_evref(seed: str) -> EvidenceRef:
    return EvidenceRef(
        record_id=f"rec-{seed}",
        record_hash=_sha(seed),
        store="decision_store",
        field="verdict",
    )


def make_claim_verdict(
    claim_id: str = "forbid_count",
    *,
    tier: PresenceTier = PresenceTier.SEALED,
    kind: ClaimKind = ClaimKind.AGGREGATE,
    value=3,
    text_span: str | None = None,
    n_evidence: int = 1,
    reason: str = "recomputed-from-rows",
    correctness_floor: float | None = None,
    coverage_mode: str | None = None,
) -> tuple[PresenceClaim, PresenceVerdict]:
    """A bound (claim, verdict) the gate could have emitted. SEALED/DERIVED carry
    evidence; build an ABSTAIN one with :func:`make_abstain` instead."""
    evidence = tuple(make_evref(f"{claim_id}-{i}") for i in range(n_evidence))
    claim = PresenceClaim(
        claim_id=claim_id,
        text_span=text_span or f"how many {claim_id.replace('_', ' ')}",
        kind=kind,
    )
    verdict = PresenceVerdict(
        claim_id=claim_id,
        tier=tier,
        evidence=evidence,
        recomputed_value=value,
        correctness_floor=correctness_floor,
        coverage_mode=coverage_mode,
        reason=reason,
    )
    return claim, verdict


def make_abstain(claim_id: str = "unknown") -> tuple[PresenceClaim, PresenceVerdict]:
    claim = PresenceClaim(claim_id, f"text {claim_id}", ClaimKind.ENTITY)
    verdict = PresenceVerdict(claim_id=claim_id, tier=PresenceTier.ABSTAIN, reason="ungrounded")
    return claim, verdict


def make_decision(*, final_score: float, verdict: Verdict = Verdict.FORBID, n: int = 0) -> Decision:
    flags = ["needs_human"] if verdict is Verdict.ABSTAIN else []
    return Decision(
        request_id=uuid4(),
        verdict=verdict,
        confidence=0.9,
        final_score=final_score,
        action_type="send_email",
        channel="email",
        environment="prod",
        content_excerpt=f"decision {n}",
        content_sha256=_sha(f"dec-{n}-{final_score}"),
        policy_version="v1",
        uncertainty_flags=flags,
    )


# ---- fake psycopg connection (for the durable / substrate-SQL tests) --------


class FakeCursor:
    def __init__(self, rows=(), rowcount: int | None = None) -> None:
        self.executed: list[tuple] = []
        self._rows = list(rows)
        self.rowcount = rowcount if rowcount is not None else len(self._rows)

    def execute(self, sql, params=None):  # noqa: ANN001
        self.executed.append((sql, params))

    def fetchall(self):
        return list(self._rows)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeConn:
    def __init__(self, cur: FakeCursor) -> None:
        self._cur = cur

    def cursor(self):
        return self._cur

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def fake_connect_factory(cur: FakeCursor):
    @contextmanager
    def _connect():
        yield FakeConn(cur)

    return _connect


# ---- fixtures --------------------------------------------------------------


@pytest.fixture
def mem() -> SealedPresenceMemory:
    """A pure in-memory authoritative store (no durable mirror)."""
    return SealedPresenceMemory(mirror=None)


@pytest.fixture
def feed(tmp_path) -> PresenceCalibrationFeed:
    return PresenceCalibrationFeed(base_dir=str(tmp_path / "calib"))
