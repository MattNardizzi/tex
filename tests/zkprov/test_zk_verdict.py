"""
Receipts for the ZK proof of the PDP **verdict** over a HIDDEN fused score
(``tex.zkprov.zk_fuse.prove_verdict`` / ``verify_verdict``) — the increment over
``prove_fuse``, which proved the fusion but PUBLISHED ``fused_q``.

What is earned here:
  * **completeness** for every verdict region (PERMIT / ABSTAIN / FORBID) and at
    the ABSTAIN lower boundary (round-half-up exactness);
  * **soundness** — a forged verdict is rejected; a proof verified under
    different thresholds or different weights is rejected; the prover refuses to
    attest a claim false for its private scores; tampered commitments/proofs and
    impossible (empty-region) verdicts are rejected;
  * **hiding (the headline)** — the verifier learns ONLY the verdict and the
    public policy: two witnesses whose fused scores DIFFER but map to the SAME
    verdict both verify, the fused score never appears in the proof bytes, and
    the per-stream commitments differ. This is strictly stronger than the fuse
    proof, where ``fused_q`` was public.

Honest proofs are the cost center (pure-Python 2048-bit modexp), so the real
proofs are module-scoped fixtures reused across the many cheap forgery checks.
"""

from __future__ import annotations

import json

import pytest

from tex.zkprov import zk_fuse as zf

SCALE = 10_000
PERMIT_Q = 3_000
FORBID_Q = 7_000

# Canonical seven-stream order; a two-contributing-stream policy keeps the
# (pure-Python 2048-bit) honest proofs cheap.
NAMES = (
    "deterministic", "specialists", "semantic", "criticality",
    "agent_identity", "agent_capability", "agent_behavioral",
)
WEIGHTS: list[tuple[str, int]] = list(zip(NAMES, [5_000, 5_000, 0, 0, 0, 0, 0]))


def _streams(scores: dict[str, int]) -> list[tuple[str, int, int]]:
    return [(n, w, scores.get(n, 0)) for n, w in WEIGHTS]


def _fused(scores: dict[str, int]) -> int:
    acc = sum(w * scores.get(n, 0) for n, w in WEIGHTS)
    return min(SCALE, max(0, (acc + SCALE // 2) // SCALE))


def _prove(verdict: str, scores: dict[str, int], *, permit_q=PERMIT_Q, forbid_q=FORBID_Q) -> bytes:
    return zf.prove_verdict(
        scale=SCALE, verdict=verdict, permit_q=permit_q, forbid_q=forbid_q,
        streams=_streams(scores),
    )


def _verify(verdict: str, pf: bytes, *, permit_q=PERMIT_Q, forbid_q=FORBID_Q, weights=WEIGHTS) -> bool:
    return zf.verify_verdict(
        scale=SCALE, verdict=verdict, permit_q=permit_q, forbid_q=forbid_q,
        weights=weights, proof_bytes=pf,
    )


# Witnesses: fused = weighted mean of the two scores (both weight 5000).
_PERMIT_A = {"deterministic": 2_000, "specialists": 2_000}   # fused 2000 → PERMIT
_PERMIT_B = {"deterministic": 1_000, "specialists": 1_000}   # fused 1000 → PERMIT (different fused!)
_ABSTAIN = {"deterministic": 5_000, "specialists": 5_000}    # fused 5000 → ABSTAIN
_FORBID = {"deterministic": 8_000, "specialists": 8_000}     # fused 8000 → FORBID


@pytest.fixture(scope="module")
def permit_a() -> bytes:
    assert _fused(_PERMIT_A) == 2_000
    return _prove("PERMIT", _PERMIT_A)


@pytest.fixture(scope="module")
def permit_b() -> bytes:
    assert _fused(_PERMIT_B) == 1_000
    return _prove("PERMIT", _PERMIT_B)


# ── completeness across the three verdict regions ────────────────────────────


def test_permit_completeness(permit_a: bytes) -> None:
    assert _verify("PERMIT", permit_a) is True


def test_abstain_completeness() -> None:
    assert _fused(_ABSTAIN) == 5_000
    assert _verify("ABSTAIN", _prove("ABSTAIN", _ABSTAIN)) is True


def test_forbid_completeness() -> None:
    assert _fused(_FORBID) == 8_000
    assert _verify("FORBID", _prove("FORBID", _FORBID)) is True


def test_abstain_lower_boundary_is_exact() -> None:
    """acc exactly on the ABSTAIN lower bound (permit_hi): fused = permit_q + 1,
    the round-half-up edge. It must verify as ABSTAIN and NOT as PERMIT."""
    scores = {"deterministic": 3_000, "specialists": 3_001}   # fused 3001 → ABSTAIN
    assert _fused(scores) == 3_001
    pf = _prove("ABSTAIN", scores)
    assert _verify("ABSTAIN", pf) is True
    assert _verify("PERMIT", pf) is False   # the boundary belongs to ABSTAIN


# ── soundness: a forged verdict is rejected ──────────────────────────────────


def test_forged_verdict_rejected(permit_a: bytes) -> None:
    """The headline soundness: a PERMIT proof cannot be re-read as any other
    verdict — the verifier derives a different region (and binds the verdict in
    the FS context), so the region range proof fails."""
    assert _verify("ABSTAIN", permit_a) is False
    assert _verify("FORBID", permit_a) is False


def test_prover_refuses_false_verdict() -> None:
    with pytest.raises(zf.FuseProofError):
        _prove("ABSTAIN", _PERMIT_A)   # these scores fuse to PERMIT
    with pytest.raises(zf.FuseProofError):
        _prove("FORBID", _PERMIT_A)


def test_prover_refuses_malformed_thresholds() -> None:
    with pytest.raises(zf.FuseProofError):
        _prove("PERMIT", _PERMIT_A, permit_q=7_000, forbid_q=3_000)  # inverted
    with pytest.raises(zf.FuseProofError):
        zf.prove_verdict(scale=SCALE, verdict="BOGUS", permit_q=PERMIT_Q,
                         forbid_q=FORBID_Q, streams=_streams(_PERMIT_A))


# ── soundness: the verifier uses ITS OWN public policy, not the proof's ───────


def test_verifier_uses_its_own_thresholds(permit_a: bytes) -> None:
    """A proof honest under (3000,7000) must not verify under thresholds for
    which the same hidden fused score would yield a DIFFERENT verdict.
    fused = 2000 is PERMIT under (3000,7000) but FORBID under (1000,2000)."""
    assert _verify("PERMIT", permit_a, permit_q=1_000, forbid_q=2_000) is False


def test_verifier_uses_its_own_weights(permit_a: bytes) -> None:
    other = list(zip(NAMES, [6_000, 4_000, 0, 0, 0, 0, 0]))
    assert _verify("PERMIT", permit_a, weights=other) is False


def test_unknown_verdict_in_verify_is_false(permit_a: bytes) -> None:
    assert _verify("MAYBE", permit_a) is False


def test_empty_region_verdict_is_rejected(permit_a: bytes) -> None:
    """forbid_q = permit_q + 1 leaves NO ABSTAIN band; an ABSTAIN claim is
    impossible and must be rejected (the verify-side empty-region guard)."""
    assert _verify("ABSTAIN", permit_a, permit_q=3_000, forbid_q=3_001) is False


# ── soundness: tampering is rejected ─────────────────────────────────────────


def test_tampered_commitment_and_proof_rejected(permit_a: bytes) -> None:
    doc = json.loads(permit_a)
    doc["streams"][0]["commitment"] = int(doc["streams"][0]["commitment"]) + 1
    assert _verify("PERMIT", bytes(json.dumps(doc), "utf-8")) is False

    doc2 = json.loads(permit_a)
    doc2["streams"] = doc2["streams"][:-1]   # drop a contributing stream
    assert _verify("PERMIT", bytes(json.dumps(doc2), "utf-8")) is False

    assert _verify("PERMIT", b"not-json") is False
    bad_scheme = json.loads(permit_a)
    bad_scheme["scheme"] = "schnorr-fuse-zk-v1"
    assert _verify("PERMIT", bytes(json.dumps(bad_scheme), "utf-8")) is False


# ── hiding: the fused score is NOT revealed (the increment over prove_fuse) ───


def test_distinct_fused_scores_same_verdict_both_verify_and_hide(
    permit_a: bytes, permit_b: bytes
) -> None:
    """Two witnesses with DIFFERENT fused scores (2000 vs 1000) that both yield
    PERMIT each verify under verdict=PERMIT — so the verifier cannot recover the
    fused score from an accepting proof. Their commitments differ, and the
    fused score appears nowhere in the proof bytes."""
    assert _fused(_PERMIT_A) != _fused(_PERMIT_B)
    assert _verify("PERMIT", permit_a) is True
    assert _verify("PERMIT", permit_b) is True

    ca = json.loads(permit_a)["streams"][0]["commitment"]
    cb = json.loads(permit_b)["streams"][0]["commitment"]
    assert ca != cb, "commitments must not leak the score"

    # the proof carries score commitments + range/window proofs only — no
    # fused score, and no opened score: the structured wire has no such field,
    # and verify never receives a fused value (its public inputs are verdict +
    # thresholds + weights). (A substring digit-scan would be meaningless: the
    # 2048-bit commitments contain arbitrary digit runs by chance.)
    doc = json.loads(permit_a)
    assert set(doc) == {"scheme", "streams", "verdict"}
    assert "fused" not in doc and "fused_q" not in doc
    for s in doc["streams"]:
        assert set(s) == {"name", "weight", "commitment", "range"}  # no opened score


def test_verdict_acc_interval_partitions_the_space() -> None:
    """The three regions tile [0, max_acc] with no gap or overlap — the
    structural reason a forged verdict is unprovable."""
    max_acc = ((1 << zf.SCORE_BITS) - 1) * sum(w for _, w in WEIGHTS)
    p_lo, p_hi = zf.verdict_acc_interval("PERMIT", PERMIT_Q, FORBID_Q, SCALE, max_acc)
    a_lo, a_hi = zf.verdict_acc_interval("ABSTAIN", PERMIT_Q, FORBID_Q, SCALE, max_acc)
    f_lo, f_hi = zf.verdict_acc_interval("FORBID", PERMIT_Q, FORBID_Q, SCALE, max_acc)
    assert p_lo == 0
    assert p_hi == a_lo            # PERMIT abuts ABSTAIN
    assert a_hi == f_lo            # ABSTAIN abuts FORBID
    assert f_hi == max_acc + 1     # FORBID covers the rest
    # every acc maps to exactly the region its verdict claims
    for acc in (0, p_hi - 1, a_lo, (a_lo + a_hi) // 2, a_hi - 1, f_lo, max_acc):
        v = zf._verdict_from_acc(acc, PERMIT_Q, FORBID_Q, SCALE)
        lo, hi = zf.verdict_acc_interval(v, PERMIT_Q, FORBID_Q, SCALE, max_acc)
        assert lo <= acc < hi, (acc, v, lo, hi)
