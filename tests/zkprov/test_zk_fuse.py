"""
Receipts for the ZK proof of the PDP decision-relation FUSE kernel
(``tex.zkprov.zk_fuse``) — the defensible L1 novelty.

What is earned here:
  * **completeness** across all three rounding cases (mid / low-clamp /
    high-clamp) and the zero-weight-skip;
  * **soundness** — a forged ``fused_q`` is rejected by the verifier, and the
    prover refuses to attest a statement that is false for its private scores;
    tampered commitments / proofs are rejected;
  * **hiding** — two DIFFERENT private witnesses that fuse to the SAME public
    ``fused_q`` both verify, and their commitments differ, so the verifier
    learns nothing about the individual scores;
  * the verifier never needs the private scores (public ``(scale, fused_q,
    weights)`` + the proof suffice), and uses the public weights it is given,
    not weights taken from the proof.

These honest proofs are the cost center (pure-Python 2048-bit modexp), so the
suite uses a small number of real proofs and many cheap forgery checks.
"""

from __future__ import annotations

import json

import pytest

from tex.zkprov import zk_fuse as zf

SCALE = 10_000
NAMES = (
    "deterministic", "specialists", "semantic", "criticality",
    "agent_identity", "agent_capability", "agent_behavioral",
)


def _fuse(weights: list[tuple[str, int]], scores: dict[str, int]) -> int:
    acc = sum(w * scores.get(n, 0) for n, w in weights)
    return min(SCALE, max(0, (acc + SCALE // 2) // SCALE))


def _weights(vals: list[int]) -> list[tuple[str, int]]:
    return list(zip(NAMES, vals))


def _streams(weights: list[tuple[str, int]], scores: dict[str, int]) -> list[tuple[str, int, int]]:
    return [(n, w, scores.get(n, 0)) for n, w in weights]


# A four-contributing-stream policy (three agent streams renormalized to 0),
# the cheap honest-proof fixture.
_W4 = _weights([2500, 2500, 2500, 2500, 0, 0, 0])
_W4 = [(n, w) for n, w in _W4]
_W4[0] = (_W4[0][0], _W4[0][1] + (SCALE - sum(w for _, w in _W4)))


def _prove(scores: dict[str, int], weights=_W4):
    fq = _fuse(weights, scores)
    pf = zf.prove_fuse(scale=SCALE, fused_q=fq, streams=_streams(weights, scores))
    return fq, pf


# ── completeness across the rounding cases ───────────────────────────────────


def test_mid_case_completeness() -> None:
    scores = {"deterministic": 2000, "specialists": 8000, "semantic": 1000, "criticality": 3000}
    fq, pf = _prove(scores)
    assert 0 < fq < SCALE
    assert zf.verify_fuse(scale=SCALE, fused_q=fq, weights=_W4, proof_bytes=pf)


def test_low_clamp_completeness() -> None:
    fq, pf = _prove({n: 0 for n, _ in _W4})
    assert fq == 0
    assert zf.verify_fuse(scale=SCALE, fused_q=fq, weights=_W4, proof_bytes=pf)


def test_high_clamp_completeness() -> None:
    fq, pf = _prove({n: SCALE for n, _ in _W4})
    assert fq == SCALE
    assert zf.verify_fuse(scale=SCALE, fused_q=fq, weights=_W4, proof_bytes=pf)


def test_zero_weight_streams_are_skipped() -> None:
    scores = {"deterministic": 4000, "specialists": 4000, "semantic": 4000,
              "criticality": 4000, "agent_identity": 9999}  # weight-0 stream
    fq, pf = _prove(scores)
    # only the four weight>0 streams are committed.
    assert len(json.loads(pf)["streams"]) == 4
    assert zf.verify_fuse(scale=SCALE, fused_q=fq, weights=_W4, proof_bytes=pf)


# ── soundness ────────────────────────────────────────────────────────────────


def test_verifier_rejects_every_forged_fused_q() -> None:
    """The headline: the proof binds the public verdict-score to the private
    scores. Re-claiming any OTHER fused_q for the same proof is rejected (these
    verifies fail fast — the changed public context breaks the FS challenges)."""
    scores = {"deterministic": 2000, "specialists": 8000, "semantic": 1000, "criticality": 3000}
    fq, pf = _prove(scores)
    for wrong in (fq - 1, fq + 1, 0, SCALE, fq // 2, min(SCALE, fq + 500)):
        if wrong == fq or not (0 <= wrong <= SCALE):
            continue
        assert zf.verify_fuse(scale=SCALE, fused_q=wrong, weights=_W4, proof_bytes=pf) is False


def test_prover_refuses_a_false_statement() -> None:
    scores = {"deterministic": 2000, "specialists": 8000, "semantic": 1000, "criticality": 3000}
    fq = _fuse(_W4, scores)
    with pytest.raises(zf.FuseProofError):
        zf.prove_fuse(scale=SCALE, fused_q=fq + 1, streams=_streams(_W4, scores))
    with pytest.raises(zf.FuseProofError):
        zf.prove_fuse(scale=SCALE, fused_q=fq - 1, streams=_streams(_W4, scores))


def test_verifier_rejects_tampered_commitment_and_proof() -> None:
    scores = {"deterministic": 2000, "specialists": 8000, "semantic": 1000, "criticality": 3000}
    fq, pf = _prove(scores)
    doc = json.loads(pf)
    # bump a score commitment
    doc["streams"][0]["commitment"] = int(doc["streams"][0]["commitment"]) + 1
    assert zf.verify_fuse(scale=SCALE, fused_q=fq, weights=_W4, proof_bytes=bytes(json.dumps(doc), "utf-8")) is False
    # drop a contributing stream (verifier requires all weight>0 streams)
    doc2 = json.loads(pf)
    doc2["streams"] = doc2["streams"][:-1]
    assert zf.verify_fuse(scale=SCALE, fused_q=fq, weights=_W4, proof_bytes=bytes(json.dumps(doc2), "utf-8")) is False
    # garbage / wrong scheme
    assert zf.verify_fuse(scale=SCALE, fused_q=fq, weights=_W4, proof_bytes=b"not-json") is False


def test_verifier_uses_its_own_weights_not_the_proofs() -> None:
    """A proof made under one weight vector must not verify under another."""
    scores = {"deterministic": 2000, "specialists": 8000, "semantic": 1000, "criticality": 3000}
    fq, pf = _prove(scores)
    other = _weights([4000, 2000, 2000, 2000, 0, 0, 0])
    other[0] = (other[0][0], other[0][1] + (SCALE - sum(w for _, w in other)))
    assert zf.verify_fuse(scale=SCALE, fused_q=fq, weights=other, proof_bytes=pf) is False


# ── hiding: the zero-knowledge property ──────────────────────────────────────


def test_distinct_witnesses_same_verdict_both_verify_and_hide() -> None:
    """Two different private score vectors that fuse to the SAME public
    ``fused_q`` both produce verifying proofs, and their commitments differ —
    so the verifier cannot recover which witness was used."""
    a = {"deterministic": 4000, "specialists": 6000, "semantic": 0, "criticality": 0}
    b = {"deterministic": 6000, "specialists": 4000, "semantic": 0, "criticality": 0}
    fqa, pfa = _prove(a)
    fqb, pfb = _prove(b)
    assert fqa == fqb  # same public verdict-score
    assert zf.verify_fuse(scale=SCALE, fused_q=fqa, weights=_W4, proof_bytes=pfa)
    assert zf.verify_fuse(scale=SCALE, fused_q=fqb, weights=_W4, proof_bytes=pfb)
    ca = json.loads(pfa)["streams"][0]["commitment"]
    cb = json.loads(pfb)["streams"][0]["commitment"]
    assert ca != cb, "commitments leak the score"
