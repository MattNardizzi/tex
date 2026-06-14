"""
Wave 3 / L1 — the arbiter with the first REAL (non-shim) backend.

This is the receipt for "L1 reaches *green* without the shim crutch":
  * a ``schnorr-fuse-zk-v1`` arbitration proof verifies with
    ``is_valid=True``, ``stand_in=False`` and ``regulator_grade=True``, and —
    unlike the keyed-hash stand-in — it does so with NO ``TEX_ZKPDP_ALLOW_SHIM``;
  * the fail-closed shim hard-gate is unchanged: the stand-in is still refused
    by default, so promoting the real backend did not weaken it;
  * soundness rides through the arbiter: a flipped verdict and a forged
    ``fused_q`` are both rejected, and the structural short-circuit path (which
    has no fuse) is refused by the real backend rather than faked.

Only weight>0 streams are committed, so these statements use a four-stream
policy to keep the (pure-Python 2048-bit) honest proofs cheap.
"""

from __future__ import annotations

import os
from dataclasses import replace

import pytest

from tex.domain.verdict import Verdict
from tex.zkprov.backends import ProofBackendId, is_regulator_grade
from tex.zkprov.zk_fuse import FuseProofError
from tex.zkpdp.arbiter import (
    SCALE,
    STREAM_NAMES,
    ArbitrationStatement,
    canonical_fuse,
    evaluate_relation,
    expected_claimed_verdict,
    prove_arbitration,
    verify_arbitration,
)

_REAL = ProofBackendId.SCHNORR_FUSE_ZK_V1
_P, _A, _F = Verdict.PERMIT.value, Verdict.ABSTAIN.value, Verdict.FORBID.value


def _four_stream_weights() -> tuple[tuple[str, int], ...]:
    vals = [2500, 2500, 2500, 2500, 0, 0, 0]
    vals[0] += SCALE - sum(vals)
    return tuple(zip(STREAM_NAMES, vals))


def _mk(scores: tuple[int, ...], *, permit_q: int = 3000, forbid_q: int = 7000) -> ArbitrationStatement:
    weights = _four_stream_weights()
    ssq = tuple(zip(STREAM_NAMES, scores))
    fused = canonical_fuse(ssq, weights)
    stmt = ArbitrationStatement(
        stream_scores_q=ssq, weights_q=weights, fused_q=fused,
        permit_q=permit_q, forbid_q=forbid_q, router_skipped=False,
        deny_floor=False, floor_sources=(), quarantine_pin=False, chain=(),
        claimed_verdict="PLACEHOLDER", request_id="req-zk",
        policy_id="default", policy_version="v",
        content_sha256="0" * 64, determinism_fingerprint="f" * 64,
    )
    return replace(stmt, claimed_verdict=expected_claimed_verdict(stmt))


@pytest.fixture(scope="module")
def permit_stmt() -> ArbitrationStatement:
    # fused ≈ 2000 → PERMIT; a mid-case fuse-path statement.
    stmt = _mk((2000, 2000, 2000, 2000, 0, 0, 0))
    assert stmt.claimed_verdict == _P
    assert evaluate_relation(stmt).satisfied
    return stmt


# ── the headline: a real backend reaches green, no shim flag ────────────────


def test_real_backend_verifies_green_without_shim_flag(
    permit_stmt: ArbitrationStatement, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TEX_ZKPDP_ALLOW_SHIM", raising=False)
    env = prove_arbitration(permit_stmt, backend_id=_REAL)
    assert env.backend == _REAL.value

    res = verify_arbitration(permit_stmt, env)
    assert res.is_valid is True, res.reason
    assert res.stand_in is False          # NOT the keyed-hash stand-in
    assert res.regulator_grade is True    # the non-shim real-proof tier
    assert res.relation is not None and res.relation.satisfied
    assert "schnorr-fuse-zk-v1" in res.note and "research-early" in res.note


def test_real_backend_is_not_shim_gated(
    permit_stmt: ArbitrationStatement, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real path must verify identically with the shim flag ON or OFF — it
    never touches the stand-in gate."""
    env = prove_arbitration(permit_stmt, backend_id=_REAL)
    monkeypatch.delenv("TEX_ZKPDP_ALLOW_SHIM", raising=False)
    off = verify_arbitration(permit_stmt, env)
    monkeypatch.setenv("TEX_ZKPDP_ALLOW_SHIM", "1")
    on = verify_arbitration(permit_stmt, env)
    assert off.is_valid is on.is_valid is True
    assert off.stand_in is on.stand_in is False


def test_tier_membership_is_honest() -> None:
    assert is_regulator_grade(_REAL) is True
    assert is_regulator_grade(ProofBackendId.DETERMINISTIC_SHIM_V1) is False


# ── the shim hard-gate is unchanged (promoting the real backend didn't weaken it)


def test_shim_still_hard_gated_after_real_backend_added(
    permit_stmt: ArbitrationStatement, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEX_ZKPDP_ALLOW_SHIM", "1")
    shim_env = prove_arbitration(permit_stmt)  # default = stand-in
    monkeypatch.delenv("TEX_ZKPDP_ALLOW_SHIM", raising=False)
    res = verify_arbitration(permit_stmt, shim_env)
    assert res.is_valid is False
    assert res.reason == "zkpdp_shim_not_a_real_proof"
    assert res.stand_in is True


# ── soundness rides through the arbiter ──────────────────────────────────────


def test_flipped_verdict_rejected_with_real_backend(
    permit_stmt: ArbitrationStatement,
) -> None:
    env = prove_arbitration(permit_stmt, backend_id=_REAL)
    for wrong in (_A, _F):
        flipped = replace(permit_stmt, claimed_verdict=wrong)
        res = verify_arbitration(flipped, env)
        assert res.is_valid is False
        # the statement digest no longer matches the envelope (binding), and the
        # flipped relation is UNSAT besides — either way, fail-closed.
        assert res.reason is not None


def test_prover_refuses_forged_fused_q() -> None:
    stmt = _mk((2000, 2000, 2000, 2000, 0, 0, 0))
    forged = replace(stmt, fused_q=stmt.fused_q + 1000)
    with pytest.raises((FuseProofError, ValueError)):
        prove_arbitration(forged, backend_id=_REAL)


def test_router_skipped_statement_is_refused_not_faked() -> None:
    """The structural short-circuit (deny-floor) path has no fuse: the real
    backend refuses to mint a proof rather than fabricate one."""
    base = _mk((2000, 2000, 2000, 2000, 0, 0, 0))
    rs = replace(
        base, router_skipped=True, deny_floor=True,
        floor_sources=("structural_specialist_deny",), fused_q=SCALE,
        claimed_verdict=_F,
    )
    assert evaluate_relation(rs).satisfied, evaluate_relation(rs).violations
    with pytest.raises(FuseProofError):
        prove_arbitration(rs, backend_id=_REAL)
