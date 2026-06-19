"""Tests for sealing the ``DecoderConstraint`` (the proof-carrying moat move)."""

from __future__ import annotations

import pytest

from tex.domain.agent import CapabilitySurface
from tex.emission.constraint import compile_constraint
from tex.emission.seal import (
    APPROACH_PROVIDER_TRUSTED,
    APPROACH_TEX_ENFORCED,
    build_constraint_fact,
    seal_constraint,
)
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind


def _constraint():
    return compile_constraint(CapabilitySurface(allowed_tools=["send_email", "http_get"]))


def test_fact_carries_stable_digest_and_narrow_claim() -> None:
    c = _constraint()
    fact = build_constraint_fact(
        c, subject_id="req-1", approach=APPROACH_TEX_ENFORCED, agent_id="agent-7"
    )
    assert fact.kind == SealedFactKind.ENFORCEMENT
    assert fact.detail["constraint_digest"] == c.digest()
    assert fact.detail["approach"] == APPROACH_TEX_ENFORCED
    assert fact.detail["allowed_tool_names"] == ["http_get", "send_email"]
    # The claim is narrow: it never asserts sampler-effectiveness or intent.
    assert "correctness" not in fact.claim.lower() or "NOT" in fact.claim
    assert "NOT judged" in fact.claim
    assert c.digest()[:12] in fact.claim


def test_digest_in_fact_is_reproducible() -> None:
    # Same surface -> byte-identical digest in the sealed fact (replayability).
    f1 = build_constraint_fact(_constraint(), subject_id="r", approach=APPROACH_TEX_ENFORCED)
    f2 = build_constraint_fact(_constraint(), subject_id="r", approach=APPROACH_TEX_ENFORCED)
    assert f1.detail["constraint_digest"] == f2.detail["constraint_digest"]


def test_seal_is_chain_and_signature_verifiable() -> None:
    ledger = SealedFactLedger()
    c = _constraint()
    rec = seal_constraint(
        ledger, c, subject_id="req-9", approach=APPROACH_PROVIDER_TRUSTED, agent_id="a1"
    )
    assert rec is not None
    # Seal a second, different constraint so the chain has real links.
    other = compile_constraint(CapabilitySurface(allowed_tools=["only_one"]))
    seal_constraint(ledger, other, subject_id="req-10", approach=APPROACH_TEX_ENFORCED)

    chain = ledger.verify_chain()
    assert chain["intact"] is True
    assert chain["checked"] == 2

    sigs = ledger.verify_signatures()
    assert sigs["valid"] is True
    assert sigs["checked"] == 2

    # The sealed record carries the same digest the constraint produces — the
    # offline-verifiable link from "what was masked" to the signed chain.
    assert rec.fact.detail["constraint_digest"] == c.digest()


def test_seal_with_no_ledger_is_noop() -> None:
    assert (
        seal_constraint(
            None, _constraint(), subject_id="r", approach=APPROACH_TEX_ENFORCED
        )
        is None
    )


def test_invalid_approach_rejected() -> None:
    with pytest.raises(ValueError, match="approach must be"):
        build_constraint_fact(_constraint(), subject_id="r", approach="hand-wave")
