"""
Wave 2 / L1 — zkPDP arbiter tests: the receipts for the narrow claim.

What is earned here (and only this):
  * N=10k differential — the verifier accepts iff the claimed verdict equals
    what the arbitration relation yields from the committed inputs, with
    **exactly 0 acceptances on flipped verdicts** (the headline), including
    against a malicious prover holding the shim's dev key.
  * Hard-gate regression — the keyed-hash stand-in is invalid-by-default with
    the named reason ``zkpdp_shim_not_a_real_proof``; the tests-only env flag
    round-trips it; it is never regulator-grade, never called a proof.
  * Fail-closed sealed-decision binding — absent/empty ledger is "not_sealed"
    (a normal state), never a raise, never a tamper claim.
  * Live-PDP cross-check — statements built from real PolicyDecisionPoint
    decisions are relation-satisfiable with claimed == live verdict.
  * The real-prover number is NOT faked: the wired Halo2 backend raises
    BackendUnavailable today (circuit artifact out-of-tree — M0c). That
    blocker is pinned, labeled RUNTIME-DEPENDENT, not worked around.
"""

from __future__ import annotations

import random
from dataclasses import replace

import pytest

from tex.agent.behavioral_evaluator import neutral_behavioral_signal
from tex.agent.capability_evaluator import neutral_capability_signal
from tex.agent.identity_evaluator import neutral_identity_signal
from tex.domain.agent_signal import AgentEvaluationBundle
from tex.domain.verdict import Verdict
from tex.engine.pdp import PolicyDecisionPoint
from tex.provenance.ledger import SealedFactLedger
from tex.zkprov.backends import (
    BackendUnavailable,
    DeterministicShimBackend,
    ProofBackendId,
    is_regulator_grade,
)
from tex.zkpdp.arbiter import (
    ArbitrationEnvelope,
    ArbitrationStatement,
    ArbitrationUnprovable,
    LoweringStep,
    SCALE,
    SHIM_GATE_REASON,
    STREAM_NAMES,
    base_verdict,
    build_statement_from_decision,
    canonical_fuse,
    check_seal_binding,
    evaluate_relation,
    expected_claimed_verdict,
    prove_arbitration,
    quantize,
    verify_arbitration,
)

from tests.factories import (
    CLEAN_CONTENT,
    COMMITMENT_CONTENT,
    DESTRUCTIVE_CONTENT,
    PII_CONTENT,
    SECRET_LEAK_CONTENT,
    make_default_policy,
    make_request,
    make_semantic_analysis,
)

_P, _A, _F = Verdict.PERMIT.value, Verdict.ABSTAIN.value, Verdict.FORBID.value


# ── helpers ──────────────────────────────────────────────────────────────────


def _equal_weights() -> tuple[tuple[str, int], ...]:
    base = SCALE // 7
    weights = [base] * 7
    weights[0] += SCALE - base * 7
    return tuple(zip(STREAM_NAMES, weights))


def _mk_statement(
    *,
    scores: tuple[int, ...] | None = None,
    weights: tuple[tuple[str, int], ...] | None = None,
    fused_q: int | None = None,
    permit_q: int = 3000,
    forbid_q: int = 7000,
    router_skipped: bool = False,
    deny_floor: bool = False,
    floor_sources: tuple[str, ...] = (),
    quarantine_pin: bool = False,
    chain: tuple[LoweringStep, ...] = (),
    claimed_verdict: str | None = None,
    request_id: str = "req-test",
) -> ArbitrationStatement:
    weights = weights or _equal_weights()
    score_values = scores or (0,) * 7
    stream_scores_q = tuple(zip(STREAM_NAMES, score_values))
    if fused_q is None:
        fused_q = (
            SCALE if router_skipped else canonical_fuse(stream_scores_q, weights)
        )
    stmt = ArbitrationStatement(
        stream_scores_q=stream_scores_q,
        weights_q=weights,
        fused_q=fused_q,
        permit_q=permit_q,
        forbid_q=forbid_q,
        router_skipped=router_skipped,
        deny_floor=deny_floor,
        floor_sources=floor_sources,
        quarantine_pin=quarantine_pin,
        chain=chain,
        claimed_verdict=claimed_verdict or "PLACEHOLDER",
        request_id=request_id,
        policy_id="default",
        policy_version="v-test",
        content_sha256="0" * 64,
        determinism_fingerprint="f" * 64,
    )
    if claimed_verdict is None:
        stmt = _with_claimed(stmt, expected_claimed_verdict(stmt))
    return stmt


def _with_claimed(
    stmt: ArbitrationStatement, claimed: str
) -> ArbitrationStatement:
    return replace(stmt, claimed_verdict=claimed)


# Independent oracles — deliberately NOT the module's own helpers, so an
# arithmetic mutation that changes generator and verifier identically (the
# self-reference trap) still fails here.


def _oracle_fuse(
    stream_scores_q: tuple[tuple[str, int], ...],
    weights_q: tuple[tuple[str, int], ...],
) -> int:
    weights = dict(weights_q)
    acc = sum(score * weights[name] for name, score in stream_scores_q)
    q, r = divmod(acc, SCALE)  # round half up, via divmod (not the module's shape)
    fused = q + (1 if 2 * r >= SCALE else 0)
    return min(SCALE, max(0, fused))


def _oracle_verdict(stmt: ArbitrationStatement) -> str:
    if stmt.deny_floor:
        verdict = "FORBID"
    elif stmt.quarantine_pin:
        verdict = "ABSTAIN"
    elif stmt.fused_q >= stmt.forbid_q:  # forbid first — router R2 before R4
        verdict = "FORBID"
    elif stmt.fused_q <= stmt.permit_q:
        verdict = "PERMIT"
    else:
        verdict = "ABSTAIN"
    for step in stmt.chain:
        verdict = step.to_verdict
    return verdict


def _malicious_envelope(stmt: ArbitrationStatement) -> ArbitrationEnvelope:
    """An adversarial prover holding the shim's dev key: it will happily tag
    ANY statement, including an UNSAT one. The verifier's own relation
    re-evaluation is what must reject it."""
    backend = DeterministicShimBackend()
    proof = backend.prove(
        statement=stmt, private_witness=stmt.canonical_bytes()
    )
    return ArbitrationEnvelope(
        backend=backend.backend_id.value,
        proof_hex=proof.hex(),
        statement_sha256=stmt.sha256_hex(),
    )


def _random_statement(rng: random.Random, i: int) -> ArbitrationStatement:
    raw = [rng.randint(1, 100) for _ in range(7)]
    total = sum(raw)
    weight_values = [r * SCALE // total for r in raw]
    weight_values[0] += SCALE - sum(weight_values)
    weights = tuple(zip(STREAM_NAMES, weight_values))
    scores = tuple(rng.randint(0, SCALE) for _ in range(7))
    permit_q = rng.randint(0, SCALE)
    forbid_q = rng.randint(permit_q, SCALE)

    roll = rng.random()
    deny_floor = roll < 0.15
    quarantine_pin = (not deny_floor) and roll < 0.25
    floor_sources: tuple[str, ...] = ()
    router_skipped = False
    if deny_floor:
        if rng.random() < 0.5:
            floor_sources = (
                rng.choice(
                    [
                        "structural_specialist_deny",
                        "contract_hard_violation",
                        "path_policy_block",
                    ]
                ),
            )
            router_skipped = True
        else:
            floor_sources = (
                rng.choice(
                    ["deterministic_block", "agent_capability_violation"]
                ),
            )

    stmt = _mk_statement(
        scores=scores,
        weights=weights,
        permit_q=permit_q,
        forbid_q=forbid_q,
        router_skipped=router_skipped,
        deny_floor=deny_floor,
        floor_sources=floor_sources,
        quarantine_pin=quarantine_pin,
        request_id=f"req-{i}",
    )

    base = base_verdict(stmt)
    chain_options: list[tuple[LoweringStep, ...]] = [()]
    if base == _P:
        chain_options += [
            (LoweringStep(_P, _A, "crc_demotion"),),
            (LoweringStep(_P, _A, "router_abstain_trigger"),),
            (LoweringStep(_P, _F, "semantic_forbid_escalation"),),
            (
                LoweringStep(_P, _A, "soft_contract_violation"),
                LoweringStep(_A, _F, "semantic_forbid_escalation"),
            ),
        ]
    elif base == _A:
        chain_options += [
            (LoweringStep(_A, _F, "semantic_forbid_escalation"),),
            (LoweringStep(_A, _F, "semantic_dominance_override"),),
        ]
    chain = chain_options[rng.randrange(len(chain_options))]

    stmt = ArbitrationStatement(
        stream_scores_q=stmt.stream_scores_q,
        weights_q=stmt.weights_q,
        fused_q=stmt.fused_q,
        permit_q=stmt.permit_q,
        forbid_q=stmt.forbid_q,
        router_skipped=stmt.router_skipped,
        deny_floor=stmt.deny_floor,
        floor_sources=stmt.floor_sources,
        quarantine_pin=stmt.quarantine_pin,
        chain=chain,
        claimed_verdict="PLACEHOLDER",
        request_id=stmt.request_id,
        policy_id=stmt.policy_id,
        policy_version=stmt.policy_version,
        content_sha256=stmt.content_sha256,
        determinism_fingerprint=stmt.determinism_fingerprint,
    )
    return _with_claimed(stmt, expected_claimed_verdict(stmt))


# ── the headline: N=10k differential, 0% accept on flipped verdicts ─────────


def test_differential_10k_accepts_iff_claimed_equals_relation_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """N=10,000 randomized (scores, policy, floor, pin, chain) tuples.

    Honest statements (claimed == relation verdict) must verify 10000/10000.
    Flipped statements — same committed inputs, claimed verdict swapped, and
    re-tagged by a MALICIOUS prover holding the shim dev key — must be
    rejected with exactly 0 acceptances, via the relation (UNSAT), not merely
    via the hash binding.
    """
    monkeypatch.setenv("TEX_ZKPDP_ALLOW_SHIM", "1")
    rng = random.Random(20260610)
    n = 10_000

    honest_accepts = 0
    flip_attempts = 0
    flip_accepts = 0

    for i in range(n):
        stmt = _random_statement(rng, i)

        # Anti-self-reference: the generator used the module's own fuse and
        # ladder; the independent oracles must agree, or an arithmetic
        # mutation that shifted both sides identically is hiding.
        if not stmt.router_skipped:
            assert stmt.fused_q == _oracle_fuse(
                stmt.stream_scores_q, stmt.weights_q
            )
        assert stmt.claimed_verdict == _oracle_verdict(stmt)

        envelope = prove_arbitration(stmt)
        result = verify_arbitration(stmt, envelope)
        if result.is_valid:
            honest_accepts += 1

        # Exhaustive both-flips on the first 500; one random flip after.
        others = [v for v in (_P, _A, _F) if v != stmt.claimed_verdict]
        flips = others if i < 500 else [rng.choice(others)]
        for wrong in flips:
            flipped = _with_claimed(stmt, wrong)
            adv = verify_arbitration(flipped, _malicious_envelope(flipped))
            flip_attempts += 1
            if adv.is_valid:
                flip_accepts += 1
            else:
                assert adv.reason is not None
                assert adv.reason.startswith(
                    "zkpdp_arbitration_relation_unsat"
                ), adv.reason

    assert honest_accepts == n
    assert flip_attempts == n + 500
    assert flip_accepts == 0  # the headline: 0% accept on flipped verdicts


# ── hard-gate regression (the nanozk discipline, inside the verifier) ───────


def test_shim_is_invalid_by_default_with_named_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEX_ZKPDP_ALLOW_SHIM", "1")
    stmt = _mk_statement()
    envelope = prove_arbitration(stmt)

    monkeypatch.delenv("TEX_ZKPDP_ALLOW_SHIM", raising=False)
    result = verify_arbitration(stmt, envelope)
    assert result.is_valid is False
    assert result.reason == SHIM_GATE_REASON
    assert result.reason == "zkpdp_shim_not_a_real_proof"
    assert result.stand_in is True
    assert result.regulator_grade is False


def test_shim_flag_zero_is_still_gated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEX_ZKPDP_ALLOW_SHIM", "1")
    stmt = _mk_statement()
    envelope = prove_arbitration(stmt)
    monkeypatch.setenv("TEX_ZKPDP_ALLOW_SHIM", "0")
    assert verify_arbitration(stmt, envelope).reason == SHIM_GATE_REASON


def test_shim_round_trips_under_tests_only_flag_and_is_never_a_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEX_ZKPDP_ALLOW_SHIM", "1")
    stmt = _mk_statement(scores=(2000,) * 7)
    envelope = prove_arbitration(stmt)
    result = verify_arbitration(stmt, envelope)

    assert result.is_valid is True
    # The stand-in is NEVER a real proof: not regulator-grade (pinned both at
    # the zkprov contract and on the verification result), and labeled.
    assert is_regulator_grade(ProofBackendId.DETERMINISTIC_SHIM_V1) is False
    assert result.stand_in is True
    assert result.regulator_grade is False
    assert "NOT a ZK proof" in result.note
    # The wire envelope carries no prover-asserted trust flags to forge.
    wire = envelope.to_bytes().decode("utf-8")
    assert "regulator" not in wire
    assert "stand_in" not in wire


def test_prover_refuses_unsat_statement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEX_ZKPDP_ALLOW_SHIM", "1")
    stmt = _with_claimed(_mk_statement(), _F)  # base PERMIT, no chain
    with pytest.raises(ValueError, match="UNSAT"):
        prove_arbitration(stmt)


# ── envelope tamper / binding ────────────────────────────────────────────────


def test_envelope_binding_and_tamper_rejections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEX_ZKPDP_ALLOW_SHIM", "1")
    stmt = _mk_statement()
    other = _mk_statement(scores=(100,) * 7, request_id="req-other")
    envelope = prove_arbitration(stmt)

    assert (
        verify_arbitration(other, envelope).reason
        == "zkpdp_statement_binding_mismatch"
    )
    assert (
        verify_arbitration(stmt, b"not-json").reason
        == "zkpdp_envelope_malformed"
    )
    bad_tag = ArbitrationEnvelope(
        backend=envelope.backend,
        proof_hex="00" * 8,
        statement_sha256=envelope.statement_sha256,
    )
    assert (
        verify_arbitration(stmt, bad_tag).reason
        == "zkpdp_stand_in_tag_mismatch"
    )
    unknown = ArbitrationEnvelope(
        backend="not-a-backend",
        proof_hex=envelope.proof_hex,
        statement_sha256=envelope.statement_sha256,
    )
    assert verify_arbitration(stmt, unknown).reason == "zkpdp_unknown_backend"


# ── the relation: UNSAT-when-violated pins ───────────────────────────────────


def test_deny_floor_without_structural_source_is_unsat() -> None:
    stmt = _mk_statement(deny_floor=True, floor_sources=())
    result = evaluate_relation(stmt)
    assert not result.satisfied
    assert "floor_without_structural_source" in result.violations


def test_probabilistic_score_can_never_be_a_floor_source() -> None:
    """The reviewer attack: a high probabilistic score must NOT fire the
    structural floor. The source enumeration has no score-valued member, so a
    statement citing one is UNSAT."""
    stmt = _mk_statement(
        scores=(9900,) * 7,
        deny_floor=True,
        floor_sources=("probabilistic_score",),
    )
    result = evaluate_relation(stmt)
    assert not result.satisfied
    assert "floor_source_unknown" in result.violations


def test_high_score_forbids_via_threshold_not_via_floor() -> None:
    """score=0.95 → FORBID through the threshold map with the floor bit
    untouched: the relation keeps 'risk crossed the forbid threshold' and
    'a structural proof fired' as distinct, non-interchangeable facts."""
    stmt = _mk_statement(scores=(9500,) * 7)
    assert stmt.deny_floor is False
    assert stmt.floor_sources == ()
    assert stmt.claimed_verdict == _F
    assert evaluate_relation(stmt).satisfied


def test_deny_floor_forces_forbid() -> None:
    stmt = _mk_statement(
        deny_floor=True, floor_sources=("deterministic_block",)
    )
    assert stmt.claimed_verdict == _F
    assert evaluate_relation(stmt).satisfied

    escaped = _with_claimed(stmt, _A)
    result = evaluate_relation(escaped)
    assert not result.satisfied
    assert "deny_floor_requires_forbid" in result.violations


def test_quarantine_pins_abstain_even_above_forbid_threshold() -> None:
    """Router R0 returns the quarantine ABSTAIN before the R2 threshold check,
    so a fused score above the forbid threshold still yields ABSTAIN. The
    relation mirrors that pin exactly."""
    stmt = _mk_statement(scores=(9500,) * 7, quarantine_pin=True)
    assert stmt.claimed_verdict == _A
    assert evaluate_relation(stmt).satisfied
    assert not evaluate_relation(_with_claimed(stmt, _F)).satisfied


def test_chain_raise_is_unsat() -> None:
    stmt = _mk_statement(
        scores=(5000,) * 7,  # base ABSTAIN
        chain=(LoweringStep(_A, _P, "unattributed_lowering"),),
        claimed_verdict=_P,
    )
    result = evaluate_relation(stmt)
    assert not result.satisfied
    assert "chain_step_not_lowering" in result.violations


def test_crc_demotion_may_only_take_permit_to_abstain() -> None:
    stmt = _mk_statement(
        scores=(5000,) * 7,  # base ABSTAIN
        chain=(LoweringStep(_A, _F, "crc_demotion"),),
        claimed_verdict=_F,
    )
    result = evaluate_relation(stmt)
    assert not result.satisfied
    assert "chain_transition_not_allowed" in result.violations


def test_chain_must_be_contiguous_from_base_with_known_reasons() -> None:
    discontinuous = _mk_statement(  # base PERMIT, chain starts at ABSTAIN
        chain=(LoweringStep(_A, _F, "semantic_forbid_escalation"),),
        claimed_verdict=_F,
    )
    assert "chain_discontinuous" in evaluate_relation(discontinuous).violations

    unknown_reason = _mk_statement(
        chain=(LoweringStep(_P, _A, "vibes"),),
        claimed_verdict=_A,
    )
    assert "chain_reason_unknown" in evaluate_relation(unknown_reason).violations


def test_permit_requires_empty_chain_and_in_region_score() -> None:
    lowered = _mk_statement(
        chain=(LoweringStep(_P, _A, "crc_demotion"),),
    )  # claimed auto-set to ABSTAIN
    assert not evaluate_relation(_with_claimed(lowered, _P)).satisfied

    out_of_region = _with_claimed(_mk_statement(scores=(5000,) * 7), _P)
    assert not evaluate_relation(out_of_region).satisfied


def test_fuse_is_exact_in_relation_arithmetic() -> None:
    stmt = _mk_statement(scores=(2000,) * 7)
    tampered = replace(stmt, fused_q=stmt.fused_q + 10)
    assert "fuse_mismatch" in evaluate_relation(tampered).violations


def test_threshold_boundaries_mirror_the_live_router_exactly() -> None:
    """Pins the boundary semantics against the live router's comparisons
    (``final_score >= forbid_threshold`` fires FORBID; ``<= permit_threshold``
    is the permit region; FORBID is checked before PERMIT, so the degenerate
    permit==forbid boundary resolves FORBID). Each assert kills a one-token
    mutant (>= → >, <= → <, order swap)."""
    at_forbid = _mk_statement(scores=(7000,) * 7)  # fused == forbid_q
    assert base_verdict(at_forbid) == _F
    assert evaluate_relation(at_forbid).satisfied
    assert not evaluate_relation(_with_claimed(at_forbid, _A)).satisfied

    at_permit = _mk_statement(scores=(3000,) * 7)  # fused == permit_q
    assert base_verdict(at_permit) == _P
    assert at_permit.claimed_verdict == _P
    assert evaluate_relation(at_permit).satisfied
    assert not evaluate_relation(_with_claimed(at_permit, _A)).satisfied

    degenerate = _mk_statement(
        scores=(5000,) * 7, permit_q=5000, forbid_q=5000
    )  # permit == forbid == fused: live R2 fires before R4 → FORBID
    assert base_verdict(degenerate) == _F
    assert degenerate.claimed_verdict == _F
    assert evaluate_relation(degenerate).satisfied
    assert not evaluate_relation(_with_claimed(degenerate, _P)).satisfied


def test_every_structural_constraint_is_individually_enforced() -> None:
    """Mutation guard: each named UNSAT code must be reachable — deleting any
    one of these constraints from evaluate_relation fails this test."""
    good = _mk_statement(scores=(2000,) * 7)  # base PERMIT, SAT
    assert evaluate_relation(good).satisfied
    cases = {
        "bad_version": replace(good, version="zkpdp-arbitration-v0"),
        "bad_scale": replace(good, scale=1000),
        "bad_stream_keys": replace(
            good, stream_scores_q=tuple(reversed(good.stream_scores_q))
        ),
        "bad_weight_keys": replace(
            good, weights_q=(("not_a_stream", SCALE),) + good.weights_q[1:]
        ),
        "value_out_of_range": replace(good, fused_q=SCALE + 1),
        "short_circuit_fused_not_max": replace(
            good,
            router_skipped=True,
            deny_floor=True,
            floor_sources=("contract_hard_violation",),
            claimed_verdict=_F,
        ),  # fused_q stays 2000 != SCALE
        "floor_sources_without_deny_floor": replace(
            good, floor_sources=("deterministic_block",)
        ),
        "claimed_verdict_unknown": replace(good, claimed_verdict="ZEBRA"),
        "chain_verdict_unknown": replace(
            good,
            chain=(LoweringStep(_P, "ZEBRA", "unattributed_lowering"),),
            claimed_verdict="ZEBRA",
        ),
        "quarantine_precedes_capability_floor": replace(
            good,
            deny_floor=True,
            floor_sources=("agent_capability_violation",),
            quarantine_pin=True,
            claimed_verdict=_F,
        ),
    }
    for code, stmt in cases.items():
        result = evaluate_relation(stmt)
        assert not result.satisfied, code
        assert code in result.violations, (code, result.violations)


def test_structural_malformations_are_unsat() -> None:
    inverted = _mk_statement(permit_q=8000, forbid_q=4000)
    assert "thresholds_inverted" in evaluate_relation(inverted).violations

    bad_weights = tuple(zip(STREAM_NAMES, [500] * 7))  # sums to 3500
    underweight = _mk_statement(weights=bad_weights)
    assert (
        "weight_sum_out_of_tolerance"
        in evaluate_relation(underweight).violations
    )

    skipped_without_cause = _mk_statement(router_skipped=True, fused_q=SCALE)
    assert (
        "short_circuit_without_structural_cause"
        in evaluate_relation(skipped_without_cause).violations
    )

    too_long = _mk_statement(
        chain=(
            LoweringStep(_P, _A, "crc_demotion"),
            LoweringStep(_A, _F, "semantic_forbid_escalation"),
            LoweringStep(_F, _F, "unattributed_lowering"),
        ),
        claimed_verdict=_F,
    )
    assert "chain_too_long" in evaluate_relation(too_long).violations


# ── fail-closed sealed-decision binding (consumes M0) ────────────────────────


def test_seal_binding_fail_closed_on_absent_or_empty_ledger() -> None:
    stmt = _mk_statement()

    none_binding = check_seal_binding(None, stmt)
    assert none_binding.status == "not_sealed"
    assert "not tamper evidence" in none_binding.note

    empty_binding = check_seal_binding(SealedFactLedger(), stmt)
    assert empty_binding.status == "not_sealed"
    assert "not tamper evidence" in empty_binding.note


def test_verify_stays_valid_when_decision_simply_not_sealed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TEX_SEAL_DECISIONS is OFF by default; an unsealed decision is a normal
    state and must not fail verification."""
    monkeypatch.setenv("TEX_ZKPDP_ALLOW_SHIM", "1")
    stmt = _mk_statement()
    envelope = prove_arbitration(stmt)
    result = verify_arbitration(stmt, envelope, ledger=SealedFactLedger())
    assert result.is_valid is True
    assert result.seal is not None
    assert result.seal.status == "not_sealed"


# ── live-PDP cross-check ─────────────────────────────────────────────────────

_LIVE_CONTENTS = (
    CLEAN_CONTENT + SECRET_LEAK_CONTENT + PII_CONTENT
    + COMMITMENT_CONTENT + DESTRUCTIVE_CONTENT
)


class _PermitSemanticAnalyzer:
    """Deterministic semantic provider recommending PERMIT with solid
    confidence. The deterministic gate, specialists, router, floor, CRC and
    PDP all stay real — only the LLM-provider seam is stubbed (the unit under
    test here is the arbiter, which consumes the resulting REAL decision)."""

    def analyze(self, *, request, retrieval_context):
        return make_semantic_analysis(
            recommended_verdict=Verdict.PERMIT,
            recommended_confidence=0.9,
            overall_confidence=0.92,
            dimension_confidence=0.8,
            evidence_sufficiency=0.6,
        )


class _QuarantinedAgentEvaluator:
    """Agent suite stub: a QUARANTINED agent that ALSO carries a capability
    violation — the live router R0 resolves this to the quarantine ABSTAIN
    (checked before the capability FORBID, router.py), which is exactly the
    precedence the builder must preserve."""

    def evaluate(self, request) -> AgentEvaluationBundle:
        return AgentEvaluationBundle(
            agent_present=True,
            agent_id="agent-quarantined",
            identity=neutral_identity_signal().model_copy(
                update={"lifecycle_status": "QUARANTINED"}
            ),
            capability=neutral_capability_signal().model_copy(
                update={"violated_dimensions": ("action",)}
            ),
            behavioral=neutral_behavioral_signal(),
        )


_ACTION_CLASS_FORBID_META = {
    "action_class": {
        "steps": [{"reversibility": "IRREVERSIBLE", "blast_radius": "PUBLIC"}]
    }
}


def _live_results():
    """Real PolicyDecisionPoint decisions covering every arbitration cell:
    threshold PERMIT/ABSTAIN/FORBID, deterministic-block floor, the pdp.py
    short-circuit (action-class structural floor), and the quarantine pin."""
    ledger = SealedFactLedger()
    policy = make_default_policy()
    pdp = PolicyDecisionPoint(decision_ledger=ledger)
    results = [
        pdp.evaluate(request=make_request(content=content), policy=policy)
        for content in _LIVE_CONTENTS
    ]
    permit_pdp = PolicyDecisionPoint(
        decision_ledger=ledger, semantic_analyzer=_PermitSemanticAnalyzer()
    )
    results.append(
        permit_pdp.evaluate(
            request=make_request(content=CLEAN_CONTENT[0]), policy=policy
        )
    )
    results.append(
        pdp.evaluate(
            request=make_request(
                content=CLEAN_CONTENT[1], metadata=dict(_ACTION_CLASS_FORBID_META)
            ),
            policy=policy,
        )
    )
    quarantine_pdp = PolicyDecisionPoint(
        decision_ledger=ledger, agent_evaluator=_QuarantinedAgentEvaluator()
    )
    results.append(
        quarantine_pdp.evaluate(
            request=make_request(content=CLEAN_CONTENT[2]), policy=policy
        )
    )
    return results, policy, ledger


def test_live_pdp_decisions_are_relation_satisfiable_and_flips_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Statements built from REAL PolicyDecisionPoint decisions: the relation
    is satisfiable with claimed == the live verdict; every flip rejects; the
    sealed DECISION fact matches and its chain (integrity) + signatures
    (authorship) verify."""
    monkeypatch.setenv("TEX_ZKPDP_ALLOW_SHIM", "1")
    results, policy, ledger = _live_results()

    live_verdicts = {r.decision.verdict for r in results}
    assert live_verdicts == {Verdict.PERMIT, Verdict.ABSTAIN, Verdict.FORBID}

    statements = []
    for result in results:
        decision = result.decision
        stmt = build_statement_from_decision(decision, policy=policy)
        statements.append(stmt)
        assert stmt.claimed_verdict == decision.verdict.value
        assert evaluate_relation(stmt).satisfied

        envelope = prove_arbitration(stmt)
        verification = verify_arbitration(stmt, envelope, ledger=ledger)
        assert verification.is_valid is True
        assert verification.seal is not None
        assert verification.seal.status == "sealed_match"
        assert verification.seal.chain_intact is True  # integrity
        assert verification.seal.signatures_valid is True  # self-consistency
        # (authorship needs a pinned key — see the pinned-key test)

        for wrong in (v for v in (_P, _A, _F) if v != stmt.claimed_verdict):
            flipped = _with_claimed(stmt, wrong)
            adv = verify_arbitration(
                flipped, _malicious_envelope(flipped), ledger=ledger
            )
            assert adv.is_valid is False
            assert adv.reason is not None
            assert adv.reason.startswith("zkpdp_arbitration_relation_unsat")

    # Every arbitration cell is exercised by a REAL decision, not only by
    # synthetic statements: live PERMIT (no chain), the pdp.py short-circuit,
    # the deterministic-block floor, and the quarantine pin.
    assert any(s.claimed_verdict == _P and not s.chain for s in statements)
    assert any(
        s.router_skipped
        and s.fused_q == SCALE
        and "structural_specialist_deny" in s.floor_sources
        for s in statements
    )
    assert any("deterministic_block" in s.floor_sources for s in statements)
    pinned = [s for s in statements if s.quarantine_pin]
    assert pinned
    # Live R0 precedence preserved: quarantined + capability-violating agent
    # pins ABSTAIN; the capability floor must NOT have been recorded.
    for s in pinned:
        assert s.claimed_verdict == _A
        assert "agent_capability_violation" not in s.floor_sources


def test_chain_omission_attack_is_caught_by_the_seal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The documented residual: a prover that OMITS lowering signals can build
    a relation-satisfiable PERMIT statement for a request the live PDP held.
    The relation alone accepts it (derivability, as documented); the sealed
    DECISION binding rejects it. Relation + seal together are the property."""
    monkeypatch.setenv("TEX_ZKPDP_ALLOW_SHIM", "1")
    results, policy, ledger = _live_results()
    held = next(
        r.decision
        for r in results
        if r.decision.verdict in (Verdict.ABSTAIN, Verdict.FORBID)
    )

    forged = _mk_statement(scores=(0,) * 7, request_id=str(held.request_id))
    forged = ArbitrationStatement(
        stream_scores_q=forged.stream_scores_q,
        weights_q=forged.weights_q,
        fused_q=forged.fused_q,
        permit_q=forged.permit_q,
        forbid_q=forged.forbid_q,
        router_skipped=False,
        deny_floor=False,
        floor_sources=(),
        quarantine_pin=False,
        chain=(),
        claimed_verdict=_P,
        request_id=str(held.request_id),
        policy_id=held.policy_id,
        policy_version=held.policy_version,
        content_sha256=held.content_sha256,
        determinism_fingerprint=held.determinism_fingerprint,
    )
    assert evaluate_relation(forged).satisfied  # derivable — as documented

    adv_envelope = _malicious_envelope(forged)
    unbound = verify_arbitration(forged, adv_envelope)
    assert unbound.is_valid is True  # the named residual, without the seal

    bound = verify_arbitration(forged, adv_envelope, ledger=ledger)
    assert bound.is_valid is False
    assert bound.reason is not None
    assert bound.reason.startswith("zkpdp_sealed_verdict_mismatch")
    assert bound.seal is not None and "verdict" in bound.seal.mismatches


def test_builder_rejects_mismatched_policy_and_unreachable_verdict() -> None:
    results, policy, _ = _live_results()
    decision = results[0].decision

    from tests.factories import make_strict_policy

    strict = make_strict_policy()
    # Guard against green-by-vacuity: the two stock policies must actually
    # differ for the mismatch assertion below to mean anything.
    assert (strict.policy_id, strict.version) != (
        decision.policy_id,
        decision.policy_version,
    )
    with pytest.raises(ValueError, match="does not match"):
        build_statement_from_decision(decision, policy=strict)

    # A claimed verdict MORE PERMISSIVE than the base (floor / midband) must
    # be refused — pick a decision whose base is stricter than PERMIT. (A held
    # decision whose base IS the permit region is the documented omission
    # residual: the builder rightly emits it and the SEAL rejects it — see
    # test_chain_omission_attack_is_caught_by_the_seal.)
    held_strict = next(
        (
            r.decision
            for r in results
            if base_verdict(build_statement_from_decision(r.decision, policy=policy))
            != _P
        ),
        None,
    )
    assert held_strict is not None  # corpus contains floor/midband decisions
    impossible = held_strict.model_copy(update={"verdict": Verdict.PERMIT})
    with pytest.raises(ArbitrationUnprovable):
        build_statement_from_decision(impossible, policy=policy)


def test_broken_ledger_chain_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sealed_match inside a ledger whose hash-chain replay FAILS (reorder /
    tamper) must reject — integrity is enforced, not merely reported."""
    monkeypatch.setenv("TEX_ZKPDP_ALLOW_SHIM", "1")
    ledger = SealedFactLedger()
    policy = make_default_policy()
    pdp = PolicyDecisionPoint(decision_ledger=ledger)
    pdp.evaluate(request=make_request(content=CLEAN_CONTENT[0]), policy=policy)
    decision = pdp.evaluate(
        request=make_request(content=SECRET_LEAK_CONTENT[0]), policy=policy
    ).decision

    stmt = build_statement_from_decision(decision, policy=policy)
    envelope = prove_arbitration(stmt)
    assert verify_arbitration(stmt, envelope, ledger=ledger).is_valid is True

    # Tamper: reorder the ledger's records — the chain replay must break and
    # the verifier must fail closed with the named integrity reason.
    ledger._entries[0], ledger._entries[1] = ledger._entries[1], ledger._entries[0]
    assert ledger.verify_chain()["intact"] is False
    result = verify_arbitration(stmt, envelope, ledger=ledger)
    assert result.is_valid is False
    assert result.reason == "zkpdp_sealed_chain_broken"
    assert result.seal is not None and result.seal.chain_intact is False


def test_authorship_requires_a_pinned_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unpinned, signatures_valid is only the ledger's self-consistency with
    its own key (and the note says so); authorship is attested only against a
    PINNED public key, and a wrong pinned key fails closed."""
    monkeypatch.setenv("TEX_ZKPDP_ALLOW_SHIM", "1")
    ledger = SealedFactLedger()
    policy = make_default_policy()
    pdp = PolicyDecisionPoint(decision_ledger=ledger)
    decision = pdp.evaluate(
        request=make_request(content=CLEAN_CONTENT[0]), policy=policy
    ).decision
    stmt = build_statement_from_decision(decision, policy=policy)
    envelope = prove_arbitration(stmt)

    unpinned = check_seal_binding(ledger, stmt)
    assert unpinned.status == "sealed_match"
    assert "self-consistency" in unpinned.note

    pinned_ok = verify_arbitration(
        stmt, envelope, ledger=ledger,
        expected_public_key_pem=ledger.public_key_pem,
    )
    assert pinned_ok.is_valid is True
    assert pinned_ok.seal is not None
    assert pinned_ok.seal.signatures_valid is True
    assert "PINNED" in pinned_ok.seal.note

    wrong_key = SealedFactLedger().public_key_pem
    pinned_bad = verify_arbitration(
        stmt, envelope, ledger=ledger, expected_public_key_pem=wrong_key
    )
    assert pinned_bad.is_valid is False
    assert pinned_bad.reason == "zkpdp_sealed_signature_invalid"


# ── real backend: honestly blocked, never faked ──────────────────────────────


def test_real_backend_prove_is_blocked_runtime_dependent() -> None:
    """RUNTIME-DEPENDENT / BLOCKED on M0c: the wired Halo2 backend cannot
    prove today — without ezkl it raises at import probe; WITH ezkl it still
    raises because the circuit artifact is out-of-tree (backends.py). This
    test pins that blocker rather than fabricating a prover number."""
    stmt = _mk_statement()
    with pytest.raises(BackendUnavailable):
        prove_arbitration(stmt, backend_id=ProofBackendId.HALO2_IPA_2026)


def test_real_backend_envelope_never_verifies_today(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A halo2-tagged envelope must fail closed (RUNTIME-DEPENDENT), with or
    without the shim flag — the real path is not shim-gated and must never be
    silently accepted."""
    monkeypatch.delenv("TEX_ZKPDP_ALLOW_SHIM", raising=False)
    stmt = _mk_statement()
    fake = ArbitrationEnvelope(
        backend=ProofBackendId.HALO2_IPA_2026.value,
        proof_hex="00" * 16,
        statement_sha256=stmt.sha256_hex(),
    )
    result = verify_arbitration(stmt, fake)
    assert result.is_valid is False
    assert result.reason == "zkpdp_backend_unavailable_runtime_dependent"


# ── determinism of the canonical encoding ────────────────────────────────────


def test_canonical_bytes_are_stable_and_quantization_is_exact() -> None:
    stmt = _mk_statement(scores=(1234,) * 7)
    assert stmt.canonical_bytes() == _mk_statement(
        scores=(1234,) * 7
    ).canonical_bytes()
    # 4-decimal recorded values quantize exactly (SCALE matches the router's
    # rounding), so the durable record loses nothing in fixed point.
    assert quantize(0.1234) == 1234
    assert quantize(0.7) == 7000
    assert quantize(1.0) == SCALE
