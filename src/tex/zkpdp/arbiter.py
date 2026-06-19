"""
zkPDP arbiter (Wave 2 / L1) — proof-carrying verdict over the ARBITRATION RELATION.

What this module proves (the narrow claim, ROADMAP.md L1 row)
--------------------------------------------------------------
One statement + proof artifact that the **arbitration relation**
(fuse → threshold → FORBID-floor → monotone gate) maps committed scores +
policy to the claimed verdict. The relation is encoded **UNSAT-when-violated**:
a flipped verdict, a raised verdict, a floor escape, or a floor fired without a
structural source makes the constraint system unsatisfiable and the verifier
rejects. Concretely, a satisfying statement guarantees:

  * **No false PERMIT** — claimed PERMIT is accepted only when no deny-floor
    fired, no quarantine pin is set, the fused score lies inside the permit
    region, and the lowering chain is empty.
  * **No floor escape** — a deny-floor (deterministic block / specialist DENY /
    contract hard violation / path block / capability violation) forces FORBID.
  * **No raise** — every committed lowering step strictly increases severity
    (PERMIT < ABSTAIN < FORBID) along a per-reason transition table; the CRC
    gate, for example, may only ever take PERMIT → ABSTAIN.
  * **Floor is structural by construction** — the deny-floor bit has no input
    path from any score; it must cite an enumerated structural source, so a
    high probabilistic score can never fire it (the structural-floor contract).

What this module does NOT prove (read before citing)
-----------------------------------------------------
  * It does **not** prove the specialist inference that produced the committed
    scores is correct — that is the L1 North-Star (ROADMAP.md, zk over real
    model execution), explicitly out of scope here.
  * It does **not** prove that each committed lowering step's *signal actually
    fired* — a prover may fabricate extra caution (a lowering it didn't earn).
    That direction is deliberately allowed: it matches the runtime doctrine
    that probabilistic signals may only ever LOWER a verdict. Fabricating
    permissiveness is what the relation makes UNSAT.
  * Symmetrically, a prover may **omit** lowering signals: a statement claiming
    PERMIT for a request the live PDP held at ABSTAIN on *non-committed*
    signals (the confidence floor, a semantic ABSTAIN recommendation) is
    relation-satisfiable. The relation proves the claimed verdict is
    *derivable* from the committed inputs; binding it to the verdict Tex
    *actually produced* is the M0 seal's job — pass the decision ledger to
    ``verify_arbitration`` (or call ``check_seal_binding``) and a claimed
    verdict that disagrees with the sealed one is rejected
    (``zkpdp_sealed_verdict_mismatch``), as is a sealed match whose ledger
    chain fails replay or whose signatures fail. Relation + seal together
    bind the *verdict*; the committed *explanation* (stream scores, weights,
    thresholds, floor bits) is bound only indirectly — thresholds and weights
    through the sealed ``policy_id``/``policy_version`` (a versioned
    snapshot), layer outputs through the sealed ``determinism_fingerprint``
    — not field-by-field inside the seal. Cite neither half alone as the
    whole, and do not present the seal's six detail fields as covering the
    full statement.
  * **Backend reality, stated precisely (updated W3/L1).** There are now TWO
    classes of non-shim backend in ``tex.zkprov.backends``. The SNARK backends
    (Halo2/ezkl, DeepProve, …) still raise ``BackendUnavailable`` — their
    circuit/binary is out-of-tree (M0c, RUNTIME-DEPENDENT). But
    ``schnorr-fuse-zk-v1`` is a **real, runnable, non-shim** backend
    (``tex.zkprov.zk_fuse``): a discrete-log Σ-protocol that proves the FUSE
    kernel of THIS relation — the public ``fused_q`` is the round-half-up,
    clamped, policy-weighted fusion of PRIVATE, range-bounded per-stream scores
    — hiding the scores, sound under discrete log, publicly verifiable offline
    with no shared secret, no SRS, no enclave. It applies to the FUSE path only
    (a router-skipped structural short-circuit has no fuse and the backend
    refuses it), and it proves the *arithmetic* kernel only: the threshold map,
    deny-floor, quarantine pin and lowering chain stay PUBLIC, checked by
    ``evaluate_relation`` — so this is NOT a ZK proof of the whole verdict, and
    it is ``research-early`` / unaudited / non-succinct / pre-quantum (2048-bit
    DLog). With ``schnorr-fuse-zk-v1`` the verifier reports ``stand_in=False``
    and ``regulator_grade=True`` (the non-shim tier), so L1 reaches *green* (not
    only ``green_test_mode``) WITHOUT ``TEX_ZKPDP_ALLOW_SHIM``. Hiding is a
    property of the proof; it is realized only when the deployment omits the raw
    scores from the published statement (a hiding deployment) — the arbiter's
    all-public ``ArbitrationStatement`` still publishes scores, so on that path
    the deterministic relation re-eval remains the load-bearing verdict check
    and the ZK proof is the binding a hiding deployment would rely on.

    The keyed-hash **stand-in** (``deterministic-shim-v1``) is unchanged and
    still the default: NOT a proof, hard-gated invalid-by-default with reason
    ``zkpdp_shim_not_a_real_proof`` unless ``TEX_ZKPDP_ALLOW_SHIM=1`` (tests/dev
    only) — the same discipline as the deactivated nanozk placeholder
    (``nanozk/layerwise_prover.py``), placed INSIDE the verifier. On the shim
    path the verifier's own deterministic re-evaluation of the relation is the
    load-bearing check; the keyed-hash tag only binds bytes and adds no
    soundness against a holder of the dev key.

Fixed-point arithmetic (the honest circuit shape)
-------------------------------------------------
All relation arithmetic is exact integer math over values quantized at
``SCALE = 10**4`` — the precision the durable ``Decision`` record already
stores (the router rounds scores to 4 decimal places) and the shape a real
ezkl/Halo2 circuit would compute (field elements, never IEEE-754 floats).
The float→fixed bridge from a live decision is a separate, named consistency
check with tolerance ``BRIDGE_TOL_Q`` quanta. Consequence, stated honestly: a
live verdict thresholded within half a quantum of a policy threshold may be
**unprovable** (the builder raises rather than emitting an inconsistent
statement) — a completeness collar, never a soundness leak. The verifier can
refuse to prove an edge-case true verdict; it cannot accept a flipped one.

Maturity: ``research-early``. The 0%-flip differential benchmark
(``tests/zkpdp/test_arbiter.py``) is what earns the relation; the real
ezkl/Halo2 prove/verify/size numbers remain ``RUNTIME-DEPENDENT`` on M0c.

Chain vs signature (when binding to the sealed decision): the ledger hash
*chain* proves integrity (``verify_chain()["intact"]``); a per-record
*signature* verified against a **pinned** public key proves authorship by the
key holder (``verify_signatures(pem)["valid"]`` — unpinned, it is only the
ledger's self-consistency with its own key). Neither is a correctness proof —
that is exactly the gap this relation begins to discharge.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from dataclasses import dataclass, field

from tex.domain.decision import Decision
from tex.domain.policy import PolicySnapshot
from tex.domain.verdict import Verdict
from tex.engine.router import DecisionRouter
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind
from tex.zkprov.backends import (
    BackendUnavailable,
    ProofBackendId,
    get_proof_backend,
    is_regulator_grade,
    resolve_backend_with_fallback,
)

# ── Constants ────────────────────────────────────────────────────────────────

STATEMENT_VERSION = "zkpdp-arbitration-v1"
ENVELOPE_FORMAT = "zkpdp-arbitration-envelope-v1"

# Fixed-point scale. 10**4 matches the 4-decimal rounding the router applies
# to every durable score, so quantization of a recorded value is exact.
SCALE = 10_000

# Float→fixed bridge tolerance (quanta) between the canonical fused score
# recomputed from committed streams and the live recorded final_score. Budget:
# 7 streams each rounded to 4dp (≤ 0.5 quanta weighted) + weight quantization
# (≤ ~3.5 quanta worst case) + the final 4dp rounding (≤ 0.5 quanta) + the
# half-quantum rounding inside canonical_fuse itself (≤ 0.5 quanta) ≈ 5.0,
# plus one quantum of explicit margin.
BRIDGE_TOL_Q = 6

# Quantized fusion weights must sum to SCALE within this many quanta
# (per-weight rounding error across seven streams).
WEIGHT_SUM_TOL_Q = 8

# Tests/dev-only opt-in for the keyed-hash stand-in, mirroring
# TEX_NANOZK_ALLOW_SHIM (nanozk/layerwise_prover.py). Default-deny.
_ALLOW_SHIM_ENV = "TEX_ZKPDP_ALLOW_SHIM"
SHIM_GATE_REASON = "zkpdp_shim_not_a_real_proof"

# The seven fusion streams, in canonical order (router.py weight keys).
STREAM_NAMES: tuple[str, ...] = (
    "deterministic",
    "specialists",
    "semantic",
    "criticality",
    "agent_identity",
    "agent_capability",
    "agent_behavioral",
)

_SEVERITY: dict[str, int] = {
    Verdict.PERMIT.value: 0,
    Verdict.ABSTAIN.value: 1,
    Verdict.FORBID.value: 2,
}

# Structural deny-floor sources. These are PROOFS over structure, never
# probabilistic scores — the enumeration is the in-relation encoding of
# "a high score must not fire the floor": there is no score-valued member.
FLOOR_SOURCES: frozenset[str] = frozenset(
    {
        "deterministic_block",          # R0: deterministic gate blocked
        "structural_specialist_deny",   # specialists/structural_floor.py proof
        "contract_hard_violation",      # behavioral-contract hard violation
        "path_policy_block",            # path-policy block severity
        "agent_capability_violation",   # R0: agent capability mismatch
    }
)

# Floor sources that short-circuit the router entirely (pdp.py hard_violation
# branch). deterministic_block / agent_capability_violation fire IN-router
# (R0), so the fuse still runs for those.
_SHORT_CIRCUIT_SOURCES: frozenset[str] = frozenset(
    {
        "structural_specialist_deny",
        "contract_hard_violation",
        "path_policy_block",
    }
)

# Lowering reasons and the verdict transitions each may justify. Severity must
# strictly increase; the table additionally restricts WHICH lowering each
# signal may claim (e.g. the CRC gate demotes PERMIT→ABSTAIN, never to FORBID).
_P, _A, _F = Verdict.PERMIT.value, Verdict.ABSTAIN.value, Verdict.FORBID.value
LOWERING_TRANSITIONS: dict[str, frozenset[tuple[str, str]]] = {
    "crc_demotion": frozenset({(_P, _A)}),
    "soft_contract_violation": frozenset({(_P, _A)}),
    "path_policy_warn": frozenset({(_P, _A)}),
    "predictive_hold": frozenset({(_P, _A)}),
    "risk_spine": frozenset({(_P, _A)}),
    "pq_durability": frozenset({(_P, _A)}),
    "router_abstain_trigger": frozenset({(_P, _A)}),
    "semantic_dominance_override": frozenset({(_P, _F), (_A, _F)}),
    "semantic_forbid_escalation": frozenset({(_P, _F), (_A, _F)}),
    # Honest fallback when a live decision's lowering can't be attributed to a
    # named signal. Still strictly lowering — the direction is what is proven;
    # the attribution gap stays visible to an auditor in the statement.
    "unattributed_lowering": frozenset({(_P, _A), (_P, _F), (_A, _F)}),
}


class ArbitrationUnprovable(ValueError):
    """A live decision cannot be expressed as a satisfiable statement.

    Raised by the builder when the quantized base verdict is STRICTER than the
    live verdict (the float→fixed quantization collar crossed a threshold).
    This is the fail-closed completeness boundary: the arbiter refuses to
    prove rather than emit an inconsistent statement. It never accepts the
    inverse direction (a flipped verdict stays UNSAT).
    """


# ── Statement ────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class LoweringStep:
    """One committed monotone-lowering step (from → to, with its reason)."""

    from_verdict: str
    to_verdict: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return {
            "from": self.from_verdict,
            "to": self.to_verdict,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ArbitrationStatement:
    """The all-public canonical statement the arbitration proof is over.

    Every field is public (mirrors ``ProvenanceStatement``: "Statement is all
    public"). Scores, weights, the fused score, and thresholds are fixed-point
    integers at ``scale``. ``canonical_bytes`` follows the ledger's stable-JSON
    idiom (sort_keys + compact separators) so offline re-verification is
    byte-stable.
    """

    stream_scores_q: tuple[tuple[str, int], ...]
    weights_q: tuple[tuple[str, int], ...]
    fused_q: int
    permit_q: int
    forbid_q: int
    router_skipped: bool
    deny_floor: bool
    floor_sources: tuple[str, ...]
    quarantine_pin: bool
    chain: tuple[LoweringStep, ...]
    claimed_verdict: str
    request_id: str
    policy_id: str
    policy_version: str
    content_sha256: str
    determinism_fingerprint: str
    version: str = STATEMENT_VERSION
    scale: int = SCALE

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {
                "version": self.version,
                "scale": self.scale,
                "stream_scores_q": [[k, v] for k, v in self.stream_scores_q],
                "weights_q": [[k, v] for k, v in self.weights_q],
                "fused_q": self.fused_q,
                "permit_q": self.permit_q,
                "forbid_q": self.forbid_q,
                "router_skipped": self.router_skipped,
                "deny_floor": self.deny_floor,
                "floor_sources": list(self.floor_sources),
                "quarantine_pin": self.quarantine_pin,
                "chain": [step.as_dict() for step in self.chain],
                "claimed_verdict": self.claimed_verdict,
                "request_id": self.request_id,
                "policy_id": self.policy_id,
                "policy_version": self.policy_version,
                "content_sha256": self.content_sha256,
                "determinism_fingerprint": self.determinism_fingerprint,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def sha256_hex(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class HiddenScoreArbitrationStatement(ArbitrationStatement):
    """A HIDING arbitration statement: it OMITS the cleartext fused score (and
    the raw per-stream scores) from its public serialization, publishing only
    the verdict + thresholds + weights + structural flags + the monotone chain.

    Same fields and ``__init__`` as ``ArbitrationStatement`` (the prover still
    holds ``fused_q`` and ``stream_scores_q`` as the PRIVATE witness the ZK
    backend consumes), but ``canonical_bytes``/``to_dict`` never emit them. The
    verdict the hidden fused score yields under the public thresholds is exposed
    as the public ``verdict`` field and bound by the ``schnorr-verdict-zk-v1``
    proof (``zk_fuse.prove_verdict`` / ``verify_verdict``). Hiding is realized
    here: an accepting proof + this public dict reveal the verdict, never the
    fused score (two distinct fused scores in the same verdict region both
    verify).

    Honesty: this is the hiding deployment the module banner describes. The
    structural invariants (floor/pin/chain legality) are still PUBLIC and
    checked by ``evaluate_relation``; only the fuse arithmetic and its fused
    score are inside the ZK proof. Same maturity collar as the fuse path:
    research-early, unaudited, non-succinct, pre-quantum.
    """

    @property
    def verdict(self) -> str:
        """The THRESHOLD verdict the (hidden) fused score yields — exactly what
        ``zk_fuse.prove_verdict`` proves and the public input the verifier binds
        against. This is the base-threshold stage only; the deny-floor,
        quarantine pin and monotone chain are applied PUBLICLY on top of it (see
        ``base_verdict`` / ``evaluate_relation``)."""
        return threshold_verdict(self.fused_q, self.permit_q, self.forbid_q)

    def canonical_bytes(self) -> bytes:
        # Deliberately OMITS ``fused_q`` and ``stream_scores_q`` (the hidden
        # witness). Publishes the bound ``verdict`` plus everything structural so
        # offline re-verification of the invariants stays byte-stable. The
        # ``hiding`` marker keeps this digest distinct from the public variant's.
        return json.dumps(
            {
                "hiding": True,
                "version": self.version,
                "scale": self.scale,
                "weights_q": [[k, v] for k, v in self.weights_q],
                "verdict": self.verdict,
                "permit_q": self.permit_q,
                "forbid_q": self.forbid_q,
                "router_skipped": self.router_skipped,
                "deny_floor": self.deny_floor,
                "floor_sources": list(self.floor_sources),
                "quarantine_pin": self.quarantine_pin,
                "chain": [step.as_dict() for step in self.chain],
                "claimed_verdict": self.claimed_verdict,
                "request_id": self.request_id,
                "policy_id": self.policy_id,
                "policy_version": self.policy_version,
                "content_sha256": self.content_sha256,
                "determinism_fingerprint": self.determinism_fingerprint,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


def _is_hiding(statement: ArbitrationStatement) -> bool:
    """Whether the statement is the hiding (fused-score-omitting) variant."""
    return isinstance(statement, HiddenScoreArbitrationStatement)


# ── Fixed-point helpers ──────────────────────────────────────────────────────


def quantize(value: float) -> int:
    """Quantize a [0, 1] float to fixed point at SCALE, genuine round-half-up
    (``math.floor(x + 0.5)``) — the same tie-break ``canonical_fuse`` uses.
    Python's built-in ``round`` is half-to-even and would disagree with the
    fuse at exact half-quantum ties."""
    return math.floor(float(value) * SCALE + 0.5)


def canonical_fuse(
    stream_scores_q: tuple[tuple[str, int], ...],
    weights_q: tuple[tuple[str, int], ...],
) -> int:
    """The fuse step in exact integer arithmetic: round(Σ w·s / SCALE), clamped.

    This is the arithmetic an in-circuit fixed-point fuse would perform; it is
    deliberately NOT a float dot product.
    """
    weights = dict(weights_q)
    acc = sum(score * weights.get(name, 0) for name, score in stream_scores_q)
    fused = (acc + SCALE // 2) // SCALE
    return min(SCALE, max(0, fused))


def threshold_verdict(fused_q: int, permit_q: int, forbid_q: int) -> str:
    """The threshold map, FORBID checked first — mirrors the R2-before-R4
    ordering in ``router._determine_verdict`` (a score sitting exactly on a
    degenerate permit==forbid boundary resolves to FORBID, as live)."""
    if fused_q >= forbid_q:
        return Verdict.FORBID.value
    if fused_q <= permit_q:
        return Verdict.PERMIT.value
    return Verdict.ABSTAIN.value


def base_verdict(statement: ArbitrationStatement) -> str:
    """Deny-floor → FORBID; else quarantine pin → ABSTAIN (router R0 returns
    ABSTAIN *before* the threshold check, so it pins, it does not lower);
    else the threshold map.

    Deny-before-pin matches the live order for every floor source except
    ``agent_capability_violation``: live R0 checks QUARANTINED → ABSTAIN
    *before* the capability FORBID (router.py), so that branch is unreachable
    for a quarantined agent. The relation therefore makes the
    (quarantine_pin ∧ capability-source) combination UNSAT
    (``quarantine_precedes_capability_floor``) rather than resolving it."""
    if statement.deny_floor:
        return Verdict.FORBID.value
    if statement.quarantine_pin:
        return Verdict.ABSTAIN.value
    if _is_hiding(statement):
        # The fused score is hidden; the threshold-stage verdict is the public,
        # ZK-bound ``verdict`` field (bound by the schnorr-verdict-zk-v1 proof),
        # NOT a recomputation from a cleartext fused_q the verifier never sees.
        return statement.verdict
    return threshold_verdict(
        statement.fused_q, statement.permit_q, statement.forbid_q
    )


# ── The relation, UNSAT-when-violated ────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RelationResult:
    """Outcome of evaluating the arbitration relation on one statement.

    ``satisfied=False`` means UNSAT — at least one named constraint is
    violated and the verifier must reject. All constraints are evaluated (no
    short-circuit) so an auditor sees the full violation set.
    """

    satisfied: bool
    violations: tuple[str, ...] = field(default_factory=tuple)


def evaluate_relation(statement: ArbitrationStatement) -> RelationResult:
    """Evaluate the arbitration relation. Pure, deterministic, integer-exact.

    Satisfiable iff the claimed verdict is exactly what the committed inputs
    yield: base verdict (floor / pin / threshold over the canonical fuse)
    transformed by a well-formed, strictly-lowering, transition-legal chain.
    """
    v: list[str] = []

    if statement.version != STATEMENT_VERSION:
        v.append("bad_version")
    if statement.scale != SCALE:
        v.append("bad_scale")

    if tuple(k for k, _ in statement.stream_scores_q) != STREAM_NAMES:
        v.append("bad_stream_keys")
    if tuple(k for k, _ in statement.weights_q) != STREAM_NAMES:
        v.append("bad_weight_keys")

    hiding = _is_hiding(statement)
    # On the hiding path the per-stream scores and the fused score are the
    # PRIVATE witness — the verifier never sees them as cleartext quantities,
    # and the schnorr-verdict-zk-v1 range proofs (not this re-eval) bound them.
    # Only the PUBLIC quantities are range-checked here.
    quantities = [w for _, w in statement.weights_q] + [
        statement.permit_q,
        statement.forbid_q,
    ]
    if not hiding:
        quantities += [s for _, s in statement.stream_scores_q]
        quantities.append(statement.fused_q)
    if any(not (0 <= q <= SCALE) for q in quantities):
        v.append("value_out_of_range")
    if statement.permit_q > statement.forbid_q:
        v.append("thresholds_inverted")

    weight_sum = sum(w for _, w in statement.weights_q)
    if abs(weight_sum - SCALE) > WEIGHT_SUM_TOL_Q:
        v.append("weight_sum_out_of_tolerance")

    # C1 — the fuse. On the short-circuit path the router never ran, so the
    # live pipeline pins final_score = 1.0; otherwise the committed fused
    # score must EXACTLY equal the canonical integer fuse of the committed
    # streams (UNSAT on any deviation — no tolerance inside the relation).
    #
    # HIDING PATH: there is no cleartext fused score or cleartext scores to
    # re-fuse — the fuse arithmetic (Σ w·s → fused → threshold verdict) is what
    # the schnorr-verdict-zk-v1 proof discharges over the PRIVATE witness, and
    # ``base_verdict`` consumes the ZK-bound public ``verdict`` field directly.
    # So the cleartext fuse re-check is NOT performed here; it is replaced by the
    # ZK proof (verified in ``verify_arbitration``). Only the public verdict
    # vocabulary is validated, so a bogus ``verdict`` string still fails.
    if statement.router_skipped:
        if not statement.deny_floor or not (
            set(statement.floor_sources) & _SHORT_CIRCUIT_SOURCES
        ):
            v.append("short_circuit_without_structural_cause")
        if not hiding and statement.fused_q != SCALE:
            v.append("short_circuit_fused_not_max")
    elif hiding:
        if statement.verdict not in _SEVERITY:
            v.append("hiding_verdict_unknown")
    else:
        if statement.fused_q != canonical_fuse(
            statement.stream_scores_q, statement.weights_q
        ):
            v.append("fuse_mismatch")

    # C2 — the deny-floor is structural by construction.
    if statement.deny_floor:
        if not statement.floor_sources:
            v.append("floor_without_structural_source")
        if any(s not in FLOOR_SOURCES for s in statement.floor_sources):
            v.append("floor_source_unknown")
    elif statement.floor_sources:
        v.append("floor_sources_without_deny_floor")
    # Live R0 checks the quarantine ABSTAIN before the capability FORBID, so a
    # quarantined agent's capability branch is unreachable — the combination
    # cannot describe a live decision and is UNSAT (see base_verdict).
    if statement.quarantine_pin and (
        "agent_capability_violation" in statement.floor_sources
    ):
        v.append("quarantine_precedes_capability_floor")

    # C3 — verdict vocabulary.
    if statement.claimed_verdict not in _SEVERITY:
        v.append("claimed_verdict_unknown")

    # C4 — the chain: contiguous from base, strictly lowering, per-reason
    # transition-legal, bounded length (PERMIT→ABSTAIN→FORBID is the longest
    # possible strict descent).
    base = base_verdict(statement)
    if len(statement.chain) > 2:
        v.append("chain_too_long")
    cursor = base
    for step in statement.chain:
        if step.from_verdict != cursor:
            v.append("chain_discontinuous")
            break
        if (
            step.from_verdict not in _SEVERITY
            or step.to_verdict not in _SEVERITY
        ):
            v.append("chain_verdict_unknown")
            break
        if _SEVERITY[step.to_verdict] <= _SEVERITY[step.from_verdict]:
            v.append("chain_step_not_lowering")
            break
        allowed = LOWERING_TRANSITIONS.get(step.reason)
        if allowed is None:
            v.append("chain_reason_unknown")
            break
        if (step.from_verdict, step.to_verdict) not in allowed:
            v.append("chain_transition_not_allowed")
            break
        cursor = step.to_verdict

    # C5 — the claimed verdict is exactly the chain's end. A flipped verdict
    # lands here (or in the floor check below) and makes the system UNSAT.
    if statement.claimed_verdict in _SEVERITY and cursor != statement.claimed_verdict:
        v.append("claimed_verdict_mismatch")

    # C6 — explicit floor check (already implied by C4+C5 since nothing lowers
    # below FORBID; named separately so a floor escape is audit-legible).
    if statement.deny_floor and statement.claimed_verdict != Verdict.FORBID.value:
        v.append("deny_floor_requires_forbid")

    return RelationResult(satisfied=not v, violations=tuple(v))


def expected_claimed_verdict(statement: ArbitrationStatement) -> str:
    """The unique claimed verdict that can satisfy the relation for these
    committed inputs (base transformed by the committed chain). Test helper —
    the verifier never trusts this; it re-evaluates the full relation."""
    cursor = base_verdict(statement)
    for step in statement.chain:
        cursor = step.to_verdict
    return cursor


# ── Prove / verify over the zkprov backend dispatcher, hard-gated ────────────


def _shim_allowed() -> bool:
    """Whether the keyed-hash stand-in may validate at all. Default-deny,
    tests/dev opt-in only — the nanozk deactivation-gate idiom verbatim."""
    return os.environ.get(_ALLOW_SHIM_ENV, "0") == "1"


@dataclass(frozen=True, slots=True)
class ArbitrationEnvelope:
    """Wire envelope for one arbitration artifact.

    Carries only the backend tag, the backend's bytes, and the statement
    digest. It deliberately does NOT carry prover-asserted trust flags
    (stand-in / regulator-grade are computed by the VERIFIER from the backend
    tag — a prover cannot upgrade its own artifact).
    """

    backend: str
    proof_hex: str
    statement_sha256: str
    format: str = ENVELOPE_FORMAT

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "format": self.format,
                "backend": self.backend,
                "proof_hex": self.proof_hex,
                "statement_sha256": self.statement_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ArbitrationEnvelope":
        data = json.loads(raw.decode("utf-8"))
        return cls(
            backend=data["backend"],
            proof_hex=data["proof_hex"],
            statement_sha256=data["statement_sha256"],
            format=data["format"],
        )


@dataclass(frozen=True, slots=True)
class ArbitrationVerification:
    """Verifier output. ``is_valid=False`` carries a named ``reason``.

    ``stand_in=True`` means the artifact is the keyed-hash stand-in — never a
    proof, never ``regulator_grade``, valid only under the tests-only env flag.
    """

    is_valid: bool
    reason: str | None
    backend: str | None
    stand_in: bool
    regulator_grade: bool
    relation: RelationResult | None
    seal: "SealBinding | None" = None
    note: str = ""


def prove_arbitration(
    statement: ArbitrationStatement,
    *,
    backend_id: ProofBackendId | str = ProofBackendId.DETERMINISTIC_SHIM_V1,
) -> ArbitrationEnvelope:
    """Produce an arbitration artifact for a SATISFIABLE statement.

    Dispatches through the zkprov backend registry with
    ``allow_shim_fallback=False`` — a configured real backend that is missing
    raises ``BackendUnavailable`` loudly instead of silently downgrading to
    the stand-in. With the default shim backend the artifact is a keyed-hash
    STAND-IN (HMAC over the statement bytes), not a proof; the verifier's
    hard gate enforces that distinction.

    Refuses (``ValueError``) to attest an UNSAT statement: the prover does not
    mint artifacts for relations it can itself see are violated.
    """
    relation = evaluate_relation(statement)
    if not relation.satisfied:
        raise ValueError(
            "refusing to attest an UNSAT arbitration statement: "
            f"{', '.join(relation.violations)}"
        )
    # The hiding variant has a fused score to HIDE, so when the caller left the
    # default (shim) in place we dispatch the real schnorr-verdict-zk-v1 backend
    # — the public/legacy ArbitrationStatement keeps the shim default so
    # capstone/compose.py's green_test_mode path is unchanged. A router-skipped
    # statement has no fuse, so it stays on the requested backend (the verdict
    # backend would refuse it). An explicitly-requested backend always wins.
    if (
        _is_hiding(statement)
        and not statement.router_skipped
        and backend_id == ProofBackendId.DETERMINISTIC_SHIM_V1
    ):
        backend_id = ProofBackendId.SCHNORR_VERDICT_ZK_V1
    backend = resolve_backend_with_fallback(backend_id, allow_shim_fallback=False)
    proof_bytes = backend.prove(
        statement=statement, private_witness=statement.canonical_bytes()
    )
    return ArbitrationEnvelope(
        backend=backend.backend_id.value,
        proof_hex=proof_bytes.hex(),
        statement_sha256=statement.sha256_hex(),
    )


def verify_arbitration(
    statement: ArbitrationStatement,
    envelope: ArbitrationEnvelope | bytes,
    *,
    ledger: SealedFactLedger | None = None,
    expected_public_key_pem: bytes | None = None,
) -> ArbitrationVerification:
    """Verify one arbitration artifact against its statement. Never raises.

    Check order (first failure names the reason):
      1. envelope parse + format,
      2. statement binding (digest match),
      3. backend tag known,
      4. **HARD GATE** — a stand-in artifact is invalid-by-default
         (``zkpdp_shim_not_a_real_proof``) unless ``TEX_ZKPDP_ALLOW_SHIM=1``,
      5. the arbitration relation itself, re-evaluated deterministically
         (load-bearing on the shim path — a flipped verdict is rejected here
         even by an adversary holding the shim's dev key),
      6. the backend's own verify (HMAC for the shim; real backends raise
         ``BackendUnavailable`` today → invalid, RUNTIME-DEPENDENT on M0c),
      7. when ``ledger`` is supplied: the M0 seal binding, fail-closed. A
         sealed DECISION fact that disagrees with the claimed verdict rejects
         (``zkpdp_sealed_verdict_mismatch`` — closes the chain-omission
         residual named in the module banner); a matching fact whose ledger
         hash chain fails replay rejects (``zkpdp_sealed_chain_broken`` —
         integrity), as does a failing signature check
         (``zkpdp_sealed_signature_invalid`` — against
         ``expected_public_key_pem`` when pinned, else the ledger's own key,
         which is only self-consistency: authorship of *Tex* is attested only
         when you PIN Tex's public key). ``not_sealed`` stays valid (the
         normal TEX_SEAL_DECISIONS-off state, never tamper evidence).
    """
    if isinstance(envelope, (bytes, bytearray)):
        try:
            envelope = ArbitrationEnvelope.from_bytes(bytes(envelope))
        except (KeyError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return ArbitrationVerification(
                is_valid=False,
                reason="zkpdp_envelope_malformed",
                backend=None,
                stand_in=False,
                regulator_grade=False,
                relation=None,
            )
    if envelope.format != ENVELOPE_FORMAT:
        return ArbitrationVerification(
            is_valid=False,
            reason="zkpdp_envelope_format_unknown",
            backend=envelope.backend,
            stand_in=False,
            regulator_grade=False,
            relation=None,
        )

    if envelope.statement_sha256 != statement.sha256_hex():
        return ArbitrationVerification(
            is_valid=False,
            reason="zkpdp_statement_binding_mismatch",
            backend=envelope.backend,
            stand_in=False,
            regulator_grade=False,
            relation=None,
        )

    try:
        backend_id = ProofBackendId(envelope.backend)
    except ValueError:
        return ArbitrationVerification(
            is_valid=False,
            reason="zkpdp_unknown_backend",
            backend=envelope.backend,
            stand_in=False,
            regulator_grade=False,
            relation=None,
        )
    stand_in = backend_id is ProofBackendId.DETERMINISTIC_SHIM_V1

    # ── HARD GATE (inside the verifier, the nanozk discipline) ──
    if stand_in and not _shim_allowed():
        return ArbitrationVerification(
            is_valid=False,
            reason=SHIM_GATE_REASON,
            backend=envelope.backend,
            stand_in=True,
            regulator_grade=False,
            relation=None,
            note=(
                "keyed-hash stand-in refused: set TEX_ZKPDP_ALLOW_SHIM=1 "
                "(tests/dev only) to validate the wiring; this is never a proof"
            ),
        )

    relation = evaluate_relation(statement)
    if not relation.satisfied:
        return ArbitrationVerification(
            is_valid=False,
            reason="zkpdp_arbitration_relation_unsat:"
            + ",".join(relation.violations),
            backend=envelope.backend,
            stand_in=stand_in,
            regulator_grade=False,
            relation=relation,
        )

    try:
        backend = get_proof_backend(backend_id)
        backend_ok = backend.verify(
            statement=statement, proof_bytes=bytes.fromhex(envelope.proof_hex)
        )
    except BackendUnavailable:
        return ArbitrationVerification(
            is_valid=False,
            reason="zkpdp_backend_unavailable_runtime_dependent",
            backend=envelope.backend,
            stand_in=stand_in,
            regulator_grade=False,
            relation=relation,
            note=(
                "real-backend verification is RUNTIME-DEPENDENT (ezkl/Halo2 + "
                "circuit artifact, M0c) — fail-closed until it lands"
            ),
        )
    except ValueError:
        backend_ok = False
    if not backend_ok:
        return ArbitrationVerification(
            is_valid=False,
            reason=(
                "zkpdp_stand_in_tag_mismatch"
                if stand_in
                else "zkpdp_proof_invalid"
            ),
            backend=envelope.backend,
            stand_in=stand_in,
            regulator_grade=False,
            relation=relation,
        )

    seal: SealBinding | None = None
    if ledger is not None:
        seal = check_seal_binding(
            ledger, statement, expected_public_key_pem=expected_public_key_pem
        )
        if seal.status == "sealed_mismatch":
            return ArbitrationVerification(
                is_valid=False,
                reason="zkpdp_sealed_verdict_mismatch:"
                + ",".join(seal.mismatches),
                backend=envelope.backend,
                stand_in=stand_in,
                regulator_grade=False,
                relation=relation,
                seal=seal,
            )
        if seal.status == "verification_error":
            return ArbitrationVerification(
                is_valid=False,
                reason="zkpdp_seal_binding_error",
                backend=envelope.backend,
                stand_in=stand_in,
                regulator_grade=False,
                relation=relation,
                seal=seal,
            )
        # Fail-closed on the seal's own crypto: a matching fact inside a
        # ledger whose chain replay fails (INTEGRITY) or whose signatures do
        # not verify (key self-consistency, or AUTHORSHIP when pinned) must
        # never validate.
        if seal.status == "sealed_match" and seal.chain_intact is not True:
            return ArbitrationVerification(
                is_valid=False,
                reason="zkpdp_sealed_chain_broken",
                backend=envelope.backend,
                stand_in=stand_in,
                regulator_grade=False,
                relation=relation,
                seal=seal,
            )
        if seal.status == "sealed_match" and seal.signatures_valid is not True:
            return ArbitrationVerification(
                is_valid=False,
                reason="zkpdp_sealed_signature_invalid",
                backend=envelope.backend,
                stand_in=stand_in,
                regulator_grade=False,
                relation=relation,
                seal=seal,
            )

    return ArbitrationVerification(
        is_valid=True,
        reason=None,
        backend=envelope.backend,
        stand_in=stand_in,
        regulator_grade=is_regulator_grade(backend_id) and not stand_in,
        relation=relation,
        seal=seal,
        note=(
            "keyed-hash stand-in verified under TEX_ZKPDP_ALLOW_SHIM=1 — "
            "NOT a ZK proof, no hiding, no soundness against the key holder"
            if stand_in
            else (
                "schnorr-fuse-zk-v1: real discrete-log proof of the FUSE kernel "
                "over PRIVATE per-stream scores (research-early/unaudited, "
                "2048-bit, pre-quantum). Proves only the weighted-fusion "
                "arithmetic → fused_q; threshold/floor/pin/chain stay public in "
                "evaluate_relation. Hiding is realized when the statement omits "
                "raw scores."
                if backend_id is ProofBackendId.SCHNORR_FUSE_ZK_V1
                else (
                    "schnorr-verdict-zk-v1: real discrete-log proof of the "
                    "FUSE-path THRESHOLD verdict over PRIVATE per-stream scores, "
                    "ALSO hiding the fused score (same toolkit/maturity as "
                    "schnorr-fuse-zk-v1: research-early/unaudited, NON-succinct, "
                    "2048-bit, pre-quantum, no soundness against the dev key "
                    "holder). Proves only the weighted-fusion → threshold-verdict "
                    "arithmetic; floor/pin/chain stay public in "
                    "evaluate_relation. Hiding is realized on this path — the "
                    "public statement omits both the raw scores and the fused "
                    "score."
                    if backend_id is ProofBackendId.SCHNORR_VERDICT_ZK_V1
                    else ""
                )
            )
        ),
    )


# ── Building a statement from a live decision ────────────────────────────────


def _infer_lowering_reason(decision: Decision, base: str, final: str) -> str:
    """Best-effort attribution of a live lowering to a named signal, from the
    decision's recorded reasons. Attribution is advisory (the relation only
    enforces transition legality); unmatched lowerings stay visibly
    ``unattributed_lowering``."""
    text = " | ".join(decision.reasons).casefold()
    flags = " | ".join(decision.uncertainty_flags).casefold()
    if "semantic dominance override" in text:
        return "semantic_dominance_override"
    if "crc" in text or "conformal" in text or "crc" in flags:
        return "crc_demotion"
    if "contract soft violation" in text:
        return "soft_contract_violation"
    if "path policy soft violation" in text:
        return "path_policy_warn"
    if "pro2guard" in text or "predictive" in text:
        return "predictive_hold"
    if "risk spine" in text or "e-process" in text or "risk_spine" in flags:
        return "risk_spine"
    if "pq" in flags or "post-quantum" in text or "pq-durable" in text:
        return "pq_durability"
    if final == Verdict.FORBID.value:
        # The only non-floor live paths that lower INTO FORBID are the R1/R2
        # semantic escalations.
        return "semantic_forbid_escalation"
    if base == Verdict.PERMIT.value and final == Verdict.ABSTAIN.value:
        return "router_abstain_trigger"
    return "unattributed_lowering"


def _legal_lowering_reason(decision: Decision, base: str, final: str) -> str:
    """Inferred reason, demoted to ``unattributed_lowering`` when the inferred
    attribution is not transition-legal for (base → final) — attribution is
    advisory and must never make a true live verdict unprovable."""
    reason = _infer_lowering_reason(decision, base, final)
    if (base, final) not in LOWERING_TRANSITIONS[reason]:
        return "unattributed_lowering"
    return reason


def build_statement_from_decision(
    decision: Decision,
    *,
    policy: PolicySnapshot,
) -> ArbitrationStatement:
    """Map one finalized live ``Decision`` (+ its exact policy snapshot) to a
    satisfiable ``ArbitrationStatement``.

    Pure read-only consumption — never touches the PDP. Raises
    ``ArbitrationUnprovable`` when the fixed-point base verdict is stricter
    than the live verdict (the quantization collar): refusing to prove is the
    fail-closed completeness boundary documented in the module banner.
    """
    if (
        policy.policy_id != decision.policy_id
        or policy.version != decision.policy_version
    ):
        raise ValueError(
            "policy snapshot does not match the decision: "
            f"decision={decision.policy_id}@{decision.policy_version}, "
            f"given={policy.policy_id}@{policy.version}"
        )

    pdp_meta = decision.metadata.get("pdp") or {}
    contracts = pdp_meta.get("contracts") or {}
    path_policy = pdp_meta.get("path_policy") or {}
    structural = pdp_meta.get("structural_floor") or {}
    deterministic = pdp_meta.get("deterministic") or {}
    agent = pdp_meta.get("agent") or {}

    floor_sources: list[str] = []
    if contracts.get("has_hard_violation"):
        floor_sources.append("contract_hard_violation")
    if path_policy.get("has_block"):
        floor_sources.append("path_policy_block")
    if structural.get("fired"):
        floor_sources.append("structural_specialist_deny")
    router_skipped = bool(floor_sources)  # the pdp.py hard_violation branch
    if deterministic.get("blocked"):
        floor_sources.append("deterministic_block")
    # Live R0 order: the quarantine ABSTAIN is checked BEFORE the capability
    # FORBID (router.py), so a quarantined agent pins ABSTAIN and its
    # capability branch never runs. The short-circuit and deterministic-block
    # floors above all precede the quarantine check live, so they win the pin.
    agent_present_meta = bool(agent.get("agent_present"))
    quarantine_pin = bool(
        not floor_sources
        and agent_present_meta
        and (agent.get("identity") or {}).get("lifecycle_status") == "QUARANTINED"
    )
    if (
        not quarantine_pin
        and agent_present_meta
        and (agent.get("capability") or {}).get("violated_dimensions")
    ):
        floor_sources.append("agent_capability_violation")
    deny_floor = bool(floor_sources)

    agent_present = any(k in decision.scores for k in STREAM_NAMES[4:])
    stream_scores_q = tuple(
        (name, quantize(decision.scores.get(name, 0.0))) for name in STREAM_NAMES
    )
    # Reused verbatim from the router (its agent-absent renormalization) so the
    # committed weights are the ones the live fuse actually used.
    weights = DecisionRouter._effective_weights(
        policy=policy, agent_present=agent_present
    )
    weights_q = tuple(
        (name, quantize(weights.get(name, 0.0))) for name in STREAM_NAMES
    )

    fused_q = (
        SCALE if router_skipped else canonical_fuse(stream_scores_q, weights_q)
    )
    recorded_q = quantize(decision.final_score)
    if abs(fused_q - recorded_q) > BRIDGE_TOL_Q:
        raise ArbitrationUnprovable(
            "float→fixed bridge exceeded: canonical fuse "
            f"{fused_q} vs recorded final_score {recorded_q} "
            f"(tolerance {BRIDGE_TOL_Q} quanta)"
        )

    permit_q = quantize(policy.permit_threshold)
    forbid_q = quantize(policy.forbid_threshold)

    final = decision.verdict.value
    skeleton = ArbitrationStatement(
        stream_scores_q=stream_scores_q,
        weights_q=weights_q,
        fused_q=fused_q,
        permit_q=permit_q,
        forbid_q=forbid_q,
        router_skipped=router_skipped,
        deny_floor=deny_floor,
        floor_sources=tuple(floor_sources),
        quarantine_pin=quarantine_pin,
        chain=(),
        claimed_verdict=final,
        request_id=str(decision.request_id),
        policy_id=decision.policy_id,
        policy_version=decision.policy_version,
        content_sha256=decision.content_sha256,
        determinism_fingerprint=decision.determinism_fingerprint,
    )
    base = base_verdict(skeleton)

    if _SEVERITY[final] < _SEVERITY[base]:
        raise ArbitrationUnprovable(
            f"live verdict {final} is more permissive than the fixed-point "
            f"base {base}: quantization collar crossed a threshold; refusing "
            "to prove (fail-closed completeness boundary)"
        )
    if final == base:
        return skeleton

    step = LoweringStep(
        from_verdict=base,
        to_verdict=final,
        reason=_legal_lowering_reason(decision, base, final),
    )
    return ArbitrationStatement(
        stream_scores_q=skeleton.stream_scores_q,
        weights_q=skeleton.weights_q,
        fused_q=skeleton.fused_q,
        permit_q=skeleton.permit_q,
        forbid_q=skeleton.forbid_q,
        router_skipped=skeleton.router_skipped,
        deny_floor=skeleton.deny_floor,
        floor_sources=skeleton.floor_sources,
        quarantine_pin=skeleton.quarantine_pin,
        chain=(step,),
        claimed_verdict=final,
        request_id=skeleton.request_id,
        policy_id=skeleton.policy_id,
        policy_version=skeleton.policy_version,
        content_sha256=skeleton.content_sha256,
        determinism_fingerprint=skeleton.determinism_fingerprint,
    )


# ── Sealed-decision binding (consume M0, fail-closed) ────────────────────────


@dataclass(frozen=True, slots=True)
class SealBinding:
    """Result of binding a statement to the M0 ``SealedFact(DECISION)`` trail.

    Statuses:
      * ``not_sealed`` — no ledger wired or no DECISION fact for this request.
        ``TEX_SEAL_DECISIONS`` is OFF by default and ``decision_ledger``
        defaults to ``None``, so this is a NORMAL state — never tamper
        evidence.
      * ``sealed_match`` — a sealed DECISION fact matches the statement's
        binding fields. ``chain_intact`` is the ledger hash chain replay
        (INTEGRITY); ``signatures_valid`` is the per-record ECDSA check
        (AUTHORSHIP). They are distinct claims; neither is correctness.
      * ``sealed_mismatch`` — a sealed fact exists but disagrees with the
        statement (the named fields are in ``mismatches``).
      * ``verification_error`` — the binding check itself failed; named, not
        silently swallowed, never raised into the caller.
    """

    status: str
    mismatches: tuple[str, ...] = field(default_factory=tuple)
    chain_intact: bool | None = None
    signatures_valid: bool | None = None
    record_sequence: int | None = None
    note: str = ""


def check_seal_binding(
    ledger: SealedFactLedger | None,
    statement: ArbitrationStatement,
    *,
    expected_public_key_pem: bytes | None = None,
) -> SealBinding:
    """Bind a statement to its sealed DECISION fact, fail-closed. Never raises.

    ``expected_public_key_pem`` pins the key the signature check runs against.
    Without it, ``signatures_valid`` is only the ledger's self-consistency
    with its OWN key — the seal proves authorship by *Tex* only when you pin
    Tex's public key.
    """
    if ledger is None:
        return SealBinding(
            status="not_sealed",
            note=(
                "no decision ledger wired (decision_ledger=None / "
                "TEX_SEAL_DECISIONS off) — a normal state, not tamper evidence"
            ),
        )
    try:
        records = ledger.list_by_kind(SealedFactKind.DECISION)
        matching = [
            r for r in records if r.fact.subject_id == statement.request_id
        ]
        if not matching:
            return SealBinding(
                status="not_sealed",
                note=(
                    "no SealedFact(DECISION) for this request — a normal "
                    "not-sealed state, not tamper evidence"
                ),
            )
        record = matching[-1]
        detail = record.fact.detail
        mismatches: list[str] = []
        if detail.get("verdict") != statement.claimed_verdict:
            mismatches.append("verdict")
        sealed_score_q = quantize(float(detail.get("final_score", -1.0)))
        if abs(sealed_score_q - statement.fused_q) > BRIDGE_TOL_Q:
            mismatches.append("final_score")
        if detail.get("policy_id") != statement.policy_id:
            mismatches.append("policy_id")
        if detail.get("policy_version") != statement.policy_version:
            mismatches.append("policy_version")
        if detail.get("content_sha256") != statement.content_sha256:
            mismatches.append("content_sha256")
        if (
            detail.get("determinism_fingerprint")
            != statement.determinism_fingerprint
        ):
            mismatches.append("determinism_fingerprint")
        if mismatches:
            return SealBinding(
                status="sealed_mismatch",
                mismatches=tuple(mismatches),
                record_sequence=record.sequence,
            )
        chain = ledger.verify_chain()
        signatures = ledger.verify_signatures(expected_public_key_pem)
        return SealBinding(
            status="sealed_match",
            chain_intact=bool(chain.get("intact")),
            signatures_valid=bool(signatures.get("valid")),
            record_sequence=record.sequence,
            note=(
                "chain_intact = ledger INTEGRITY (hash-chain replay); "
                "signatures_valid = per-record ECDSA-P256 against "
                + (
                    "the PINNED key (authorship of the key holder)"
                    if expected_public_key_pem is not None
                    else "the ledger's OWN key (self-consistency only — pin "
                    "Tex's key for an authorship claim)"
                )
                + "; neither is verdict correctness — that is this "
                "relation's job"
            ),
        )
    except Exception as exc:  # noqa: BLE001 — fail-closed, named, never raised
        return SealBinding(
            status="verification_error",
            note=f"seal binding check failed: {type(exc).__name__}: {exc}",
        )
