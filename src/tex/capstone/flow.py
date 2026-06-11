"""
Capstone flow — drives one mixed epoch through a REAL ledger-wired PDP and
hands the materials to the composer.

[Architecture: composition layer / demo runner core. Maturity: research-early.]

Everything below runs the live verdict path: the deterministic gate, the
specialist suite (including the action-class floor), the router, the
structural floor, CRC, the risk spine, the PQ-maturity hold, the attempt
hook, M0 decision sealing, the reflexive governor, the checkpoint publisher
and the witnesses are all the real wired modules. **The ONLY stub is the
LLM-provider seam** (``_PermitSemanticAnalyzer``): a deterministic semantic
provider recommending PERMIT with solid confidence so the routed baseline is
a real PERMIT the signals can lower — the same one stub the twelve-leap
composition suite and the zkpdp live cross-check use (see
``tests/test_wave2_twelveleap_composition.py``).

The epoch this flow drives, in order (each step's facts land on ONE
``SealedFactLedger`` chain):

  1. request A — a PQ-non-repudiation claim the live ECDSA-P256 signer
     cannot honor: L10 lowers PERMIT→ABSTAIN, seals the PQ-durable=false
     fact; the ABSTAIN carries the L8 hold.
  2. pre checkpoint, cosigned by three in-process witnesses (L6).
  3. the reflexive governor binds; a weakening activation through the real
     policy-store chokepoint is DENIED (L5); customer traffic continues
     under the binding: request B breaches the drift spine (L9, DRIFT fact)
     and lowers PERMIT→ABSTAIN.
  4. request C — THE capstone decision: a refund-without-identity-check
     carrying both the path-policy action graph and an IRREVERSIBLE x
     PUBLIC action-class step. The structural floor fires (L4): FORBID.
  5. the L12 seeded paraphrase neighborhood runs through the SAME PDP
     (every sample seals ATTEMPT+DECISION facts into the same epoch).
  6. the L7 adversary-completeness campaign runs its mutated attacks
     through the SAME PDP and is sealed onto the evidence chain (chain 2).
  7. the L11 spoken seal + entailment commitment land on the voice chain
     (chain 3), with a proof_ref back to C's DECISION fact (cross-chain).
  8. post checkpoint, cosigned; then ``compose_capstone`` verifies every
     property via its own module, seals the manifest into the chain, and
     witnesses the post-seal head.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from tex.adversarial.adaptive import AttackSeed, ScoreResult
from tex.adversarial.completeness import (
    run_certified_campaign,
    seal_certified_campaign,
)
from tex.bench.replay_trial import (
    PARAPHRASES,
    STRUCTURAL_METADATA,
    run_seeded_neighborhood_trial,
)
from tex.domain.evaluation import EvaluationRequest
from tex.domain.policy import PolicySnapshot
from tex.domain.verdict import Verdict
from tex.engine.pdp import PolicyDecisionPoint
from tex.engine.risk_spine import RiskSpine
from tex.evidence.seal import build_evidence_chain_signer
from tex.interchange.gix import CheckpointPublisher, Ed25519NoteSigner
from tex.interchange.gix_witness import Witness, gather_cosignatures
from tex.policies.defaults import build_default_policy
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind
from tex.selfgov.governor import bound_reflexive_governor
from tex.semantic.schema import (
    SemanticAnalysis,
    SemanticDimensionResult,
    SemanticVerdictRecommendation,
    semantic_dimensions,
)
from tex.stores.policy_store import InMemoryPolicyStore
from tex.voice.attestation import VoiceAttestor
from tex.voice.entailment_cert import (
    commitment_for_scorer,
    seal_entailment_commitment,
)
from tex.voice.voice_gate import NeuralNLIScorer

from tex.capstone.compose import (
    CapstoneMaterials,
    ComposeResult,
    compose_capstone,
)

# The capstone request carries BOTH structural carriers: the action-graph
# path policy (refund only after confirm_identity) AND the L4 lattice cell
# (IRREVERSIBLE x PUBLIC). Content is attacker-controlled; structure is not.
CAPSTONE_METADATA: dict = {
    **STRUCTURAL_METADATA,
    "action_class": {
        "steps": [{"reversibility": "IRREVERSIBLE", "blast_radius": "PUBLIC"}]
    },
}

GIX_ORIGIN = "tex.example/capstone-epoch"

# Env the test-mode halves need. The flow scopes them for its own duration —
# they are the HONEST opt-ins (L1 stand-in, L2 alg=none JWT), recorded as
# such in the manifest's caveats.
_FLOW_ENV = {
    "TEX_ZKPDP_ALLOW_SHIM": "1",
    "TEX_TEE_ATTESTATION_MODE": "test",
}


class _PermitSemanticAnalyzer:
    """THE one stub in the capstone flow — the LLM-provider seam.

    Deterministic semantic provider recommending PERMIT with solid
    confidence, so the routed baseline is a real PERMIT the L9/L10 signals
    can lower. The deterministic gate, specialists, router, floor, CRC and
    PDP all stay real (the twelve-leap suite's pattern, restated here on
    purpose: tests/factories.py is not importable from src/)."""

    def analyze(self, *, request, retrieval_context) -> SemanticAnalysis:
        dims = tuple(
            SemanticDimensionResult(
                dimension=dimension,
                score=0.05,
                confidence=0.8,
                summary=f"Deterministic capstone-stub result for {dimension}.",
                rationale=f"Deterministic capstone-stub rationale for {dimension}.",
                evidence_spans=(),
                matched_policy_clause_ids=(),
                uncertainty_flags=(),
            )
            for dimension in semantic_dimensions()
        )
        return SemanticAnalysis(
            dimension_results=dims,
            recommended_verdict=SemanticVerdictRecommendation(
                verdict=Verdict.PERMIT,
                confidence=0.9,
                summary="Deterministic capstone stub: recommend PERMIT.",
            ),
            overall_confidence=0.92,
            evidence_sufficiency=0.6,
            rationale_quality=0.55,
            summary="Deterministic PERMIT-recommending stub (LLM-provider seam).",
            provider_name="capstone-stub",
            model_name="deterministic-stub",
        )


def _strict_policy(version: str, *, active: bool = False) -> PolicySnapshot:
    return PolicySnapshot(
        policy_id="p",
        version=version,
        is_active=active,
        permit_threshold=0.30,
        forbid_threshold=0.70,
        minimum_confidence=0.50,
        blocked_terms=("ssn",),
        enabled_recognizers=("secrets",),
    )


def _weak_policy(version: str) -> PolicySnapshot:
    """Weakens vs ``_strict_policy`` on every named axis — the walk-down
    payload the reflexive governor must deny (the L5 suite's shape)."""
    return PolicySnapshot(
        policy_id="p",
        version=version,
        is_active=False,
        permit_threshold=0.69,
        forbid_threshold=0.71,
        minimum_confidence=0.0,
        blocked_terms=(),
        enabled_recognizers=(),
    )


def _make_request(content: str, metadata: dict) -> EvaluationRequest:
    return EvaluationRequest(
        request_id=uuid4(),
        action_type="outbound_message",
        content=content,
        recipient="external@example.com",
        channel="email",
        environment="production",
        metadata=metadata,
        policy_id=None,
        requested_at=datetime.now(UTC),
    )


@dataclass(slots=True)
class CapstoneFlowResult:
    """The driven epoch + the composed bundle, with the live handles the
    tamper matrix needs (witnesses keep protocol state; the log signer is
    what a rogue operator would hold)."""

    compose: ComposeResult
    materials: CapstoneMaterials
    work_dir: Path

    @property
    def bundle_dir(self) -> Path:
        return self.compose.bundle_dir

    @property
    def pins_path(self) -> Path:
        return self.compose.paths["pins.json"]


def run_capstone_flow(
    work_dir: str | Path,
    *,
    neighborhood_samples: int = 40,
    campaign_seeds: int = 8,
    campaign_query_budget: int = 60,
    trial_seed: int = 20260611,
) -> CapstoneFlowResult:
    """Drive the epoch, compose the object, return everything."""
    work = Path(work_dir)
    work.mkdir(parents=True, exist_ok=True)
    saved_env = {k: os.environ.get(k) for k in _FLOW_ENV}
    os.environ.update(_FLOW_ENV)
    try:
        return _run(work, neighborhood_samples, campaign_seeds,
                    campaign_query_budget, trial_seed)
    finally:
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _run(
    work: Path,
    neighborhood_samples: int,
    campaign_seeds: int,
    campaign_query_budget: int,
    trial_seed: int,
) -> CapstoneFlowResult:
    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(
        decision_ledger=ledger,
        risk_spine=RiskSpine(alpha=0.05, ledger=ledger),
        semantic_analyzer=_PermitSemanticAnalyzer(),
    )
    policy = build_default_policy()

    log_signer = Ed25519NoteSigner(GIX_ORIGIN)
    publisher = CheckpointPublisher(
        origin=GIX_ORIGIN,
        read_record_hashes=lambda: [r.record_hash for r in ledger.list_all()],
        signer=log_signer,
    )
    witnesses = tuple(
        Witness(
            f"capstone-w{i}.example/witness",
            trusted_logs={GIX_ORIGIN: publisher.log_verifier},
        )
        for i in range(1, 4)
    )

    # Controller state staged BEFORE binding (saves while bound would be
    # unsealed stage passes — the twelve-leap suite's discipline).
    store = InMemoryPolicyStore()
    store.save(_strict_policy("v1"))
    store.activate("v1")
    store.save(_weak_policy("v2"))

    # 1) request A — the PQ-non-repudiation claim (L10 + L8). Benign content
    # on purpose: the baseline must be a real PERMIT for the maturity signal
    # to be the thing that lowers it (monotone-lowering, PERMIT→ABSTAIN only).
    pq_result = pdp.evaluate(
        request=_make_request(
            "Quarterly customer newsletter draft for review.",
            {"pq_non_repudiation": True},
        ),
        policy=policy,
    )
    assert pq_result.decision.verdict is Verdict.ABSTAIN

    # 2) pre checkpoint (L6).
    cp_pre = gather_cosignatures(
        publisher.build_add_checkpoint_request(0), witnesses
    )
    cp_pre_size = len(ledger)

    # 3) the reflexive binding + the denied weakening + the drift breach.
    bind_sequence = len(ledger)
    with bound_reflexive_governor(pdp=pdp, ledger=ledger):
        gate_attempt_sequence = len(ledger)
        returned = store.activate("v2")
        ruling_sequence = len(ledger) - 1
        drift_result = pdp.evaluate(
            request=_make_request(
                "Quarterly customer outreach message.",
                {"risk_spine": {"observations": {"drift": 8.0}}},
            ),
            policy=policy,
        )
    unbind_sequence = len(ledger) - 1
    assert drift_result.decision.verdict is Verdict.ABSTAIN
    assert returned.is_active is False
    assert store.get_active().version == "v1"

    # 4) request C — THE capstone decision (L4 floor: FORBID).
    capstone_result = pdp.evaluate(
        request=_make_request(PARAPHRASES[0], dict(CAPSTONE_METADATA)),
        policy=policy,
    )
    assert capstone_result.decision.verdict is Verdict.FORBID

    # 5) L12 — the seeded neighborhood through the SAME PDP. The adapter
    # only re-shapes the call (`evaluate_action_command.execute`); every
    # sample seals its ATTEMPT+DECISION facts into the same epoch.
    trial_start = len(ledger)
    adapter = SimpleNamespace(
        evaluate_action_command=SimpleNamespace(
            execute=lambda req: pdp.evaluate(request=req, policy=policy)
        )
    )
    trial = run_seeded_neighborhood_trial(
        adapter, seed=trial_seed, n_samples=neighborhood_samples
    )
    trial_segment = (trial_start, len(ledger))

    # 6) L7 — the adaptive campaign through the SAME PDP. The scorer keeps
    # the structural metadata fixed: the attacker controls the content, not
    # the action graph (the replay-trial threat model).
    campaign_start = len(ledger)

    def scorer(content: str, metadata: dict | None = None) -> ScoreResult:
        res = pdp.evaluate(
            request=_make_request(content, dict(CAPSTONE_METADATA)),
            policy=policy,
        )
        return ScoreResult(res.decision.verdict, res.decision.final_score)

    seeds = tuple(
        AttackSeed(
            seed_id=f"capstone_structural_{i}",
            content=PARAPHRASES[i % len(PARAPHRASES)],
            defense_class="structural",
        )
        for i in range(campaign_seeds)
    )
    campaign = run_certified_campaign(
        seeds, scorer, alpha=0.05, query_budget=campaign_query_budget
    )
    campaign_segment = (campaign_start, len(ledger))
    evidence_signer = build_evidence_chain_signer(key_dir=str(work / "seal_keys"))
    campaign_records = seal_certified_campaign(campaign, signer=evidence_signer)

    # 7) L11 — the spoken seal (chain 3), with a proof_ref back to C's
    # DECISION fact, then the entailment commitment.
    decision_rec = next(
        r
        for r in reversed(ledger.list_all())
        if r.fact.kind is SealedFactKind.DECISION
        and r.fact.subject_id == str(capstone_result.decision.request_id)
    )
    attestor = VoiceAttestor()
    attestor.seal(
        transcript="capstone demo: read back the sealed verdict",
        routed_dimension="evidence",
        verdict=capstone_result.decision.verdict.value,
        answer=(
            f"The sealed verdict for request "
            f"{capstone_result.decision.request_id} is "
            f"{capstone_result.decision.verdict.value}. The hash chain "
            "proves integrity; each signature proves authorship of one "
            "record against the pinned key."
        ),
        object_=None,
        proof_ref={
            "kind": "sealed_fact",
            "request_id": str(capstone_result.decision.request_id),
            "record_hash": decision_rec.record_hash,
            "sequence": decision_rec.sequence,
        },
        gate={"scorer": "exact-match", "reason": "capstone-readback"},
    )
    commitment = commitment_for_scorer(NeuralNLIScorer())
    seal_entailment_commitment(attestor, commitment)

    # 8) post checkpoint over the full pre-seal epoch (L6).
    cp_post = gather_cosignatures(
        publisher.build_add_checkpoint_request(cp_pre_size), witnesses
    )

    materials = CapstoneMaterials(
        ledger=ledger,
        policy=policy,
        alpha=0.05,
        capstone_result=capstone_result,
        pq_result=pq_result,
        drift_result=drift_result,
        bind_sequence=bind_sequence,
        gate_attempt_sequence=gate_attempt_sequence,
        reflexive_sequence=gate_attempt_sequence + 1,
        ruling_sequence=ruling_sequence,
        unbind_sequence=unbind_sequence,
        trial_segment=trial_segment,
        campaign_segment=campaign_segment,
        store_active_version=store.get_active().version,
        returned_snapshot_active=returned.is_active,
        trial=trial,
        campaign=campaign,
        campaign_records=campaign_records,
        evidence_signer=evidence_signer,
        attestor=attestor,
        voice_commitment=commitment,
        publisher=publisher,
        log_signer=log_signer,
        witnesses=witnesses,
        cp_pre=cp_pre,
        cp_post=cp_post,
    )
    compose = compose_capstone(materials, work / "bundle")
    return CapstoneFlowResult(compose=compose, materials=materials, work_dir=work)


__all__ = [
    "CAPSTONE_METADATA",
    "CapstoneFlowResult",
    "GIX_ORIGIN",
    "run_capstone_flow",
]
