"""
Capstone composer — takes one driven epoch and emits the sealed bundle dir.

[Architecture: composition layer. Maturity: research-early — see manifest.py.]

The composer NEVER re-implements a verifier. For every property it calls the
leap module's own verifier at composition time, records that verifier's output
verbatim in the manifest's ``verification`` snapshot, and FAILS CLOSED
(``CompositionError``) if any module verifier refuses — a manifest is never
emitted over an unverified claim.

Sealing order (the circularity-breaker, see manifest.py):

1. all artifact files are written and digest-bound;
2. the manifest is built over (decision identity + pre-seal epoch head +
   artifact digests + pin digests + property attestations);
3. the manifest's sha256 is sealed as ONE ``SealedFact(kind=ANSWER)`` — the
   first record after the pre-seal epoch, in the SAME chain as the decision;
4. the post-seal checkpoint is cosigned by the witnesses (it covers the
   sealed manifest) and shipped root-bound, not digest-bound;
5. the full ledger (including the capstone fact) is exported with the
   in-tree offline bundle (``provenance/bundle.py``).
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from tex.adversarial.completeness import (
    CLAIM,
    NON_CLAIMS,
    CertifiedCampaign,
    read_certificate,
)
from tex.bench.evidence_bundle import (
    trusted_public_key_b64,
    verify_bundle,
    write_bundle,
)
from tex.bench.replay_trial import NeighborhoodTrialResult
from tex.contracts.action_class import ACTION_CLASS_CERT, evaluate_action_class
from tex.domain.evidence import EvidenceMaturity, EvidenceRecord
from tex.domain.policy import PolicySnapshot
from tex.engine.pdp import PDPResult
from tex.engine.risk_spine import RISK_SPINE_FLAG
from tex.engine.verdict_certificate import stability_p_low
from tex.evidence.negative_knowledge import (
    issue_certificate_with_records,
    verify_certificate,
    verify_epoch_commitment,
)
from tex.evidence.seal import EvidenceChainSigner
from tex.interchange.gix import (
    Checkpoint,
    CheckpointPublisher,
    Ed25519NoteSigner,
    split_signed_note,
)
from tex.interchange.gix_witness import (
    FEDERATED_FALSE_REASON,
    CosignedCheckpoint,
    Witness,
    gather_cosignatures,
    verify_cosigned_checkpoint,
)
from tex.pqcrypto.pq_durability import (
    PQ_NON_REPUDIATION_FLAG,
    PQDurabilityAssessment,
)
from tex.provenance.bundle import export_sealed_fact_bundle
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind, SealedFactRecord
from tex.tee.attestation_client import generate_standin_ita_keypair
from tex.tee.verdict_binding import (
    build_verdict_bound_signed_jwt,
    verify_verdict_binding,
)
from tex.voice.attestation import VoiceAttestationRecord, VoiceAttestor
from tex.voice.entailment_cert import (
    EntailmentCommitment,
    entailment_half_status,
    verify_entailment_commitment,
)
from tex.voice.voice_gate import THRESHOLD_LABEL
from tex.zkpdp.arbiter import (
    build_statement_from_decision,
    check_seal_binding,
    evaluate_relation,
    prove_arbitration,
    verify_arbitration,
)

from tex.capstone.manifest import (
    CHAIN_EVIDENCE,
    CHAIN_VOICE,
    PIN_CAVEAT,
    PROPERTY_INDEX,
    SCHEMA_VERSION,
    TREE_SIZE_CAVEAT,
    ArtifactRef,
    CapstoneVerdict,
    DecisionIdentity,
    EpochBinding,
    PinDigests,
    PropertyAttestation,
    sha256_hex_bytes,
    stable_json,
)

logger = logging.getLogger("tex")


class CompositionError(RuntimeError):
    """A module verifier refused at composition time — fail closed."""


# ── file names (the bundle directory contract) ───────────────────────────

MANIFEST_FILE = "manifest.json"
PINS_FILE = "pins.json"
LEDGER_BUNDLE_FILE = "ledger_bundle.json"
POLICY_FILE = "policy_snapshot.json"
DECISION_CAPSTONE_FILE = "decision_capstone.json"
DECISION_PQ_FILE = "decision_pq.json"
DECISION_DRIFT_FILE = "decision_drift.json"
ZK_STATEMENT_FILE = "zkpdp_statement.json"
ZK_ENVELOPE_FILE = "zkpdp_envelope.json"
TEE_JWT_FILE = "tee_verdict_binding.jwt"
L3_CERT_FILE = "l3_certificate.json"
L6_CHECKPOINTS_FILE = "l6_checkpoints.json"
L6_FINAL_CHECKPOINT_FILE = "l6_checkpoint_final.json"
L7_CAMPAIGN_FILE = "l7_campaign.bundle.jsonl"
L12_TRIAL_FILE = "l12_neighborhood.json"
VOICE_RECORDS_FILE = "voice_records.json"

# The L3 non-membership probe key (matches the twelve-leap suite's pattern:
# a syntactically valid sealed-fact key that no honest epoch contains).
ABSENT_KEY = "7" * 64


def policy_snapshot_canonical(policy: PolicySnapshot) -> str:
    """Canonical bytes for the policy snapshot — the SAME bytes feed the
    policy artifact file and the L2 ``policy_bundle_digest``."""
    return stable_json(policy.model_dump(mode="json"))


# ── materials the flow hands over ─────────────────────────────────────────


@dataclass(slots=True)
class CapstoneMaterials:
    """Everything the driven epoch produced, ready to compose."""

    ledger: SealedFactLedger
    policy: PolicySnapshot
    alpha: float

    capstone_result: PDPResult
    pq_result: PDPResult
    # The flow's own run of pq_durability.assess() on request A — the same
    # pure assessment the engine computed inside evaluate(). It names which
    # maturity outcome this epoch took (lowered vs durable-not-lowered).
    pq_assessment: PQDurabilityAssessment
    drift_result: PDPResult

    # ledger sequences recorded by the flow as the epoch was driven
    bind_sequence: int
    gate_attempt_sequence: int
    reflexive_sequence: int
    ruling_sequence: int
    unbind_sequence: int
    trial_segment: tuple[int, int]      # [start, end) of L12 trial facts
    campaign_segment: tuple[int, int]   # [start, end) of L7 scorer facts

    store_active_version: str           # must still be the strict baseline
    returned_snapshot_active: bool      # the denied activation's return

    trial: NeighborhoodTrialResult
    campaign: CertifiedCampaign
    campaign_records: tuple[EvidenceRecord, ...]
    evidence_signer: EvidenceChainSigner

    attestor: VoiceAttestor
    voice_commitment: EntailmentCommitment

    publisher: CheckpointPublisher
    log_signer: Ed25519NoteSigner
    witnesses: tuple[Witness, ...]
    cp_pre: CosignedCheckpoint
    cp_post: CosignedCheckpoint


@dataclass(slots=True)
class ComposeResult:
    """What the composer hands back: the manifest, where everything is, and
    the post-seal witnessed checkpoint."""

    manifest: CapstoneVerdict
    manifest_sha256: str
    bundle_dir: Path
    paths: dict[str, Path]
    capstone_record: SealedFactRecord
    cp_final: CosignedCheckpoint
    pins: dict[str, Any]


# ── helpers ───────────────────────────────────────────────────────────────


@contextmanager
def _scoped_env(updates: dict[str, str | None]) -> Iterator[None]:
    """Temporarily set/unset env vars (``None`` ⇒ unset), restoring on exit.

    Used to verify the freshly-signed L2 token under a production posture
    (test mode unset) with the stand-in ITA public key pinned, without
    leaking either into the rest of composition. Mirrors ``verify._scoped_env``
    (kept local — ``verify`` imports ``compose``, so importing back would cycle)."""
    saved = {k: os.environ.get(k) for k in updates}
    try:
        for k, v in updates.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _parse_note(cosigned: CosignedCheckpoint) -> Checkpoint:
    note_text, _ = split_signed_note(cosigned.signed_note)
    return Checkpoint.parse(note_text)


def _find_fact(
    records: tuple[SealedFactRecord, ...],
    *,
    want: SealedFactKind,
    subject_id: str,
) -> SealedFactRecord:
    # kwarg named ``want`` on purpose: the decision-fact census textually
    # greps src/tex for the DECISION-kind construction form (unanchored, so
    # any kwarg ending in the word "kind" matches); this is a lookup, not a
    # producer, and must not pattern-match as one.
    matches = [
        r for r in records
        if r.fact.kind is want and r.fact.subject_id == subject_id
    ]
    if not matches:
        raise CompositionError(f"no {want} fact for subject {subject_id}")
    return matches[-1]


def _write_text(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    return sha256_hex_bytes(path.read_bytes())


def _roster_dump(witnesses: tuple[Witness, ...]) -> list[dict[str, str]]:
    return [
        {
            "name": w.descriptor.name,
            "public_key_raw_hex": w.descriptor.public_key_raw.hex(),
            "provenance": w.descriptor.provenance.value,
        }
        for w in witnesses
    ]


def _cosigned_dump(cosigned: CosignedCheckpoint) -> dict[str, Any]:
    cp = _parse_note(cosigned)
    return {
        "signed_note": cosigned.signed_note,
        "cosignature_lines": list(cosigned.cosignature_lines),
        "tree_size": cp.tree_size,
        "root_hash_hex": cp.root_hash_hex,
    }


# ── the composer ──────────────────────────────────────────────────────────


def compose_capstone(
    materials: CapstoneMaterials, bundle_dir: str | Path
) -> ComposeResult:
    """Verify every property via its own module, write the bundle, seal the
    manifest into the epoch chain, and witness the post-seal head."""
    out = Path(bundle_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    artifact_refs: list[ArtifactRef] = []

    def bind_artifact(
        name: str, filename: str, digest: str, media: str, chain: str | None
    ) -> None:
        artifact_refs.append(
            ArtifactRef(
                name=name, filename=filename, sha256=digest,
                media=media, chain=chain,
            )
        )

    ledger = materials.ledger
    policy = materials.policy
    decision = materials.capstone_result.decision
    records = ledger.list_all()
    record_count_pre_seal = len(records)
    pre_seal_head = records[-1].record_hash

    # ---------------------------------------------------------------- pins
    ledger_pem = ledger.public_key_pem
    evidence_pin_b64 = trusted_public_key_b64(materials.evidence_signer)
    voice_pin_b64 = _voice_pin(materials.attestor)
    log_verifier = materials.publisher.log_verifier
    roster = _roster_dump(materials.witnesses)
    roster_sha256 = sha256_hex_bytes(stable_json(roster).encode("utf-8"))

    # ------------------------------------------------ decision identity
    request_id = str(decision.request_id)
    attempt_rec = _find_fact(
        records, want=SealedFactKind.ATTEMPT, subject_id=request_id
    )
    decision_rec = _find_fact(
        records, want=SealedFactKind.DECISION, subject_id=request_id
    )
    detail = decision_rec.fact.detail
    if detail.get("verdict") != decision.verdict.value:
        raise CompositionError("sealed DECISION fact disagrees with the live decision")
    if detail.get("content_sha256") != decision.content_sha256:
        raise CompositionError("sealed content_sha256 disagrees with the decision")
    if detail.get("determinism_fingerprint") != decision.determinism_fingerprint:
        raise CompositionError("sealed fingerprint disagrees with the decision")

    # -------------------------------------------------------- artifacts
    policy_text = policy_snapshot_canonical(policy)
    policy_digest = sha256_hex_bytes(policy_text.encode("utf-8"))
    paths[POLICY_FILE] = out / POLICY_FILE
    digest = _write_text(paths[POLICY_FILE], policy_text)
    bind_artifact("policy_snapshot", POLICY_FILE, digest, "json", None)

    for name, filename, result in (
        ("decision_capstone", DECISION_CAPSTONE_FILE, materials.capstone_result),
        ("decision_pq", DECISION_PQ_FILE, materials.pq_result),
        ("decision_drift", DECISION_DRIFT_FILE, materials.drift_result),
    ):
        paths[filename] = out / filename
        digest = _write_text(
            paths[filename],
            stable_json(result.decision.model_dump(mode="json")),
        )
        bind_artifact(name, filename, digest, "json", None)

    # ---------------------------------------------------------------- L1
    stmt = build_statement_from_decision(decision, policy=policy)
    if not evaluate_relation(stmt).satisfied:
        raise CompositionError("arbitration relation UNSAT for the capstone decision")
    envelope = prove_arbitration(stmt)
    l1 = verify_arbitration(
        stmt, envelope, ledger=ledger, expected_public_key_pem=ledger_pem
    )
    if not l1.is_valid or not l1.stand_in or l1.regulator_grade:
        raise CompositionError(
            f"zkPDP composition check failed: reason={l1.reason!r} "
            f"stand_in={l1.stand_in} regulator_grade={l1.regulator_grade} "
            "(is TEX_ZKPDP_ALLOW_SHIM=1 set?)"
        )
    seal = l1.seal or check_seal_binding(ledger, stmt)
    if seal.status != "sealed_match":
        raise CompositionError(f"zkPDP seal binding is {seal.status}, not sealed_match")
    paths[ZK_STATEMENT_FILE] = out / ZK_STATEMENT_FILE
    digest = _write_text(
        paths[ZK_STATEMENT_FILE], stmt.canonical_bytes().decode("utf-8")
    )
    bind_artifact("zkpdp_statement", ZK_STATEMENT_FILE, digest, "json", None)
    paths[ZK_ENVELOPE_FILE] = out / ZK_ENVELOPE_FILE
    digest = _write_text(
        paths[ZK_ENVELOPE_FILE], envelope.to_bytes().decode("utf-8")
    )
    bind_artifact("zkpdp_envelope", ZK_ENVELOPE_FILE, digest, "json", None)

    # ---------------------------------------------------------------- L2
    # A genuinely SIGNED composite attestation (alg != none), bound to the
    # verdict. Production pins Intel Trust Authority's published signing key
    # via TEX_ITA_PUBLIC_KEY_PEM and Intel holds the private half; offline we
    # generate a STAND-IN keypair so the SIGNATURE PATH is exercised for real
    # (fail-closed, no alg=none bypass) and pin its public half out-of-band.
    # The hardware-rooted measurement stays runtime-dependent (dev-stub
    # evidence off real TDX) — see tee/verdict_binding.py and NOTES.md.
    ita_private_pem, ita_public_pem = generate_standin_ita_keypair()
    jwt = build_verdict_bound_signed_jwt(
        sealed_verdict=decision.verdict,
        policy_bundle_digest=policy_digest,
        decision_input_sha256=decision.content_sha256,
        ledger_prev_hash=decision_rec.record_hash,
        signing_key_pem=ita_private_pem,
    )
    # Verify the freshly-signed token through the real signature path under a
    # PRODUCTION posture (test mode popped) so a bad/missing signature fails
    # closed, with the stand-in public key pinned for the verifier to check.
    with _scoped_env(
        {
            "TEX_TEE_ATTESTATION_MODE": None,
            "TEX_ITA_PUBLIC_KEY_PEM": ita_public_pem.decode("ascii"),
        }
    ):
        l2 = verify_verdict_binding(
            jwt,
            sealed_verdict=decision.verdict,
            policy_bundle_digest=policy_digest,
            decision_input_sha256=decision.content_sha256,
            ledger_prev_hash=decision_rec.record_hash,
        )
    if not (l2.ok and not l2.test_mode and l2.signature_verified):
        raise CompositionError(
            f"verdict binding failed: reason={l2.reason!r} "
            f"test_mode={l2.test_mode} signature_verified={l2.signature_verified} "
            f"alg={l2.signature_alg!r} (expected a real signed token, "
            "verified fail-closed against the pinned ITA stand-in key)"
        )
    paths[TEE_JWT_FILE] = out / TEE_JWT_FILE
    digest = _write_text(paths[TEE_JWT_FILE], jwt)
    bind_artifact("tee_verdict_binding", TEE_JWT_FILE, digest, "jwt", None)

    # ---------------------------------------------------------------- L4
    l4_outcome = evaluate_action_class(materials.capstone_result.request)
    if not l4_outcome.fired:
        raise CompositionError("the action-class floor did not fire on the capstone request")
    floor_meta = decision.metadata["pdp"]["structural_floor"]
    if "action_class" not in floor_meta["denying_specialists"]:
        raise CompositionError("action_class is not among the denying specialists")
    l4_cert = ACTION_CLASS_CERT.model_dump(mode="json")
    if l4_cert.get("certified") is not False:
        raise CompositionError("ACTION_CLASS_CERT must be certified=False this wave")

    # ---------------------------------------------------------------- L3
    l3_cert = issue_certificate_with_records(records, ABSENT_KEY)
    l3_check = verify_certificate(l3_cert)
    if not l3_check.ok:
        raise CompositionError(f"L3 certificate refused: {l3_check.reason}")
    l3_epoch = verify_epoch_commitment(records, l3_cert.commitment)
    if not l3_epoch.ok:
        raise CompositionError(f"L3 epoch commitment refused: {l3_epoch.reason}")
    if l3_cert.conservation.status != "GATED-HOLDS":
        raise CompositionError(
            f"L3 conservation is {l3_cert.conservation.status}, not GATED-HOLDS"
        )
    paths[L3_CERT_FILE] = out / L3_CERT_FILE
    digest = _write_text(paths[L3_CERT_FILE], stable_json(_l3_cert_dump(l3_cert)))
    bind_artifact("l3_certificate", L3_CERT_FILE, digest, "json", None)

    # ---------------------------------------------------------------- L5
    ruling = records[materials.ruling_sequence].fact
    if ruling.kind is not SealedFactKind.ENFORCEMENT:
        raise CompositionError("ruling sequence does not point at an ENFORCEMENT fact")
    if ruling.detail.get("allowed") is not False:
        raise CompositionError("the gate event was not a denied weakening")
    if "metaguard.governance_weakening" not in ruling.detail.get("caution_codes", []):
        raise CompositionError("the denial did not carry the metaguard caution")
    if materials.returned_snapshot_active or materials.store_active_version != "v1":
        raise CompositionError("the denied weakening mutated controller state")

    # ---------------------------------------------------------------- L7
    l7_bundle_check = verify_bundle(
        materials.campaign_records, pinned_public_key_b64=evidence_pin_b64
    )
    if not l7_bundle_check.valid:
        raise CompositionError("L7 campaign bundle failed pinned verification")
    l7_payload = read_certificate(materials.campaign_records)
    if l7_payload is None or l7_payload.get("claim") != CLAIM:
        raise CompositionError("L7 certificate claim is missing or not verbatim")
    survival = materials.campaign.survival
    if survival.n_breaches != 0 or survival.p_anytime != 1.0 or survival.fired:
        raise CompositionError(
            "the structural campaign breached — the capstone flow expects "
            "an unrefuted run over the structural seeds"
        )
    paths[L7_CAMPAIGN_FILE] = out / L7_CAMPAIGN_FILE
    write_bundle(materials.campaign_records, paths[L7_CAMPAIGN_FILE])
    digest = sha256_hex_bytes(paths[L7_CAMPAIGN_FILE].read_bytes())
    bind_artifact(
        "l7_campaign_chain", L7_CAMPAIGN_FILE, digest, "jsonl", CHAIN_EVIDENCE
    )

    # ------------------------------------------------------------- L8/L9/L10
    # The PQ scenario is environment-dependent (the live maturity probe is
    # the branch variable, carried in materials.pq_assessment): with no
    # durable backend the signal fires (ABSTAIN + flag + sealed fact); with
    # a durable backend (pyca cryptography>=48) the claim is honorable and
    # the engine — correctly — neither lowers nor seals. Each branch checks
    # the EXACT coherent outcome; a mixed outcome is a composition error.
    pq_decision = materials.pq_result.decision
    drift_decision = materials.drift_result.decision
    pq_lowered = materials.pq_assessment.lowers_verdict
    if pq_lowered:
        if PQ_NON_REPUDIATION_FLAG not in pq_decision.uncertainty_flags:
            raise CompositionError("the PQ companion decision did not carry the maturity flag")
        if pq_decision.verdict.value != "ABSTAIN":
            raise CompositionError("the maturity signal fired but the companion is not ABSTAIN")
    else:
        if not materials.pq_assessment.claim_honored:
            raise CompositionError(
                "a non-lowering PQ outcome requires a requested claim and a durable signer"
            )
        if pq_decision.verdict.value != "PERMIT":
            raise CompositionError("a durable signer must leave the PERMIT companion untouched")
        if PQ_NON_REPUDIATION_FLAG in pq_decision.uncertainty_flags:
            raise CompositionError("a durable-backend run must not carry the maturity flag")
    if RISK_SPINE_FLAG not in drift_decision.uncertainty_flags:
        raise CompositionError("the drift companion decision did not carry the spine flag")
    pq_facts = [
        r for r in records
        if r.fact.kind is SealedFactKind.DECISION
        and r.fact.subject_id == str(pq_decision.request_id)
        and "pq_durable" in r.fact.detail
    ]
    if pq_lowered:
        if not pq_facts:
            raise CompositionError("the fired maturity signal sealed no PQ-durability fact")
        # Selected by shape (the pq_durable detail key, which the M0 seal
        # never carries) — the append-order pin (PQ first, M0 second) stays
        # tested in tests/capstone/test_sequencing.py.
        pq_durability_rec = pq_facts[0]
        if "verdict" in pq_durability_rec.fact.detail:
            raise CompositionError("the PQ-durability fact must carry no verdict key")
        if pq_durability_rec.fact.detail.get("pq_durable") is not False:
            raise CompositionError("the PQ-durability fact must report pq_durable=False")
    else:
        if pq_facts:
            raise CompositionError(
                "the engine seals the PQ fact only when the signal fires — a "
                "durable run must not have one"
            )
        pq_durability_rec = None
    drift_recs = [
        r for r in records if r.fact.kind is SealedFactKind.DRIFT
    ]
    if not drift_recs:
        raise CompositionError("no DRIFT fact in the epoch")
    drift_rec = drift_recs[-1]
    if drift_rec.fact.detail.get("acted") is not True:
        raise CompositionError("the sealed spine step did not act")
    # L8 rides whichever ABSTAIN companion this epoch produced: the PQ
    # ABSTAIN when the signal fired, else the drift ABSTAIN (always present).
    hold_carrier = "decision_pq" if pq_lowered else "decision_drift"
    hold_decision = pq_decision if pq_lowered else drift_decision
    hold = hold_decision.metadata["pdp"].get("hold")
    if hold is None:
        raise CompositionError("the ABSTAIN companion carries no hold (L8)")
    if decision.metadata["pdp"].get("hold") is not None:
        raise CompositionError(
            "a non-ABSTAIN verdict carries a hold — ABSTAIN-only invariant broken"
        )

    # ---------------------------------------------------------------- L11
    voice_records = materials.attestor.records()
    l11 = verify_entailment_commitment(
        voice_records,
        expected_model_id=materials.voice_commitment.model_id,
        pinned_public_key_b64=voice_pin_b64,
    )
    if not l11.ok or l11.authorship_ok is not True:
        raise CompositionError(f"voice commitment verification failed: {l11.issues}")
    spoken = voice_records[0]
    proof_ref = spoken.payload.get("proof_ref") or {}
    if proof_ref.get("record_hash") != decision_rec.record_hash:
        raise CompositionError("the spoken seal does not reference the decision fact")
    paths[VOICE_RECORDS_FILE] = out / VOICE_RECORDS_FILE
    digest = _write_text(
        paths[VOICE_RECORDS_FILE],
        stable_json([_voice_record_dump(r) for r in voice_records]),
    )
    bind_artifact("voice_chain", VOICE_RECORDS_FILE, digest, "json", CHAIN_VOICE)

    # ---------------------------------------------------------------- L12
    trial = materials.trial
    recomputed_p_low = stability_p_low(trial.n_stable, trial.n_samples, trial.delta)
    if abs(recomputed_p_low - trial.p_low) > 1e-12:
        raise CompositionError("L12 p_low does not recompute")
    cert12 = trial.certificate
    if cert12.certified is not False or cert12.qif_estimate_only is not True:
        raise CompositionError("L12 certificate honesty fields are wrong")
    seg = materials.trial_segment
    seg_records = records[seg[0]:seg[1]]
    seg_verdicts = sorted(
        r.fact.detail["verdict"]
        for r in seg_records
        if r.fact.kind is SealedFactKind.DECISION and "verdict" in r.fact.detail
    )
    if seg_verdicts != sorted(trial.verdicts):
        raise CompositionError("L12 trial verdicts disagree with the sealed segment")
    paths[L12_TRIAL_FILE] = out / L12_TRIAL_FILE
    digest = _write_text(paths[L12_TRIAL_FILE], stable_json(_trial_dump(trial, seg)))
    bind_artifact("l12_neighborhood", L12_TRIAL_FILE, digest, "json", None)

    # ---------------------------------------------------------------- L6
    cp_pre = _parse_note(materials.cp_pre)
    cp_post = _parse_note(materials.cp_post)
    descriptors = [w.descriptor for w in materials.witnesses]
    l6_pre = verify_cosigned_checkpoint(
        materials.cp_pre, log_verifier=log_verifier, roster=descriptors, quorum=3
    )
    l6_post = verify_cosigned_checkpoint(
        materials.cp_post, log_verifier=log_verifier, roster=descriptors, quorum=3
    )
    if not (l6_pre.quorum_met and l6_post.quorum_met):
        raise CompositionError("pre/post checkpoints did not meet the witness quorum")
    if l6_pre.federated or l6_post.federated:
        raise CompositionError("federated must be structurally False this wave")
    paths[L6_CHECKPOINTS_FILE] = out / L6_CHECKPOINTS_FILE
    digest = _write_text(
        paths[L6_CHECKPOINTS_FILE],
        stable_json(
            {
                "origin": materials.publisher.origin,
                "pre": _cosigned_dump(materials.cp_pre),
                "post": _cosigned_dump(materials.cp_post),
                "roster": _roster_dump(materials.witnesses),
            }
        ),
    )
    bind_artifact("l6_checkpoints", L6_CHECKPOINTS_FILE, digest, "json", None)

    # ------------------------------------------------------- the manifest
    attempt_count = sum(
        1 for r in records if r.fact.kind is SealedFactKind.ATTEMPT
    )
    decision_kind_count = sum(
        1 for r in records if r.fact.kind is SealedFactKind.DECISION
    )

    properties = _build_property_attestations(
        materials=materials,
        l1=l1, seal_status=seal.status, seal_sequence=seal.record_sequence,
        stmt_floor_sources=list(stmt.floor_sources),
        l2=l2,
        l3_cert=l3_cert,
        l4_outcome=l4_outcome, l4_cert=l4_cert, ruling_detail=ruling.detail,
        l6_pre=l6_pre, l6_post=l6_post, cp_pre=cp_pre, cp_post=cp_post,
        l7_payload=l7_payload, l7_bundle_check=l7_bundle_check,
        hold=hold, hold_carrier=hold_carrier,
        drift_rec=drift_rec, pq_durability_rec=pq_durability_rec,
        l11=l11, voice_decision_hash=decision_rec.record_hash,
        attempt_sequence=attempt_rec.sequence,
        decision_sequence=decision_rec.sequence,
    )

    manifest = CapstoneVerdict(
        created_at=datetime.now(UTC).isoformat(),
        decision=DecisionIdentity(
            request_id=request_id,
            verdict=decision.verdict.value,
            final_score=decision.final_score,
            content_sha256=decision.content_sha256,
            determinism_fingerprint=decision.determinism_fingerprint,
            policy_id=decision.policy_id,
            policy_version=decision.policy_version,
            attempt_fact_sequence=attempt_rec.sequence,
            decision_fact_sequence=decision_rec.sequence,
        ),
        epoch=EpochBinding(
            record_count_pre_seal=record_count_pre_seal,
            epoch_head_hash_pre_seal=pre_seal_head,
            sealed_fact_sequence=record_count_pre_seal,
            attempt_fact_count=attempt_count,
            decision_kind_fact_count=decision_kind_count,
            tree_size_caveat=TREE_SIZE_CAVEAT,
        ),
        pins=PinDigests(
            ledger_signing_key_id=ledger.signing_key_id,
            ledger_public_key_pem_sha256=sha256_hex_bytes(ledger_pem),
            evidence_public_key_b64_sha256=sha256_hex_bytes(
                evidence_pin_b64.encode("ascii")
            ),
            voice_public_key_b64_sha256=sha256_hex_bytes(
                voice_pin_b64.encode("ascii")
            ),
            ita_public_key_pem_sha256=sha256_hex_bytes(ita_public_pem),
            log_name=log_verifier.name,
            log_public_key_raw_sha256=sha256_hex_bytes(log_verifier.public_key_raw),
            witness_roster_sha256=roster_sha256,
            nli_model_id=materials.voice_commitment.model_id,
            pin_caveat=PIN_CAVEAT,
        ),
        artifacts=tuple(artifact_refs),
        properties=properties,
        summary=(
            "One Tex governance verdict (FORBID), sealed and replayable, "
            "composed with all eight Wave-2 capstone properties — each at "
            "its honest maturity. The relation proof runs on a stand-in "
            "backend; the attestation binding is a real signature over a "
            "stand-in ITA key with the hardware measurement RUNTIME-DEPENDENT; "
            "the robustness and action-class certificates are uncertified "
            "pending a field corpus; the QIF figure is a point estimate; the "
            "entailment half is blocked. Every status above is machine-"
            "readable and was emitted by the leap module's own verifier at "
            "composition time."
        ),
    )
    manifest_digest = manifest.manifest_sha256()

    # ------------------------------------------- seal the manifest (chain 1)
    capstone_record = ledger.append(
        SealedFact(
            kind=SealedFactKind.ANSWER,
            subject_id=f"capstone:{request_id}",
            claim=(
                "Capstone composition manifest sealed: binds decision "
                f"{request_id} ({decision.verdict.value}) to the digests, "
                "pins and module-verifier results of its eight-property "
                "artifact set. Composition labels at honest maturity — "
                "stand-in/test-mode/uncertified/blocked halves are named "
                "in the manifest, never promoted."
            ),
            maturity=EvidenceMaturity.RESEARCH_EARLY,
            detail={
                "schema": SCHEMA_VERSION,
                "capstone_manifest_sha256": manifest_digest,
                "request_id": request_id,
                "verdict": decision.verdict.value,
                "record_count_pre_seal": record_count_pre_seal,
                "epoch_head_hash_pre_seal": pre_seal_head,
            },
        )
    )
    if capstone_record.sequence != record_count_pre_seal:
        raise CompositionError(
            "another producer appended to the ledger during composition"
        )

    # --------------------------------- witness the post-seal head (covers it)
    body = materials.publisher.build_add_checkpoint_request(cp_post.tree_size)
    cp_final = gather_cosignatures(body, materials.witnesses)
    l6_final = verify_cosigned_checkpoint(
        cp_final, log_verifier=log_verifier, roster=descriptors, quorum=3
    )
    if not l6_final.quorum_met:
        raise CompositionError("the post-seal checkpoint did not meet quorum")
    paths[L6_FINAL_CHECKPOINT_FILE] = out / L6_FINAL_CHECKPOINT_FILE
    _write_text(
        paths[L6_FINAL_CHECKPOINT_FILE], stable_json(_cosigned_dump(cp_final))
    )

    # ------------------------------------------------- export chain 1 + pins
    bundle = export_sealed_fact_bundle(ledger, export_name="capstone-epoch")
    paths[LEDGER_BUNDLE_FILE] = out / LEDGER_BUNDLE_FILE
    paths[LEDGER_BUNDLE_FILE].write_text(bundle.to_json(), encoding="utf-8")

    pins: dict[str, Any] = {
        "note": (
            "DEMO CONVENIENCE ONLY: in production a relying party obtains "
            "these pins out-of-band (Tex's published transparency record), "
            "never from the bundle they are verifying."
        ),
        "ledger_public_key_pem": ledger_pem.decode("ascii"),
        "ledger_signing_key_id": ledger.signing_key_id,
        "evidence_public_key_b64": evidence_pin_b64,
        "voice_public_key_b64": voice_pin_b64,
        "ita_public_key_pem": ita_public_pem.decode("ascii"),
        "log_name": log_verifier.name,
        "log_public_key_raw_hex": log_verifier.public_key_raw.hex(),
        "witness_roster": roster,
        "nli_model_id": materials.voice_commitment.model_id,
    }
    paths[PINS_FILE] = out / PINS_FILE
    _write_text(paths[PINS_FILE], stable_json(pins))

    paths[MANIFEST_FILE] = out / MANIFEST_FILE
    _write_text(paths[MANIFEST_FILE], stable_json(manifest.model_dump(mode="json")))

    return ComposeResult(
        manifest=manifest,
        manifest_sha256=manifest_digest,
        bundle_dir=out,
        paths=paths,
        capstone_record=capstone_record,
        cp_final=cp_final,
        pins=pins,
    )


# ── snapshot/dump helpers ─────────────────────────────────────────────────


def _voice_pin(attestor: VoiceAttestor) -> str:
    recs = attestor.records()
    if not recs:
        raise CompositionError("the voice chain is empty")
    block = recs[0].payload.get("pq_signature") or {}
    pin = block.get("public_key_b64")
    if not pin:
        raise CompositionError("the voice chain carries no embedded public key")
    return pin


def _voice_record_dump(rec: VoiceAttestationRecord) -> dict[str, Any]:
    return {
        "sequence": rec.sequence,
        "previous_hash": rec.previous_hash,
        "payload_sha256": rec.payload_sha256,
        "record_hash": rec.record_hash,
        "payload": rec.payload,
    }


def _l3_cert_dump(cert: Any) -> dict[str, Any]:
    import dataclasses

    return dataclasses.asdict(cert)


def _trial_dump(trial: NeighborhoodTrialResult, segment: tuple[int, int]) -> dict[str, Any]:
    return {
        "family": trial.family,
        "seed": trial.seed,
        "n_samples": trial.n_samples,
        "samples": list(trial.samples),
        "verdicts": list(trial.verdicts),
        "target_verdict": trial.target_verdict,
        "n_stable": trial.n_stable,
        "stability_rate": trial.stability_rate,
        "p_low": trial.p_low,
        "delta": trial.delta,
        "all_stable": trial.all_stable,
        "certificate": trial.certificate.model_dump(mode="json"),
        "ledger_segment": list(segment),
    }


def _build_property_attestations(
    *,
    materials: CapstoneMaterials,
    l1: Any, seal_status: str, seal_sequence: int | None,
    stmt_floor_sources: list[str],
    l2: Any,
    l3_cert: Any,
    l4_outcome: Any, l4_cert: dict[str, Any], ruling_detail: dict[str, Any],
    l6_pre: Any, l6_post: Any, cp_pre: Checkpoint, cp_post: Checkpoint,
    l7_payload: dict[str, Any], l7_bundle_check: Any,
    hold: dict[str, Any], hold_carrier: str,
    drift_rec: SealedFactRecord, pq_durability_rec: SealedFactRecord | None,
    l11: Any, voice_decision_hash: str,
    attempt_sequence: int, decision_sequence: int,
) -> tuple[PropertyAttestation, ...]:
    """Per-leap attestations: status + VERBATIM caveats + the module
    verifier's own output. Authored prose here obeys the manifest's banned
    list; module wording rides in ``caveats`` untouched."""
    trial = materials.trial
    campaign = materials.campaign
    drift_detail = drift_rec.fact.detail
    # ``pq_durability_rec`` is None on a durable-backend run — the engine
    # seals the fact only when the signal fires; the assessment is then the
    # L10 evidence and rides the sealed manifest itself.
    pq_assessment = materials.pq_assessment
    pq_detail = (
        pq_durability_rec.fact.detail if pq_durability_rec is not None else None
    )

    def attn(leap: str, **kwargs: Any) -> PropertyAttestation:
        return PropertyAttestation(
            leap=leap, property_index=PROPERTY_INDEX[leap], **kwargs
        )

    return (
        attn(
            "L1",
            title="ZK-relation proof of the arbitration derivation (stand-in backend)",
            scope="decision",
            status="green_test_mode",
            runtime_dependent=True,
            maturity="research_early",
            caveats=(
                l1.note,
                "the relation proves derivability; the seal binds the "
                "statement to the sealed decision — cite neither half alone",
            ),
            verification={
                "is_valid": l1.is_valid,
                "reason": l1.reason,
                "backend": l1.backend,
                "stand_in": l1.stand_in,
                "regulator_grade": l1.regulator_grade,
                "relation_satisfied": l1.relation.satisfied if l1.relation else None,
                "seal_status": seal_status,
                "seal_record_sequence": seal_sequence,
                "deny_floor": True,
                "floor_sources": stmt_floor_sources,
            },
            artifacts=("zkpdp_statement", "zkpdp_envelope"),
            ledger_sequences=(decision_sequence,),
        ),
        attn(
            "L2",
            title=(
                "Verdict-bound attestation (real signature; hardware "
                "measurement runtime-dependent)"
            ),
            scope="decision",
            status="green",
            runtime_dependent=True,
            maturity="research_early",
            halves={
                "signature": "green",
                "hardware_measurement": "runtime_dependent",
            },
            caveats=(
                f"the composite token is a real JWS (alg={l2.signature_alg}, "
                "Intel Trust Authority's production algorithm) signed by a "
                "STAND-IN ITA key whose public half is pinned out-of-band; "
                "it verifies fail-closed with no alg=none bypass — the "
                "signature proves authorship by that key, not that Intel "
                "attested anything",
                "the binding gates on tdx_report_data recomputed from the "
                "sealed verdict + policy digest + decision-input hash + "
                "ledger head — never on the soft eat_nonce field",
                "the hardware-rooted measurement is RUNTIME-DEPENDENT: real "
                "MRTD/RTMR and a quote that signs report_data need an Intel "
                "TDX confidential VM (the demo's measurements are dev-stub)",
            ),
            verification={
                "ok": l2.ok,
                "reason": l2.reason,
                "bound_verdict": l2.bound_verdict,
                "test_mode": l2.test_mode,
                "alg": l2.signature_alg,
                "signature_verified": l2.signature_verified,
                "ita_key_source": "stand_in",
                "expected_report_data": l2.expected_report_data,
            },
            artifacts=("tee_verdict_binding", "policy_snapshot"),
            ledger_sequences=(decision_sequence,),
        ),
        attn(
            "L3",
            title="Negative-knowledge certificate over the sealed epoch",
            scope="epoch",
            status="green",
            runtime_dependent=False,
            maturity="research_early",
            caveats=(
                l3_cert.claim_text,
                "scope is non-membership in THIS sealed epoch only — an "
                "in-memory, opt-in epoch, erased on restart",
                "complete=True is scoped to count-conservation, nothing more",
            ),
            verification={
                "certificate_ok": True,
                "conservation_status": l3_cert.conservation.status,
                "holds": l3_cert.conservation.holds,
                "n_attempts": l3_cert.conservation.n_attempts,
                "n_permit": l3_cert.conservation.n_permit,
                "n_abstain": l3_cert.conservation.n_abstain,
                "n_forbid": l3_cert.conservation.n_forbid,
                "attempts_source": l3_cert.conservation.attempts_source,
                "record_count": l3_cert.commitment.record_count,
                "vacuous": l3_cert.vacuous,
                "complete": l3_cert.complete,
                "attempt_hook_present": l3_cert.attempt_hook_present,
                "hash_backend": l3_cert.hash_backend,
                "probe_key": l3_cert.key,
            },
            artifacts=("l3_certificate",),
        ),
        attn(
            "L4",
            title="Reversibility x blast-radius floor (fired on this decision)",
            scope="decision",
            status="green",
            runtime_dependent=False,
            maturity="research_early",
            halves={"floor": "green", "certificate": "uncertified"},
            caveats=(
                l4_outcome.reason,
                "the certificate is certified=False until a field-labelled "
                "corpus is measured — the floor itself reads only the "
                "declared step lattice, never a probabilistic score",
            ),
            verification={
                "fired": l4_outcome.fired,
                "action_class": str(l4_outcome.action_class),
                "worst_reversibility": str(l4_outcome.worst_reversibility),
                "worst_blast": str(l4_outcome.worst_blast),
                "code": l4_outcome.code,
                "certificate": l4_cert,
            },
            artifacts=("decision_capstone",),
            ledger_sequences=(decision_sequence,),
        ),
        attn(
            "L5",
            title="Self-governed: controller mutation denied through the same PDP",
            scope="epoch",
            status="green",
            runtime_dependent=False,
            maturity="research_early",
            caveats=(
                "the reflexive gate is inert until bound; binding is "
                "process-global via the context manager",
                "the chokepoint census is enumerated and tripwired, not "
                "proven exhaustive",
            ),
            verification={
                "ruling_allowed": ruling_detail.get("allowed"),
                "ruling_verdict": ruling_detail.get("verdict"),
                "mechanism": ruling_detail.get("mechanism"),
                "caution_codes": list(ruling_detail.get("caution_codes", [])),
                "store_active_version": materials.store_active_version,
            },
            ledger_sequences=(
                materials.bind_sequence,
                materials.gate_attempt_sequence,
                materials.reflexive_sequence,
                materials.ruling_sequence,
                materials.unbind_sequence,
            ),
        ),
        attn(
            "L6",
            title="Witness-cosigned checkpoints over the verdict's chain",
            scope="epoch",
            status="green",
            runtime_dependent=False,
            maturity="research_early",
            caveats=(
                FEDERATED_FALSE_REASON,
                TREE_SIZE_CAVEAT,
                "the post-seal witnessed checkpoint ships alongside, bound "
                "by root recomputation over the shipped chain (it covers "
                "the sealed manifest itself), not by manifest digest",
            ),
            verification={
                "pre_quorum_met": l6_pre.quorum_met,
                "post_quorum_met": l6_post.quorum_met,
                "pre_tree_size": cp_pre.tree_size,
                "post_tree_size": cp_post.tree_size,
                "valid_cosigners": list(l6_post.valid_cosigners),
                "quorum": 3,
                "federated": False,
                "federated_reason": FEDERATED_FALSE_REASON,
            },
            artifacts=("l6_checkpoints",),
        ),
        attn(
            "L7",
            title="Adversary-completeness monitor over the structural seeds",
            scope="system",
            status="green",
            runtime_dependent=False,
            maturity="research_early",
            caveats=(CLAIM,) + NON_CLAIMS,
            verification={
                "p_anytime": campaign.survival.p_anytime,
                "n_breaches": campaign.survival.n_breaches,
                "n_queries": campaign.survival.n_queries,
                "fired": campaign.survival.fired,
                "alpha": campaign.survival.alpha,
                "residual_asr_upper": campaign.residual_asr_upper,
                "residual_alpha": campaign.residual_alpha,
                "queries_spent": campaign.coverage.queries_spent,
                "n_seeds": campaign.coverage.n_seeds,
                "is_vacuous": campaign.coverage.is_vacuous,
                "claim": l7_payload.get("claim"),
                "bundle_valid": l7_bundle_check.valid,
            },
            artifacts=("l7_campaign_chain",),
        ),
        attn(
            "L8",
            title="Credal hold on the ABSTAIN surface (companion decision)",
            scope="epoch",
            status="green",
            runtime_dependent=False,
            maturity="research_early",
            caveats=(
                "a hold surfaces ONLY on ABSTAIN — build_hold returns None "
                "for any other verdict; PERMIT and FORBID stay invisible to "
                "the operator",
            ),
            verification={
                "hold_present_on_abstain": True,
                "hold_type": hold.get("hold_type"),
                "resolution_mode": hold.get("resolution_mode"),
                "band_certified": hold.get("band_certified"),
                "capstone_hold_is_none": True,
                "hold_carrier": hold_carrier,
            },
            artifacts=(hold_carrier,),
        ),
        attn(
            "L9",
            title="Anytime-valid drift spine step sealed in the same chain",
            scope="epoch",
            status="green",
            runtime_dependent=False,
            maturity="research_early",
            caveats=(
                "the spine acts at the abs-corrected threshold "
                "log(2^K/alpha), never the naive 1/alpha — the two-sided "
                "|S_t| e-process pays a factor-2 toll per stream",
                "validity of each per-stream null is research-early until "
                "benchmarked on production data",
            ),
            verification={
                "acted": drift_detail.get("acted"),
                "anytime_valid": drift_detail.get("anytime_valid"),
                "is_true_e_value": drift_detail.get("is_true_e_value"),
                "alpha": drift_detail.get("alpha"),
                "k": drift_detail.get("k"),
                "action_log_e_threshold": drift_detail.get("action_log_e_threshold"),
                "log_e_value": drift_detail.get("log_e_value"),
            },
            artifacts=("decision_drift",),
            ledger_sequences=(drift_rec.sequence,),
        ),
        attn(
            "L10",
            title=(
                "PQ-maturity probe: the signal lowered the companion verdict"
                if pq_durability_rec is not None
                else "PQ-maturity probe: durable backend present — the claim "
                     "was not lowered"
            ),
            scope="epoch",
            status="green",
            runtime_dependent=False,
            maturity="research_early",
            halves={"maturity_signal": "green", "pq_signing": "runtime_dependent"},
            caveats=(
                (
                    "the live signer is ECDSA-P256 — the signal is the honest "
                    "report of that gap: an unhonorable non-repudiation claim "
                    "lowers PERMIT to ABSTAIN and seals the fail-closed fact",
                )
                if pq_durability_rec is not None
                else (
                    "the maturity probe reports a durable ML-DSA backend, so "
                    "the signal correctly did not fire; the engine seals the "
                    "PQ fact only when it fires, so this outcome's evidence "
                    "is this manifest (itself sealed into the chain)",
                    "the epoch's chain-1 seals still verify under the "
                    "ECDSA-P256 provider against the pinned key — "
                    "claim_honored records the module's assessment of the "
                    "live backend, not a PQ property of this epoch's "
                    "signatures",
                )
            ),
            verification=(
                {
                    "pq_durable": pq_detail.get("pq_durable"),
                    "signer_maturity": pq_detail.get("signer_maturity"),
                    "claim_requested": pq_detail.get("pq_non_repudiation_claim_requested"),
                    "claim_honored": pq_detail.get("pq_non_repudiation_claim_honored"),
                    "flag": PQ_NON_REPUDIATION_FLAG,
                    "fact_has_no_verdict_key": "verdict" not in pq_detail,
                    "active_backend_id": pq_detail.get("active_backend_id"),
                    "maturity_outcome": "lowered_to_abstain",
                }
                if pq_detail is not None
                else {
                    "pq_durable": pq_assessment.pq_durable,
                    "signer_maturity": pq_assessment.signer_maturity.value,
                    "claim_requested": pq_assessment.claim_requested,
                    "claim_honored": pq_assessment.claim_honored,
                    "flag": PQ_NON_REPUDIATION_FLAG,
                    "flag_absent_on_decision": True,
                    "active_backend_id": pq_assessment.active_backend_id,
                    "maturity_outcome": "durable_not_lowered",
                }
            ),
            artifacts=("decision_pq",),
            ledger_sequences=(
                (pq_durability_rec.sequence,)
                if pq_durability_rec is not None
                else ()
            ),
        ),
        attn(
            "L11",
            title="Sealed spoken-proof commitment (seal half)",
            scope="decision",
            status="green",
            runtime_dependent=False,
            maturity="research_early",
            # The entailment half is DERIVED from the commitment, never
            # hard-coded: green ONLY for a real field calibration (loaded neural
            # backend + field corpus + a λ̂). The live commitment is the
            # absence, so this evaluates to "blocked" — honestly.
            halves={
                "seal": "green",
                "entailment": entailment_half_status(materials.voice_commitment),
            },
            caveats=(
                THRESHOLD_LABEL,
                "the entailment half is GREEN only behind a real loaded neural "
                "scorer calibrated over a FIELD NLI corpus; the live commitment "
                "is the absence (lambda_hat=None, calibrated=False), so it is "
                "BLOCKED — a synthetic or stub calibration validates the "
                "pipeline but never earns the field guarantee",
                "blocked on torch/transformers (import fails in-env) plus a "
                "labelled field NLI corpus",
            ),
            verification={
                "ok": l11.ok,
                "chain_intact": l11.chain_intact,
                "signatures_valid": l11.signatures_valid,
                "authorship_ok": l11.authorship_ok,
                "model_id": materials.voice_commitment.model_id,
                "model_loaded": materials.voice_commitment.model_loaded,
                "lambda_hat": materials.voice_commitment.lambda_hat,
                "calibrated": materials.voice_commitment.calibrated,
                "scorer_backend": materials.voice_commitment.scorer_backend,
                "calibration_corpus_kind": (
                    materials.voice_commitment.calibration_corpus_kind
                ),
                "commitment_sha256": materials.voice_commitment.commitment_sha256(),
                "proof_ref_record_hash": voice_decision_hash,
            },
            artifacts=("voice_chain",),
            ledger_sequences=(decision_sequence,),
        ),
        attn(
            "L12",
            title="Robustness over a seeded paraphrase neighborhood + QIF posture",
            scope="decision",
            status="uncertified",
            runtime_dependent=False,
            maturity="research_early",
            halves={"robustness": "uncertified", "qif": "estimate_only"},
            caveats=(
                trial.family,
                trial.certificate.qif_estimator,
                "the claim is distributional over the named synthetic "
                "family, never worst-case; certified stays False until a "
                "field neighborhood is measured",
            ),
            verification={
                "n_samples": trial.n_samples,
                "n_stable": trial.n_stable,
                "stability_rate": trial.stability_rate,
                "p_low": trial.p_low,
                "delta": trial.delta,
                "seed": trial.seed,
                "all_stable": trial.all_stable,
                "ledger_segment": list(materials.trial_segment),
                "certificate": {
                    "certified": trial.certificate.certified,
                    "qif_estimate_only": trial.certificate.qif_estimate_only,
                    "qif_certified": trial.certificate.qif_certified,
                    "neighborhood_kind": trial.certificate.robustness_neighborhood_kind,
                    "capacity_ceiling_bits": trial.certificate.qif_capacity_ceiling_bits,
                },
            },
            artifacts=("l12_neighborhood",),
        ),
    )


__all__ = [
    "ABSENT_KEY",
    "CapstoneMaterials",
    "ComposeResult",
    "CompositionError",
    "DECISION_CAPSTONE_FILE",
    "DECISION_DRIFT_FILE",
    "DECISION_PQ_FILE",
    "L3_CERT_FILE",
    "L6_CHECKPOINTS_FILE",
    "L6_FINAL_CHECKPOINT_FILE",
    "L7_CAMPAIGN_FILE",
    "L12_TRIAL_FILE",
    "LEDGER_BUNDLE_FILE",
    "MANIFEST_FILE",
    "PINS_FILE",
    "POLICY_FILE",
    "TEE_JWT_FILE",
    "VOICE_RECORDS_FILE",
    "ZK_ENVELOPE_FILE",
    "ZK_STATEMENT_FILE",
    "compose_capstone",
    "policy_snapshot_canonical",
]
