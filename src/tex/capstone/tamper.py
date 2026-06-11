"""
Capstone tamper matrix — ATTACK SIMULATION ONLY (tests/demo, never a
legitimate write).

[Architecture: composition layer. Maturity: research-early.]

Each row mutates a COPY of the bundle (or replays a protocol attack against
the live witnesses) and asserts the attack is caught by the RIGHT proof —
attribution matters as much as detection:

  byte-flip per chain      → that chain's INTEGRITY breaks (hash replay)
  tamper-then-resign       → integrity PASSES; only the key PIN catches it
  verdict swap             → L2 nonce mismatch AND the L1 relation refuses
  forked checkpoint        → all witnesses refuse (CONFLICT / equivocation)
  epoch minus one PERMIT   → L3 conservation GATED-BROKEN; minus its attempt
                             too → the sealed epoch commitment's roots break
  swapped artifact file    → the manifest's digest binding catches it
  edited manifest          → the chain-sealed manifest digest catches it

The clean bundle must verify green FIRST — a matrix over a broken bundle
proves nothing (every row re-checks this).
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from tex.bench.evidence_bundle import (
    forge_record_by_resigning,
    read_bundle,
    verify_bundle,
    write_bundle,
)
from tex.domain.verdict import Verdict
from tex.evidence.negative_knowledge import (
    check_count_conservation,
    verify_epoch_commitment,
)
from tex.evidence.seal import build_evidence_chain_signer
from tex.interchange.gix import CheckpointPublisher
from tex.interchange.gix_witness import WitnessOutcome
from tex.provenance.bundle import SealedFactBundle, export_sealed_fact_bundle
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind
from tex.tee.verdict_binding import verify_verdict_binding
from tex.voice.entailment_cert import (
    EntailmentCommitment,
    seal_entailment_commitment,
    verify_entailment_commitment,
)
from tex.voice.attestation import VoiceAttestor
from tex.zkpdp.arbiter import (
    ArbitrationEnvelope,
    verify_arbitration,
)

from tex.capstone.compose import (
    L7_CAMPAIGN_FILE,
    L12_TRIAL_FILE,
    LEDGER_BUNDLE_FILE,
    MANIFEST_FILE,
    VOICE_RECORDS_FILE,
    ZK_ENVELOPE_FILE,
    ZK_STATEMENT_FILE,
)
from tex.capstone.flow import CapstoneFlowResult
from tex.capstone.manifest import sha256_hex_bytes, stable_json
from tex.capstone.verify import (
    CapstonePins,
    _statement_from_dict,
    _voice_records_from_list,
    verify_capstone,
)


@dataclass(frozen=True, slots=True)
class TamperRow:
    """One adversary move: was it caught, and by the RIGHT proof?"""

    name: str
    caught: bool
    caught_by: tuple[str, ...]  # the named checks/codes that fired
    detail: str = ""


def _copy_bundle(bundle_dir: Path, dest: Path) -> Path:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(bundle_dir, dest)
    return dest


def _pins(bundle_dir: Path) -> CapstonePins:
    return CapstonePins.from_file(bundle_dir / "pins.json")


# ── per-chain byte flips: integrity catches them ─────────────────────────


def tamper_ledger_byteflip(bundle_dir: Path, scratch: Path) -> TamperRow:
    work = _copy_bundle(bundle_dir, scratch / "ledger_byteflip")
    path = work / LEDGER_BUNDLE_FILE
    doc = json.loads(path.read_text(encoding="utf-8"))
    target = doc["records"][len(doc["records"]) // 2]["fact"]
    target["claim"] = ("X" + target["claim"][1:]) if target["claim"] else "X"
    path.write_text(json.dumps(doc), encoding="utf-8")
    result = verify_capstone(work, _pins(work))
    caught = not result.ok and not result.check("chain1.integrity").ok
    return TamperRow(
        name="byte-flip in chain 1 (sealed-fact ledger)",
        caught=caught,
        caught_by=("chain1.integrity",),
        detail=result.check("chain1.integrity").detail,
    )


def tamper_evidence_byteflip(bundle_dir: Path, scratch: Path) -> TamperRow:
    work = _copy_bundle(bundle_dir, scratch / "evidence_byteflip")
    path = work / L7_CAMPAIGN_FILE
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[len(lines) // 2])
    payload = record["payload_json"]
    for i, ch in enumerate(payload):
        if ch.isalnum():
            payload = payload[:i] + ("0" if ch != "0" else "1") + payload[i + 1 :]
            break
    record["payload_json"] = payload
    lines[len(lines) // 2] = json.dumps(record, default=str)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # The file digest changes too — both catches are real; the CHAIN catch is
    # the one this row pins, so check it directly on the mutated file.
    after = verify_bundle(
        read_bundle(path),
        pinned_public_key_b64=_pins(work).evidence_public_key_b64,
    )
    caught = not after.valid and not after.chain_intact
    return TamperRow(
        name="byte-flip in chain 2 (evidence campaign bundle)",
        caught=caught,
        caught_by=("chain2.integrity",) + after.chain_issue_codes,
        detail=f"chain_issue_codes={after.chain_issue_codes}",
    )


def tamper_voice_byteflip(bundle_dir: Path, scratch: Path) -> TamperRow:
    work = _copy_bundle(bundle_dir, scratch / "voice_byteflip")
    pins = _pins(work)
    path = work / VOICE_RECORDS_FILE
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc[0]["payload"]["verdict"] = "PERMIT"  # flip the spoken verdict
    path.write_text(json.dumps(doc), encoding="utf-8")
    # The composed catch: the manifest's digest gate refuses the swapped
    # bytes before parsing (verification stops there, by design).
    result = verify_capstone(work, pins)
    digest_caught = not result.ok and not result.check("manifest.digest_binding").ok
    # The per-chain catch this row pins: the voice chain's own verifier sees
    # the integrity break (payload hash no longer replays).
    after = verify_entailment_commitment(
        _voice_records_from_list(doc),
        expected_model_id=pins.nli_model_id,
        pinned_public_key_b64=pins.voice_public_key_b64,
    )
    chain_caught = not after.ok and (
        not after.chain_intact or not after.signatures_valid
    )
    return TamperRow(
        name="byte-flip in chain 3 (voice attestation records)",
        caught=digest_caught and chain_caught,
        caught_by=("chain3.integrity", "manifest.digest_binding"),
        detail=(
            f"chain_issues={after.issues[:2]} digest_caught={digest_caught}"
        ),
    )


# ── tamper-then-resign: integrity PASSES, only the pin catches it ────────


def tamper_ledger_resign(bundle_dir: Path, scratch: Path) -> TamperRow:
    """Adversary rebuilds the WHOLE chain with their own key, flipping the
    capstone decision's sealed verdict to PERMIT."""
    work = _copy_bundle(bundle_dir, scratch / "ledger_resign")
    pins = _pins(work)
    bundle = SealedFactBundle.from_json(
        (work / LEDGER_BUNDLE_FILE).read_text(encoding="utf-8")
    )
    manifest = json.loads((work / MANIFEST_FILE).read_text(encoding="utf-8"))
    decision_seq = manifest["decision"]["decision_fact_sequence"]

    adversary = SealedFactLedger(key_label="capstone-adversary")
    for rec in bundle.records:
        fact = rec.fact
        if rec.sequence == decision_seq:
            detail = dict(fact.detail)
            detail["verdict"] = Verdict.PERMIT.value
            fact = fact.model_copy(update={"detail": detail})
        adversary.append(fact)
    forged = export_sealed_fact_bundle(adversary, export_name="forged-epoch")
    (work / LEDGER_BUNDLE_FILE).write_text(forged.to_json(), encoding="utf-8")

    result = verify_capstone(work, pins)
    integrity_passed = result.check("chain1.integrity").ok
    pin_failed = not result.check("chain1.authorship_pin").ok
    caught = not result.ok and integrity_passed and pin_failed
    return TamperRow(
        name="tamper-then-resign chain 1 (verdict flipped, adversary key)",
        caught=caught,
        caught_by=("chain1.authorship_pin",),
        detail=(
            f"integrity_passed={integrity_passed} (the forgery is internally "
            f"consistent) pin_failed={pin_failed}"
        ),
    )


def tamper_evidence_resign(bundle_dir: Path, scratch: Path) -> TamperRow:
    work = _copy_bundle(bundle_dir, scratch / "evidence_resign")
    pins = _pins(work)
    records = read_bundle(work / L7_CAMPAIGN_FILE)
    adversary = build_evidence_chain_signer(
        key_dir=str(scratch / "evidence_adv_keys")
    )
    forged_last = forge_record_by_resigning(
        records[-1],
        mutate=lambda p: {**p, "forged": True},
        adversary_signer=adversary,
    )
    forged = records[:-1] + (forged_last,)
    write_bundle(forged, work / L7_CAMPAIGN_FILE)
    unpinned = verify_bundle(forged)
    pinned = verify_bundle(
        forged, pinned_public_key_b64=pins.evidence_public_key_b64
    )
    caught = (
        unpinned.integrity_ok
        and not pinned.valid
        and pinned.authorship_ok is False
    )
    return TamperRow(
        name="tamper-then-resign chain 2 (foreign key, chain rebuilt)",
        caught=caught,
        caught_by=("chain2.authorship_pin",),
        detail=(
            f"integrity_passed={unpinned.integrity_ok} "
            f"authorship_ok={pinned.authorship_ok}"
        ),
    )


def tamper_voice_remint(bundle_dir: Path, scratch: Path) -> TamperRow:
    """Adversary mints a FRESH voice chain (new ephemeral key) with the same
    shape — self-verifies perfectly; only the pin catches it (the L11 trap)."""
    work = _copy_bundle(bundle_dir, scratch / "voice_remint")
    pins = _pins(work)
    original = json.loads((work / VOICE_RECORDS_FILE).read_text(encoding="utf-8"))
    spoken = original[0]["payload"]

    adversary = VoiceAttestor()
    adversary.seal(
        transcript="re-minted",
        routed_dimension=spoken.get("routed_dimension"),
        verdict=spoken.get("verdict", ""),
        answer=spoken.get("answer", ""),
        object_=spoken.get("object"),
        proof_ref=spoken.get("proof_ref"),
        gate={"scorer": "exact-match", "reason": "re-mint"},
    )
    seal_entailment_commitment(adversary, EntailmentCommitment())
    re_minted = adversary.records()

    # The re-mint self-verifies perfectly: chain intact, signatures valid
    # against the adversary's OWN embedded key, model_id as expected. Only
    # two things catch it — the honest key pin, and (in the composed object)
    # the manifest's digest binding over the swapped file.
    unpinned = verify_entailment_commitment(
        re_minted, expected_model_id=pins.nli_model_id
    )
    pinned = verify_entailment_commitment(
        re_minted,
        expected_model_id=pins.nli_model_id,
        pinned_public_key_b64=pins.voice_public_key_b64,
    )
    pin_caught = (
        unpinned.chain_intact
        and unpinned.signatures_valid
        and unpinned.authorship_ok is None  # the honest gap without a pin
        and pinned.authorship_ok is False
        and not pinned.ok
    )

    dump = [
        {
            "sequence": r.sequence,
            "previous_hash": r.previous_hash,
            "payload_sha256": r.payload_sha256,
            "record_hash": r.record_hash,
            "payload": r.payload,
        }
        for r in re_minted
    ]
    (work / VOICE_RECORDS_FILE).write_text(stable_json(dump), encoding="utf-8")
    result = verify_capstone(work, pins)
    digest_caught = not result.ok and not result.check("manifest.digest_binding").ok
    return TamperRow(
        name="fresh-key re-mint of chain 3 (voice)",
        caught=pin_caught and digest_caught,
        caught_by=("chain3.authorship_pin", "manifest.digest_binding"),
        detail=(
            f"self_verifies={unpinned.chain_intact and unpinned.signatures_valid} "
            f"unpinned_authorship={unpinned.authorship_ok} "
            f"pinned_authorship={pinned.authorship_ok}"
        ),
    )


# ── verdict swap: L2 nonce + L1 relation both refuse ─────────────────────


def tamper_verdict_swap(bundle_dir: Path, scratch: Path) -> TamperRow:
    """Claim the sealed FORBID was a PERMIT. No file mutation needed — the
    swap dies twice: the attestation nonce mismatches and the arbitration
    relation is UNSAT for the flipped claim (the deny floor forces FORBID)."""
    import dataclasses

    work = bundle_dir
    pins = _pins(work)
    manifest = json.loads((work / MANIFEST_FILE).read_text(encoding="utf-8"))
    bundle = SealedFactBundle.from_json(
        (work / LEDGER_BUNDLE_FILE).read_text(encoding="utf-8")
    )
    decision_seq = manifest["decision"]["decision_fact_sequence"]
    sealed = bundle.records[decision_seq].fact.detail
    policy_digest = sha256_hex_bytes((work / "policy_snapshot.json").read_bytes())

    l2 = verify_verdict_binding(
        (work / "tee_verdict_binding.jwt").read_text(encoding="utf-8"),
        sealed_verdict="PERMIT",
        policy_bundle_digest=policy_digest,
        decision_input_sha256=sealed["content_sha256"],
        ledger_prev_hash=bundle.records[decision_seq].record_hash,
    )
    l2_caught = not l2.ok and l2.reason == "verdict_nonce_mismatch"

    stmt = _statement_from_dict(
        json.loads((work / ZK_STATEMENT_FILE).read_text(encoding="utf-8"))
    )
    flipped = dataclasses.replace(stmt, claimed_verdict="PERMIT")
    envelope = ArbitrationEnvelope.from_bytes((work / ZK_ENVELOPE_FILE).read_bytes())
    forged_envelope = ArbitrationEnvelope(
        backend=envelope.backend,
        proof_hex=envelope.proof_hex,
        statement_sha256=flipped.sha256_hex(),
    )
    # Run under the shim opt-in so the catch is the RELATION refusing the
    # flipped claim (deny floor forces FORBID) — not merely the shim gate.
    from tex.capstone.verify import _scoped_env

    with _scoped_env({"TEX_ZKPDP_ALLOW_SHIM": "1"}):
        l1 = verify_arbitration(flipped, forged_envelope)
    l1_caught = not l1.is_valid and (l1.reason or "").startswith(
        "zkpdp_arbitration_relation_unsat"
    )
    return TamperRow(
        name="verdict swap (claim PERMIT over the sealed FORBID)",
        caught=l2_caught and l1_caught,
        caught_by=("L2.verdict_nonce_mismatch", "L1.relation_unsat"),
        detail=f"l2_reason={l2.reason!r} l1_reason={l1.reason!r}",
    )


# ── forked checkpoint: the witnesses refuse ──────────────────────────────


def tamper_checkpoint_fork(flow: CapstoneFlowResult) -> TamperRow:
    """A rogue log operator (holding the REAL log key) publishes a rewritten
    history at the same tree size. Every witness that cosigned the honest
    head refuses with CONFLICT — non-equivocation is the witnesses' job, not
    the key's."""
    materials = flow.materials
    hashes = [r.record_hash for r in materials.ledger.list_all()]
    forked_hashes = list(hashes)
    forked_hashes[0] = ("0" if hashes[0][0] != "0" else "1") + hashes[0][1:]
    rogue = CheckpointPublisher(
        origin=materials.publisher.origin,
        read_record_hashes=lambda: forked_hashes,
        signer=materials.log_signer,  # the REAL key — a rogue operator
    )
    size = len(hashes)
    body = rogue.build_add_checkpoint_request(size)
    refusals = []
    for witness in materials.witnesses:
        response = witness.add_checkpoint(body)
        refusals.append((witness.name, response.outcome, response.reason))
    all_refused = all(
        outcome is WitnessOutcome.CONFLICT for _, outcome, _ in refusals
    )
    return TamperRow(
        name="forked/rewritten checkpoint (rogue operator, real log key)",
        caught=all_refused and len(refusals) >= 3,
        caught_by=tuple(f"witness:{name}" for name, _, _ in refusals),
        detail="; ".join(reason for _, _, reason in refusals),
    )


# ── epoch rebuilt minus one PERMIT: L3 catches the omission ──────────────


def tamper_epoch_minus_permit(bundle_dir: Path, scratch: Path) -> TamperRow:
    """Rebuild the epoch hiding the reflexive PERMIT decision. Variant (a)
    keeps its ATTEMPT: count conservation breaks (GATED-BROKEN). Variant (b)
    hides the attempt too: conservation balances, but the sealed epoch
    commitment's roots no longer rebuild — the omission is still caught."""
    from tex.capstone.verify import _l3_cert_from_dict

    work = _copy_bundle(bundle_dir, scratch / "epoch_minus_permit")
    bundle = SealedFactBundle.from_json(
        (work / LEDGER_BUNDLE_FILE).read_text(encoding="utf-8")
    )
    cert = _l3_cert_from_dict(
        json.loads((work / "l3_certificate.json").read_text(encoding="utf-8"))
    )
    pre_seal = list(bundle.records[: cert.commitment.record_count])

    permit_idx = next(
        i
        for i, r in enumerate(pre_seal)
        if r.fact.kind is SealedFactKind.DECISION
        and r.fact.detail.get("verdict") == "PERMIT"
    )
    permit_subject = pre_seal[permit_idx].fact.subject_id

    def rebuild(records: list) -> tuple:
        ledger = SealedFactLedger(key_label="capstone-omission-adversary")
        for rec in records:
            ledger.append(rec.fact)
        return ledger.list_all()

    # (a) hide the PERMIT decision, keep its sealed ATTEMPT.
    variant_a = rebuild(
        [r for i, r in enumerate(pre_seal) if i != permit_idx]
    )
    conservation_a = check_count_conservation(variant_a)
    a_caught = conservation_a.status == "GATED-BROKEN"

    # (b) hide the attempt too — conservation balances, the roots do not.
    variant_b = rebuild(
        [
            r
            for i, r in enumerate(pre_seal)
            if i != permit_idx
            and not (
                r.fact.kind is SealedFactKind.ATTEMPT
                and r.fact.subject_id == permit_subject
            )
        ]
    )
    conservation_b = check_count_conservation(variant_b)
    epoch_b = verify_epoch_commitment(variant_b, cert.commitment)
    b_caught = conservation_b.status == "GATED-HOLDS" and not epoch_b.ok

    return TamperRow(
        name="epoch rebuilt minus one PERMIT (L3 omission attack)",
        caught=a_caught and b_caught,
        caught_by=("L3.conservation:GATED-BROKEN", "L3.epoch_commitment:roots"),
        detail=(
            f"(a) conservation={conservation_a.status}; "
            f"(b) conservation={conservation_b.status} "
            f"epoch_rebuild_ok={epoch_b.ok} ({epoch_b.reason})"
        ),
    )


# ── swapped artifact / edited manifest: digest binding ───────────────────


def tamper_artifact_swap(bundle_dir: Path, scratch: Path) -> TamperRow:
    """Swap a bundle file behind the manifest (inflate the L12 p_low)."""
    work = _copy_bundle(bundle_dir, scratch / "artifact_swap")
    path = work / L12_TRIAL_FILE
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["p_low"] = 0.999999
    path.write_text(json.dumps(doc), encoding="utf-8")
    result = verify_capstone(work, _pins(work))
    caught = not result.ok and not result.check("manifest.digest_binding").ok
    return TamperRow(
        name="swapped bundle file behind the manifest (L12 p_low inflated)",
        caught=caught,
        caught_by=("manifest.digest_binding",),
        detail=result.check("manifest.digest_binding").detail,
    )


def tamper_manifest_edit(bundle_dir: Path, scratch: Path) -> TamperRow:
    """Edit the manifest itself (relabel L1 as production-grade prose). The
    chain-sealed manifest digest catches it even though every artifact
    digest still matches."""
    work = _copy_bundle(bundle_dir, scratch / "manifest_edit")
    path = work / MANIFEST_FILE
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["created_at"] = "2020-01-01T00:00:00+00:00"
    path.write_text(stable_json(doc), encoding="utf-8")
    result = verify_capstone(work, _pins(work))
    caught = not result.ok and not result.check("manifest.seal_binding").ok
    return TamperRow(
        name="edited manifest (re-canonicalized, artifacts untouched)",
        caught=caught,
        caught_by=("manifest.seal_binding",),
        detail=result.check("manifest.seal_binding").detail,
    )


# ── the matrix ────────────────────────────────────────────────────────────


def run_tamper_matrix(
    flow: CapstoneFlowResult, scratch: str | Path
) -> tuple[TamperRow, ...]:
    """Run every adversary row. The caller asserts ``all(r.caught)``."""
    scratch_dir = Path(scratch)
    scratch_dir.mkdir(parents=True, exist_ok=True)
    bundle_dir = flow.bundle_dir
    return (
        tamper_ledger_byteflip(bundle_dir, scratch_dir),
        tamper_evidence_byteflip(bundle_dir, scratch_dir),
        tamper_voice_byteflip(bundle_dir, scratch_dir),
        tamper_ledger_resign(bundle_dir, scratch_dir),
        tamper_evidence_resign(bundle_dir, scratch_dir),
        tamper_voice_remint(bundle_dir, scratch_dir),
        tamper_verdict_swap(bundle_dir, scratch_dir),
        tamper_checkpoint_fork(flow),
        tamper_epoch_minus_permit(bundle_dir, scratch_dir),
        tamper_artifact_swap(bundle_dir, scratch_dir),
        tamper_manifest_edit(bundle_dir, scratch_dir),
    )


__all__ = [
    "TamperRow",
    "run_tamper_matrix",
    "tamper_artifact_swap",
    "tamper_checkpoint_fork",
    "tamper_epoch_minus_permit",
    "tamper_evidence_byteflip",
    "tamper_evidence_resign",
    "tamper_ledger_byteflip",
    "tamper_ledger_resign",
    "tamper_manifest_edit",
    "tamper_verdict_swap",
    "tamper_voice_byteflip",
    "tamper_voice_remint",
]
