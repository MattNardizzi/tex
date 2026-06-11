"""
Offline capstone verifier — files + pins in, named checks out.

[Architecture: composition layer; standalone like ``provenance/bundle.py``.
Maturity: research-early — see manifest.py.]

``verify_capstone`` needs NO live ledger, runtime, or network: only the
bundle directory and the relying party's out-of-band ``CapstonePins``. It
NEVER re-implements a chain or proof verifier — every cryptographic check is
delegated to the owning module:

  chain 1  ``provenance.bundle.verify_sealed_fact_bundle`` (pinned PEM)
  chain 2  ``bench.evidence_bundle.verify_bundle``         (pinned b64 key)
  chain 3  ``voice.entailment_cert.verify_entailment_commitment`` (pinned b64)
  L1       ``zkpdp.arbiter.verify_arbitration`` (over a rehydrated ledger view)
  L2       ``tee.verdict_binding.verify_verdict_binding``
  L3       ``evidence.negative_knowledge.verify_certificate`` +
           ``verify_epoch_commitment`` + ``check_count_conservation``
  L6       ``interchange.gix_witness.verify_cosigned_checkpoint`` +
           ``interchange.gix`` root/consistency recomputation

What this module DOES own: recomputing artifact digests from raw bytes before
parsing anything (the manifest-swap catch), closing the seal loop (the chain's
final ANSWER fact must carry the recomputed manifest digest), and comparing
the manifest's claimed per-property statuses against what the module
verifiers say offline (no status drift).

Two flags mirror the composition's honest test-mode halves: ``allow_shim``
(L1's keyed-hash stand-in is refused fail-closed without it — that refusal is
the module's own ``zkpdp_shim_not_a_real_proof`` gate, demonstrably intact)
and ``tee_test_mode`` (the alg=none JWT verifies only in test mode). Both are
recorded in the result; neither is ever silently assumed.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from tex.adversarial.completeness import CLAIM, NON_CLAIMS, read_certificate
from tex.bench.evidence_bundle import read_bundle, verify_bundle
from tex.engine.verdict_certificate import stability_p_low
from tex.evidence.negative_knowledge import (
    ConservationCheck,
    EpochCommitment,
    NegativeKnowledgeCertificate,
    NonMembershipProof,
    check_count_conservation,
    verify_certificate,
    verify_epoch_commitment,
)
from tex.interchange.gix import (
    Checkpoint,
    Ed25519NoteVerifier,
    consistency_path,
    merkle_root,
    split_signed_note,
    verify_consistency,
)
from tex.interchange.gix_witness import (
    CosignedCheckpoint,
    WitnessDescriptor,
    WitnessProvenance,
    verify_cosigned_checkpoint,
)
from tex.provenance.bundle import SealedFactBundle, verify_sealed_fact_bundle
from tex.provenance.models import SealedFactKind, SealedFactRecord
from tex.voice.attestation import VoiceAttestationRecord
from tex.voice.entailment_cert import verify_entailment_commitment
from tex.zkpdp.arbiter import (
    ArbitrationEnvelope,
    ArbitrationStatement,
    LoweringStep,
    verify_arbitration,
)
from tex.zkprov.commitment import MerkleInclusionProof

from tex.capstone.compose import (
    L6_FINAL_CHECKPOINT_FILE,
    L7_CAMPAIGN_FILE,
    LEDGER_BUNDLE_FILE,
    MANIFEST_FILE,
)
from tex.capstone.manifest import CapstoneVerdict, sha256_hex_bytes


# ── pins (the relying party's out-of-band trust anchors) ─────────────────


@dataclass(frozen=True, slots=True)
class CapstonePins:
    """The trust inputs. In production these come from Tex's published
    transparency record, never from the bundle under verification."""

    ledger_public_key_pem: bytes
    evidence_public_key_b64: str
    voice_public_key_b64: str
    log_name: str
    log_public_key_raw_hex: str
    witness_roster: tuple[tuple[str, str, str], ...]  # (name, pk_hex, provenance)
    nli_model_id: str

    @classmethod
    def from_file(cls, path: str | Path) -> "CapstonePins":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            ledger_public_key_pem=data["ledger_public_key_pem"].encode("ascii"),
            evidence_public_key_b64=data["evidence_public_key_b64"],
            voice_public_key_b64=data["voice_public_key_b64"],
            log_name=data["log_name"],
            log_public_key_raw_hex=data["log_public_key_raw_hex"],
            witness_roster=tuple(
                (w["name"], w["public_key_raw_hex"], w["provenance"])
                for w in data["witness_roster"]
            ),
            nli_model_id=data["nli_model_id"],
        )

    def log_verifier(self) -> Ed25519NoteVerifier:
        return Ed25519NoteVerifier(
            name=self.log_name,
            public_key_raw=bytes.fromhex(self.log_public_key_raw_hex),
        )

    def roster(self) -> tuple[WitnessDescriptor, ...]:
        return tuple(
            WitnessDescriptor(
                name=name,
                public_key_raw=bytes.fromhex(pk_hex),
                provenance=WitnessProvenance(provenance),
            )
            for name, pk_hex, provenance in self.witness_roster
        )


# ── result shape ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CheckResult:
    """One named offline check. The name IS the attribution — tamper rows
    assert which check caught them."""

    name: str
    ok: bool
    detail: str = ""


@dataclass(slots=True)
class CapstoneVerification:
    checks: list[CheckResult] = field(default_factory=list)
    manifest: CapstoneVerdict | None = None
    offline_status: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)

    @property
    def failures(self) -> tuple[CheckResult, ...]:
        return tuple(c for c in self.checks if not c.ok)

    def failed_names(self) -> tuple[str, ...]:
        return tuple(c.name for c in self.failures)

    def check(self, name: str) -> CheckResult:
        for c in self.checks:
            if c.name == name:
                return c
        raise KeyError(name)

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append(CheckResult(name=name, ok=bool(ok), detail=detail))

    def summary(self) -> str:
        lines = [
            f"capstone offline verification: {'VALID' if self.ok else 'INVALID'} "
            f"({sum(c.ok for c in self.checks)}/{len(self.checks)} checks)"
        ]
        for c in self.checks:
            mark = "ok " if c.ok else "FAIL"
            lines.append(f"  [{mark}] {c.name}" + (f" — {c.detail}" if c.detail and not c.ok else ""))
        return "\n".join(lines)


# ── env scoping for the two honest test-mode halves ──────────────────────


@contextmanager
def _scoped_env(updates: dict[str, str | None]) -> Iterator[None]:
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


# ── rehydration (format readers, never verifiers) ────────────────────────


class _LedgerView:
    """Duck-typed read-only ledger over a rehydrated bundle, for
    ``check_seal_binding`` inside ``verify_arbitration``. All verification is
    DELEGATED to ``verify_sealed_fact_bundle`` against the pinned key."""

    def __init__(self, bundle: SealedFactBundle, pinned_pem: bytes) -> None:
        self._bundle = bundle
        self._pem = pinned_pem

    def list_all(self) -> tuple[SealedFactRecord, ...]:
        return tuple(self._bundle.records)

    def list_by_kind(self, kind: SealedFactKind) -> tuple[SealedFactRecord, ...]:
        return tuple(r for r in self._bundle.records if r.fact.kind is kind)

    def verify_chain(self) -> dict[str, Any]:
        report = verify_sealed_fact_bundle(
            self._bundle, pinned_public_key_pem=self._pem
        )
        return {
            "intact": report.chain_intact,
            "checked": report.record_count,
            "break_at": report.chain_break_at,
        }

    def verify_signatures(self, public_key_pem: bytes | None = None) -> dict[str, Any]:
        report = verify_sealed_fact_bundle(
            self._bundle, pinned_public_key_pem=public_key_pem or self._pem
        )
        return {
            "valid": report.signatures_valid,
            "checked": report.record_count,
            "invalid_at": report.signature_invalid_at,
        }


def _statement_from_dict(data: dict[str, Any]) -> ArbitrationStatement:
    return ArbitrationStatement(
        stream_scores_q=tuple((k, int(v)) for k, v in data["stream_scores_q"]),
        weights_q=tuple((k, int(v)) for k, v in data["weights_q"]),
        fused_q=int(data["fused_q"]),
        permit_q=int(data["permit_q"]),
        forbid_q=int(data["forbid_q"]),
        router_skipped=bool(data["router_skipped"]),
        deny_floor=bool(data["deny_floor"]),
        floor_sources=tuple(data["floor_sources"]),
        quarantine_pin=bool(data["quarantine_pin"]),
        chain=tuple(
            LoweringStep(
                from_verdict=step["from"],
                to_verdict=step["to"],
                reason=step["reason"],
            )
            for step in data["chain"]
        ),
        claimed_verdict=data["claimed_verdict"],
        request_id=data["request_id"],
        policy_id=data["policy_id"],
        policy_version=data["policy_version"],
        content_sha256=data["content_sha256"],
        determinism_fingerprint=data["determinism_fingerprint"],
        version=data["version"],
        scale=int(data["scale"]),
    )


def _inclusion_from_dict(data: dict[str, Any] | None) -> MerkleInclusionProof | None:
    if data is None:
        return None
    return MerkleInclusionProof(
        leaf_index=int(data["leaf_index"]),
        siblings=tuple(data["siblings"]),
        poseidon_root=data["poseidon_root"],
    )


def _l3_cert_from_dict(data: dict[str, Any]) -> NegativeKnowledgeCertificate:
    commitment = EpochCommitment(**data["commitment"])
    proof = NonMembershipProof(
        kind=data["proof"]["kind"],
        left_key=data["proof"]["left_key"],
        right_key=data["proof"]["right_key"],
        left_proof=_inclusion_from_dict(data["proof"]["left_proof"]),
        right_proof=_inclusion_from_dict(data["proof"]["right_proof"]),
    )
    conservation = ConservationCheck(**data["conservation"])
    return NegativeKnowledgeCertificate(
        key=data["key"],
        commitment=commitment,
        proof=proof,
        conservation=conservation,
        claim_text=data["claim_text"],
        vacuous=data["vacuous"],
        hash_backend=data["hash_backend"],
        complete=data["complete"],
        attempt_hook_present=data["attempt_hook_present"],
        ledger_in_memory=data["ledger_in_memory"],
        ledger_opt_in=data["ledger_opt_in"],
        maturity=data["maturity"],
    )


def _voice_records_from_list(
    items: list[dict[str, Any]],
) -> tuple[VoiceAttestationRecord, ...]:
    return tuple(
        VoiceAttestationRecord(
            sequence=int(r["sequence"]),
            previous_hash=r["previous_hash"],
            payload_sha256=r["payload_sha256"],
            record_hash=r["record_hash"],
            payload=r["payload"],
        )
        for r in items
    )


def _cosigned_from_dict(data: dict[str, Any]) -> CosignedCheckpoint:
    return CosignedCheckpoint(
        signed_note=data["signed_note"],
        cosignature_lines=tuple(data["cosignature_lines"]),
    )


def _parse_checkpoint(cosigned: CosignedCheckpoint) -> Checkpoint:
    note_text, _ = split_signed_note(cosigned.signed_note)
    return Checkpoint.parse(note_text)


# ── the offline verifier ──────────────────────────────────────────────────


def verify_capstone(
    bundle_dir: str | Path,
    pins: CapstonePins,
    *,
    allow_shim: bool = True,
    tee_test_mode: bool = True,
) -> CapstoneVerification:
    """Verify the whole composed object offline. Never raises on tampered
    input — every failure is a named ``CheckResult``."""
    out = CapstoneVerification()
    root = Path(bundle_dir)

    # 1) the manifest itself ------------------------------------------------
    try:
        manifest_bytes = (root / MANIFEST_FILE).read_bytes()
        manifest = CapstoneVerdict.model_validate_json(manifest_bytes)
    except Exception as exc:  # noqa: BLE001 — tampered input must not raise
        out.add("manifest.parse", False, f"{type(exc).__name__}: {exc}")
        return out
    out.manifest = manifest
    manifest_digest = manifest.manifest_sha256()
    out.add("manifest.parse", True)

    # 2) chain 1 — the sealed-fact epoch -------------------------------------
    try:
        bundle = SealedFactBundle.from_json(
            (root / LEDGER_BUNDLE_FILE).read_text(encoding="utf-8")
        )
    except Exception as exc:  # noqa: BLE001
        out.add("chain1.parse", False, f"{type(exc).__name__}: {exc}")
        return out
    out.add("chain1.parse", True)
    report = verify_sealed_fact_bundle(
        bundle, pinned_public_key_pem=pins.ledger_public_key_pem
    )
    out.add(
        "chain1.integrity",
        report.chain_intact,
        f"break_at={report.chain_break_at}",
    )
    out.add(
        "chain1.authorship_pin",
        report.signatures_valid and report.key_matches_pin,
        f"signatures_valid={report.signatures_valid} "
        f"key_matches_pin={report.key_matches_pin} "
        f"invalid_at={report.signature_invalid_at}",
    )
    records = tuple(bundle.records)

    # 3) the seal loop: chain head commits to THIS manifest ------------------
    seal_ok = False
    seal_detail = ""
    if records:
        last = records[-1]
        sealed_digest = last.fact.detail.get("capstone_manifest_sha256")
        seal_ok = (
            last.fact.kind is SealedFactKind.ANSWER
            and sealed_digest == manifest_digest
            and last.sequence == manifest.epoch.sealed_fact_sequence
            and len(records) == manifest.epoch.record_count_pre_seal + 1
            and records[-2].record_hash == manifest.epoch.epoch_head_hash_pre_seal
        )
        seal_detail = (
            f"sealed={str(sealed_digest)[:16]} recomputed={manifest_digest[:16]} "
            f"kind={last.fact.kind} seq={last.sequence}"
        )
    out.add("manifest.seal_binding", seal_ok, seal_detail)

    pre_seal = records[:-1] if records else ()
    attempt_count = sum(1 for r in pre_seal if r.fact.kind is SealedFactKind.ATTEMPT)
    decision_count = sum(1 for r in pre_seal if r.fact.kind is SealedFactKind.DECISION)
    out.add(
        "manifest.epoch_counts",
        attempt_count == manifest.epoch.attempt_fact_count
        and decision_count == manifest.epoch.decision_kind_fact_count
        and decision_count != len(records),
        f"attempts={attempt_count} decisions={decision_count} records={len(records)}",
    )

    # 4) artifact digests, recomputed from raw bytes BEFORE parsing ----------
    digests_ok = True
    digest_detail = []
    raw: dict[str, bytes] = {}
    for ref in manifest.artifacts:
        path = root / ref.filename
        try:
            data = path.read_bytes()
        except OSError as exc:
            digests_ok = False
            digest_detail.append(f"{ref.name}: unreadable ({exc})")
            continue
        raw[ref.name] = data
        actual = sha256_hex_bytes(data)
        if actual != ref.sha256:
            digests_ok = False
            digest_detail.append(
                f"{ref.name}: digest mismatch ({actual[:16]} != {ref.sha256[:16]})"
            )
    out.add("manifest.digest_binding", digests_ok, "; ".join(digest_detail))

    # 5) pins file consistency with the manifest's pin digests ---------------
    pins_ok = (
        sha256_hex_bytes(pins.ledger_public_key_pem)
        == manifest.pins.ledger_public_key_pem_sha256
        and sha256_hex_bytes(pins.evidence_public_key_b64.encode("ascii"))
        == manifest.pins.evidence_public_key_b64_sha256
        and sha256_hex_bytes(pins.voice_public_key_b64.encode("ascii"))
        == manifest.pins.voice_public_key_b64_sha256
        and sha256_hex_bytes(bytes.fromhex(pins.log_public_key_raw_hex))
        == manifest.pins.log_public_key_raw_sha256
        and pins.nli_model_id == manifest.pins.nli_model_id
    )
    out.add(
        "pins.digest",
        pins_ok,
        "the supplied pins do not match the keys the composition declared",
    )

    if not (digests_ok and records):
        # Without trustworthy artifact bytes the per-property phases would
        # report noise; the digest failure is the verdict.
        return out

    # 6) the decision's identity, from sealed facts --------------------------
    decision_seq = manifest.decision.decision_fact_sequence
    attempt_seq = manifest.decision.attempt_fact_sequence
    identity_ok = False
    identity_detail = ""
    decision_doc: dict[str, Any] = {}
    try:
        decision_doc = json.loads(raw["decision_capstone"])
        decision_rec = records[decision_seq]
        attempt_rec = records[attempt_seq]
        d = decision_rec.fact.detail
        identity_ok = (
            decision_rec.fact.kind is SealedFactKind.DECISION
            and attempt_rec.fact.kind is SealedFactKind.ATTEMPT
            and decision_rec.fact.subject_id == manifest.decision.request_id
            and attempt_rec.fact.subject_id == manifest.decision.request_id
            and attempt_seq < decision_seq
            and d.get("verdict") == manifest.decision.verdict
            and d.get("content_sha256") == manifest.decision.content_sha256
            and d.get("determinism_fingerprint")
            == manifest.decision.determinism_fingerprint
            and d.get("policy_id") == manifest.decision.policy_id
            and d.get("policy_version") == manifest.decision.policy_version
            and decision_doc.get("request_id") == manifest.decision.request_id
            and decision_doc.get("verdict") == manifest.decision.verdict
            and decision_doc.get("content_sha256") == manifest.decision.content_sha256
        )
    except Exception as exc:  # noqa: BLE001
        identity_detail = f"{type(exc).__name__}: {exc}"
    out.add("decision.identity", identity_ok, identity_detail)

    # 7) L1 — relation proof + seal binding (module verifier) -----------------
    shim_env = {"TEX_ZKPDP_ALLOW_SHIM": "1" if allow_shim else None}
    l1_ok = False
    l1_seal_ok = False
    l1_detail = ""
    try:
        stmt = _statement_from_dict(json.loads(raw["zkpdp_statement"]))
        envelope = ArbitrationEnvelope.from_bytes(raw["zkpdp_envelope"])
        stmt_binds = (
            stmt.sha256_hex() == envelope.statement_sha256
            and stmt.request_id == manifest.decision.request_id
            and stmt.claimed_verdict == manifest.decision.verdict
            and stmt.content_sha256 == manifest.decision.content_sha256
            and stmt.determinism_fingerprint
            == manifest.decision.determinism_fingerprint
        )
        with _scoped_env(shim_env):
            l1 = verify_arbitration(
                stmt,
                envelope,
                ledger=_LedgerView(bundle, pins.ledger_public_key_pem),
                expected_public_key_pem=pins.ledger_public_key_pem,
            )
        l1_ok = (
            stmt_binds and l1.is_valid and l1.stand_in and not l1.regulator_grade
        )
        l1_seal_ok = l1.seal is not None and l1.seal.status == "sealed_match"
        l1_detail = (
            f"reason={l1.reason!r} stand_in={l1.stand_in} "
            f"seal={l1.seal.status if l1.seal else None} "
            f"allow_shim={allow_shim} stmt_binds={stmt_binds}"
        )
        if l1_ok:
            out.offline_status["L1"] = "green_test_mode"
    except Exception as exc:  # noqa: BLE001
        l1_detail = f"{type(exc).__name__}: {exc}"
    out.add("L1.relation", l1_ok, l1_detail)
    out.add("L1.seal_binding", l1_seal_ok, l1_detail)

    # 8) L2 — verdict binding, inputs re-derived from SEALED data -------------
    tee_env = {"TEX_TEE_ATTESTATION_MODE": "test" if tee_test_mode else None}
    l2_ok = False
    l2_detail = ""
    try:
        from tex.tee.verdict_binding import verify_verdict_binding

        policy_digest = sha256_hex_bytes(raw["policy_snapshot"])
        sealed = records[decision_seq].fact.detail
        with _scoped_env(tee_env):
            l2 = verify_verdict_binding(
                raw["tee_verdict_binding"].decode("ascii"),
                sealed_verdict=sealed["verdict"],
                policy_bundle_digest=policy_digest,
                decision_input_sha256=sealed["content_sha256"],
                ledger_prev_hash=records[decision_seq].record_hash,
            )
        l2_ok = l2.ok and l2.test_mode
        l2_detail = f"reason={l2.reason!r} test_mode={l2.test_mode}"
        if l2_ok:
            out.offline_status["L2"] = "green_test_mode"
    except Exception as exc:  # noqa: BLE001
        l2_detail = f"{type(exc).__name__}: {exc}"
    out.add("L2.verdict_binding", l2_ok, l2_detail)

    # 9) L3 — negative knowledge over the pre-seal epoch ----------------------
    l3_cert_ok = False
    l3_epoch_ok = False
    l3_cons_ok = False
    l3_detail = ""
    try:
        cert = _l3_cert_from_dict(json.loads(raw["l3_certificate"]))
        cert_check = verify_certificate(cert)
        epoch_slice = records[: cert.commitment.record_count]
        epoch_check = verify_epoch_commitment(epoch_slice, cert.commitment)
        conservation = check_count_conservation(epoch_slice)
        l3_cert_ok = cert_check.ok
        l3_epoch_ok = epoch_check.ok and cert.commitment.record_count == len(pre_seal)
        l3_cons_ok = (
            conservation.status == "GATED-HOLDS"
            and conservation.holds is True
            and cert.conservation.status == "GATED-HOLDS"
            and conservation.n_attempts == cert.conservation.n_attempts
        )
        l3_detail = (
            f"cert={cert_check.reason!r} epoch={epoch_check.reason!r} "
            f"conservation={conservation.status} n_attempts={conservation.n_attempts}"
        )
        if l3_cert_ok and l3_epoch_ok and l3_cons_ok:
            out.offline_status["L3"] = "green"
    except Exception as exc:  # noqa: BLE001
        l3_detail = f"{type(exc).__name__}: {exc}"
    out.add("L3.certificate", l3_cert_ok, l3_detail)
    out.add("L3.epoch_commitment", l3_epoch_ok, l3_detail)
    out.add("L3.conservation", l3_cons_ok, l3_detail)

    # 10) L6 — witnessed checkpoints + root binding over the shipped chain ----
    l6_quorum_ok = False
    l6_root_ok = False
    l6_consistency_ok = False
    l6_federated_ok = False
    l6_detail = ""
    try:
        cps = json.loads(raw["l6_checkpoints"])
        final_doc = json.loads(
            (root / L6_FINAL_CHECKPOINT_FILE).read_text(encoding="utf-8")
        )
        log_verifier = pins.log_verifier()
        roster = pins.roster()
        pre = _cosigned_from_dict(cps["pre"])
        post = _cosigned_from_dict(cps["post"])
        final = _cosigned_from_dict(final_doc)
        v_pre = verify_cosigned_checkpoint(
            pre, log_verifier=log_verifier, roster=roster, quorum=3
        )
        v_post = verify_cosigned_checkpoint(
            post, log_verifier=log_verifier, roster=roster, quorum=3
        )
        v_final = verify_cosigned_checkpoint(
            final, log_verifier=log_verifier, roster=roster, quorum=3
        )
        l6_quorum_ok = (
            v_pre.quorum_met and v_post.quorum_met and v_final.quorum_met
        )
        l6_federated_ok = (
            v_final.federated is False and bool(v_final.federated_reason)
        )
        cp_pre = _parse_checkpoint(pre)
        cp_post = _parse_checkpoint(post)
        cp_final = _parse_checkpoint(final)
        hashes = [r.record_hash for r in records]
        l6_root_ok = (
            cp_final.tree_size == len(records)
            and cp_final.root_hash_hex == merkle_root(hashes)
        )
        proof_post = consistency_path(cp_pre.tree_size, hashes[: cp_post.tree_size])
        proof_final = consistency_path(cp_post.tree_size, hashes)
        l6_consistency_ok = verify_consistency(
            cp_pre.tree_size,
            cp_pre.root_hash_hex,
            cp_post.tree_size,
            cp_post.root_hash_hex,
            proof_post,
        ) and verify_consistency(
            cp_post.tree_size,
            cp_post.root_hash_hex,
            cp_final.tree_size,
            cp_final.root_hash_hex,
            proof_final,
        )
        l6_detail = (
            f"quorum=({v_pre.quorum_met},{v_post.quorum_met},{v_final.quorum_met}) "
            f"final_size={cp_final.tree_size} records={len(records)}"
        )
        if l6_quorum_ok and l6_root_ok and l6_consistency_ok and l6_federated_ok:
            out.offline_status["L6"] = "green"
    except Exception as exc:  # noqa: BLE001
        l6_detail = f"{type(exc).__name__}: {exc}"
    out.add("L6.quorum", l6_quorum_ok, l6_detail)
    out.add("L6.root_binding", l6_root_ok, l6_detail)
    out.add("L6.consistency", l6_consistency_ok, l6_detail)
    out.add("L6.federated", l6_federated_ok, l6_detail)

    # 11) L7 — chain 2: campaign bundle + sealed certificate ------------------
    l7_chain_ok = False
    l7_pin_ok = False
    l7_cert_ok = False
    l7_detail = ""
    try:
        campaign_records = read_bundle(root / L7_CAMPAIGN_FILE)
        v7 = verify_bundle(
            campaign_records, pinned_public_key_b64=pins.evidence_public_key_b64
        )
        l7_chain_ok = v7.integrity_ok
        l7_pin_ok = v7.authorship_ok is True
        payload = read_certificate(campaign_records)
        l7_cert_ok = (
            payload is not None
            and payload.get("claim") == CLAIM
            and payload.get("non_claims") == list(NON_CLAIMS)
            and payload["survival"]["n_breaches"] == 0
            and payload["survival"]["p_anytime"] == 1.0
        )
        l7_detail = (
            f"integrity={v7.integrity_ok} authorship={v7.authorship_ok} "
            f"codes={v7.chain_issue_codes}"
        )
        if l7_chain_ok and l7_pin_ok and l7_cert_ok:
            out.offline_status["L7"] = "green"
    except Exception as exc:  # noqa: BLE001
        l7_detail = f"{type(exc).__name__}: {exc}"
    out.add("chain2.integrity", l7_chain_ok, l7_detail)
    out.add("chain2.authorship_pin", l7_pin_ok, l7_detail)
    out.add("L7.certificate", l7_cert_ok, l7_detail)

    # 12) L11 — chain 3: spoken seal + entailment commitment ------------------
    l11_chain_ok = False
    l11_pin_ok = False
    l11_ok = False
    l11_cross_ok = False
    l11_detail = ""
    try:
        voice_records = _voice_records_from_list(json.loads(raw["voice_chain"]))
        v11 = verify_entailment_commitment(
            voice_records,
            expected_model_id=pins.nli_model_id,
            pinned_public_key_b64=pins.voice_public_key_b64,
        )
        l11_chain_ok = v11.chain_intact and v11.signatures_valid
        l11_pin_ok = v11.authorship_ok is True
        l11_ok = (
            v11.ok
            and len(v11.commitments) == 1
            and v11.commitments[0].lambda_hat is None
            and v11.commitments[0].calibrated is False
        )
        proof_ref = voice_records[0].payload.get("proof_ref") or {}
        l11_cross_ok = (
            proof_ref.get("record_hash") == records[decision_seq].record_hash
            and proof_ref.get("request_id") == manifest.decision.request_id
        )
        l11_detail = f"issues={v11.issues} authorship={v11.authorship_ok}"
        if l11_chain_ok and l11_pin_ok and l11_ok:
            out.offline_status["L11"] = "green"
    except Exception as exc:  # noqa: BLE001
        l11_detail = f"{type(exc).__name__}: {exc}"
    out.add("chain3.integrity", l11_chain_ok, l11_detail)
    out.add("chain3.authorship_pin", l11_pin_ok, l11_detail)
    out.add("L11.commitment", l11_ok, l11_detail)
    out.add("L11.cross_chain", l11_cross_ok, l11_detail)

    # 13) L12 — recompute the robustness numbers + segment cross-check --------
    l12_ok = False
    l12_detail = ""
    try:
        trial = json.loads(raw["l12_neighborhood"])
        n, k = trial["n_samples"], trial["n_stable"]
        recomputed = stability_p_low(k, n, trial["delta"])
        seg = trial["ledger_segment"]
        seg_verdicts = sorted(
            r.fact.detail["verdict"]
            for r in records[seg[0]:seg[1]]
            if r.fact.kind is SealedFactKind.DECISION
            and "verdict" in r.fact.detail
        )
        cert12 = trial["certificate"]
        l12_ok = (
            abs(recomputed - trial["p_low"]) < 1e-12
            and k == sum(1 for v in trial["verdicts"] if v == trial["target_verdict"])
            and seg_verdicts == sorted(trial["verdicts"])
            and cert12["certified"] is False
            and cert12["qif_estimate_only"] is True
            and cert12["robustness_neighborhood_kind"] == "synthetic"
        )
        l12_detail = f"p_low={trial['p_low']} recomputed={recomputed} n={n} k={k}"
        if l12_ok:
            out.offline_status["L12"] = "uncertified"
    except Exception as exc:  # noqa: BLE001
        l12_detail = f"{type(exc).__name__}: {exc}"
    out.add("L12.recompute", l12_ok, l12_detail)

    # 14) fact-level properties: L5 / L9 / L10 / L8 / M0 ----------------------
    l5_prop = manifest.property_for("L5")
    l5_ok = False
    l5_detail = ""
    try:
        ruling = records[l5_prop.ledger_sequences[3]].fact
        l5_ok = (
            ruling.kind is SealedFactKind.ENFORCEMENT
            and ruling.detail.get("allowed") is False
            and "metaguard.governance_weakening"
            in ruling.detail.get("caution_codes", [])
        )
        if l5_ok:
            out.offline_status["L5"] = "green"
    except Exception as exc:  # noqa: BLE001
        l5_detail = f"{type(exc).__name__}: {exc}"
    out.add("L5.ruling", l5_ok, l5_detail)

    l9_ok = False
    l9_detail = ""
    try:
        import math

        l9_prop = manifest.property_for("L9")
        drift = records[l9_prop.ledger_sequences[0]].fact
        d = drift.detail
        threshold = d["k"] * math.log(2.0) + math.log(1.0 / d["alpha"])
        l9_ok = (
            drift.kind is SealedFactKind.DRIFT
            and d.get("acted") is True
            and d.get("anytime_valid") is True
            and abs(d["action_log_e_threshold"] - threshold) < 1e-9
            and d["log_e_value"] >= d["action_log_e_threshold"]
        )
        if l9_ok:
            out.offline_status["L9"] = "green"
    except Exception as exc:  # noqa: BLE001
        l9_detail = f"{type(exc).__name__}: {exc}"
    out.add("L9.drift", l9_ok, l9_detail)

    l10_ok = False
    l10_detail = ""
    try:
        l10_prop = manifest.property_for("L10")
        pq = records[l10_prop.ledger_sequences[0]].fact
        pq_doc = json.loads(raw["decision_pq"])
        l10_ok = (
            pq.kind is SealedFactKind.DECISION
            and pq.detail.get("pq_durable") is False
            and "verdict" not in pq.detail
            and pq.detail.get("pq_non_repudiation_claim_honored") is False
            and "pq_non_repudiation_unavailable" in pq_doc.get("uncertainty_flags", [])
            and pq_doc.get("verdict") == "ABSTAIN"
        )
        if l10_ok:
            out.offline_status["L10"] = "green"
    except Exception as exc:  # noqa: BLE001
        l10_detail = f"{type(exc).__name__}: {exc}"
    out.add("L10.fact", l10_ok, l10_detail)

    l8_ok = False
    l8_detail = ""
    try:
        pq_doc = json.loads(raw["decision_pq"])
        hold = (pq_doc.get("metadata") or {}).get("pdp", {}).get("hold")
        capstone_hold = (decision_doc.get("metadata") or {}).get("pdp", {}).get("hold")
        l8_ok = (
            pq_doc.get("verdict") == "ABSTAIN"
            and isinstance(hold, dict)
            and bool(hold.get("hold_type"))
            and decision_doc.get("verdict") in ("PERMIT", "FORBID")
            and capstone_hold is None
        )
        if l8_ok:
            out.offline_status["L8"] = "green"
    except Exception as exc:  # noqa: BLE001
        l8_detail = f"{type(exc).__name__}: {exc}"
    out.add("L8.hold", l8_ok, l8_detail)

    m0_ok = False
    m0_detail = ""
    try:
        per_request: dict[str, list[SealedFactKind]] = {}
        for rec in pre_seal:
            sid = rec.fact.subject_id
            if sid is None:
                continue
            per_request.setdefault(sid, []).append(rec.fact.kind)
        m0_ok = bool(per_request)
        for sid, kinds in per_request.items():
            attempts = [i for i, k in enumerate(kinds) if k is SealedFactKind.ATTEMPT]
            decisions = [i for i, k in enumerate(kinds) if k is SealedFactKind.DECISION]
            if attempts and decisions and min(attempts) > min(decisions):
                m0_ok = False
                m0_detail = f"DECISION precedes ATTEMPT for {sid}"
    except Exception as exc:  # noqa: BLE001
        m0_detail = f"{type(exc).__name__}: {exc}"
    out.add("M0.order", m0_ok, m0_detail)

    # L4: the floor's offline witness is the proven relation (deny_floor with
    # structural sources) + the decision document; the certificate posture is
    # pinned by the manifest validators.
    l4_ok = False
    l4_detail = ""
    try:
        floor_meta = (decision_doc.get("metadata") or {})["pdp"]["structural_floor"]
        l4_prop = manifest.property_for("L4")
        l4_ok = (
            l1_ok
            and "action_class" in floor_meta.get("denying_specialists", [])
            and l4_prop.verification["certificate"]["certified"] is False
        )
        if l4_ok:
            out.offline_status["L4"] = "green"
    except Exception as exc:  # noqa: BLE001
        l4_detail = f"{type(exc).__name__}: {exc}"
    out.add("L4.floor", l4_ok, l4_detail)

    # 15) no status drift: manifest claims == offline findings ----------------
    expected_status = {
        "L1": "green_test_mode",
        "L2": "green_test_mode",
        "L3": "green",
        "L4": "green",
        "L5": "green",
        "L6": "green",
        "L7": "green",
        "L8": "green",
        "L9": "green",
        "L10": "green",
        "L11": "green",
        "L12": "uncertified",
    }
    drift = [
        leap
        for leap, want in expected_status.items()
        if manifest.property_for(leap).status != want
        or out.offline_status.get(leap) != want
    ]
    out.add(
        "manifest.status_drift",
        not drift,
        f"leaps with drift between claim and offline finding: {drift}",
    )

    return out


__all__ = [
    "CapstonePins",
    "CapstoneVerification",
    "CheckResult",
    "verify_capstone",
]
