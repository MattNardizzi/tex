"""
Offline evidence bundle — the court-exhibit core.

[Architecture: Layer 5 (Evidence) — proof-of-superiority tooling]

A *bundle* is a self-contained file of sealed ``EvidenceRecord``s plus nothing
else: no database, no running Tex, no network. The promise is the one the whole
product rests on — *a relying party who holds this file AND Tex's published
public key can prove, offline, that the records are intact (nothing was
reordered, deleted, or altered) and authentic (Tex's key — not some other key —
signed each one).*

Two properties, and the subtle line between them
------------------------------------------------
- **Integrity** is self-verifying *from the record alone*: the hash chain
  (SHA-256 over payload + prior link) is recomputed and checked, so any reorder,
  deletion, or one-byte edit surfaces. ``verify_evidence_chain`` does this and
  trusts nothing it is handed — it re-derives every hash.
- **Authorship** is NOT self-verifying. Each ``pq_signature`` block carries the
  public key that signed it, so a signature embedded with *any* key verifies
  against *that* key. An adversary can therefore alter a payload, re-sign it
  with their own freshly-minted key, embed their own public key, and the
  signature checks out. Authorship is only proven by **pinning** Tex's known
  public key out-of-band and rejecting any record signed by a different key.
  This module makes that pin a required input for the court-grade verdict — a
  verifier that skips it proves integrity only, and says so.

The live signer is ECDSA-P256 unless an ML-DSA backend is installed; the
algorithm that actually signed each record is read back from
``pq_signature.algorithm`` and reported verbatim. This bundle does not hide its
payload (plaintext-auditable by design) and is not post-quantum today. We claim
integrity and pinned-key authorship; nothing more.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from tex.domain.evidence import EvidenceRecord
from tex.evidence.chain import (
    _build_record_hash,
    _sha256_hex,
    _stable_json,
    verify_evidence_chain,
)
from tex.evidence.seal import PQ_SIGNATURE_FIELD, EvidenceChainSigner, verify_payload_signature


# ── trust anchor ─────────────────────────────────────────────────────────


def trusted_public_key_b64(signer: EvidenceChainSigner) -> str:
    """The pin: Tex's evidence-seal public key, taken from the trusted signer.

    In production a relying party obtains this from Tex's published transparency
    record, NOT from the bundle. Here we read it from the signer object the
    sealing process controls — the legitimate out-of-band source — so the
    verifier can reject any record signed by a different key.
    """
    return base64.b64encode(signer.key.public_key).decode("ascii")


# ── bundle I/O ───────────────────────────────────────────────────────────


def write_bundle(records: Iterable[EvidenceRecord], path: str | Path) -> Path:
    """Write a JSONL bundle (one record per line) and return the path."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record.model_dump(mode="json"), default=str))
            fh.write("\n")
    return out


def read_bundle(path: str | Path) -> tuple[EvidenceRecord, ...]:
    """Read a JSONL bundle back into validated ``EvidenceRecord``s, in order."""
    src = Path(path)
    records: list[EvidenceRecord] = []
    with src.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            records.append(EvidenceRecord.model_validate(json.loads(line)))
    return tuple(records)


# ── verification result ──────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RecordSignatureCheck:
    index: int
    record_hash: str
    self_verifies: bool  # signature valid against its OWN embedded key
    key_is_pinned: bool | None  # embedded key == Tex pin (None if no pin given)
    algorithm: str | None


@dataclass(frozen=True, slots=True)
class BundleVerification:
    """The offline verdict on a bundle.

    Read the three booleans precisely:
    - ``integrity_ok``    — chain intact AND every signature self-verifies.
    - ``authorship_pinned`` — a Tex public key was supplied to check against.
    - ``authorship_ok``   — every record was signed by the pinned Tex key
      (``None`` when no pin was supplied — authorship is then UNVERIFIED).
    - ``valid`` — the court-grade verdict: integrity AND pinned authorship.
    """

    record_count: int
    chain_intact: bool
    chain_issue_codes: tuple[str, ...]
    signatures_self_verify: bool
    authorship_pinned: bool
    authorship_ok: bool | None
    signature_algorithms: tuple[str, ...]
    per_record_signatures: tuple[RecordSignatureCheck, ...]

    @property
    def integrity_ok(self) -> bool:
        return self.chain_intact and self.signatures_self_verify and self.record_count > 0

    @property
    def valid(self) -> bool:
        """Court-grade: integrity proven AND authorship pinned to Tex's key."""
        return self.integrity_ok and self.authorship_ok is True

    def summary(self) -> str:
        algos = ", ".join(sorted(set(self.signature_algorithms))) or "unsigned"
        head = (
            self.per_record_signatures[-1].record_hash[:16]
            if self.per_record_signatures
            else "—"
        )
        if not self.authorship_pinned:
            author_line = (
                "  authorship       : UNVERIFIED (no Tex public key pinned — "
                "integrity only)"
            )
        else:
            author_line = f"  authorship       : {self.authorship_ok}  (pinned to Tex key)"
        status = "VALID (integrity + authorship)" if self.valid else (
            "INTEGRITY-ONLY" if self.integrity_ok else "INVALID"
        )
        lines = [
            f"Offline bundle verification: {status}",
            f"  records          : {self.record_count}",
            f"  chain intact     : {self.chain_intact}"
            + ("" if self.chain_intact else f"  (issues: {', '.join(self.chain_issue_codes)})"),
            f"  signatures self-verify : {self.signatures_self_verify}  (algorithm: {algos})",
            author_line,
            f"  chain head       : {head}…",
        ]
        return "\n".join(lines)


# ── the offline verifier ─────────────────────────────────────────────────


def verify_bundle(
    records_or_path: Iterable[EvidenceRecord] | str | Path,
    *,
    pinned_public_key_b64: str | None = None,
) -> BundleVerification:
    """Verify a bundle offline, from the records (+ the pinned Tex key) alone.

    Integrity: ``verify_evidence_chain`` recomputes ``payload_sha256`` from
    ``payload_json`` and ``record_hash`` from ``payload_sha256 + previous_hash``
    and checks the backward links — so a tampered payload, a forged hash, a
    reorder, or a deletion all surface.

    Authorship: each record's embedded signature is verified against its own
    embedded key (``self_verifies``) AND — when ``pinned_public_key_b64`` is
    supplied — the embedded key is compared to Tex's pinned key. WITHOUT the pin,
    authorship is reported as UNVERIFIED, because an adversary can re-sign a
    forged payload with their own key. This is the difference between "the file
    is internally consistent" and "Tex actually wrote this."
    """
    if isinstance(records_or_path, (str, Path)):
        records = read_bundle(records_or_path)
    else:
        records = tuple(records_or_path)

    chain = verify_evidence_chain(records)

    sig_checks: list[RecordSignatureCheck] = []
    algorithms: list[str] = []
    all_self_verify = True
    all_keys_pinned = True
    for index, record in enumerate(records):
        try:
            payload = json.loads(record.payload_json)
        except json.JSONDecodeError:
            sig_checks.append(
                RecordSignatureCheck(
                    index=index,
                    record_hash=record.record_hash,
                    self_verifies=False,
                    key_is_pinned=(False if pinned_public_key_b64 else None),
                    algorithm=None,
                )
            )
            all_self_verify = False
            all_keys_pinned = False
            continue

        block = payload.get(PQ_SIGNATURE_FIELD)
        algorithm = block.get("algorithm") if isinstance(block, dict) else None
        embedded_key = block.get("public_key_b64") if isinstance(block, dict) else None

        self_ok = verify_payload_signature(payload)
        if algorithm is not None:
            algorithms.append(algorithm)
        if not self_ok:
            all_self_verify = False

        key_pinned: bool | None
        if pinned_public_key_b64 is None:
            key_pinned = None
        else:
            key_pinned = embedded_key == pinned_public_key_b64
            if not key_pinned:
                all_keys_pinned = False

        sig_checks.append(
            RecordSignatureCheck(
                index=index,
                record_hash=record.record_hash,
                self_verifies=self_ok,
                key_is_pinned=key_pinned,
                algorithm=algorithm,
            )
        )

    signatures_self_verify = all_self_verify and len(records) > 0
    if pinned_public_key_b64 is None:
        authorship_ok: bool | None = None
    else:
        authorship_ok = all_keys_pinned and signatures_self_verify and len(records) > 0

    return BundleVerification(
        record_count=chain.record_count,
        chain_intact=chain.is_valid,
        chain_issue_codes=tuple(issue.code for issue in chain.issues),
        signatures_self_verify=signatures_self_verify,
        authorship_pinned=pinned_public_key_b64 is not None,
        authorship_ok=authorship_ok,
        signature_algorithms=tuple(algorithms),
        per_record_signatures=tuple(sig_checks),
    )


# ── adversary simulation (tests/demos only) ──────────────────────────────


def forge_record_by_resigning(
    record: EvidenceRecord,
    *,
    mutate: Callable[[dict], dict],
    adversary_signer: EvidenceChainSigner,
) -> EvidenceRecord:
    """ATTACK SIMULATION — rebuild ``record`` with a mutated payload re-signed by
    a *foreign* key, chaining consistently to the same ``previous_hash``.

    This models the tamper-then-resign attack the pinned verifier must defeat:
    the returned record self-verifies (the adversary signed their own forgery)
    and — if it is the last record — leaves the chain internally consistent, so
    integrity checks PASS. Only pinning Tex's public key catches it. Used by the
    Replay Trial and tests to prove the pin matters; never a legitimate write.
    """
    payload = json.loads(record.payload_json)
    payload.pop(PQ_SIGNATURE_FIELD, None)
    payload = mutate(dict(payload))
    block = adversary_signer.sign_payload(payload)
    signed = dict(payload)
    signed[PQ_SIGNATURE_FIELD] = block
    payload_json = _stable_json(signed)
    payload_sha256 = _sha256_hex(payload_json)
    record_hash = _build_record_hash(
        payload_sha256=payload_sha256, previous_hash=record.previous_hash
    )
    return record.model_copy(
        update={
            "payload_json": payload_json,
            "payload_sha256": payload_sha256,
            "record_hash": record_hash,
        }
    )


__all__ = [
    "BundleVerification",
    "RecordSignatureCheck",
    "forge_record_by_resigning",
    "read_bundle",
    "trusted_public_key_b64",
    "verify_bundle",
    "write_bundle",
]
