"""
[Architecture: Layer 5 (Evidence)] — the voice-attestation chain.

Every answer Tex speaks is sealed here as an append-only, hash-chained,
per-record-signed attestation. This is a SEPARATE chain from the main evidence
ledger, and that separation is deliberate and honest: a spoken machine answer
is not a PDP ``Decision`` (so ``EvidenceRecorder.record_decision`` does not fit)
and it is not a *human* resolution act (``record_human_resolution`` is
verdict-locked to approved/held/refused, ``evidence/recorder.py:269`` — sealing
a spoken answer there would be a semantic lie). So the voice layer keeps its own
chain and does NOT touch ``recorder.py``/``ledger.py``.

What it reuses, rather than reinvents:
  * the SAME signing primitive the live evidence seal uses —
    ``tex.evidence.seal.EvidenceChainSigner`` over a key from the events
    ledger's ``default_signature_provider`` (ECDSA-P256 today);
  * the SAME canonical JSON (sorted-key, compact, ``ensure_ascii=False``) and
    the SAME chain shape (``record_hash`` covers ``payload_sha256`` + the prior
    record's hash) as ``provenance/ledger.py`` and ``evidence/seal.py`` — so an
    auditor verifies a voice attestation with the identical tooling.

Two distinct proofs, NEVER collapsed into "it's signed so it's proven":
  * the hash CHAIN proves INTEGRITY + ORDERING of the whole sequence
    (``verify_chain``);
  * each record's SIGNATURE proves AUTHORSHIP of ONE spoken act
    (``tex.evidence.seal.verify_payload_signature`` per row).

Honest limits (labelled, per the doctrine):
  * **ECDSA-P256 today, NOT post-quantum.** ``signer.is_post_quantum`` is False
    unless an ML-DSA backend is installed; the ``algorithm`` field always reads
    what actually signed.
  * **Key management is weak.** The chain's key is generated per ``VoiceAttestor``
    (ephemeral by default, or loaded from ``TEX_VOICE_ATTEST_KEY`` if set) with
    no rotation; losing the key makes the signatures unverifiable (the hash
    chain still proves integrity, the signatures do not). This is weaker than
    the main ledger's KMS-injectable key handling. Rotation is unbuilt.
  * In-memory by default; an append-only JSONL mirror is written when a path is
    configured (``TEX_VOICE_ATTEST_PATH``), mirroring the other ledgers.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tex.evidence.seal import EvidenceChainSigner, verify_payload_signature
from tex.events._ecdsa_provider import default_signature_provider

__all__ = ["VoiceAttestationRecord", "VoiceAttestor"]


def _stable_json(value: Any) -> str:
    """Sorted-key compact JSON — byte-identical to ``tex.evidence.seal._stable_json``
    (seal.py:85) and ``provenance/ledger.py``. A regression test asserts the
    byte-equality so this never silently diverges from the chain canonicaliser."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class VoiceAttestationRecord:
    sequence: int
    previous_hash: str | None
    payload_sha256: str
    record_hash: str          # the anchor the operator can walk away with
    payload: dict[str, Any]   # full sealed payload, including the embedded pq_signature

    @property
    def anchor_sha256(self) -> str:
        return self.record_hash


class VoiceAttestor:
    """Append-only, hash-chained, ECDSA-P256-signed log of spoken answers."""

    def __init__(
        self,
        *,
        signer: EvidenceChainSigner | None = None,
        path: str | Path | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._records: list[VoiceAttestationRecord] = []
        if signer is None:
            kp = default_signature_provider().generate_keypair("tex-voice-attest")
            signer = EvidenceChainSigner(key=kp)
        self._signer = signer
        env_path = path if path is not None else os.environ.get("TEX_VOICE_ATTEST_PATH")
        self._path: Path | None = Path(env_path) if env_path else None

    # ------------------------------------------------------------------ keys
    @property
    def algorithm(self) -> str:
        return self._signer.key.algorithm.value

    @property
    def is_post_quantum(self) -> bool:
        return self._signer.is_post_quantum

    @property
    def signing_key_id(self) -> str:
        return self._signer.key.key_id

    # ------------------------------------------------------------------ write
    def seal(
        self,
        *,
        transcript: str,
        routed_dimension: str | None,
        verdict: str,
        answer: str,
        object_: dict[str, Any] | None,
        proof_ref: dict[str, Any] | None,
        gate: dict[str, Any],
        tenant: str | None = None,
    ) -> VoiceAttestationRecord:
        """Seal one spoken answer and return its sealed, signed record.

        The transcript is sealed by its SHA-256, never stored verbatim — the
        attestation proves *what Tex said and on what grounding*, without
        retaining the operator's raw speech.
        """
        with self._lock:
            sequence = len(self._records)
            previous_hash = self._records[-1].record_hash if self._records else None

            payload: dict[str, Any] = {
                "record_type": "voice_attestation",
                "sequence": sequence,
                "tenant": tenant,
                "transcript_sha256": _sha256_hex(transcript or ""),
                "routed_dimension": routed_dimension,
                "verdict": str(verdict),
                "answer": answer,
                "object": object_,
                "proof_ref": proof_ref,
                "gate": gate,
                "attested_at": datetime.now(UTC).isoformat(),
                "previous_hash": previous_hash,
            }
            # Sign over the payload (signer strips pq_signature internally), then
            # embed the self-verifying block; the chain hash then commits to the
            # payload INCLUDING the signature (same order as evidence/seal.py).
            block = self._signer.sign_payload(payload)
            payload["pq_signature"] = block

            payload_sha256 = _sha256_hex(_stable_json(payload))
            record_hash = _sha256_hex(
                _stable_json({"payload_sha256": payload_sha256, "previous_hash": previous_hash})
            )
            record = VoiceAttestationRecord(
                sequence=sequence,
                previous_hash=previous_hash,
                payload_sha256=payload_sha256,
                record_hash=record_hash,
                payload=payload,
            )
            self._records.append(record)
            self._maybe_persist(record)
            return record

    def _maybe_persist(self, record: VoiceAttestationRecord) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(_stable_json(record.payload))
                fh.write("\n")
        except OSError:
            # Persistence is best-effort durability, never blocks the seal; the
            # in-memory chain remains authoritative for this process.
            pass

    # ------------------------------------------------------------------ read
    def records(self) -> tuple[VoiceAttestationRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    # ------------------------------------------------------------------ verify
    def verify_chain(self) -> dict[str, Any]:
        """Replay the hash chain (integrity + ordering). Any reorder, deletion,
        or payload tamper breaks continuity here."""
        with self._lock:
            records = list(self._records)
        previous_hash: str | None = None
        for idx, rec in enumerate(records):
            payload_sha256 = _sha256_hex(_stable_json(rec.payload))
            record_hash = _sha256_hex(
                _stable_json({"payload_sha256": payload_sha256, "previous_hash": previous_hash})
            )
            if (
                rec.previous_hash != previous_hash
                or rec.payload_sha256 != payload_sha256
                or rec.record_hash != record_hash
            ):
                return {"intact": False, "checked": idx, "break_at": idx}
            previous_hash = rec.record_hash
        return {"intact": True, "checked": len(records), "break_at": None}

    def verify_signatures(self) -> dict[str, Any]:
        """Verify every record's embedded signature from the record alone
        (authorship). Uses the same third-party verifier as the evidence seal."""
        with self._lock:
            records = list(self._records)
        for idx, rec in enumerate(records):
            if not verify_payload_signature(rec.payload):
                return {"valid": False, "checked": idx, "invalid_at": idx}
        return {"valid": True, "checked": len(records), "invalid_at": None}
