"""
Behavioural provenance ledger — Certificate Transparency for agents.

This is the seal. Every behavioural-identity event (a birth, a sighting,
a re-identification across a rotation, a drift, a sleep, a wake) is
written here as an append-only, hash-chained, *and per-entry signed*
record. The chain shape is the same SHA-256 construction the discovery
and evidence ledgers use — ``record_hash`` covers ``payload_sha256`` plus
the prior record's hash, so any reordering, deletion, or tamper is
detectable by replay. On top of that, each record's hash is signed with
the ledger's key, so a relying party can verify *authenticity* (Tex
wrote it) as well as *integrity* (it wasn't altered) — offline, holding
only the public key.

That combination is what makes the inventory provable rather than merely
current. Okta and Entra produce a directory: mutable state, trust-me.
This produces a transparency log: append-only, signed, check-it-yourself.
It is the EU AI Act's "automatic recording of events over the lifetime of
the system" satisfied by architecture, not bolted on.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from typing import Any
from uuid import UUID

from tex.events._ecdsa_provider import default_signature_provider
from tex.pqcrypto.algorithm_agility import SignatureKeyPair, SignatureProvider
from tex.provenance.models import ProvenanceEventKind, ProvenanceRecord


def _stable_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class BehavioralProvenanceLedger:
    """
    Append-only, hash-chained, signed log of behavioural-identity events.

    Thread-safe. In-memory by default (the discovery ledger follows the
    same pattern); a Postgres mirror can be layered later without
    changing this contract, exactly as the other ledgers did.
    """

    def __init__(
        self,
        *,
        signing_key: SignatureKeyPair | None = None,
        signing_provider: SignatureProvider | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._entries: list[ProvenanceRecord] = []
        self._by_agent: dict[str, list[int]] = {}
        self._provider: SignatureProvider = (
            signing_provider or default_signature_provider()
        )
        self._key: SignatureKeyPair = (
            signing_key or self._provider.generate_keypair("tex-provenance-ledger")
        )

    # ------------------------------------------------------------------ keys
    @property
    def public_key_pem(self) -> bytes:
        """The PEM public key a relying party uses to verify the log."""
        return self._key.public_key

    @property
    def signing_key_id(self) -> str:
        return self._key.key_id

    # ------------------------------------------------------------------ write
    def append(
        self,
        *,
        event_kind: ProvenanceEventKind,
        agent_id: UUID,
        signature_hash: str,
        confidence: float = 1.0,
        signal_tier: int = 3,
        observation_count: int = 0,
        linked_agent_id: UUID | None = None,
        detail: dict[str, Any] | None = None,
    ) -> ProvenanceRecord:
        """Seal one provenance event into the log and return the record."""
        with self._lock:
            sequence = len(self._entries)
            previous_hash = (
                self._entries[-1].record_hash if self._entries else None
            )

            payload = {
                "event_kind": str(event_kind),
                "agent_id": str(agent_id),
                "signature_hash": signature_hash,
                "confidence": round(float(confidence), 6),
                "signal_tier": int(signal_tier),
                "observation_count": int(observation_count),
                "linked_agent_id": str(linked_agent_id) if linked_agent_id else None,
                "detail": detail or {},
            }
            payload_json = _stable_json(payload)
            payload_sha256 = _sha256_hex(payload_json)
            record_hash = _sha256_hex(
                _stable_json(
                    {"payload_sha256": payload_sha256, "previous_hash": previous_hash}
                )
            )
            signature = self._provider.sign(record_hash.encode("ascii"), self._key)
            signature_b64 = base64.b64encode(signature).decode("ascii")

            record = ProvenanceRecord(
                sequence=sequence,
                event_kind=event_kind,
                agent_id=agent_id,
                signature_hash=signature_hash,
                confidence=float(confidence),
                signal_tier=int(signal_tier),
                observation_count=int(observation_count),
                linked_agent_id=linked_agent_id,
                detail=detail or {},
                payload_sha256=payload_sha256,
                previous_hash=previous_hash,
                record_hash=record_hash,
                signature_b64=signature_b64,
                signing_key_id=self._key.key_id,
            )
            self._entries.append(record)
            self._by_agent.setdefault(str(agent_id), []).append(sequence)
            return record

    # ------------------------------------------------------------------ read
    def list_all(self) -> tuple[ProvenanceRecord, ...]:
        with self._lock:
            return tuple(self._entries)

    def list_for_agent(self, agent_id: UUID) -> tuple[ProvenanceRecord, ...]:
        with self._lock:
            seqs = self._by_agent.get(str(agent_id), [])
            return tuple(self._entries[s] for s in seqs)

    def birth_record(self, agent_id: UUID) -> ProvenanceRecord | None:
        for rec in self.list_for_agent(agent_id):
            if rec.event_kind is ProvenanceEventKind.BIRTH:
                return rec
        return None

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    # ------------------------------------------------------------------ verify
    def verify_chain(self) -> dict[str, Any]:
        """
        Replay the hash chain. Returns {intact, checked, break_at}. Any
        reordering, deletion, or payload tamper breaks continuity here.
        """
        with self._lock:
            entries = list(self._entries)

        previous_hash: str | None = None
        for idx, rec in enumerate(entries):
            expected_payload = {
                "event_kind": str(rec.event_kind),
                "agent_id": str(rec.agent_id),
                "signature_hash": rec.signature_hash,
                "confidence": round(float(rec.confidence), 6),
                "signal_tier": int(rec.signal_tier),
                "observation_count": int(rec.observation_count),
                "linked_agent_id": str(rec.linked_agent_id) if rec.linked_agent_id else None,
                "detail": rec.detail or {},
            }
            payload_sha256 = _sha256_hex(_stable_json(expected_payload))
            record_hash = _sha256_hex(
                _stable_json(
                    {"payload_sha256": payload_sha256, "previous_hash": previous_hash}
                )
            )
            if (
                rec.previous_hash != previous_hash
                or rec.payload_sha256 != payload_sha256
                or rec.record_hash != record_hash
            ):
                return {"intact": False, "checked": idx, "break_at": idx}
            previous_hash = rec.record_hash

        return {"intact": True, "checked": len(entries), "break_at": None}

    def verify_signatures(self, public_key_pem: bytes | None = None) -> dict[str, Any]:
        """
        Verify every record's signature against the public key. Returns
        {valid, checked, invalid_at}. This is the authenticity proof —
        that Tex, holding this key, wrote each record.
        """
        pub = public_key_pem or self._key.public_key
        with self._lock:
            entries = list(self._entries)

        for idx, rec in enumerate(entries):
            try:
                sig = base64.b64decode(rec.signature_b64.encode("ascii"))
            except Exception:  # noqa: BLE001
                return {"valid": False, "checked": idx, "invalid_at": idx}
            ok = self._provider.verify(rec.record_hash.encode("ascii"), sig, pub)
            if not ok:
                return {"valid": False, "checked": idx, "invalid_at": idx}

        return {"valid": True, "checked": len(entries), "invalid_at": None}
