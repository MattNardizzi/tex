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
from tex.provenance.models import (
    ProvenanceEventKind,
    ProvenanceRecord,
    SealedFact,
    SealedFactKind,
    SealedFactRecord,
    SealPublicKey,
)
from tex.provenance.seal_envelope import CryptoAgileSealer, verify_envelope


def _stable_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _verify_seal_envelopes(
    entries: list[Any], pinned_keys: dict[str, bytes]
) -> dict[str, Any]:
    """Verify the crypto-agile seal envelope on every record (duck-typed over
    both record kinds — each has ``record_hash`` + ``seal_envelope``).

    Returns ``{dual_signed, ecdsa_valid, pq_valid, checked, invalid_at,
    mismatch_at}``. ``dual_signed`` is True only when *every* record carried a
    two-algorithm envelope; ``pq_valid`` only when every record's post-quantum
    signature verified against a pinned key. A legacy ECDSA-only record (no
    envelope) honestly drops ``dual_signed``/``pq_valid`` to False.
    """
    total = len(entries)
    checked = 0
    ecdsa_valid = True
    pq_valid = True
    all_dual = total > 0
    invalid_at: int | None = None
    mismatch_at: int | None = None
    for idx, rec in enumerate(entries):
        env = rec.seal_envelope
        res = verify_envelope(rec.record_hash, env, pinned_keys=pinned_keys)
        if not res.present:
            all_dual = False
            pq_valid = False
            continue
        checked += 1
        if not (env is not None and env.is_dual):
            all_dual = False
        if res.mismatch and mismatch_at is None:
            mismatch_at = idx
        if not res.ecdsa_verified:
            ecdsa_valid = False
            if invalid_at is None:
                invalid_at = idx
        if not res.pq_verified:
            pq_valid = False
            if res.mismatch and invalid_at is None:
                invalid_at = idx
    return {
        "dual_signed": all_dual,
        "ecdsa_valid": ecdsa_valid,
        "pq_valid": pq_valid,
        "checked": checked,
        "invalid_at": invalid_at,
        "mismatch_at": mismatch_at,
    }


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
        pq_signing_key: SignatureKeyPair | None = None,
        pq_signing_provider: SignatureProvider | None = None,
        enable_pq: bool = True,
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
        # Crypto-agile sealer: ECDSA-P256 (the unchanged ``_provider``/``_key``,
        # primary) plus ML-DSA-65 when a post-quantum backend is live. Degrades
        # honestly to ECDSA-only if none is present (``is_dual`` is then False and
        # records carry ``seal_envelope is None``).
        self._sealer = CryptoAgileSealer.from_primary(
            self._provider,
            self._key,
            pq_provider=pq_signing_provider,
            pq_key=pq_signing_key,
            enable_pq=enable_pq,
        )

    # ------------------------------------------------------------------ keys
    @property
    def public_key_pem(self) -> bytes:
        """The PEM public key a relying party uses to verify the log."""
        return self._key.public_key

    @property
    def signing_key_id(self) -> str:
        return self._key.key_id

    @property
    def is_dual_signed(self) -> bool:
        """True when new records are dual-signed (ECDSA-P256 + post-quantum)."""
        return self._sealer.is_dual

    @property
    def pq_public_key(self) -> bytes | None:
        """The raw post-quantum (ML-DSA) public key, or ``None`` if ECDSA-only."""
        signer = self._sealer.pq_signer
        return signer.key.public_key if signer else None

    @property
    def pq_signing_key_id(self) -> str | None:
        signer = self._sealer.pq_signer
        return signer.key.key_id if signer else None

    @property
    def seal_public_keys(self) -> tuple[SealPublicKey, ...]:
        """One public key per seal algorithm — what an offline bundle carries so
        a verifier can check each signature against a pinned key."""
        return self._sealer.public_keys

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
            # Dual-sign the SAME record_hash (ECDSA mirrors signature_b64; ML-DSA
            # added). None when sealing ECDSA-only — byte-identical to a legacy
            # record, so the chain is unchanged either way.
            seal_envelope = (
                self._sealer.envelope_with_primary(record_hash, signature)
                if self._sealer.is_dual
                else None
            )

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
                seal_envelope=seal_envelope,
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

    def verify_seal_envelopes(
        self, *, pinned_keys: dict[str, bytes] | None = None
    ) -> dict[str, Any]:
        """Verify every record's crypto-agile seal envelope (the post-quantum
        authorship proof). Defaults to this ledger's own public keys. See
        :func:`_verify_seal_envelopes` for the returned shape. This is additive
        to :meth:`verify_signatures` (the unchanged ECDSA path)."""
        keys = pinned_keys if pinned_keys is not None else self._sealer.pinned_keys()
        with self._lock:
            entries = list(self._entries)
        return _verify_seal_envelopes(entries, keys)


class SealedFactLedger:
    """
    Typed, proof-carrying generalization of the transparency log.

    Same construction as :class:`BehavioralProvenanceLedger` — append-only,
    SHA-256 hash-chained, and per-entry ECDSA-signed — but over arbitrary
    typed :class:`SealedFact` objects (DECISION / ENFORCEMENT / DRIFT / BLAME /
    IDENTITY / ANSWER) rather than only behavioural-identity events. Each
    appended fact becomes one canonical Proof-Carrying Verdict Record (PCVR):
    the claim, its embedded e-value proof (``SealedFact.evidence``), and the
    cryptographic linkage, all verifiable offline by anyone holding the public
    key. ``BehavioralProvenanceLedger`` is one domain-specific instance of this
    same pattern; this is the general sealed-truth object the rest of Tex writes.

    Thread-safe. In-memory by default; a Postgres mirror can be layered later
    without changing this contract, exactly as the behavioural ledger allows.

    Honesty note (re-verify if the crypto stack changes): the *primary* signer is
    ECDSA-P256 (``_ecdsa_provider``), kept unchanged for every verifier shipping
    today (``signature_b64``). Alongside it, each record is dual-signed with
    ML-DSA-65 (FIPS 204) in a crypto-agile ``SealEnvelope`` *when a post-quantum
    backend is live* — both signatures cover the same ``record_hash``, so the
    hash *chain* (which proves integrity: no reordering/deletion/tamper) is
    byte-for-byte unchanged. A lone signature proves authorship of one record;
    the ML-DSA signature is the post-quantum authorship proof. With no PQ backend
    present, sealing degrades honestly to ECDSA-only (``seal_envelope is None``),
    never a faked post-quantum signature.
    """

    def __init__(
        self,
        *,
        signing_key: SignatureKeyPair | None = None,
        signing_provider: SignatureProvider | None = None,
        key_label: str = "tex-sealed-fact-ledger",
        pq_signing_key: SignatureKeyPair | None = None,
        pq_signing_provider: SignatureProvider | None = None,
        enable_pq: bool = True,
    ) -> None:
        self._lock = threading.RLock()
        self._entries: list[SealedFactRecord] = []
        self._by_kind: dict[str, list[int]] = {}
        self._provider: SignatureProvider = (
            signing_provider or default_signature_provider()
        )
        self._key: SignatureKeyPair = (
            signing_key or self._provider.generate_keypair(key_label)
        )
        # Crypto-agile sealer — ECDSA-P256 (primary, unchanged) + ML-DSA-65 when a
        # post-quantum backend is live. See ``seal_envelope.CryptoAgileSealer``.
        self._sealer = CryptoAgileSealer.from_primary(
            self._provider,
            self._key,
            pq_provider=pq_signing_provider,
            pq_key=pq_signing_key,
            enable_pq=enable_pq,
            pq_key_label=f"{key_label}-ml-dsa",
        )

    # ------------------------------------------------------------------ keys
    @property
    def public_key_pem(self) -> bytes:
        """The PEM public key a relying party uses to verify the log."""
        return self._key.public_key

    @property
    def signing_key_id(self) -> str:
        return self._key.key_id

    @property
    def is_dual_signed(self) -> bool:
        """True when new PCVRs are dual-signed (ECDSA-P256 + post-quantum)."""
        return self._sealer.is_dual

    @property
    def pq_public_key(self) -> bytes | None:
        """The raw post-quantum (ML-DSA) public key, or ``None`` if ECDSA-only."""
        signer = self._sealer.pq_signer
        return signer.key.public_key if signer else None

    @property
    def pq_signing_key_id(self) -> str | None:
        signer = self._sealer.pq_signer
        return signer.key.key_id if signer else None

    @property
    def seal_public_keys(self) -> tuple[SealPublicKey, ...]:
        """One public key per seal algorithm — what an offline bundle carries so
        a verifier can check each signature against a pinned key."""
        return self._sealer.public_keys

    # ------------------------------------------------------------------ write
    def append(self, fact: SealedFact) -> SealedFactRecord:
        """Seal one typed fact into the log and return its PCVR.

        The record hash covers ``payload_sha256`` plus the prior record's hash
        (the chain), and is then signed (authorship). Identical construction to
        the behavioural ledger, so a single verifier can check either log.
        """
        with self._lock:
            sequence = len(self._entries)
            previous_hash = (
                self._entries[-1].record_hash if self._entries else None
            )

            payload = fact.canonical_payload()
            payload_json = _stable_json(payload)
            payload_sha256 = _sha256_hex(payload_json)
            record_hash = _sha256_hex(
                _stable_json(
                    {"payload_sha256": payload_sha256, "previous_hash": previous_hash}
                )
            )
            signature = self._provider.sign(record_hash.encode("ascii"), self._key)
            signature_b64 = base64.b64encode(signature).decode("ascii")
            # Dual-sign the SAME record_hash (ECDSA mirrors signature_b64; ML-DSA
            # added). None when ECDSA-only — identical to a legacy PCVR, so the
            # chain is unchanged regardless of whether PQ is active.
            seal_envelope = (
                self._sealer.envelope_with_primary(record_hash, signature)
                if self._sealer.is_dual
                else None
            )

            record = SealedFactRecord(
                sequence=sequence,
                fact=fact,
                payload_sha256=payload_sha256,
                previous_hash=previous_hash,
                record_hash=record_hash,
                signature_b64=signature_b64,
                signing_key_id=self._key.key_id,
                seal_envelope=seal_envelope,
            )
            self._entries.append(record)
            self._by_kind.setdefault(str(fact.kind), []).append(sequence)
            return record

    # ------------------------------------------------------------------ read
    def list_all(self) -> tuple[SealedFactRecord, ...]:
        with self._lock:
            return tuple(self._entries)

    def list_by_kind(self, kind: SealedFactKind) -> tuple[SealedFactRecord, ...]:
        with self._lock:
            seqs = self._by_kind.get(str(kind), [])
            return tuple(self._entries[s] for s in seqs)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    # ------------------------------------------------------------------ verify
    def verify_chain(self) -> dict[str, Any]:
        """
        Replay the hash chain over the sealed facts. Returns
        ``{intact, checked, break_at}``. Any reordering, deletion, or payload
        tamper (including inside an embedded e-value proof) breaks continuity
        here, because ``payload_sha256`` is recomputed from the fact's own
        canonical payload.
        """
        with self._lock:
            entries = list(self._entries)

        previous_hash: str | None = None
        for idx, rec in enumerate(entries):
            payload_sha256 = _sha256_hex(_stable_json(rec.fact.canonical_payload()))
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
        ``{valid, checked, invalid_at}`` — the authenticity proof that Tex,
        holding this key, authored each record.
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

    def verify_seal_envelopes(
        self, *, pinned_keys: dict[str, bytes] | None = None
    ) -> dict[str, Any]:
        """Verify every PCVR's crypto-agile seal envelope (the post-quantum
        authorship proof). Defaults to this ledger's own public keys. See
        :func:`_verify_seal_envelopes` for the returned shape. Additive to
        :meth:`verify_signatures` (the unchanged ECDSA path)."""
        keys = pinned_keys if pinned_keys is not None else self._sealer.pinned_keys()
        with self._lock:
            entries = list(self._entries)
        return _verify_seal_envelopes(entries, keys)
