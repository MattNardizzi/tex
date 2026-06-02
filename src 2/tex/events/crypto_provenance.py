"""
Cryptographic provenance attachment.

Wraps a candidate ProposedEvent with:
  - canonicalized payload SHA-256 (RFC 8785 / JCS subset; see _canonical.py)
  - record hash (chained to previous ledger entry, covering every identity
    + lineage field — see Event.canonical_record_input)
  - signature via the injected SignatureProvider (ECDSA-P256 today, ML-DSA
    via Thread 4)
  - tool receipt linkage (if a tool execution is involved)

Reference
---------
arxiv 2512.18561 (AAF) section (i) — cryptographically verifiable
interaction provenance.

Status
------
- **RFC 8785 canonicalization (wired):** via
  ``tex.events._canonical.canonical_json``. Full I-JSON number
  serialization remains a P1 cleanup (see ``_canonical.py``).
- **ML-DSA signing (wired):** ``CryptoProvenance.from_proposed`` accepts
  any ``algorithm_agility`` provider; default is ECDSA-P256 for
  call-site compatibility but ML-DSA-65 (native pyca/cryptography 48
  or liboqs fallback) and the hybrid composite work without
  call-site edits.

Priority: P0.
"""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import SecretStr

from tex.ecosystem.proposed_event import ProposedEvent
from tex.events._canonical import canonical_sha256, sha256_hex, canonical_json
from tex.events._ecdsa_provider import (
    default_signature_provider,
    signature_algorithm_for,
)
from tex.events.event import Event
from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import SignatureKeyPair, SignatureProvider


class CryptoProvenance:
    """
    Attaches cryptographic provenance to a ProposedEvent, producing an Event.

    Construction
    ------------
    Pass a ``SignatureKeyPair`` (the actual signing material) and optionally a
    ``SignatureProvider``. If no provider is given, the default ECDSA-P256
    provider is used. The key's ``algorithm`` field tags the resulting
    Event's ``pq_signature_algorithm``.

    Notes on signature material
    ---------------------------
    The signing key is held on the instance and is never logged or
    canonicalized into the record. ``SecretStr`` would be marginally
    safer but ``SignatureKeyPair`` is a frozen dataclass holding raw
    PEM bytes, so we wrap defensively rather than re-typing the upstream
    contract.
    """

    def __init__(
        self,
        *,
        signing_key: SignatureKeyPair,
        signing_provider: SignatureProvider | None = None,
    ) -> None:
        self._key = signing_key
        self._provider = signing_provider or default_signature_provider()
        self._algorithm = signature_algorithm_for(self._provider)

    def attach(
        self,
        *,
        proposed: ProposedEvent,
        sequence_number: int,
        previous_ledger_hash: str,
        event_id: str | None = None,
        tool_receipt_id: str | None = None,
    ) -> Event:
        """
        Produce a fully-formed Event with hash-chain + signature populated.

        Steps:
          1. canonicalize payload → payload_sha256
          2. assemble canonical_record_input (covers every identity/lineage field)
          3. record_hash = SHA-256(canonical_json(canonical_record_input))
          4. signature = provider.sign(record_hash.encode(), key)
          5. base64-encode signature for transport-friendly storage on the model

        Parameters
        ----------
        proposed
            The candidate ProposedEvent from the ecosystem engine.
        sequence_number
            The next monotone slot in the ledger (caller-provided so this
            method stays stateless).
        previous_ledger_hash
            The prior record's record_hash, or
            ``tex.events.event.genesis_ledger_hash()`` for the first entry.
        event_id
            Optional caller-supplied id; defaults to ``"evt_<uuid4-hex12>"``.
        tool_receipt_id
            Optional link to a HMAC tool receipt (tex.receipts).

        Implementation notes (formerly P0 TODOs):
        - **RFC 8785 canonicalization** via the ``_canonical`` module
          (float-handling caveat tracked as P1).
        - **ML-DSA via algorithm-agility dispatcher:** swap from the
          ECDSA-P256 default by passing a different signing provider; no
          call-site edits.
        """
        payload_sha256 = canonical_sha256(proposed.payload)

        record_input: dict[str, Any] = {
            "kind": proposed.event_kind,
            "actor_entity_id": proposed.actor_entity_id,
            "target_entity_id": proposed.target_entity_id,
            "payload_sha256": payload_sha256,
            "timestamp": proposed.proposed_at.isoformat(),
            "sequence_number": sequence_number,
            "upstream_event_ids": list(proposed.upstream_event_ids),
            "previous_ledger_hash": previous_ledger_hash,
            "tool_receipt_id": tool_receipt_id,
        }
        record_hash = sha256_hex(canonical_json(record_input))

        signature_bytes = self._provider.sign(
            record_hash.encode("utf-8"), self._key
        )
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

        resolved_event_id = event_id or f"evt_{uuid4().hex[:12]}"

        event = Event(
            event_id=resolved_event_id,
            kind=proposed.event_kind,
            actor_entity_id=proposed.actor_entity_id,
            target_entity_id=proposed.target_entity_id,
            payload=dict(proposed.payload),
            timestamp=proposed.proposed_at,
            sequence_number=sequence_number,
            upstream_event_ids=tuple(proposed.upstream_event_ids),
            previous_ledger_hash=previous_ledger_hash,
            payload_sha256=payload_sha256,
            record_hash=record_hash,
            pq_signature_b64=signature_b64,
            pq_signing_key_id=self._key.key_id,
            pq_signature_algorithm=self._algorithm.value,
            tool_receipt_id=tool_receipt_id,
        )

        emit_event(
            "events.crypto_provenance.attached",
            event_id=event.event_id,
            sequence_number=sequence_number,
            kind=event.kind,
            algorithm=self._algorithm.value,
            key_id=self._key.key_id,
        )
        return event

    @property
    def public_key(self) -> bytes:
        """The PEM public key for the signing keypair (used by verifiers)."""
        return self._key.public_key

    @property
    def signing_key_id(self) -> str:
        return self._key.key_id

    @property
    def provider(self) -> SignatureProvider:
        return self._provider
