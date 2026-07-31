"""
Cryptographically-keyed, append-only governance log.

Per arxiv 2601.11369 §6.2.2 + Appendix D the governance log is the
"immutable, append-only execution trace that links every institutional
action back to the manifest". The paper carries the manifest semantic
digest on every log entry so an external auditor can join log entries
to a specific public manifest version.

Tex extends the paper by *signing* every log entry with a key
deliberately distinct from the main events ledger key. This satisfies
two operating constraints:

1. **Independent audit channel.** A regulator (insurer, NAIC,
   investigator) verifying the institutional layer should not need
   access to, or trust in, the operational events ledger key. Signing
   the governance log with a separate key means the regulator can
   request only the public key of the institutional signer and verify
   institutional decisions in isolation.

2. **Algorithm agility.** The signing provider is plumbed through
   tex.pqcrypto.algorithm_agility so the institutional log can adopt
   ML-DSA-65 (FIPS 204) ahead of, behind, or in lockstep with the
   main ledger — whichever the deployment requires.

Reference
---------
arxiv 2601.11369 (Bracale Syrnikov et al., 2026), §6.2.2, Appendix D
arxiv 2601.10599 (Pierucci et al., 2026), §5.4 (audit interfaces)
NIST FIPS 186-5 (ECDSA-P256 default), FIPS 204 (ML-DSA target)

Priority: P1.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from tex.ecosystem.proposed_event import ProposedEvent
from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import (
    SignatureKeyPair,
    SignatureProvider,
)


# Ontology event kinds the governance log uses (see tex.ontology.event_types).
_KIND_OBSERVATION: str = "policy_decision"  # Oracle observations
_KIND_DECISION: str = "governance_graph_transition"  # Controller decisions
_KIND_SANCTION: str = "sanction_applied"
_KIND_RESTORATION: str = "restorative_path_triggered"


class GovernanceLog:
    """
    Append-only signed log of Oracle observations and Controller
    decisions, separately keyed from the main events ledger.

    Construction
    ------------
    >>> from tex.events._ecdsa_provider import EcdsaP256Provider
    >>> provider = EcdsaP256Provider()
    >>> keypair = provider.generate_keypair("institutional-log")
    >>> log = GovernanceLog(
    ...     signing_key_id="institutional-log",
    ...     signing_keypair=keypair,
    ...     signing_provider=provider,
    ... )

    The simpler scaffolded constructor `GovernanceLog(signing_key_id=...)`
    is preserved for back-compat and auto-generates a fresh ECDSA-P256
    keypair via the algorithm-agility default provider.

    Production callers should pass ``signing_keypair`` and
    ``signing_provider`` explicitly so the log is bound to a managed
    HSM key.

    TODO(P1): canonicalize, sign with ML-DSA, append, return record id
        — DONE for canonicalize+sign+append+return. ML-DSA itself is
        wired via tex.pqcrypto.algorithm_agility once liboqs lands;
        Thread 12 ships ECDSA-P256 by default with HYBRID_ML_DSA_ED25519
        available as a constructor argument.
    """

    def __init__(
        self,
        *,
        signing_key_id: str,
        signing_keypair: SignatureKeyPair | None = None,
        signing_provider: SignatureProvider | None = None,
        manifest_semantic_sha256: str | None = None,
    ) -> None:
        if not signing_key_id:
            raise ValueError("GovernanceLog requires non-empty signing_key_id")

        # Lazy imports: avoid the tex.events.__init__ circular and let
        # the dispatcher pick the right provider.
        from tex.events._ecdsa_provider import default_signature_provider
        from tex.events.crypto_provenance import CryptoProvenance
        from tex.events.ledger import InMemoryLedger

        provider = signing_provider or default_signature_provider()
        if signing_keypair is None:
            keypair = provider.generate_keypair(signing_key_id)
        else:
            keypair = signing_keypair
            if keypair.key_id != signing_key_id:
                raise ValueError(
                    f"signing_keypair.key_id={keypair.key_id!r} does not "
                    f"match signing_key_id={signing_key_id!r}"
                )

        self._key_id: str = signing_key_id
        self._keypair: SignatureKeyPair = keypair
        self._provider: SignatureProvider = provider
        self._provenance = CryptoProvenance(
            signing_key=keypair, signing_provider=provider
        )
        self._ledger = InMemoryLedger(
            verifying_public_key=keypair.public_key,
            signing_provider=provider,
        )
        self._manifest_semantic_sha256 = manifest_semantic_sha256

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    @property
    def signing_key_id(self) -> str:
        return self._key_id

    @property
    def public_key(self) -> bytes:
        """PEM public key for offline auditor verification."""
        return self._keypair.public_key

    def __len__(self) -> int:
        return len(self._ledger)

    def record_observation(
        self,
        *,
        oracle_observation: Any,
    ) -> str:
        """
        Append an Oracle observation to the log and return its event_id.

        ``oracle_observation`` may be an OracleObservation pydantic model,
        a dict (for back-compat with the original scaffold signature), or
        any object with a ``model_dump(mode="json")`` method.

        TODO(P1): canonicalize, sign with ML-DSA, append, return record id
            — DONE.
        """
        payload = self._coerce_to_payload(oracle_observation)
        actor = str(payload.get("actor_entity_id", "_oracle"))
        return self._append(
            kind=_KIND_OBSERVATION,
            actor_entity_id=actor,
            target_entity_id=None,
            payload=payload,
        )

    def record_decision(
        self,
        *,
        controller_decision: Any,
    ) -> str:
        """
        Append a Controller decision to the log and return its event_id.

        For decisions whose outcome is SANCTION or REMEDIATE we also
        emit a separate paired record under the more specific event
        kind so downstream consumers can subscribe just to those streams.

        TODO(P1): canonicalize, sign — DONE.
        """
        payload = self._coerce_to_payload(controller_decision)
        actor = str(payload.get("actor_entity_id", "_controller"))
        target = payload.get("to_state")
        target_id: str | None = str(target) if target else None

        # Always append the primary decision record.
        primary_id = self._append(
            kind=_KIND_DECISION,
            actor_entity_id=actor,
            target_entity_id=target_id,
            payload=payload,
        )

        # Paired record for sanctions / remediations — gives downstream
        # subscribers a clean stream filter (e.g. an insurance auditor
        # wanting only SANCTION_APPLIED events).
        outcome = payload.get("decision")
        if outcome == "SANCTION":
            self._append(
                kind=_KIND_SANCTION,
                actor_entity_id=actor,
                target_entity_id=payload.get("sanction_id"),
                payload={
                    "decision_id": payload.get("decision_id"),
                    "sanction_id": payload.get("sanction_id"),
                    "edge_key": payload.get("edge_key"),
                    "rule_id": payload.get("rule_id"),
                    "manifest_semantic_sha256": payload.get(
                        "manifest_semantic_sha256"
                    ),
                },
            )
        elif outcome == "REMEDIATE":
            self._append(
                kind=_KIND_RESTORATION,
                actor_entity_id=actor,
                target_entity_id=payload.get("restorative_path_id"),
                payload={
                    "decision_id": payload.get("decision_id"),
                    "restorative_path_id": payload.get("restorative_path_id"),
                    "edge_key": payload.get("edge_key"),
                    "rule_id": payload.get("rule_id"),
                    "manifest_semantic_sha256": payload.get(
                        "manifest_semantic_sha256"
                    ),
                },
            )
        return primary_id

    def verify_chain(self, *, from_sequence: int = 1, to_sequence: int = -1) -> bool:
        """
        Re-verify the slice [from_sequence, to_sequence]. Default
        verifies the entire log.
        """
        last = len(self._ledger)
        if last == 0:
            return True
        if to_sequence == -1:
            to_sequence = last
        return self._ledger.verify_chain(
            from_sequence=from_sequence, to_sequence=to_sequence
        )

    def all_records(self) -> tuple:
        """Stream every record from the start of the log."""
        return self._ledger.stream_after(-1)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _coerce_to_payload(self, obj: Any) -> dict:
        """
        Normalise to a JSON-canonicalisable dict.

        - pydantic v2 models -> model_dump(mode='json')
        - dicts              -> shallow copy with Enum/datetime coercion
        - other              -> raise TypeError

        Floats are rejected by the events canonicaliser (RFC 8785 / JCS
        with the float caveat from tex.events._canonical), so we coerce
        any incoming floats to milli-units. This matches the
        governance_graph._coerce_jsonable convention.
        """
        if hasattr(obj, "model_dump"):
            data = obj.model_dump(mode="json")
        elif isinstance(obj, dict):
            data = dict(obj)
        else:
            raise TypeError(
                f"GovernanceLog payload must be pydantic model or dict, "
                f"got {type(obj).__name__}"
            )
        return _canonicalise_payload(data)

    def _append(
        self,
        *,
        kind: str,
        actor_entity_id: str,
        target_entity_id: str | None,
        payload: dict,
    ) -> str:
        """Build a ProposedEvent, attach provenance, append, return id."""
        proposed = ProposedEvent(
            event_kind=kind,
            actor_entity_id=actor_entity_id,
            target_entity_id=target_entity_id,
            payload=payload,
            proposed_at=datetime.now(UTC),
        )
        event = self._ledger.append_proposed(
            proposed=proposed, provenance=self._provenance
        )
        emit_event(
            "institutional.governance_log.appended",
            event_id=event.event_id,
            kind=kind,
            actor=actor_entity_id,
            sequence_number=event.sequence_number,
            signing_key_id=self._key_id,
            manifest_semantic_sha256=payload.get("manifest_semantic_sha256")
            or self._manifest_semantic_sha256,
        )
        return event.event_id


def _canonicalise_payload(data: Any) -> Any:
    """
    Recursively coerce a JSON-shaped value into the subset accepted by
    tex.events._canonical.canonical_json (no floats, no datetime, no
    enum). Floats become milli-unit ints; datetimes become ISO strings.
    """
    if data is None or isinstance(data, (str, bool)):
        return data
    if isinstance(data, int):
        return data
    if isinstance(data, float):
        return int(round(data * 1000))
    if isinstance(data, datetime):
        return data.isoformat()
    if hasattr(data, "value") and hasattr(data, "name"):
        # Enum
        return str(data.value)
    if isinstance(data, dict):
        return {str(k): _canonicalise_payload(v) for k, v in data.items()}
    if isinstance(data, (list, tuple)):
        return [_canonicalise_payload(v) for v in data]
    return str(data)
