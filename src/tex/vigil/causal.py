"""
[Architecture: Cross-cutting (Vigil cognition)] — v5 CAUSAL MODEL.

The frontier rung. EFE reasons over whatever generative model it is given;
v5 hands it a *causal* one. With causal structure underneath, the vigil
climbs from "this happened and it's surprising" to "this caused that; those
other lines were symptoms, not separate events; here is what would have
happened if Tex hadn't gated it."

This does not replace EFE — it is the kind of model EFE selects over. The
stack is: surprise (v1) -> EFE (v4) -> over a causal model (v5).

Binds to the causal infrastructure already in the tree:

    tex.causal.attribution_engine.compute_attribution — root-cause attribution
                                                         (runs the HCG +
                                                         counterfactual screener
                                                         internally)

PROVABILITY CONSTRAINT (load-bearing): "this caused that" is a stronger claim
than "this happened," so it must be MORE provable, not less. Every causal
edge and every counterfactual a line rests on is SEALED into an append-only,
hash-chained attribution ledger before it can inform speech. The gate is in
code: an attribution that does not return a non-empty seal hash whose chain
verifies is REFUSED — the symptom keeps its standalone line, no causal claim
is spoken. When a full evidence recorder + signing key are present, a
decision-backed attribution additionally seals a first-class, COSE-signed row
into the main evidence chain (the regulator-grade path); otherwise the
hash-chained ledger here is the seal.

Iron rule still holds: a counterfactual is spoken in an AUTHORED form filled
only from sealed attribution data (see vigil/utterances.py), never improvised.
Witness law holds: a counterfactual recalls what would have happened; it
never advises.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass, field
from threading import RLock
from typing import Any

from tex.vigil.dimensions import DimensionReading, ProofRef

__all__ = [
    "CausalAttributionPort",
    "CausalSeal",
    "CausalAttribution",
    "CounterfactualClaim",
]


# --------------------------------------------------------------------------- sealed records


@dataclass(frozen=True, slots=True)
class CausalAttribution:
    """A sealed cause -> symptom edge. ``proof`` points to the seal."""

    cause_key: str
    symptom_key: str
    method: str
    confidence: float
    proof: ProofRef
    sealed: bool = True


@dataclass(frozen=True, slots=True)
class CounterfactualClaim:
    """A sealed "what would have happened" claim for a spoken line."""

    dimension: str
    form_key: str            # authored form in utterances.py to fill
    slots: dict[str, Any]    # sealed values that fill the form
    method: str
    proof: ProofRef
    sealed: bool = True


# --------------------------------------------------------------------------- seal


@dataclass(slots=True)
class _SealEntry:
    sequence: int
    payload_sha256: str
    previous_hash: str | None
    record_hash: str


class CausalSeal:
    """Append-only, hash-chained ledger of causal attributions.

    The same SHA-256 chain shape Tex uses everywhere (discovery ledger,
    evidence recorder): ``record_hash = sha256(payload_sha256 +
    previous_hash)``. Any reordering, deletion, or tamper breaks the chain on
    ``verify_chain()``. This is the vigil's causal evidence ledger — always
    available, no signing key required, and fully verifiable.
    """

    __slots__ = ("_lock", "_entries", "_payloads")

    def __init__(self) -> None:
        self._lock = RLock()
        self._entries: list[_SealEntry] = []
        self._payloads: list[str] = []

    def append(self, payload: dict[str, Any]) -> _SealEntry:
        with self._lock:
            sequence = len(self._entries)
            previous_hash = self._entries[-1].record_hash if self._entries else None
            payload_json = _stable_json(payload)
            payload_sha256 = _sha256_hex(payload_json)
            record_hash = _sha256_hex(
                _stable_json(
                    {"payload_sha256": payload_sha256, "previous_hash": previous_hash}
                )
            )
            entry = _SealEntry(
                sequence=sequence,
                payload_sha256=payload_sha256,
                previous_hash=previous_hash,
                record_hash=record_hash,
            )
            self._entries.append(entry)
            self._payloads.append(payload_json)
            return entry

    def verify_chain(self) -> bool:
        with self._lock:
            previous_hash: str | None = None
            for entry, payload_json in zip(self._entries, self._payloads):
                payload_sha256 = _sha256_hex(payload_json)
                if payload_sha256 != entry.payload_sha256:
                    return False
                expected = _sha256_hex(
                    _stable_json(
                        {"payload_sha256": payload_sha256, "previous_hash": previous_hash}
                    )
                )
                if expected != entry.record_hash:
                    return False
                if entry.previous_hash != previous_hash:
                    return False
                previous_hash = entry.record_hash
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


# --------------------------------------------------------------------------- port


class CausalAttributionPort:
    """v5: cause-vs-symptom attribution and counterfactuals for the vigil.

        attribute(readings, tenant) -> readings
        counterfactual(reading, tenant) -> CounterfactualClaim | None

    Constructed with optional collaborators. The seal is always present (its
    own hash-chained ledger). A decision_store lets the port bind decision-
    backed readings to the real attribution engine. An evidence_recorder +
    signing_key_resolver enable the regulator-grade COSE-signed seal path.
    """

    __slots__ = ("_seal", "_decision_store", "_evidence_recorder", "_signing_key_resolver")

    def __init__(
        self,
        *,
        seal: CausalSeal | None = None,
        decision_store: Any | None = None,
        evidence_recorder: Any | None = None,
        signing_key_resolver: Any | None = None,
    ) -> None:
        self._seal = seal if seal is not None else CausalSeal()
        self._decision_store = decision_store
        self._evidence_recorder = evidence_recorder
        self._signing_key_resolver = signing_key_resolver

    @property
    def seal(self) -> CausalSeal:
        return self._seal

    # ------------------------------------------------------------------ attribute

    def attribute(
        self, readings: list[DimensionReading], *, tenant: str | None
    ) -> list[DimensionReading]:
        """Re-tag readings with sealed cause -> symptom structure.

        Generalizes v1.5's *declared* ``explained_by`` into *attributed,
        sealed* structure. A declared edge is only kept (and only feeds the
        EFE collapse) when its cause is actually present and elevated this
        cycle AND the attribution seals successfully and the chain verifies.
        An unsealed attribution is refused: the symptom keeps a standalone
        line with no causal claim.
        """
        by_key: dict[str, DimensionReading] = {r.key: r for r in readings}
        out: list[DimensionReading] = []

        for r in readings:
            if not r.explained_by:
                out.append(r)
                continue

            confirmed: list[str] = []
            attribution: CausalAttribution | None = None
            for cause_key in r.explained_by:
                cause = by_key.get(cause_key)
                conf = _edge_confidence(cause, r)
                if conf <= 0.0:
                    # Cause not present/elevated this cycle: not attributable.
                    continue
                sealed = self._seal_attribution(
                    tenant=tenant, cause=cause, symptom=r, confidence=conf
                )
                if sealed is None:
                    # Provability gate: refuse an unsealed attribution.
                    continue
                confirmed.append(cause_key)
                attribution = sealed

            if confirmed and attribution is not None:
                out.append(
                    dataclasses.replace(
                        r, explained_by=tuple(confirmed), causal=attribution
                    )
                )
            else:
                # No attributable, sealed cause -> drop the declared edge so
                # the symptom is not silently collapsed on an unproven claim.
                out.append(dataclasses.replace(r, explained_by=()))

        return out

    # ------------------------------------------------------------------ counterfactual

    def counterfactual(
        self, reading: DimensionReading, *, tenant: str | None
    ) -> CounterfactualClaim | None:
        """A sealed "what would have happened" claim for a spoken line.

        Binds to ``compute_attribution`` for a decision-backed reading (the
        engine runs the HCG + counterfactual screener); otherwise derives a
        structural counterfactual from the reading's own sealed slots. Either
        way the claim is SEALED before return. If it cannot be sealed, returns
        None and no counterfactual line may be spoken (provability gate).
        """
        spec = _counterfactual_spec(reading)
        if spec is None:
            return None
        form_key, slots, method = spec

        attribution_method = method
        # Strengthen with the real attribution engine when a decision is
        # resolvable for this reading (binds to tex.causal.attribution_engine).
        root_cause = self._attribution_root_cause(reading)
        if root_cause is not None:
            slots = {**slots, "root_cause": root_cause}
            attribution_method = f"{method}+compute_attribution"

        payload = {
            "record_type": "counterfactual",
            "tenant": tenant,
            "dimension": reading.key,
            "form_key": form_key,
            "slots": _jsonable(slots),
            "method": attribution_method,
        }
        entry = self._append_sealed(payload)
        if entry is None or not self._seal.verify_chain():
            return None  # provability gate: unsealed -> not spoken

        proof = ProofRef(kind="causal_seal", sha256=entry.record_hash, seq=entry.sequence)
        return CounterfactualClaim(
            dimension=reading.key,
            form_key=form_key,
            slots=slots,
            method=attribution_method,
            proof=proof,
        )

    # ------------------------------------------------------------------ gate

    @staticmethod
    def is_sealed(obj: Any, seal: CausalSeal | None = None) -> bool:
        """Provability gate: True iff ``obj`` carries a non-empty seal hash
        and (when a seal is given) that ledger's chain verifies."""
        if obj is None:
            return False
        proof = getattr(obj, "proof", None)
        if proof is None or getattr(proof, "sha256", None) in (None, ""):
            return False
        if not bool(getattr(obj, "sealed", False)):
            return False
        if seal is not None and not seal.verify_chain():
            return False
        return True

    # ------------------------------------------------------------------ internals

    def _seal_attribution(
        self,
        *,
        tenant: str | None,
        cause: DimensionReading | None,
        symptom: DimensionReading,
        confidence: float,
    ) -> CausalAttribution | None:
        method = "dimension_edge"
        # Regulator-grade path: if a decision is resolvable and a recorder +
        # signing key are present, also seal a first-class COSE-signed row.
        strong_hash = self._maybe_seal_decision_attribution(symptom)
        if strong_hash is not None:
            method = "dimension_edge+evidence_chain"

        payload = {
            "record_type": "attribution",
            "tenant": tenant,
            "cause": cause.key if cause else None,
            "symptom": symptom.key,
            "confidence": round(float(confidence), 6),
            "method": method,
            "cause_proof": _proof_dict(getattr(cause, "proof", None)),
            "symptom_proof": _proof_dict(symptom.proof),
            "evidence_chain_hash": strong_hash,
        }
        entry = self._append_sealed(payload)
        if entry is None or not self._seal.verify_chain():
            return None
        proof = ProofRef(kind="causal_seal", sha256=entry.record_hash, seq=entry.sequence)
        return CausalAttribution(
            cause_key=cause.key if cause else "",
            symptom_key=symptom.key,
            method=method,
            confidence=round(float(confidence), 6),
            proof=proof,
        )

    def _append_sealed(self, payload: dict[str, Any]) -> _SealEntry | None:
        try:
            return self._seal.append(payload)
        except Exception:  # noqa: BLE001 — sealing must never crash the cycle
            return None

    def _resolve_decision(self, reading: DimensionReading) -> Any | None:
        if self._decision_store is None or reading.proof is None:
            return None
        if reading.proof.kind != "decision" or not reading.proof.id:
            return None
        try:
            from uuid import UUID

            return self._decision_store.get(UUID(reading.proof.id))
        except Exception:  # noqa: BLE001
            return None

    def _attribution_root_cause(self, reading: DimensionReading) -> str | None:
        decision = self._resolve_decision(reading)
        if decision is None:
            return None
        try:
            from tex.causal.attribution_engine import compute_attribution

            result = compute_attribution(decision)
            return result.primary_root_cause.agent_id
        except Exception:  # noqa: BLE001
            return None

    def _maybe_seal_decision_attribution(self, reading: DimensionReading) -> str | None:
        """Seal a first-class COSE-signed attribution row into the main
        evidence chain when the full machinery is present. Returns the
        evidence record hash, or None if the strong path is unavailable."""
        if self._evidence_recorder is None or self._signing_key_resolver is None:
            return None
        decision = self._resolve_decision(reading)
        if decision is None:
            return None
        try:
            from tex.causal.attribution_engine import compute_attribution
            from tex.evidence.scitt_cose_alg import cose_alg_for
            from tex.evidence.scitt_statement import mint_signed_statement

            result = compute_attribution(decision)
            signing_key = self._signing_key_resolver()
            claim_set = {
                "decision_id": str(decision.decision_id),
                "attribution": {
                    "primary_root_cause": result.primary_root_cause.agent_id,
                    "attribution_method": result.attribution_method,
                },
            }
            signed = mint_signed_statement(claim_set=claim_set, signing_key=signing_key)
            record = self._evidence_recorder.record_attribution(
                decision_id=decision.decision_id,
                request_id=decision.request_id,
                policy_version=decision.policy_version,
                attribution_payload={
                    "primary_root_cause": result.primary_root_cause.agent_id,
                    "attribution_method": result.attribution_method,
                },
                signed_statement_cose_hex=signed.envelope_cbor.hex(),
                signed_statement_cose_alg=cose_alg_for(signing_key.algorithm),
            )
            return record.record_hash
        except Exception:  # noqa: BLE001 — strong path is best-effort
            return None


# --------------------------------------------------------------------------- helpers


def _edge_confidence(cause: DimensionReading | None, symptom: DimensionReading) -> float:
    """A declared cause -> symptom edge is only attributable when the cause
    actually fired this cycle. Confidence scales with the cause's observed
    volume relative to the symptom's. Zero means not attributable."""
    if cause is None:
        return 0.0
    cause_obs = float(cause.observation[0]) if cause.observation else 0.0
    sym_obs = float(symptom.observation[0]) if symptom.observation else 0.0
    if cause_obs <= 0.0:
        return 0.0
    # Cause must be at least as large as the symptom to plausibly explain it;
    # confidence is the share of the symptom the cause could account for.
    if sym_obs <= 0.0:
        return min(1.0, cause_obs)
    return min(1.0, cause_obs / sym_obs)


def _counterfactual_spec(
    reading: DimensionReading,
) -> tuple[str, dict[str, Any], str] | None:
    """Authored counterfactual form key + sealed slots for a reading, or None
    when the reading has no counterfactual to draw from sealed data."""
    key = reading.key
    count = int(reading.slots.get("count", 0) or 0)
    if key == "execution" and count > 0:
        return "execution_counterfactual", {"count": count}, "structural"
    if key == "identity" and count > 0:
        return "identity_counterfactual", {"count": count}, "structural"
    return None


def _proof_dict(proof: Any) -> dict[str, Any] | None:
    if proof is None:
        return None
    return {
        "kind": getattr(proof, "kind", None),
        "id": getattr(proof, "id", None),
        "sha256": getattr(proof, "sha256", None),
        "seq": getattr(proof, "seq", None),
    }


def _jsonable(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
