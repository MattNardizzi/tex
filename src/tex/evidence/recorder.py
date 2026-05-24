from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from threading import RLock
from typing import Any, Protocol

from tex.domain.decision import Decision
from tex.domain.evidence import EvidenceRecord
from tex.domain.outcome import OutcomeRecord
from tex.evidence.c2pa_emitter import (
    C2paEmissionContext,
    C2paEmitter,
    ManifestMirrorProtocol,
    _maybe_emit_c2pa,
)


_logger = logging.getLogger(__name__)


class EvidenceMirror(Protocol):
    """
    Optional sink that mirrors every appended evidence record.

    Implementations include the Postgres mirror (durable, tenant-
    partitioned, retention-aware). Mirrors must be best-effort: a
    failed mirror write must NEVER block or corrupt the JSONL
    chain. The recorder logs and continues.
    """

    def record(self, record: EvidenceRecord) -> None:
        ...


class EvidenceRecorder:
    """
    Append-only JSONL evidence recorder with a tamper-evident hash chain.

    This recorder is deliberately small and strict:
    - writes canonical JSON payloads into an append-only log
    - wraps each payload in an EvidenceRecord envelope
    - maintains record-to-record linkage via previous_hash
    - does not own chain verification logic
    - optionally mirrors every appended record into a durable sink

    The domain contract for EvidenceRecord is the source of truth. This class
    must serialize into that contract exactly and must not invent parallel field
    names such as `payload` or `payload_hash`.
    """

    __slots__ = (
        "_path",
        "_lock",
        "_last_record_hash",
        "_mirror",
        "_c2pa_emitter",
        "_manifest_mirror",
    )

    def __init__(
        self,
        path: str | Path,
        *,
        mirror: EvidenceMirror | None = None,
        c2pa_emitter: "C2paEmitter | None" = None,
        manifest_mirror: "ManifestMirrorProtocol | None" = None,
    ) -> None:
        self._path = Path(path)
        self._lock = RLock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._last_record_hash = self._load_last_record_hash()
        self._mirror = mirror
        # Thread 5: optional C2PA emitter + manifest mirror. When the
        # emitter is None, ``record_decision(..., outbound_artifact=...)``
        # falls back to recording the artifact hash in the payload but
        # produces no manifest. Existing callers (and the 2,269 baseline
        # tests) pass neither argument and observe no change.
        self._c2pa_emitter = c2pa_emitter
        self._manifest_mirror = manifest_mirror

    @property
    def path(self) -> Path:
        """Returns the backing JSONL path."""
        return self._path

    @property
    def has_c2pa_emitter(self) -> bool:
        """True iff this recorder will emit C2PA manifests on PERMIT verdicts."""
        return self._c2pa_emitter is not None

    def record_decision(
        self,
        decision: Decision,
        *,
        metadata: dict[str, Any] | None = None,
        outbound_artifact: bytes | None = None,
        c2pa_context: "C2paEmissionContext | None" = None,
    ) -> EvidenceRecord:
        """
        Appends an evidence record for a decision.

        When ``outbound_artifact`` is supplied AND the decision verdict
        is PERMIT AND a ``C2paEmitter`` is wired in the recorder
        constructor, this method:

          1. produces a C2PA 2.4 manifest with the Tex evidence cosign
             (ML-DSA-65 by default — see ``tex.c2pa.evidence_emission``),
          2. stores the manifest in the ``evidence_manifests`` mirror
             keyed by this evidence record's ``record_id``,
          3. records the manifest SHA-256 hash under
             ``c2pa.manifest_hash`` in the evidence payload so the
             chain is the retention anchor for the manifest (NSA paper
             attack #5 — credentials expire before retention obligation).

        When the verdict is FORBID and ``c2pa_context.refusal_reason``
        is non-empty, a SCITT refusal event is recorded under
        ``scitt.refusal_event`` per ``draft-kamimura-scitt-refusal-
        events-02`` taxonomy.
        """
        payload: dict[str, Any] = {
            "record_type": "decision",
            "decision_id": str(decision.decision_id),
            "request_id": str(decision.request_id),
            "verdict": decision.verdict.value,
            "confidence": decision.confidence,
            "final_score": decision.final_score,
            "action_type": decision.action_type,
            "channel": decision.channel,
            "environment": decision.environment,
            "recipient": decision.recipient,
            "policy_id": decision.policy_id,
            "policy_version": decision.policy_version,
            "content_excerpt": decision.content_excerpt,
            "content_sha256": decision.content_sha256,
            "scores": dict(decision.scores),
            "reasons": list(decision.reasons),
            "uncertainty_flags": list(decision.uncertainty_flags),
            "findings": [
                self._serialize_model(finding)
                for finding in decision.findings
            ],
            "retrieval_context": self._make_json_safe(decision.retrieval_context),
            "metadata": self._merge_metadata(decision.metadata, metadata),
            "evidence_hash": decision.evidence_hash,
            "decided_at": decision.decided_at.isoformat(),
        }

        # Thread 5: capture an outbound-artifact fingerprint into the payload
        # so the chain is the retention anchor for the manifest. The actual
        # manifest is built AFTER append (next step) and the manifest hash
        # is stored back in the mirror; the chain entry already commits to
        # the artifact bytes via this hash, so a later manifest tied to
        # this record_id cannot be substituted without breaking the chain.
        c2pa_emission_payload: dict[str, Any] | None = None
        if outbound_artifact is not None:
            import hashlib as _hashlib  # local import — keeps the bare-module
                                        # path lean for non-c2pa callers

            payload["outbound_artifact"] = {
                "byte_length": len(outbound_artifact),
                "sha256": _hashlib.sha256(outbound_artifact).hexdigest(),
            }
            c2pa_emission_payload = _maybe_emit_c2pa(
                emitter=self._c2pa_emitter,
                decision=decision,
                outbound_artifact=outbound_artifact,
                context=c2pa_context,
            )
            if c2pa_emission_payload is not None:
                payload["c2pa"] = {
                    "manifest_hash": c2pa_emission_payload["manifest_hash"],
                    "has_cosign": c2pa_emission_payload["has_cosign"],
                    "cosign_algorithm": c2pa_emission_payload.get(
                        "cosign_algorithm"
                    ),
                    "canonicalization_version": c2pa_emission_payload.get(
                        "canonicalization_version"
                    ),
                    "full_file_sha256": c2pa_emission_payload.get(
                        "full_file_sha256"
                    ),
                }

        # Thread 5: emit a SCITT refusal event on FORBID when a refusal
        # reason was supplied. Recorded inline in the payload so the
        # refusal taxonomy is part of the hash-chained evidence row.
        if (
            decision.verdict.value == "FORBID"
            and c2pa_context is not None
            and c2pa_context.refusal_event is not None
        ):
            payload["scitt"] = {
                "refusal_event": c2pa_context.refusal_event.as_payload(),
                "spec": "draft-kamimura-scitt-refusal-events-02",
            }

        record = self._append(
            decision_id=decision.decision_id,
            request_id=decision.request_id,
            record_type="decision",
            policy_version=decision.policy_version,
            payload=payload,
        )

        # Thread 5: store the manifest in the Postgres mirror keyed by the
        # parent record. This happens AFTER append so the record_id exists.
        # Mirror failure is best-effort, like the evidence mirror.
        if c2pa_emission_payload is not None and self._manifest_mirror is not None:
            try:
                self._manifest_mirror.record(
                    manifest_id=c2pa_emission_payload["manifest_id"],
                    record_id=record.evidence_id,
                    decision_id=decision.decision_id,
                    tenant_id=c2pa_emission_payload.get("tenant_id", "default"),
                    manifest_row=c2pa_emission_payload["manifest_row"],
                    cosign_metadata=c2pa_emission_payload.get("cosign_metadata"),
                    bound_timestamp=c2pa_emission_payload.get("bound_timestamp"),
                )
            except Exception as exc:  # noqa: BLE001
                _logger.warning(
                    "EvidenceRecorder: manifest mirror write failed for "
                    "record_id=%s: %s",
                    record.evidence_id,
                    exc,
                )

        return record

    def record_outcome(
        self,
        outcome: OutcomeRecord,
        *,
        metadata: dict[str, Any] | None = None,
        policy_version: str | None = None,
    ) -> EvidenceRecord:
        """
        Appends an evidence record for an outcome.

        OutcomeRecord does not carry policy_version directly, so callers may
        pass it explicitly. If omitted, this method will also accept
        `decision_policy_version` inside metadata for compatibility with the
        current command layer.
        """
        resolved_policy_version = self._resolve_outcome_policy_version(
            metadata=metadata,
            policy_version=policy_version,
        )

        payload: dict[str, Any] = {
            "record_type": "outcome",
            "outcome_id": str(outcome.outcome_id),
            "decision_id": str(outcome.decision_id),
            "request_id": str(outcome.request_id),
            "verdict": outcome.verdict.value,
            "outcome_kind": outcome.outcome_kind.value,
            "was_safe": outcome.was_safe,
            "human_override": outcome.human_override,
            "summary": outcome.summary,
            "reporter": outcome.reporter,
            "label": outcome.label.value,
            "policy_version": resolved_policy_version,
            "metadata": self._merge_metadata(None, metadata),
            "recorded_at": outcome.recorded_at.isoformat(),
        }

        return self._append(
            decision_id=outcome.decision_id,
            request_id=outcome.request_id,
            record_type="outcome",
            policy_version=resolved_policy_version,
            payload=payload,
        )

    def record_contract_violation(
        self,
        *,
        decision_id: Any,
        request_id: Any,
        policy_version: str,
        contract_id: str,
        violated_clause: str,
        clause_ltl: str,
        step_index: int,
        compliance_gap: float,
        severity_class: str,
        is_soft: bool,
        rule_name: str,
        message: str,
        parent_evidence_hash: str | None,
        session_key: str | None = None,
        replayed_window_size: int = 0,
        recovery_deadline_step: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        """
        Append a first-class evidence record for one behavioral contract violation.

        This is the "evidence on demand" surface for behavioral contracts:
        every violation gets its own row in the JSONL chain, its own
        ``payload_sha256``, its own ``record_hash``, and a
        ``parent_evidence_hash`` field inside the payload that links back
        to the decision evidence row that triggered it. A buyer can verify
        a single violation receipt without re-verifying the entire
        parent Decision row.

        Why this is separate from ``record_decision``
        ----------------------------------------------
        Today, contract findings travel inside ``Decision.findings`` and
        are hashed into the parent Decision evidence row by reference,
        not as their own line. That's enough for "the chain contains the
        violation" but not enough for "here is a cryptographic receipt
        for this single violation." First-class records make the latter
        possible because:

          * Each violation has a stable, addressable ``record_hash`` an
            auditor can verify in isolation.
          * Selective disclosure becomes trivial: a buyer can hand a
            regulator just the violation row plus the chain segment up
            to its parent, without exposing the full decision payload.
          * Audit-time queries ("show me every soft-governance violation
            on contract X this week") no longer require scanning every
            Decision row's findings array.

        Parent-linkage
        --------------
        ``parent_evidence_hash`` MUST be the ``record_hash`` of the
        Decision evidence row this violation belongs to. The chain
        verifier in ``tex.evidence.chain`` does NOT consume this field
        (chain integrity is computed from ``payload_sha256`` and
        ``previous_hash`` alone). The parent link is a semantic
        cross-reference, not a chain edge. This is deliberate: the chain
        stays a simple linear hash chain, but contract violations carry
        the audit trail needed to bind them back to their parent decision
        without trusting the chain order.

        Source-paper alignment
        ----------------------
          * arxiv 2602.22302 §5.2 (AgentAssert evidence model) — each
            contract violation is a discrete, signable, cryptographically
            chained event.
          * arxiv 2602.22302 §3.3 (p, δ, k)-satisfaction — the
            ``recovery_deadline_step`` field surfaces the bound that
            scopes the violation's recovery window.
        """
        payload: dict[str, Any] = {
            "record_type": "contract_violation",
            "decision_id": str(decision_id),
            "request_id": str(request_id),
            "policy_version": policy_version,
            "contract_id": contract_id,
            "violated_clause": violated_clause,
            "clause_ltl": clause_ltl,
            "step_index": step_index,
            "compliance_gap": compliance_gap,
            "severity_class": severity_class,
            "is_soft": is_soft,
            "rule_name": rule_name,
            "message": message,
            "parent_evidence_hash": parent_evidence_hash,
            "session_key": session_key,
            "replayed_window_size": replayed_window_size,
            "recovery_deadline_step": recovery_deadline_step,
            "metadata": self._merge_metadata(None, metadata),
        }

        return self._append(
            decision_id=decision_id,
            request_id=request_id,
            record_type="contract_violation",
            policy_version=policy_version,
            payload=payload,
        )

    def record_attribution(
        self,
        *,
        decision_id: Any,
        request_id: Any,
        policy_version: str,
        attribution_payload: dict[str, Any],
        signed_statement_cose_hex: str,
        signed_statement_cose_alg: int,
        ptv_envelope: dict[str, Any] | None = None,
        tee_attestation: dict[str, Any] | None = None,
        parent_evidence_hash: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        """Append a first-class evidence record for one causal attribution.

        Adds a hash-chained row representing the post-incident attribution
        computed by ``tex.causal.attribution_engine.compute_attribution``.
        The row links back to the originating Decision row via
        ``parent_evidence_hash`` (semantic cross-reference, same idiom as
        ``record_contract_violation``) and carries the full SCITT-shaped
        COSE_Sign1 signed statement as hex inside the payload.

        Why this is separate from ``record_decision``
        ----------------------------------------------
        Attribution is a post-hoc analysis distinct from the live decision.
        Putting it in its own row lets buyers / regulators query
        attributions independently and verify each one in isolation —
        the same "evidence on demand" surface that makes
        ``record_contract_violation`` a first-class row.

        Parent-linkage
        --------------
        ``parent_evidence_hash`` MUST be the ``record_hash`` of the
        Decision evidence row this attribution was computed for. Chain
        integrity is computed from ``payload_sha256`` and
        ``previous_hash`` alone; the parent link is a semantic
        cross-reference only.

        Source-paper alignment
        ----------------------
        * arxiv 2602.23701 (CHIEF, Feb 2026) — hierarchical causal
          graph attribution
        * arxiv 2604.04035 (ARM, Apr 2026) — causality laundering
          surfacing
        * arxiv 2605.07509 (MASPrism, May 7 2026) — prefill-stage
          signals
        * arxiv 2605.03581 (ZK-Value LSH-Shapley, May 2026) — blame
          distribution
        * draft-kamimura-scitt-refusal-events-02 (Jan 29 2026) — claim
          set extension point for ``event-type=ATTRIBUTE``
        * draft-anandakrishnan-ptv-attested-agent-identity-00 (Mar 2026)
          — PTV envelope shape for optional ZK proof
        * NVIDIA NRAS production v3 — EAT JWT for optional TEE binding
        """
        payload: dict[str, Any] = {
            "record_type": "attribution",
            "decision_id": str(decision_id),
            "request_id": str(request_id),
            "parent_evidence_hash": parent_evidence_hash,
            "attribution": attribution_payload,
            "signed_statement": {
                "envelope_cose_hex": signed_statement_cose_hex,
                "cose_algorithm_label": signed_statement_cose_alg,
            },
            "ptv_envelope": ptv_envelope,
            "tee_attestation": tee_attestation,
            "metadata": self._merge_metadata(None, metadata),
        }

        return self._append(
            decision_id=decision_id,
            request_id=request_id,
            record_type="attribution",
            policy_version=policy_version,
            payload=payload,
        )


    def read_all(self) -> tuple[EvidenceRecord, ...]:
        """Reads and validates all evidence records from disk."""
        if not self._path.exists():
            return tuple()

        records: list[EvidenceRecord] = []

        with self._lock:
            with self._path.open("r", encoding="utf-8") as handle:
                for line_number, raw_line in enumerate(handle, start=1):
                    line = raw_line.strip()
                    if not line:
                        continue

                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ValueError(
                            f"invalid JSON in evidence file at line {line_number}"
                        ) from exc

                    try:
                        record = EvidenceRecord.model_validate(payload)
                    except Exception as exc:
                        raise ValueError(
                            f"invalid evidence record at line {line_number}"
                        ) from exc

                    records.append(record)

        return tuple(records)

    def last_record(self) -> EvidenceRecord | None:
        """Returns the most recent evidence record, if any."""
        records = self.read_all()
        return records[-1] if records else None

    def read_contract_violations(
        self,
        *,
        decision_id: Any | None = None,
        contract_id: str | None = None,
    ) -> tuple[EvidenceRecord, ...]:
        """
        Return all contract-violation evidence records, optionally
        filtered by ``decision_id`` and/or ``contract_id``.

        This is the "evidence on demand" read surface. A buyer (or a
        regulator) can pull every violation receipt for a given
        decision or contract without scanning the parent decision
        records' findings arrays.

        Implementation note: this reads the JSONL chain on every call.
        For high-cadence query workloads, layer a Postgres-backed
        ``EvidenceMirror`` and query that instead — the JSONL chain
        remains the source of truth.
        """
        all_records = self.read_all()
        results: list[EvidenceRecord] = []
        for record in all_records:
            if record.record_type != "contract_violation":
                continue
            if decision_id is not None and str(record.decision_id) != str(decision_id):
                continue
            if contract_id is not None:
                try:
                    payload = self.decode_payload(record)
                except ValueError:
                    continue
                if payload.get("contract_id") != contract_id:
                    continue
            results.append(record)
        return tuple(results)

    def decode_payload(self, record: EvidenceRecord) -> dict[str, Any]:
        """
        Parses the canonical payload_json for a stored evidence record.

        This is a convenience for higher layers such as exporters and filters.
        """
        try:
            value = json.loads(record.payload_json)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"evidence record {record.evidence_id} contains invalid payload_json"
            ) from exc

        if not isinstance(value, dict):
            raise ValueError(
                f"evidence record {record.evidence_id} payload_json must decode to an object"
            )

        return value

    def _append(
        self,
        *,
        decision_id: Any,
        request_id: Any,
        record_type: str,
        policy_version: str,
        payload: dict[str, Any],
    ) -> EvidenceRecord:
        with self._lock:
            payload_json = self._stable_json(self._make_json_safe(payload))
            payload_sha256 = self._sha256_hex(payload_json)

            record_hash = self._build_record_hash(
                payload_sha256=payload_sha256,
                previous_hash=self._last_record_hash,
            )

            record = EvidenceRecord(
                decision_id=decision_id,
                request_id=request_id,
                record_type=record_type,
                payload_json=payload_json,
                payload_sha256=payload_sha256,
                previous_hash=self._last_record_hash,
                record_hash=record_hash,
                policy_version=policy_version,
            )

            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(self._stable_json(record.model_dump(mode="json")))
                handle.write("\n")

            self._last_record_hash = record.record_hash

            # Best-effort mirror. A mirror failure must never block or
            # corrupt the JSONL chain, which is the source of truth.
            if self._mirror is not None:
                try:
                    self._mirror.record(record)
                except Exception as exc:  # noqa: BLE001
                    _logger.warning(
                        "EvidenceRecorder: mirror write failed for evidence_id=%s: %s",
                        record.evidence_id,
                        exc,
                    )

            return record

    def _load_last_record_hash(self) -> str | None:
        if not self._path.exists():
            return None

        last_non_empty_line: str | None = None

        with self._lock:
            with self._path.open("r", encoding="utf-8") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if line:
                        last_non_empty_line = line

        if last_non_empty_line is None:
            return None

        try:
            parsed = json.loads(last_non_empty_line)
            record = EvidenceRecord.model_validate(parsed)
        except Exception as exc:
            raise ValueError("failed to read last evidence record from file") from exc

        return record.record_hash

    @staticmethod
    def _resolve_outcome_policy_version(
        *,
        metadata: dict[str, Any] | None,
        policy_version: str | None,
    ) -> str:
        if policy_version is not None:
            normalized = policy_version.strip()
            if not normalized:
                raise ValueError("policy_version must not be blank")
            return normalized

        if metadata is not None:
            value = metadata.get("decision_policy_version")
            if isinstance(value, str):
                normalized = value.strip()
                if normalized:
                    return normalized

        raise ValueError(
            "record_outcome requires a policy_version or metadata['decision_policy_version']"
        )

    @staticmethod
    def _merge_metadata(
        base: dict[str, Any] | None,
        override: dict[str, Any] | None,
    ) -> dict[str, Any]:
        merged: dict[str, Any] = {}

        if base is not None:
            merged.update(dict(base))

        if override is not None:
            merged.update(dict(override))

        return EvidenceRecorder._make_json_safe(merged)

    @staticmethod
    def _serialize_model(value: Any) -> dict[str, Any]:
        if not hasattr(value, "model_dump"):
            raise TypeError("value must be a pydantic model with model_dump()")
        dumped = value.model_dump(mode="json")
        if not isinstance(dumped, dict):
            raise TypeError("serialized model must produce a JSON object")
        return dumped

    @staticmethod
    def _build_record_hash(
        *,
        payload_sha256: str,
        previous_hash: str | None,
    ) -> str:
        chain_input = EvidenceRecorder._stable_json(
            {
                "payload_sha256": payload_sha256,
                "previous_hash": previous_hash,
            }
        )
        return EvidenceRecorder._sha256_hex(chain_input)

    @staticmethod
    def _make_json_safe(value: Any) -> Any:
        """
        Normalizes arbitrary nested values into JSON-safe data.

        This keeps evidence serialization explicit and stable even when metadata
        contains UUIDs, datetimes, enums, tuples, or nested pydantic models.
        """
        if value is None or isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, Path):
            return str(value)

        if hasattr(value, "isoformat") and callable(value.isoformat):
            try:
                return value.isoformat()
            except TypeError:
                pass

        if hasattr(value, "value"):
            enum_value = getattr(value, "value")
            if isinstance(enum_value, (str, int, float, bool)):
                return enum_value

        if hasattr(value, "model_dump") and callable(value.model_dump):
            return EvidenceRecorder._make_json_safe(value.model_dump(mode="json"))

        if isinstance(value, dict):
            normalized: dict[str, Any] = {}
            for key, item in value.items():
                normalized[str(key)] = EvidenceRecorder._make_json_safe(item)
            return normalized

        if isinstance(value, (list, tuple, set, frozenset)):
            return [EvidenceRecorder._make_json_safe(item) for item in value]

        return str(value)

    @staticmethod
    def _stable_json(value: Any) -> str:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @staticmethod
    def _sha256_hex(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()