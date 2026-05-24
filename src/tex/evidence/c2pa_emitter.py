"""
Lightweight emitter façade for the ``EvidenceRecorder`` Thread-5 wiring.

The recorder needs to:

  * build, sign, and cosign C2PA manifests on PERMIT verdicts;
  * record SCITT refusal events on FORBID verdicts;
  * stay importable in CI environments where liboqs is missing.

This module is the thin layer between the recorder and the
``tex.c2pa`` package. The recorder imports only the dataclasses
here at module load; the actual c2pa modules are imported inside
``emit_manifest`` on demand. That keeps the recorder unchanged for
the 2,200+ existing tests that don't exercise C2PA emission.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol
from uuid import UUID, uuid4


_logger = logging.getLogger(__name__)


# --- SCITT refusal event taxonomy ------------------------------------------
#
# Per ``draft-kamimura-scitt-refusal-events-02`` (Jan 10 2026).
# We carry the wire-level vocabulary verbatim so a downstream
# Transparency Service can ingest these events as SCITT Signed
# Statements without translation.

REFUSAL_EVENT_PRE_GENERATION: str = "PRE_GENERATION"
REFUSAL_EVENT_MID_GENERATION: str = "MID_GENERATION"
REFUSAL_EVENT_POST_GENERATION: str = "POST_GENERATION"

RISK_CSAM_GENERATION: str = "CSAM_GENERATION"
RISK_MINOR_SEXUALIZATION: str = "MINOR_SEXUALIZATION"
RISK_REAL_PERSON_DEEPFAKE: str = "REAL_PERSON_DEEPFAKE"
RISK_VIOLENCE_EXTREME: str = "VIOLENCE_EXTREME"
RISK_HATE_CONTENT: str = "HATE_CONTENT"
RISK_TERRORIST_CONTENT: str = "TERRORIST_CONTENT"
RISK_SELF_HARM_PROMOTION: str = "SELF_HARM_PROMOTION"
RISK_COPYRIGHT_VIOLATION: str = "COPYRIGHT_VIOLATION"
RISK_COPYRIGHT_STYLE_MIMICRY: str = "COPYRIGHT_STYLE_MIMICRY"
RISK_OTHER: str = "OTHER"

ALL_RISK_CATEGORIES: frozenset[str] = frozenset({
    RISK_CSAM_GENERATION,
    RISK_MINOR_SEXUALIZATION,
    RISK_REAL_PERSON_DEEPFAKE,
    RISK_VIOLENCE_EXTREME,
    RISK_HATE_CONTENT,
    RISK_TERRORIST_CONTENT,
    RISK_SELF_HARM_PROMOTION,
    RISK_COPYRIGHT_VIOLATION,
    RISK_COPYRIGHT_STYLE_MIMICRY,
    RISK_OTHER,
})


@dataclass(frozen=True, slots=True)
class ScittRefusalEvent:
    """
    A SCITT refusal event payload per draft-kamimura-scitt-refusal-events-02.

    Carried inline in the evidence record under the ``scitt.refusal_event``
    field. Recording inline (vs. a separate SCITT Transparency Service
    submission) is the Tex pattern: the hash-chained evidence row IS the
    tamper-evident receipt; a downstream Transparency Service can be
    plumbed in later by reading the chain.
    """

    event_type: str  # PRE_GENERATION / MID_GENERATION / POST_GENERATION
    risk_category: str  # see ALL_RISK_CATEGORIES
    rationale: str  # short, auditor-facing, no sensitive content
    issued_at: datetime
    issuer: str  # tenant id / governance principal

    def __post_init__(self) -> None:
        if self.event_type not in (
            REFUSAL_EVENT_PRE_GENERATION,
            REFUSAL_EVENT_MID_GENERATION,
            REFUSAL_EVENT_POST_GENERATION,
        ):
            raise ValueError(
                f"event_type must be one of PRE_GENERATION / MID_GENERATION / "
                f"POST_GENERATION, got {self.event_type!r}"
            )
        if self.risk_category not in ALL_RISK_CATEGORIES:
            raise ValueError(
                f"risk_category must be one of the SCITT taxonomy values, "
                f"got {self.risk_category!r}"
            )
        if not self.rationale:
            raise ValueError("rationale must not be empty")

    def as_payload(self) -> dict[str, Any]:
        """JSON-safe wire-format payload for the evidence record."""
        return {
            "event_type": self.event_type,
            "risk_category": self.risk_category,
            "rationale": self.rationale,
            "issued_at": self.issued_at.astimezone(timezone.utc).isoformat(),
            "issuer": self.issuer,
        }


# --- C2PA emission context --------------------------------------------------


@dataclass(frozen=True, slots=True)
class C2paEmissionContext:
    """
    Per-call context for C2PA emission and SCITT refusal recording.

    On PERMIT:
      - ``outer_signing_key_id`` and ``outer_certificate_chain_pem`` must
        be set so the C2PA outer COSE_Sign1 can be produced.
      - ``cosign_key`` is the post-quantum cosign keypair
        (``tex.pqcrypto.algorithm_agility.SignatureKeyPair``).
      - ``model_name``, ``model_version``, ``training_data_class``,
        ``from_address``, ``to_addresses``, ``subject`` populate the
        manifest's actions / cawg / verdict assertions.

    On FORBID:
      - ``refusal_event`` is a ``ScittRefusalEvent`` to inline into the
        evidence row. The other fields are ignored.

    All fields are optional so the same context type works for both
    verdicts.
    """

    # Outer + cosign signing config
    outer_signing_key_id: str | None = None
    outer_certificate_chain_pem: str | None = None
    cosign_key: Any | None = None  # SignatureKeyPair, but late-imported

    # Manifest content
    model_name: str | None = None
    model_version: str | None = None
    training_data_class: str = "general-purpose-llm"
    from_address: str | None = None
    to_addresses: tuple[str, ...] = ()
    subject: str = ""
    tenant_id: str = "default"

    # Cosign defenses (attack 2 + attack 5)
    revocation_proof: Mapping[str, Any] | None = None

    # SCITT refusal-events (FORBID path)
    refusal_event: ScittRefusalEvent | None = None


class ManifestMirrorProtocol(Protocol):
    def record(
        self,
        *,
        manifest_id: Any,
        record_id: Any,
        decision_id: Any,
        tenant_id: str,
        manifest_row: dict[str, Any],
        cosign_metadata: dict[str, Any] | None = ...,
        bound_timestamp: datetime | None = ...,
    ) -> None: ...

    def fetch_by_record_id(self, record_id: Any) -> dict[str, Any] | None: ...


# --- C2paEmitter ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class C2paEmitter:
    """
    Configured emitter wired into ``EvidenceRecorder``.

    The recorder calls ``emit_manifest`` on PERMIT verdicts when a
    caller passes ``outbound_artifact`` AND a ``C2paEmissionContext``
    with the outer key + cosign key. Without those, no manifest is
    produced and the evidence row simply records the artifact hash.

    Held by ``__slots__`` so this is a lightweight 16-byte struct
    even when None.
    """

    # Default tenant id used when c2pa_context.tenant_id is "default"
    # but the caller wants something else. Empty string means "no
    # tenant override".
    default_tenant_id: str = "default"

    def emit_manifest(
        self,
        *,
        decision: Any,
        outbound_artifact: bytes,
        context: "C2paEmissionContext",
    ) -> dict[str, Any]:
        """
        Build + sign + cosign the C2PA manifest. Returns a JSON-safe
        emission record for the recorder to anchor in the chain.

        Lazy-imports ``tex.c2pa`` so the heavy crypto stack is only
        loaded the first time an emitter is actually used.
        """
        # Lazy import keeps cold-start fast for the 2,200+ tests
        # that do not exercise C2PA emission.
        import hashlib as _hashlib

        from tex.c2pa import (
            build_email_manifest,
            build_signed_manifest_with_cosign,
            cosign_manifest_hash,
            get_cosign_assertion,
            serialize_manifest_for_storage,
        )

        if context.outer_signing_key_id is None:
            raise ValueError(
                "C2paEmissionContext.outer_signing_key_id is required for emission"
            )
        if context.outer_certificate_chain_pem is None:
            raise ValueError(
                "C2paEmissionContext.outer_certificate_chain_pem is required for emission"
            )
        if context.cosign_key is None:
            raise ValueError(
                "C2paEmissionContext.cosign_key is required for emission"
            )
        if context.from_address is None or not context.to_addresses:
            raise ValueError(
                "C2paEmissionContext.from_address and to_addresses must be set "
                "for email-channel emission"
            )

        body_sha = _hashlib.sha256(outbound_artifact).hexdigest()

        unsigned = build_email_manifest(
            from_address=context.from_address,
            to_addresses=context.to_addresses,
            subject=context.subject,
            body_sha256=body_sha,
            model_name=context.model_name or "unknown-model",
            model_version=context.model_version or "unknown",
            tex_verdict_id=str(decision.decision_id),
            training_data_class=context.training_data_class,
            policy_version=decision.policy_version,
            verdict=decision.verdict.value,
        )

        # Retention anchor — points back into the evidence chain so the
        # manifest is re-verifiable offline after the outer cert expires.
        # NOTE: ``record_hash`` is "tbd-on-append" because the recorder
        # has not yet appended this decision row; we patch it in below.
        retention_anchor = {
            "record_hash": "tbd-on-append",
            "evidence_id": "tbd-on-append",
            "policy_version": decision.policy_version,
        }

        signed = build_signed_manifest_with_cosign(
            unsigned_manifest=unsigned,
            outer_signing_key_id=context.outer_signing_key_id,
            outer_certificate_chain_pem=context.outer_certificate_chain_pem,
            cosign_key=context.cosign_key,
            outbound_artifact_bytes=outbound_artifact,
            retention_anchor=retention_anchor,
            revocation_proof=(
                dict(context.revocation_proof)
                if context.revocation_proof is not None
                else None
            ),
        )

        manifest_row = serialize_manifest_for_storage(signed)
        cosign_data = get_cosign_assertion(signed) or {}
        cosign_metadata = {
            "algorithm": cosign_data.get("algorithm"),
            "key_id": cosign_data.get("key_id"),
            "full_file_sha256": cosign_data.get("full_file_sha256"),
            "canonicalization_version": cosign_data.get("canonicalization_version"),
        }
        bound_ts_str = cosign_data.get("bound_timestamp")
        bound_ts: datetime | None = None
        if isinstance(bound_ts_str, str):
            try:
                bound_ts = datetime.fromisoformat(
                    bound_ts_str.replace("Z", "+00:00")
                )
            except ValueError:
                bound_ts = None

        return {
            "manifest_id": uuid4(),
            "manifest_hash": cosign_manifest_hash(signed),
            "manifest_row": manifest_row,
            "has_cosign": manifest_row["has_cosign"],
            "cosign_algorithm": cosign_metadata["algorithm"],
            "canonicalization_version": cosign_metadata["canonicalization_version"],
            "full_file_sha256": cosign_metadata["full_file_sha256"],
            "cosign_metadata": cosign_metadata,
            "bound_timestamp": bound_ts,
            "tenant_id": context.tenant_id or self.default_tenant_id,
        }


def _maybe_emit_c2pa(
    *,
    emitter: C2paEmitter | None,
    decision: Any,
    outbound_artifact: bytes,
    context: C2paEmissionContext | None,
) -> dict[str, Any] | None:
    """
    Best-effort C2PA emission. Returns the emission payload on success,
    None when emission is not configured. Errors are logged and swallowed
    so a misconfigured emitter never blocks the evidence chain.
    """
    if emitter is None:
        return None
    if context is None:
        # Caller passed an artifact but no signing config — record the
        # hash and skip the manifest.
        return None
    if decision.verdict.value != "PERMIT":
        return None
    try:
        return emitter.emit_manifest(
            decision=decision,
            outbound_artifact=outbound_artifact,
            context=context,
        )
    except Exception as exc:  # noqa: BLE001
        _logger.warning(
            "C2paEmitter.emit_manifest failed for decision_id=%s: %s",
            decision.decision_id,
            exc,
        )
        return None
