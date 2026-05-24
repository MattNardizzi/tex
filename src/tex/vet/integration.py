"""
VET integration hook for the ``/v1/guardrail`` evidence path.

When Tex routes a decision through a third-party LLM API (the typical
case for closed-model deployments) the evidence record should carry a
Web Proof of the upstream call so auditors can verify the response Tex
received was actually produced by the named provider. This module is
the small glue layer that produces that proof and serializes it into
the evidence-record payload.

Design properties
-----------------
*   **Optional / opt-in.** The hook is only fired when the live
    decision path calls
    ``attach_web_proof_to_payload(payload, web_proof=...)``. The base
    ``EvidenceRecorder`` (Thread 1) is unchanged; existing callers and
    existing evidence chains see no behavioral diff.
*   **Fail-open on attach.** A failed Web Proof attachment NEVER
    blocks decision evidence — Tex logs the failure and proceeds with
    the un-proofed payload. The opposite (fail-closed) would create
    an availability cliff every time an attestor was unreachable.
*   **Fail-closed on verify.** When an auditor verifies an evidence
    record carrying a Web Proof, an invalid proof is treated as
    tampering and the record is flagged.
*   **No re-derivation of evidence.** This module assumes the WebProof
    was produced *during* the upstream API call by the LLM router; it
    does NOT initiate notarization at evidence-record-write time. The
    correct call site is the LLM adapter (e.g.
    ``tex.semantic.openai_provider``), which has the live TLS session
    to notarize.
"""

from __future__ import annotations

import logging
from typing import Any

from tex.vet.web_proofs import WebProof, verify_web_proof


__all__ = [
    "attach_web_proof_to_payload",
    "verify_payload_web_proof",
    "PAYLOAD_KEY_WEB_PROOF",
]


_logger = logging.getLogger(__name__)


# Payload key used on the evidence record.
PAYLOAD_KEY_WEB_PROOF = "vet_web_proof"


def attach_web_proof_to_payload(
    payload: dict[str, Any],
    *,
    web_proof: WebProof,
) -> dict[str, Any]:
    """
    Return a new dict copy of ``payload`` with the WebProof attached.

    The proof is serialized as Pydantic's JSON-compatible dump, which
    preserves all field types and is round-trippable via
    ``WebProof.model_validate``.
    """
    new_payload = dict(payload)
    new_payload[PAYLOAD_KEY_WEB_PROOF] = web_proof.model_dump(mode="json")
    return new_payload


def verify_payload_web_proof(
    payload: dict[str, Any],
    *,
    expected_target_host: str,
    expected_response_hash: str,
    trusted_attestor_pubkeys: set[str] | None = None,
    allow_stub: bool = False,
) -> bool:
    """
    Verify a Web Proof embedded in an evidence payload.

    Returns ``True`` iff the payload contains a Web Proof and that
    proof verifies against the supplied expectations. Fail-closed on
    every error.
    """
    raw = payload.get(PAYLOAD_KEY_WEB_PROOF)
    if not isinstance(raw, dict):
        return False
    try:
        proof = WebProof.model_validate(raw)
    except (ValueError, RuntimeError) as exc:
        _logger.warning("Failed to parse WebProof from payload: %s", exc)
        return False
    return verify_web_proof(
        proof,
        expected_target_host=expected_target_host,
        expected_response_hash=expected_response_hash,
        trusted_attestor_pubkeys=trusted_attestor_pubkeys,
        allow_stub=allow_stub,
    )


# --------------------------------------------------------------------------- #
# SCITT integration (Thread 13.1)                                              #
# --------------------------------------------------------------------------- #


from tex.vet.scitt import (  # noqa: E402 — local import to avoid module cycle
    ScittIssuer,
    ScittReceipt,
    ScittRegistrationResult,
    ScittTransparentStatement,
    ScittVerificationResult,
    SCITT_SUBJECT_DECISION_PREFIX,
    TransparencyService,
    default_transparency_service,
    register_decision,
    verify_transparent_statement,
)
from tex.pqcrypto.algorithm_agility import (  # noqa: E402
    SignatureAlgorithm,
    SignatureKeyPair,
)


__all__ += [
    "PAYLOAD_KEY_SCITT_RECEIPT",
    "PAYLOAD_KEY_SCITT_TRANSPARENT",
    "attach_scitt_to_decision_payload",
    "verify_payload_scitt_transparent",
]


# Payload keys used on the evidence record.
PAYLOAD_KEY_SCITT_RECEIPT = "scitt_receipt"
PAYLOAD_KEY_SCITT_TRANSPARENT = "scitt_transparent_statement"


def attach_scitt_to_decision_payload(
    payload: dict[str, Any],
    *,
    decision_id: str,
    issuer: ScittIssuer,
    signing_keypair: SignatureKeyPair,
    ts: TransparencyService | None = None,
) -> tuple[dict[str, Any], ScittRegistrationResult]:
    """
    Register a decision payload with a SCITT Transparency Service and
    attach both the Receipt and the full Transparent Statement to a
    copy of the payload.

    Behavior:
      * **Fail-open.** If TS registration fails (server unreachable,
        signature error), the original payload is returned unchanged
        and the exception is logged. The base evidence chain (Thread 1)
        is never blocked by SCITT availability.
      * **Three-axis verification** is then possible on the attached
        payload: SHA-256 chain (Thread 1) + TEE JWT (Thread 12) +
        SCITT Receipt (this).

    Args:
        payload: the decision evidence record dict.
        decision_id: stable identifier for the decision; used as the
            SCITT statement subject (``tex:decision:{decision_id}``).
        issuer: the registering identity.
        signing_keypair: the issuer's signing key.
        ts: optional Transparency Service. Defaults to the process-wide
            ``default_transparency_service()``.

    Returns:
        A ``(new_payload, registration_result)`` tuple. If registration
        failed, ``registration_result`` is ``None`` and the payload is
        returned unchanged.
    """
    try:
        result = register_decision(
            decision_payload=payload,
            issuer=issuer,
            signing_keypair=signing_keypair,
            decision_id=decision_id,
            ts=ts,
        )
    except Exception as exc:  # noqa: BLE001 - fail-open on any error
        _logger.warning(
            "SCITT registration failed for decision %s: %s; payload unchanged",
            decision_id, exc,
        )
        return dict(payload), None  # type: ignore[return-value]

    new_payload = dict(payload)
    new_payload[PAYLOAD_KEY_SCITT_RECEIPT] = result.receipt.model_dump(mode="json")
    new_payload[PAYLOAD_KEY_SCITT_TRANSPARENT] = (
        result.transparent_statement.model_dump(mode="json")
    )
    return new_payload, result


def verify_payload_scitt_transparent(
    payload: dict[str, Any],
    *,
    expected_issuer: str | None = None,
    expected_decision_id: str | None = None,
    expected_ts_uri: str | None = None,
    expected_ts_public_key_b64u: str | None = None,
) -> ScittVerificationResult:
    """
    Verify the SCITT Transparent Statement embedded in an evidence payload.

    Returns ``ScittVerificationResult`` with ``valid=True`` iff:
      1. The Signed Statement signature verifies.
      2. The Receipt's TS signature verifies.
      3. The inclusion proof recomputes to the TS-signed root.
      4. (Optional) iss/sub pins match.

    Fail-closed on every error.
    """
    raw = payload.get(PAYLOAD_KEY_SCITT_TRANSPARENT)
    if not isinstance(raw, dict):
        return ScittVerificationResult(
            valid=False, reason="no SCITT transparent statement in payload",
        )
    try:
        transparent = ScittTransparentStatement.model_validate(raw)
    except (ValueError, RuntimeError) as exc:
        _logger.warning("Failed to parse SCITT Transparent Statement: %s", exc)
        return ScittVerificationResult(
            valid=False, reason=f"parse error: {exc}",
        )

    subject_prefix = None
    if expected_decision_id is not None:
        subject_prefix = f"{SCITT_SUBJECT_DECISION_PREFIX}:{expected_decision_id}"

    return verify_transparent_statement(
        transparent,
        expected_issuer=expected_issuer,
        expected_subject_prefix=subject_prefix,
        expected_ts_uri=expected_ts_uri,
        expected_ts_public_key_b64u=expected_ts_public_key_b64u,
    )
