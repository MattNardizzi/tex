"""
Incident attribution endpoint — POST /v1/incidents/{decision_id}/attribute.

Endpoint surface
----------------
``POST /v1/incidents/{decision_id}/attribute``

Looks up a stored ``Decision`` by id, runs
``tex.causal.attribution_engine.compute_attribution`` against it,
optionally constructs a PTV-shaped ZK envelope and/or a TEE
attestation, assembles a SCITT-shaped claim set per
``draft-kamimura-scitt-refusal-events-02`` using the ``ATTRIBUTE``
event-type extension, signs the claim set as a COSE_Sign1_Tagged
statement via Tex's algorithm-agile signature provider, hash-chains
the result into the evidence ledger with ``record_attribution``,
and returns the full ``CausalAttributionResponseDTO``.

Why this lives in its own router
--------------------------------
``tex.api.routes`` carries the existing surfaces (guardrail,
replay, evidence export, policy, outcomes, calibration). Adding a
new resource family (``incidents``) keeps the routes mid-sized and
testable. ``tex.main`` mounts both routers; nothing else in the
existing routes is touched.

Read-only on the hot path
-------------------------
The endpoint reads the decision store, computes attribution (a
pure function of the stored Decision), and writes one new
evidence row. It does NOT modify the original Decision, the
policy state, or any other live system state. The
``/v1/guardrail`` hot path is unaffected.

SCITT claim set shape
---------------------
Per refusal-events-02 §3 plus the ``* tstr => any`` extension
point, the claim set is::

    {
      "event-type":      "ATTRIBUTE",
      "event-id":        "<uuidv4 hex>",
      "timestamp":       <epoch-seconds>,
      "issuer":          "urn:tex:aegis:<environment>",
      "references_attempt_id":  "<decision-uuid>",
      "references_outcome_id":  "<decision-uuid>",
      "attribution": {
        "primary_root_cause": { agent_id, step_id, confidence,
                                integrity_level, reasoning_perspective },
        "candidates":             [ ... ],
        "blame_distribution":     { agent_id: share, ... },
        "causality_laundering_suspected": bool,
        "attribution_method":     "graph" | "graph+prefill" | ...,
        "slm_model_id":           "<id or empty>",
        "slm_model_weight_sha256": "<hex or empty>",
        "confidence_signals":     { mean_nll, max_nll, ... }
      },
      "ptv_envelope":     { method, proof, model_hash, ... } | absent,
      "tee_attestation":  { format, nras_jwt_sha256, ... } | absent
    }

Field naming uses hyphenated strings (``event-type``,
``event-id``) per the draft's literal CDDL. Optional fields are
omitted, not set to null, to match the draft's ``? key:`` syntax.

References
----------
* draft-kamimura-scitt-refusal-events-02 (Jan 29, 2026) — claim set
* draft-anandakrishnan-ptv-attested-agent-identity-00 (Mar 2026) —
  PTV envelope shape
* arxiv 2602.23701 (CHIEF, Feb 2026)
* arxiv 2604.04035 (ARM, Apr 2026)
* arxiv 2605.07509 (MASPrism, May 7, 2026)
* arxiv 2605.03581 (ZK-Value LSH-Shapley, May 2026)
* NVIDIA NRAS production v3 (docs.attestation.nvidia.com)
"""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from typing import Any, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status

from tex.api.auth import RequireScope
from tex.api.schemas import (
    CausalAttributionRequestDTO,
    CausalAttributionResponseDTO,
    CausalCandidateDTO,
    ConformalPredictionSetDTO,
    PTVEnvelopeDTO,
    SignedAttributionStatementDTO,
    TEEAttestationDTO,
)
from tex.causal.attribution_engine import (
    CausalAttributionResult,
    compute_attribution,
)
from tex.causal.prefill_signals import render_trace_for_signals
from tex.domain.decision import Decision
from tex.evidence.attribution_zk import (
    PTV_METHOD_NANOZK_LAYERWISE_2026,
    PTV_METHOD_PROOF_PENDING,
    PTVEnvelope,
    build_envelope_stub,
    build_envelope_with_layerwise_proof,
    canonical_input_hash,
    canonical_signals_hash,
)
from tex.evidence.scitt_cose_alg import cose_alg_for
from tex.evidence.scitt_statement import mint_signed_statement
from tex.evidence.tee_binding import (
    NRAS_PROD_ISSUER,
    TEEAttestation,
    build_tee_attestation,
    build_test_mode_jwt,
    verify_nras_jwt,
)
from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    get_signature_provider,
)


# Module-level router. Mounted by ``tex.main`` via
# ``app.include_router(build_incident_router())``.
_router = APIRouter()


# ---------------------------------------------------------------------------
# Claim set assembly
# ---------------------------------------------------------------------------


def _candidate_to_claim_dict(candidate: Any) -> dict[str, Any]:
    """Project a CausalCandidate to a claim-set-friendly dict.

    Float fields are converted to fixed-point integers (parts-per-
    million) for CBOR-deterministic encoding. The Tex C2PA-style
    deterministic CBOR encoder (``tex.c2pa._cbor``) intentionally
    refuses floats because IEEE-754 representation differences make
    cross-language hash-chain integrity fragile — encoding "0.95"
    on different runtimes can produce different bytes. Integer
    parts-per-million preserves three significant digits of
    precision (sufficient for confidence values) and is bit-exact.

    Consumers reconstructing the original float divide by 1_000_000.
    The DTO surface preserves the raw float for API ergonomics; only
    the signed claim set uses fixed-point.
    """
    return {
        "agent_id": candidate.agent_id,
        "decisive_step_index": candidate.decisive_step_index,
        "step_id": candidate.step_id,
        "confidence_ppm": int(round(candidate.confidence * 1_000_000)),
        "integrity_level": candidate.integrity_level,
        "reasoning_perspective": candidate.reasoning_perspective,
    }


def _float_map_to_ppm(mapping: dict[str, float]) -> dict[str, int]:
    """Convert a string->float map to a string->ppm-int map.

    Same reasoning as ``_candidate_to_claim_dict``: float values
    aren't CBOR-deterministically encodable, so we fixed-point them.
    """
    return {
        key: int(round(value * 1_000_000))
        for key, value in mapping.items()
    }


def _build_attribution_section(result: CausalAttributionResult) -> dict[str, Any]:
    """Build the ``attribution`` sub-claim per the shape above."""
    primary = result.primary_root_cause
    return {
        "primary_root_cause": _candidate_to_claim_dict(primary),
        "candidates": [
            _candidate_to_claim_dict(c) for c in result.candidates
        ],
        "blame_distribution_ppm": _float_map_to_ppm(
            dict(result.blame_distribution)
        ),
        "causality_laundering_suspected": result.causality_laundering_suspected,
        "attribution_method": result.attribution_method,
        "slm_model_id": result.slm_model_id,
        "slm_model_weight_sha256": result.slm_model_weight_sha256,
        "confidence_signals_ppm": _float_map_to_ppm(
            dict(result.confidence_signals)
        ),
        "attribution_latency_us": int(
            round(result.attribution_latency_ms * 1000)
        ),
    }


def _build_scitt_claim_set(
    *,
    decision: Decision,
    result: CausalAttributionResult,
    issuer: str,
    ptv_envelope: PTVEnvelope | None,
    tee_attestation: TEEAttestation | None,
) -> dict[str, Any]:
    """Assemble the SCITT-shaped claim set per refusal-events-02.

    Uses the literal hyphenated keys from the draft's CDDL grammar
    (``event-type``, ``event-id``, etc.) so the claim set is
    intelligible to any conformant refusal-events verifier.

    The ``ATTRIBUTE`` event-type is a Tex extension via the draft's
    ``* tstr => any`` extension point. We document this explicitly
    in CLAIMS.md so consumers can tell standardized event-types apart
    from Tex extensions.
    """
    claim_set: dict[str, Any] = {
        "event-type": "ATTRIBUTE",
        "event-id": uuid4().hex,
        "timestamp": int(time.time()),
        "issuer": issuer,
        "references_attempt_id": str(decision.decision_id),
        "references_outcome_id": str(decision.decision_id),
        "attribution": _build_attribution_section(result),
    }
    if ptv_envelope is not None:
        # PTV draft §B.2 envelope shape; we copy fields rather than
        # nesting the pydantic model because mint_signed_statement
        # needs plain mapping input for CBOR encoding.
        claim_set["ptv_envelope"] = {
            "method": ptv_envelope.method,
            "proof": ptv_envelope.proof,
            "model_hash": ptv_envelope.model_hash,
            "input_hash": ptv_envelope.input_hash,
            "output_hash": ptv_envelope.output_hash,
        }
    if tee_attestation is not None:
        # We embed the JWT digest (not the full JWT) into the
        # claim set to keep the COSE_Sign1 envelope small. The
        # full JWT is returned in the API response for verifiers
        # that want to re-check the NRAS signature, but the
        # cryptographic binding from the signed statement points
        # at the digest. This is the same pattern as PTV draft
        # §B.2 (the JWT is referenced by hash, not embedded).
        tee_dict: dict[str, Any] = {
            "format": tee_attestation.format,
            "nras_jwt_sha256": tee_attestation.nras_jwt_sha256,
            "nonce": tee_attestation.nonce,
            "issuer": tee_attestation.issuer,
            "test_mode": tee_attestation.test_mode,
        }
        if tee_attestation.gpu_measurement_sha256 is not None:
            tee_dict["gpu_measurement_sha256"] = (
                tee_attestation.gpu_measurement_sha256
            )
        claim_set["tee_attestation"] = tee_dict
    # Conformal prediction set per arxiv 2605.06788. Floats are
    # encoded as ppm integers for CBOR-deterministic signing,
    # matching the same convention used for confidence and blame
    # shares elsewhere in the claim set.
    if result.conformal_set is not None:
        cs = result.conformal_set
        claim_set["conformal_set"] = {
            "algorithm": cs.algorithm,
            "start_index": cs.start_index,
            "end_index": cs.end_index,
            "set_size": cs.set_size,
            "trace_length": cs.trace_length,
            "alpha_ppm": int(round(cs.alpha * 1_000_000)),
            "target_coverage_ppm": int(round(cs.target_coverage * 1_000_000)),
            # threshold can be -inf/inf in degenerate cases; clamp to a
            # finite ppm integer range for CBOR encoding.
            "threshold_ppm": (
                int(round(cs.threshold * 1_000_000))
                if cs.threshold not in (float("inf"), float("-inf"))
                else (2**31 - 1 if cs.threshold == float("inf") else -(2**31 - 1))
            ),
            "score_source": cs.score_source,
            "coverage_mode": cs.coverage_mode,
            "step_ids_in_set": list(cs.step_ids_in_set),
        }
    return claim_set


# ---------------------------------------------------------------------------
# Signing key resolution
# ---------------------------------------------------------------------------


def _resolve_signing_key(request: Request) -> SignatureKeyPair:
    """Return the SCITT signing key for this server.

    Prefers an app-state ``scitt_signing_key`` if installed by
    ``tex.main`` at startup. Otherwise generates an ephemeral
    ECDSA-P256 key per request — fine for test environments and
    fully signed-verifiable, but rotates every request so verifiers
    must consume the included public key from the COSE envelope's
    ``kid`` header (a follow-on thread will wire persistent
    SCITT keys).
    """
    if hasattr(request.app.state, "scitt_signing_key"):
        candidate = getattr(request.app.state, "scitt_signing_key")
        if isinstance(candidate, SignatureKeyPair):
            return candidate

    # Ephemeral fallback: ECDSA-P256 (the algorithm Tex's events
    # ledger uses for its classical-signature path). Real
    # deployments install a persistent ML-DSA-65 key on startup.
    provider = get_signature_provider(SignatureAlgorithm.ECDSA_P256)
    return provider.generate_keypair("tex-scitt-ephemeral")


# ---------------------------------------------------------------------------
# PTV envelope construction (proof_pending mode)
# ---------------------------------------------------------------------------


def _build_ptv_envelope(
    *,
    result: CausalAttributionResult,
    decision: Decision,
) -> PTVEnvelope:
    """Build a PTV envelope.

    Modes
    -----
    * ``TEX_FRONTIER_NANOZK != "1"`` (default) — proof_pending mode.
      Envelope binds the hashes; the proof field is empty. Honest
      label: the verifier accepts only in test mode.

    * ``TEX_FRONTIER_NANOZK == "1"`` (Thread 15 frontier flag) —
      attach a live ``LayerProofSet`` over the Fisher-selected
      transformer layers. The method tag becomes
      ``tex:nanozk-layerwise-2026`` and the verifier flips from
      ``nanozk_verifier_not_implemented_in_this_thread`` to a real
      verdict.

    Bindings (both modes):
      * ``model_hash`` = SHA-256 of the prefill SLM weights (zeros
        when no SLM was used)
      * ``input_hash`` = SHA-256 of the rendered trace text
      * ``output_hash`` = SHA-256 of the canonicalised confidence
        signals (zeros when signals_available is False)
    """
    # Re-derive the trace and render it the same way the engine did.
    from tex.causal.attribution_engine import _trace_from_decision

    trace = _trace_from_decision(decision)
    rendered, _, _ = render_trace_for_signals(trace)
    input_h = canonical_input_hash(rendered)

    if result.signals_available and result.confidence_signals:
        signal_map = {
            "aggregate": dict(result.confidence_signals),
        }
    else:
        signal_map = {}
    output_h = canonical_signals_hash(signal_map)

    model_hash = result.slm_model_weight_sha256 or ("0" * 64)

    # Thread 15 frontier path.
    if os.environ.get("TEX_FRONTIER_NANOZK", "0") == "1":
        return _build_layerwise_envelope(
            model_hash=model_hash,
            input_hash=input_h,
            output_hash=output_h,
        )

    return build_envelope_stub(
        model_hash=model_hash,
        input_hash=input_h,
        output_hash=output_h,
    )


def _build_layerwise_envelope(
    *,
    model_hash: str,
    input_hash: str,
    output_hash: str,
    total_layers: int = 12,
    fisher_budget_fraction: float = 0.5,
) -> PTVEnvelope:
    """Build a live NANOZK layerwise envelope.

    Selection strategy (Thread 15)
    ------------------------------
    We default to a GPT-2-shaped 12-layer transformer and a budget
    that covers ~50% of layers — the NANOZK paper's headline
    setting, where high-Fisher layers capture 65-86% of the
    inference's information at 50% of the proving cost. The
    Fisher scores here are stand-ins (uniform across layers when
    we don't have a real estimate from the caller); the selector
    still produces a deterministic top-k by index.

    Layer-input/output chain
    ------------------------
    Layer 0's input_hash is bound to the envelope's input_hash.
    The last layer's output_hash is bound to the envelope's
    output_hash. Interior layer chains are derived deterministically
    by HMAC'ing the prior layer's output. This is the structural
    binding that gives the verifier its anchor pair — the same
    pair the live verifier in attribution_zk._verify_nanozk_layerwise
    checks against.

    The weights commitment is bound to ``model_hash`` so a verifier
    can refuse to accept a proof against a different model.
    """
    from tex.nanozk import (
        compute_fisher_budget,
        prove_layer_set,
        select_layers_to_prove,
    )

    # Uniform Fisher scores when we don't have a real estimator
    # plumbed in (the public surface accepts a caller-supplied
    # vector; the wired path here uses a tilted-uniform default
    # that captures the empirical observation in NANOZK §3.3 that
    # later layers tend to carry slightly more output sensitivity).
    fisher_scores = tuple(
        1.0 + (0.02 * i) for i in range(total_layers)
    )

    # Pick at least enough layers to cover the target fraction.
    k_target = compute_fisher_budget(
        total_layers=total_layers,
        target_information_fraction=fisher_budget_fraction,
        fisher_scores=fisher_scores,
    )
    selection = select_layers_to_prove(
        total_layers=total_layers,
        budget=k_target,
        fisher_scores=fisher_scores,
    )

    # Derive deterministic per-layer i/o hex hashes anchored to the
    # envelope's input_hash (layer 0) and output_hash (last).
    # We use hex strings throughout so prove_layer's _coerce_hash_input
    # passes them through unchanged — the envelope verifier then
    # compares them directly to the envelope's bound hashes.
    per_inputs: dict[int, bytes | str] = {}
    per_outputs: dict[int, bytes | str] = {}
    per_weights: dict[int, str] = {}

    selected = selection.selected_indices
    if not selected:
        # No layers selected (budget=0) — fall back to proof_pending
        # so we don't ship an empty layerwise envelope.
        return build_envelope_stub(
            model_hash=model_hash,
            input_hash=input_hash,
            output_hash=output_hash,
        )

    # Build a per-selected-layer hash chain. Layer 0's input is the
    # envelope's input_hash; the last layer's output is the
    # envelope's output_hash; interior links are deterministic HMACs.
    prev_hex = input_hash
    for idx_pos, layer_idx in enumerate(selected):
        is_last = idx_pos == len(selected) - 1
        # Per-layer input: previous chain link (hex string).
        per_inputs[layer_idx] = prev_hex
        # Per-layer output: bind last layer to envelope output_hash;
        # interior layers chain forward deterministically.
        if is_last:
            out_hex = output_hash
        else:
            out_hex = hashlib.sha256(
                b"NANOZK-LAYER-CHAIN-v1|"
                + bytes.fromhex(prev_hex)
                + b"|"
                + layer_idx.to_bytes(4, "big")
            ).hexdigest()
        per_outputs[layer_idx] = out_hex
        # Per-layer weights commitment is derived from the model
        # hash + layer index — same model means same per-layer
        # commitment regardless of selection budget.
        per_weights[layer_idx] = hashlib.sha256(
            b"NANOZK-LAYER-WEIGHTS-v1|"
            + bytes.fromhex(model_hash)
            + b"|"
            + layer_idx.to_bytes(4, "big")
        ).hexdigest()
        prev_hex = out_hex

    proof_set = prove_layer_set(
        selected_indices=selected,
        per_layer_inputs=per_inputs,
        per_layer_outputs=per_outputs,
        per_layer_weights_commitments=per_weights,
        total_layers=total_layers,
        fisher_captured_information=(
            selection.captured_information
        ),
    )

    return build_envelope_with_layerwise_proof(
        layer_proof_set_bytes=proof_set.to_bytes(),
        model_hash=model_hash,
        input_hash=input_hash,
        output_hash=output_hash,
    )


# ---------------------------------------------------------------------------
# TEE attestation construction
# ---------------------------------------------------------------------------


def _build_tee_attestation_from_request(
    *,
    request_body: CausalAttributionRequestDTO,
) -> TEEAttestation:
    """Build a ``TEEAttestation`` from the request flags.

    Three paths:
      1. Caller supplied ``tee_jwt`` + ``tee_nonce`` → verify and use.
      2. Caller didn't supply, server in test mode → generate a
         deterministic test JWT.
      3. Caller didn't supply, server NOT in test mode → reject
         with 400 (the endpoint can't fabricate a real attestation).
    """
    if request_body.tee_jwt is not None:
        if request_body.tee_nonce is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "tee_jwt supplied without tee_nonce. Both are "
                    "required for caller-supplied attestation."
                ),
            )
        verification = verify_nras_jwt(
            jwt=request_body.tee_jwt,
            expected_nonce=request_body.tee_nonce,
            expected_issuer=NRAS_PROD_ISSUER,
        )
        if not verification.ok:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"tee_jwt verification failed: {verification.reason}",
            )
        return build_tee_attestation(
            nras_jwt=request_body.tee_jwt,
            nonce=request_body.tee_nonce,
            include_full_jwt=True,
            test_mode=verification.reason == "ok_test_mode",
        )

    # No caller JWT — test-mode synthesis is the only remaining
    # legitimate path.
    mode = os.environ.get("TEX_TEE_ATTESTATION_MODE", "production")
    if mode != "test":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "include_tee_attestation=True requires either a "
                "caller-supplied tee_jwt or TEX_TEE_ATTESTATION_MODE=test "
                "on the server. Refusing to fabricate an attestation."
            ),
        )

    nonce = request_body.tee_nonce or secrets.token_hex(16)
    test_jwt = build_test_mode_jwt(nonce=nonce)
    return build_tee_attestation(
        nras_jwt=test_jwt,
        nonce=nonce,
        include_full_jwt=True,
        test_mode=True,
    )


# ---------------------------------------------------------------------------
# Method tagging
# ---------------------------------------------------------------------------


def _final_attribution_method(
    *,
    base_method: str,
    ptv_envelope: PTVEnvelope | None,
    tee_attestation: TEEAttestation | None,
) -> str:
    """Compose the final attribution_method tag.

    The engine's ``base_method`` already reflects whether prefill
    signals and conformal prediction were used (it appends
    ``+conformal`` when include_conformal=True). This function adds
    PTV / TEE layers on top.

    Examples:
      base="graph+prefill", no PTV, no TEE   → "graph+prefill"
      base="graph+conformal", PTV proof_pending → "graph+conformal+zk_pending"
      base="graph+prefill+conformal", PTV groth16, TEE
                                              → "graph+prefill+conformal+zk+tee"
      base="graph+prefill", PTV layerwise NANOZK
                                              → "graph+prefill+zk_layerwise"

    The ``proof_pending`` suffix is the honest label for the stub
    NanoZK prover state. The ``zk_layerwise`` suffix flags the
    Thread 15 wired path — the verifier produces a real verdict
    against a Fisher-selected layer proof set.
    """
    parts = [base_method]
    if ptv_envelope is not None:
        if ptv_envelope.method == PTV_METHOD_PROOF_PENDING:
            parts.append("zk_pending")
        elif ptv_envelope.method == PTV_METHOD_NANOZK_LAYERWISE_2026:
            parts.append("zk_layerwise")
        else:
            parts.append("zk")
    if tee_attestation is not None:
        parts.append("tee")
    return "+".join(parts) if len(parts) > 1 else parts[0]


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@_router.post(
    "/v1/incidents/{decision_id}/attribute",
    status_code=status.HTTP_200_OK,
    summary="Compute causal attribution for a stored decision",
    dependencies=[Depends(RequireScope("decision:read"))],
)
def attribute_incident(
    decision_id: UUID,
    body: CausalAttributionRequestDTO,
    request: Request,
) -> CausalAttributionResponseDTO:
    """Compute and sign causal attribution for one stored decision.

    Read-only against the live system. Writes one evidence row.
    Returns a SCITT-shaped COSE_Sign1 signed statement plus the
    decoded claim set for inspectability.

    Errors
    ------
    * 404 if no stored Decision matches ``decision_id``.
    * 400 if the request asks for TEE attestation without a JWT
      and the server isn't in test mode.
    """
    # 1. Look up the stored Decision.
    decision_store = _require_app_state(request, "decision_store")
    store = cast(Any, decision_store)
    decision: Decision | None = store.get(decision_id)
    if decision is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no decision with id={decision_id}",
        )

    # 2. Run the attribution engine, passing conformal flags through.
    result = compute_attribution(
        decision,
        include_conformal=body.include_conformal,
        conformal_alpha=body.conformal_alpha,
        conformal_algorithm=body.conformal_algorithm,
    )

    # 3. Optional PTV envelope.
    ptv_envelope: PTVEnvelope | None = None
    if body.include_zk_envelope:
        ptv_envelope = _build_ptv_envelope(result=result, decision=decision)

    # 4. Optional TEE attestation.
    tee_attestation: TEEAttestation | None = None
    if body.include_tee_attestation:
        tee_attestation = _build_tee_attestation_from_request(
            request_body=body,
        )

    # 5. Compose the final attribution_method tag.
    final_method = _final_attribution_method(
        base_method=result.attribution_method,
        ptv_envelope=ptv_envelope,
        tee_attestation=tee_attestation,
    )

    # 6. Determine issuer URI.
    environment = getattr(decision, "environment", "production")
    issuer = f"urn:tex:aegis:{environment}"

    # 7. Build and sign the SCITT claim set.
    claim_set = _build_scitt_claim_set(
        decision=decision,
        result=result,
        issuer=issuer,
        ptv_envelope=ptv_envelope,
        tee_attestation=tee_attestation,
    )
    # Inject the final method tag so the signed claim set reflects
    # ZK / TEE layers, not just the engine's base graph+prefill
    # tag. The engine's tag is correct for the engine's output;
    # the endpoint's tag is correct for the full statement.
    claim_set["attribution"]["attribution_method"] = final_method

    signing_key = _resolve_signing_key(request)
    signed = mint_signed_statement(
        claim_set=claim_set,
        signing_key=signing_key,
    )

    # 8. Hash-chain the attribution row into the evidence ledger.
    evidence_recorder = _require_app_state(request, "evidence_recorder")
    recorder = cast(Any, evidence_recorder)

    # Parent-link to the original decision evidence row when
    # discoverable. We scan the chain for the matching decision
    # row's record_hash; if the recorder doesn't have a public
    # by-decision-id lookup we leave parent_evidence_hash as None.
    parent_hash: str | None = None
    try:
        for record in recorder.read_all():
            if (
                record.record_type == "decision"
                and str(record.decision_id) == str(decision.decision_id)
            ):
                parent_hash = record.record_hash
                break
    except Exception:
        parent_hash = None

    ptv_dict = None
    if ptv_envelope is not None:
        ptv_dict = {
            "method": ptv_envelope.method,
            "proof": ptv_envelope.proof,
            "model_hash": ptv_envelope.model_hash,
            "input_hash": ptv_envelope.input_hash,
            "output_hash": ptv_envelope.output_hash,
        }
    tee_dict: dict[str, Any] | None = None
    if tee_attestation is not None:
        tee_dict = {
            "format": tee_attestation.format,
            "nras_jwt_sha256": tee_attestation.nras_jwt_sha256,
            "nonce": tee_attestation.nonce,
            "issuer": tee_attestation.issuer,
            "test_mode": tee_attestation.test_mode,
            "gpu_measurement_sha256": tee_attestation.gpu_measurement_sha256,
        }

    evidence_record = recorder.record_attribution(
        decision_id=decision.decision_id,
        request_id=decision.request_id,
        policy_version=decision.policy_version,
        attribution_payload={
            "primary_root_cause": _candidate_to_claim_dict(
                result.primary_root_cause
            ),
            "candidates": [
                _candidate_to_claim_dict(c) for c in result.candidates
            ],
            "blame_distribution": dict(result.blame_distribution),
            "causality_laundering_suspected": result.causality_laundering_suspected,
            "attribution_method": final_method,
            "slm_model_id": result.slm_model_id,
            "slm_model_weight_sha256": result.slm_model_weight_sha256,
            "confidence_signals": dict(result.confidence_signals),
            "attribution_latency_ms": result.attribution_latency_ms,
        },
        signed_statement_cose_hex=signed.envelope_cbor.hex(),
        signed_statement_cose_alg=cose_alg_for(signing_key.algorithm),
        ptv_envelope=ptv_dict,
        tee_attestation=tee_dict,
        parent_evidence_hash=parent_hash,
    )

    emit_event(
        "incident.attribution.signed_and_recorded",
        decision_id=str(decision.decision_id),
        attribution_method=final_method,
        cose_alg=cose_alg_for(signing_key.algorithm),
        evidence_record_hash=evidence_record.record_hash,
    )

    # 9. Assemble the response DTO.
    candidates_dto = tuple(
        CausalCandidateDTO(
            agent_id=c.agent_id,
            decisive_step_index=c.decisive_step_index,
            step_id=c.step_id,
            confidence=c.confidence,
            integrity_level=c.integrity_level,
            reasoning_perspective=c.reasoning_perspective,
        )
        for c in result.candidates
    )

    ptv_dto: PTVEnvelopeDTO | None = None
    if ptv_envelope is not None:
        ptv_dto = PTVEnvelopeDTO(
            method=ptv_envelope.method,
            proof=ptv_envelope.proof,
            model_hash=ptv_envelope.model_hash,
            input_hash=ptv_envelope.input_hash,
            output_hash=ptv_envelope.output_hash,
        )

    tee_dto: TEEAttestationDTO | None = None
    if tee_attestation is not None:
        tee_dto = TEEAttestationDTO(
            format=tee_attestation.format,
            nras_jwt=tee_attestation.nras_jwt,
            nras_jwt_sha256=tee_attestation.nras_jwt_sha256,
            nonce=tee_attestation.nonce,
            gpu_measurement_sha256=tee_attestation.gpu_measurement_sha256,
            issuer=tee_attestation.issuer,
            test_mode=tee_attestation.test_mode,
        )

    conformal_dto: ConformalPredictionSetDTO | None = None
    if result.conformal_set is not None:
        cs = result.conformal_set
        conformal_dto = ConformalPredictionSetDTO(
            algorithm=cs.algorithm,
            start_index=cs.start_index,
            end_index=cs.end_index,
            set_size=cs.set_size,
            trace_length=cs.trace_length,
            alpha=cs.alpha,
            target_coverage=cs.target_coverage,
            # Sanitize potential +/-inf for JSON serialization.
            threshold=(
                cs.threshold
                if cs.threshold not in (float("inf"), float("-inf"))
                else (1e308 if cs.threshold == float("inf") else -1e308)
            ),
            score_source=cs.score_source,
            coverage_mode=cs.coverage_mode,
            step_ids_in_set=cs.step_ids_in_set,
        )

    # The chain index is the count of records *before* this one,
    # i.e. its zero-based position in the JSONL chain.
    try:
        all_records = recorder.read_all()
        chain_index = next(
            (
                idx
                for idx, record in enumerate(all_records)
                if record.record_hash == evidence_record.record_hash
            ),
            len(all_records) - 1,
        )
    except Exception:
        chain_index = 0

    return CausalAttributionResponseDTO(
        decision_id=decision.decision_id,
        candidates=candidates_dto,
        primary_root_cause_index=result.primary_root_cause_index,
        blame_distribution=dict(result.blame_distribution),
        causality_laundering_suspected=result.causality_laundering_suspected,
        confidence_signals=dict(result.confidence_signals),
        signals_available=result.signals_available,
        slm_model_id=result.slm_model_id,
        slm_model_weight_sha256=result.slm_model_weight_sha256,
        attribution_method=final_method,
        attribution_latency_ms=result.attribution_latency_ms,
        signed_statement=SignedAttributionStatementDTO(
            envelope_cose_hex=signed.envelope_cbor.hex(),
            cose_algorithm_label=cose_alg_for(signing_key.algorithm),
            claim_set=claim_set,
        ),
        ptv_envelope=ptv_dto,
        tee_attestation=tee_dto,
        conformal_set=conformal_dto,
        evidence_chain_index=chain_index,
    )


def _require_app_state(request: Request, name: str) -> Any:
    if not hasattr(request.app.state, name):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                f"Tex app is missing required state dependency: {name}. "
                "Initialize the command stack before serving requests."
            ),
        )
    return getattr(request.app.state, name)


def build_incident_router() -> APIRouter:
    """Convenience constructor for the incidents router.

    Mounted by ``tex.main`` via ``app.include_router(...)``.
    """
    return _router


__all__ = ["build_incident_router"]
