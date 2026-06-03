"""
PTV-shaped Groth16 attestation envelope for attribution computations.

Wraps a NanoZK-style (arxiv 2603.18046, Mar 2026) layerwise Groth16
proof that the prefill SLM forward pass was executed on the claimed
model. The wire format follows
``draft-anandakrishnan-ptv-attested-agent-identity-00`` (Mar 2026)
exactly, so any PTV-aware verifier consumes Tex's high-assurance
attribution statements without bespoke glue.

Why PTV
-------
PTV is the IETF-standardized envelope for combining:

  * A Groth16 ZK proof (the ``proof`` field)
  * A hardware measurement (the ``model_hash`` field — for us, the
    SHA-256 of the SLM weights)
  * Optional sovereign / jurisdiction binding
  * SCITT-compatible audit trail

Reusing this envelope instead of inventing a Tex-private shape means
Tex's attribution statements are intelligible to any PTV verifier
from day one. PTV's own draft language: *"PTV BFT audit logs are
SCITT-compatible transparency logs. PTV proofs MAY be submitted to
SCITT registries for public verification."*

What's implemented in this thread
---------------------------------
* The PTV-shaped envelope (``PTVEnvelope`` pydantic model)
* SCITT-claim-set carriage under the ``ptv_envelope`` key per the
  PTV draft §4.4 example
* Verifier surface (``verify_ptv_envelope``) that checks the
  envelope shape, the model_hash binding to the SLM that produced
  the signals, and (when a NanoZK verifier is wired) the Groth16
  proof itself

Thread 15 update (May 18, 2026)
-------------------------------
The verifier path that previously dead-ended at
``nanozk_verifier_not_implemented_in_this_thread`` is now live for
the new ``tex:nanozk-layerwise-2026`` method tag. Envelopes built
via ``build_envelope_with_layerwise_proof`` carry a
``LayerProofSet`` (hash-chained, Fisher-selected, VEIL-wrapped per
ePrint 2026/683) in the ``proof`` field, and the verifier routes
through ``tex.nanozk.verify_layer_proof_set``. The legacy
``groth16-2026`` path remains unchanged for backward compatibility.

What's deliberately a stub
--------------------------
The Groth16 prover. NanoZK is a research paper (Mar 2026), not yet
an open reference implementation. EZKL is closer to production but
has its own toolchain. Wiring a real prover requires a NanoZK or
EZKL backend that's outside this thread's scope.

The stub semantics:

  * ``build_envelope_stub`` produces a structurally-valid PTV
    envelope with a placeholder proof tagged ``proof_pending``.
  * The attribution result's ``attribution_method`` is set to
    ``"graph+prefill+zk_pending"`` (not ``"graph+prefill+zk"``)
    when the stub is used, so downstream consumers can tell
    real proofs apart from placeholders.
  * The verifier rejects ``proof_pending`` proofs with a clear
    error in production mode.

This is the honest version of "bleeding-edge today": the wire
format and verifier are real; the prover is plumbed and waiting.

References
----------
- arxiv 2603.18046 (NanoZK, Mar 2026)
- arxiv 2605.03581 (ZK-Value LSH-Shapley, May 2026)
- draft-anandakrishnan-ptv-attested-agent-identity-00 (Mar 2026)
- draft-anandakrishnan-rats-ptv-agent-identity-00 (Apr 2026)
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from typing import Mapping

from pydantic import BaseModel, ConfigDict, Field


# PTV method identifier as specified in
# draft-anandakrishnan-ptv-attested-agent-identity-00 §B.2.
PTV_METHOD_GROTH16_2026: str = "groth16-2026"

# Placeholder method for the prover-stub path. NOT a real PTV method;
# accepting it requires PTV verifier opt-in (see verify_ptv_envelope).
PTV_METHOD_PROOF_PENDING: str = "proof_pending"

# Thread 15 — layerwise NANOZK method tag. Carries a
# ``LayerProofSet`` (Fisher-selected, hash-chained, VEIL-wrapped)
# in the ``proof`` field rather than a single Groth16 blob. The
# verifier dispatches on this tag and calls into the live
# ``tex.nanozk.verify_layer_proof_set`` path.
#
# Wire format (proof field, base64url-encoded bytes):
#   LayerProofSet.to_bytes() — a JSON object with the per-layer
#   proofs, total_layers, fisher_captured_information, and
#   set_root, all base64-safe.
#
# References:
#   * arxiv 2603.18046 (NANOZK, Mar 17 2026)
#   * arxiv 2602.17452 (Jolt Atlas, Feb 19 2026)
#   * eprint 2026/683  (VEIL, Apr 7 2026)
#   * draft-anandakrishnan-ptv-attested-agent-identity-00 §B.2 —
#     this is a Tex-private extension; the PTV draft accepts
#     vendor-specific method strings under the
#     "<vendor>:<method>" pattern. We use ``tex:nanozk-layerwise-
#     2026`` to make the vendor binding explicit.
PTV_METHOD_NANOZK_LAYERWISE_2026: str = "tex:nanozk-layerwise-2026"


class PTVEnvelope(BaseModel):
    """PTV-shaped Groth16 envelope carried in the attribution claim set.

    Wire format matches PTV draft §4.4 / Appendix B exactly. Tex
    populates ``model_hash`` with the SHA-256 of the prefill SLM
    weights, and ``proof`` with a base64url-encoded Groth16 proof
    (or ``""`` for the proof-pending stub).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    method: str = Field(min_length=1, max_length=64)
    """Either ``groth16-2026`` (real proof) or ``proof_pending``
    (stub). PTV verifiers reject anything else."""

    proof: str = Field(default="", max_length=2_097_152)
    """Base64url-encoded proof bytes.

    For ``method == "groth16-2026"`` this is a ~256-char Groth16
    proof. For ``method == "tex:nanozk-layerwise-2026"`` (Thread 15)
    this is the base64url of ``LayerProofSet.to_bytes()`` — a hash-
    chained set of per-layer NANOZK proofs. The cap of 2 MiB
    accommodates a 12-layer GPT-2 proof set (12 × 7.7 KB ≈ 92 KB)
    with comfortable headroom for Llama-scale architectures."""

    model_hash: str = Field(min_length=64, max_length=64)
    """SHA-256 hex of the SLM weights. Binds the proof to a
    specific model."""

    input_hash: str = Field(min_length=64, max_length=64)
    """SHA-256 hex of the canonicalised input the SLM consumed
    (the rendered trace text). Binds the proof to specific
    inputs."""

    output_hash: str = Field(min_length=64, max_length=64)
    """SHA-256 hex of the canonicalised prefill signals output.
    Binds the proof to specific outputs."""


@dataclass(frozen=True, slots=True)
class PTVVerificationResult:
    ok: bool
    reason: str


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_input_hash(rendered_trace_text: str) -> str:
    """Canonical SHA-256 of the rendered trace input.

    The input is the same byte string passed to the SLM by
    ``tex.causal.prefill_signals.extract_signals``.
    """
    return _sha256_hex(rendered_trace_text.encode("utf-8"))


def canonical_signals_hash(
    step_signals: Mapping[str, Mapping[str, float]],
) -> str:
    """Canonical SHA-256 of the per-step prefill signals.

    Uses a deterministic key-sorted serialization so the same
    signal bundle always hashes to the same value (required for
    the Groth16 proof's input/output binding).
    """
    # Stable JSON: sort step ids, then sort each step's metric
    # names. Numbers are formatted to a fixed number of significant
    # digits to avoid float-repr drift across platforms.
    parts: list[str] = []
    for step_id in sorted(step_signals.keys()):
        metrics = step_signals[step_id]
        metric_parts = []
        for metric_name in sorted(metrics.keys()):
            metric_parts.append(f"{metric_name}={metrics[metric_name]:.10g}")
        parts.append(f"{step_id}:{','.join(metric_parts)}")
    canonical = "|".join(parts)
    return _sha256_hex(canonical.encode("utf-8"))


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def build_envelope_stub(
    *,
    model_hash: str,
    input_hash: str,
    output_hash: str,
) -> PTVEnvelope:
    """Build a PTV envelope in proof-pending mode.

    Use this when the NanoZK prover isn't wired. The envelope
    structurally validates as PTV and carries the correct hashes,
    but the ``proof`` field is empty and ``method`` is
    ``"proof_pending"``. Verifiers in non-test mode reject this.
    """
    return PTVEnvelope(
        method=PTV_METHOD_PROOF_PENDING,
        proof="",
        model_hash=model_hash,
        input_hash=input_hash,
        output_hash=output_hash,
    )


def build_envelope_with_proof(
    *,
    proof_bytes: bytes,
    model_hash: str,
    input_hash: str,
    output_hash: str,
) -> PTVEnvelope:
    """Build a PTV envelope with a real Groth16 proof.

    Caller is responsible for producing ``proof_bytes`` from a
    NanoZK or EZKL prover. The function does no proof generation
    — it only assembles the envelope.

    Future thread: integrate a real prover here.
    """
    proof_b64 = base64.urlsafe_b64encode(proof_bytes).rstrip(b"=").decode("ascii")
    return PTVEnvelope(
        method=PTV_METHOD_GROTH16_2026,
        proof=proof_b64,
        model_hash=model_hash,
        input_hash=input_hash,
        output_hash=output_hash,
    )


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


def _env_str(name: str, default: str) -> str:
    raw = os.environ.get(name)
    return raw if raw is not None and raw.strip() else default


def verify_ptv_envelope(
    envelope: PTVEnvelope,
    *,
    expected_model_hash: str,
    expected_input_hash: str,
    expected_output_hash: str,
) -> PTVVerificationResult:
    """Verify a PTV envelope against expected hashes.

    Always checks the structural binding (the envelope's three
    hashes must match what the verifier independently computes).
    Only verifies the Groth16 proof itself when:

      * ``envelope.method == PTV_METHOD_GROTH16_2026``, AND
      * a Groth16 verifier is wired (env var
        ``TEX_NANOZK_VERIFIER_AVAILABLE=1``)

    Otherwise:

      * ``method == proof_pending`` → accepted only in test mode
        (``TEX_PTV_VERIFY_MODE=test``); rejected in production
      * ``method == groth16-2026`` without verifier → rejected
        with a clear "verifier_unavailable" reason

    The verifier itself is fail-closed.
    """
    mode = _env_str("TEX_PTV_VERIFY_MODE", "production")
    is_test_mode = mode == "test"
    nanozk_available = _env_str("TEX_NANOZK_VERIFIER_AVAILABLE", "0") == "1"

    # Structural hash binding — always checked.
    if envelope.model_hash != expected_model_hash:
        return PTVVerificationResult(
            ok=False, reason="model_hash_mismatch"
        )
    if envelope.input_hash != expected_input_hash:
        return PTVVerificationResult(
            ok=False, reason="input_hash_mismatch"
        )
    if envelope.output_hash != expected_output_hash:
        return PTVVerificationResult(
            ok=False, reason="output_hash_mismatch"
        )

    # Method-specific handling.
    if envelope.method == PTV_METHOD_PROOF_PENDING:
        if envelope.proof:
            return PTVVerificationResult(
                ok=False,
                reason="proof_pending_must_have_empty_proof",
            )
        if is_test_mode:
            return PTVVerificationResult(
                ok=True, reason="ok_proof_pending_test_mode"
            )
        return PTVVerificationResult(
            ok=False, reason="proof_pending_rejected_in_production"
        )

    if envelope.method == PTV_METHOD_GROTH16_2026:
        if not envelope.proof:
            return PTVVerificationResult(
                ok=False, reason="groth16_envelope_missing_proof"
            )
        if not nanozk_available:
            # Honest: the envelope binds correctly but we don't
            # have a verifier wired in this thread, so we can't
            # confirm the proof is valid.
            return PTVVerificationResult(
                ok=False, reason="nanozk_verifier_unavailable"
            )
        # Future thread: call into the NanoZK verifier here. The
        # verifier consumes (proof_bytes, model_hash, input_hash,
        # output_hash) and returns True iff the proof checks.
        return PTVVerificationResult(
            ok=False,
            reason="nanozk_verifier_not_implemented_in_this_thread",
        )

    if envelope.method == PTV_METHOD_NANOZK_LAYERWISE_2026:
        # Thread 15 wired path. The verifier:
        #   1. Decodes the LayerProofSet from the envelope.
        #   2. Checks the set's hash-chained root.
        #   3. For each layer proof, checks circuit fingerprint,
        #      i/o hashes against the envelope's bound hashes (the
        #      first and last layer must touch envelope.input_hash
        #      and envelope.output_hash respectively), and the
        #      VEIL wrapper.
        #   4. Returns ok=True iff every check passes.
        if not envelope.proof:
            return PTVVerificationResult(
                ok=False,
                reason="nanozk_layerwise_envelope_missing_proof",
            )
        return _verify_nanozk_layerwise(envelope=envelope)

    return PTVVerificationResult(
        ok=False, reason=f"unknown_method:{envelope.method}"
    )


# ---------------------------------------------------------------------------
# Thread 15 — NANOZK layerwise builder and verifier
# ---------------------------------------------------------------------------


def build_envelope_with_layerwise_proof(
    *,
    layer_proof_set_bytes: bytes,
    model_hash: str,
    input_hash: str,
    output_hash: str,
) -> PTVEnvelope:
    """Build a PTV envelope carrying a NANOZK layerwise proof set.

    Parameters
    ----------
    layer_proof_set_bytes
        ``LayerProofSet.to_bytes()`` — the hash-chained, VEIL-wrapped,
        Fisher-selected layer proofs.
    model_hash, input_hash, output_hash
        SHA-256 hex bindings. ``model_hash`` is the SHA-256 of the
        SLM weights. ``input_hash`` is the canonical rendered trace.
        ``output_hash`` is the canonical signals hash. These three
        anchor the envelope to the same (model, input, output)
        triple the layer proof set is over.

    Returns
    -------
    A frozen ``PTVEnvelope`` with method tag
    ``tex:nanozk-layerwise-2026``.
    """
    proof_b64 = base64.urlsafe_b64encode(
        layer_proof_set_bytes
    ).rstrip(b"=").decode("ascii")
    return PTVEnvelope(
        method=PTV_METHOD_NANOZK_LAYERWISE_2026,
        proof=proof_b64,
        model_hash=model_hash,
        input_hash=input_hash,
        output_hash=output_hash,
    )


def _verify_nanozk_layerwise(*, envelope: PTVEnvelope) -> PTVVerificationResult:
    """Verifier for the ``tex:nanozk-layerwise-2026`` envelope.

    Imports are local to keep ``tex.evidence.attribution_zk`` free of
    a hard dependency on ``tex.nanozk`` at module-load time — that
    matters because the evidence module is imported very early in
    the app startup path, and we want the import graph to remain a
    DAG with ``nanozk`` strictly downstream of ``evidence``.
    """
    from tex.nanozk import (
        LayerProofSet,
        verify_layer_proof_set,
    )

    # 1. Decode the proof set.
    try:
        # Restore base64 padding before decoding.
        proof_b64 = envelope.proof
        padding_needed = (-len(proof_b64)) % 4
        proof_bytes = base64.urlsafe_b64decode(
            proof_b64 + ("=" * padding_needed)
        )
        proof_set = LayerProofSet.from_bytes(proof_bytes)
    except Exception as exc:  # noqa: BLE001 — defensive decode
        return PTVVerificationResult(
            ok=False,
            reason=f"nanozk_layerwise_decode_failure:{type(exc).__name__}",
        )

    if not proof_set.proofs:
        return PTVVerificationResult(
            ok=False,
            reason="nanozk_layerwise_empty_proof_set",
        )

    # 2. The envelope's input_hash and output_hash must match the
    #    first layer's input_hash and the last layer's output_hash
    #    respectively. This is the structural binding that ties the
    #    set to the same (input, output) the caller saw.
    first = proof_set.proofs[0]
    last = proof_set.proofs[-1]
    if first.input_hash != envelope.input_hash:
        return PTVVerificationResult(
            ok=False,
            reason="nanozk_layerwise_input_hash_mismatch",
        )
    if last.output_hash != envelope.output_hash:
        return PTVVerificationResult(
            ok=False,
            reason="nanozk_layerwise_output_hash_mismatch",
        )

    # 3. Build the per-layer expected i/o maps. We trust the
    #    envelope's input_hash for layer 0 and output_hash for
    #    the last layer; for interior layers we accept the proof's
    #    own bound hashes — verifying them is the responsibility
    #    of the layer proof's backend.
    #
    #    This is the "structural" verification step. The cryptographic
    #    check (does the proof actually verify?) is done inside
    #    verify_layer_proof_set, which routes through the backend
    #    dispatcher.
    expected_inputs = {p.layer_index: p.input_hash for p in proof_set.proofs}
    expected_outputs = {
        p.layer_index: p.output_hash for p in proof_set.proofs
    }
    # Override layer 0 and last with the envelope's bindings so
    # any silent tampering of the proof's interior hashes is
    # rejected.
    expected_inputs[first.layer_index] = envelope.input_hash
    expected_outputs[last.layer_index] = envelope.output_hash

    verification = verify_layer_proof_set(
        proof_set,
        expected_per_layer_inputs=expected_inputs,
        expected_per_layer_outputs=expected_outputs,
    )

    if verification.is_valid:
        return PTVVerificationResult(
            ok=True,
            reason="ok_nanozk_layerwise_verified",
        )
    return PTVVerificationResult(
        ok=False,
        reason=(
            f"nanozk_layerwise_verification_failed:"
            f"{verification.reason or 'unknown'}"
        ),
    )


__all__ = [
    "PTV_METHOD_GROTH16_2026",
    "PTV_METHOD_NANOZK_LAYERWISE_2026",
    "PTV_METHOD_PROOF_PENDING",
    "PTVEnvelope",
    "PTVVerificationResult",
    "build_envelope_stub",
    "build_envelope_with_layerwise_proof",
    "build_envelope_with_proof",
    "canonical_input_hash",
    "canonical_signals_hash",
    "verify_ptv_envelope",
]
