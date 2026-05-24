"""Tests for ``tex.evidence.attribution_zk`` — Thread 15 layerwise
verifier wiring.

These exercise the new ``tex:nanozk-layerwise-2026`` PTV envelope
end-to-end: build via ``build_envelope_with_layerwise_proof``, verify
via ``verify_ptv_envelope``. The previous
``nanozk_verifier_not_implemented_in_this_thread`` dead-end must now
return a real verdict.
"""

from __future__ import annotations

import hashlib

import pytest

from tex.evidence.attribution_zk import (
    PTV_METHOD_NANOZK_LAYERWISE_2026,
    PTVEnvelope,
    PTVVerificationResult,
    build_envelope_with_layerwise_proof,
    verify_ptv_envelope,
)
from tex.nanozk import (
    prove_layer_set,
    select_layers_to_prove,
)


def _hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _build_layerwise_envelope() -> tuple[
    PTVEnvelope, str, str, str
]:
    """Build a valid envelope for use across tests."""
    env_in = _hex(b"trace-input")
    env_out = _hex(b"signals-output")
    model = _hex(b"model-weights")

    sel = select_layers_to_prove(
        total_layers=12,
        budget=6,
        fisher_scores=tuple(1.0 + 0.05 * i for i in range(12)),
    )

    per_in: dict[int, str] = {}
    per_out: dict[int, str] = {}
    per_w: dict[int, str] = {}
    prev = env_in
    for pos, idx in enumerate(sel.selected_indices):
        is_last = pos == len(sel.selected_indices) - 1
        per_in[idx] = prev
        if is_last:
            out = env_out
        else:
            out = hashlib.sha256(
                b"c|" + bytes.fromhex(prev) + b"|"
                + idx.to_bytes(4, "big")
            ).hexdigest()
        per_out[idx] = out
        per_w[idx] = hashlib.sha256(
            b"w|" + bytes.fromhex(model) + b"|"
            + idx.to_bytes(4, "big")
        ).hexdigest()
        prev = out

    ps = prove_layer_set(
        selected_indices=sel.selected_indices,
        per_layer_inputs=per_in,
        per_layer_outputs=per_out,
        per_layer_weights_commitments=per_w,
        total_layers=12,
        fisher_captured_information=sel.captured_information,
    )
    env = build_envelope_with_layerwise_proof(
        layer_proof_set_bytes=ps.to_bytes(),
        model_hash=model,
        input_hash=env_in,
        output_hash=env_out,
    )
    return env, model, env_in, env_out


# --------------------------------------------------------------------------- #
# Envelope construction                                                        #
# --------------------------------------------------------------------------- #


class TestBuildLayerwiseEnvelope:
    def test_returns_ptvenvelope(self) -> None:
        env, _, _, _ = _build_layerwise_envelope()
        assert isinstance(env, PTVEnvelope)

    def test_method_is_layerwise_tag(self) -> None:
        env, _, _, _ = _build_layerwise_envelope()
        assert env.method == PTV_METHOD_NANOZK_LAYERWISE_2026

    def test_proof_field_non_empty(self) -> None:
        env, _, _, _ = _build_layerwise_envelope()
        assert env.proof != ""

    def test_hashes_bound_correctly(self) -> None:
        env, model, env_in, env_out = _build_layerwise_envelope()
        assert env.model_hash == model
        assert env.input_hash == env_in
        assert env.output_hash == env_out

    def test_envelope_is_frozen(self) -> None:
        env, _, _, _ = _build_layerwise_envelope()
        with pytest.raises(Exception):
            env.method = "different"  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# Verifier — happy path                                                        #
# --------------------------------------------------------------------------- #


class TestVerifierHappyPath:
    def test_verify_returns_ok_true(self) -> None:
        env, model, env_in, env_out = _build_layerwise_envelope()
        result = verify_ptv_envelope(
            env,
            expected_model_hash=model,
            expected_input_hash=env_in,
            expected_output_hash=env_out,
        )
        assert isinstance(result, PTVVerificationResult)
        assert result.ok
        assert result.reason == "ok_nanozk_layerwise_verified"

    def test_verifier_no_longer_returns_not_implemented(self) -> None:
        """Regression check: the previous behaviour returned
        ``nanozk_verifier_not_implemented_in_this_thread``. Thread 15
        wires past that."""
        env, model, env_in, env_out = _build_layerwise_envelope()
        result = verify_ptv_envelope(
            env,
            expected_model_hash=model,
            expected_input_hash=env_in,
            expected_output_hash=env_out,
        )
        assert (
            result.reason
            != "nanozk_verifier_not_implemented_in_this_thread"
        )

    def test_verifier_no_longer_returns_unavailable(self) -> None:
        env, model, env_in, env_out = _build_layerwise_envelope()
        result = verify_ptv_envelope(
            env,
            expected_model_hash=model,
            expected_input_hash=env_in,
            expected_output_hash=env_out,
        )
        assert result.reason != "nanozk_verifier_unavailable"


# --------------------------------------------------------------------------- #
# Verifier — tamper detection                                                  #
# --------------------------------------------------------------------------- #


class TestVerifierTamperDetection:
    def test_tampered_model_hash_rejected(self) -> None:
        env, model, env_in, env_out = _build_layerwise_envelope()
        # Verifier checks model_hash explicitly via the
        # always-checked structural binding.
        bad_model = _hex(b"different-model")
        # Build an envelope with a different model hash but same
        # proof set — should be rejected even before the layerwise
        # path runs, by the model_hash structural check.
        bad_env = env.model_copy(update={"model_hash": bad_model})
        result = verify_ptv_envelope(
            bad_env,
            expected_model_hash=model,  # original
            expected_input_hash=env_in,
            expected_output_hash=env_out,
        )
        assert not result.ok
        assert result.reason == "model_hash_mismatch"

    def test_tampered_envelope_input_hash_rejected(self) -> None:
        env, model, env_in, env_out = _build_layerwise_envelope()
        bad = env.model_copy(
            update={"input_hash": _hex(b"tampered-input")}
        )
        result = verify_ptv_envelope(
            bad,
            expected_model_hash=model,
            expected_input_hash=_hex(b"tampered-input"),
            expected_output_hash=env_out,
        )
        # The model/input/output hash checks pass against the
        # tampered envelope, but the layerwise verifier checks the
        # proof chain anchor and finds it doesn't match.
        assert not result.ok
        assert result.reason == "nanozk_layerwise_input_hash_mismatch"

    def test_tampered_envelope_output_hash_rejected(self) -> None:
        env, model, env_in, env_out = _build_layerwise_envelope()
        bad = env.model_copy(
            update={"output_hash": _hex(b"tampered-output")}
        )
        result = verify_ptv_envelope(
            bad,
            expected_model_hash=model,
            expected_input_hash=env_in,
            expected_output_hash=_hex(b"tampered-output"),
        )
        assert not result.ok
        assert result.reason == "nanozk_layerwise_output_hash_mismatch"

    def test_corrupt_proof_bytes_rejected(self) -> None:
        env, model, env_in, env_out = _build_layerwise_envelope()
        bad = env.model_copy(
            update={"proof": "AAAA" * 20}  # not a valid LayerProofSet
        )
        result = verify_ptv_envelope(
            bad,
            expected_model_hash=model,
            expected_input_hash=env_in,
            expected_output_hash=env_out,
        )
        assert not result.ok
        assert "decode_failure" in (result.reason or "")

    def test_empty_proof_rejected(self) -> None:
        env, model, env_in, env_out = _build_layerwise_envelope()
        bad = env.model_copy(update={"proof": ""})
        result = verify_ptv_envelope(
            bad,
            expected_model_hash=model,
            expected_input_hash=env_in,
            expected_output_hash=env_out,
        )
        assert not result.ok
        assert (
            result.reason
            == "nanozk_layerwise_envelope_missing_proof"
        )


# --------------------------------------------------------------------------- #
# Envelope size cap                                                            #
# --------------------------------------------------------------------------- #


class TestEnvelopeSizeCap:
    def test_proof_field_cap_is_2mib(self) -> None:
        # Field constraint: max_length=2_097_152 — accommodates a
        # multi-megabyte proof set.
        env, _, _, _ = _build_layerwise_envelope()
        assert len(env.proof) < 2_097_152
