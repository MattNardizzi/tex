"""Tests for ``tex.nanozk.layerwise_prover``.

Covers:
  * LayerCircuit fingerprint determinism and field validation
  * Single-layer prove + verify happy path
  * Single-layer tamper detection on every bound field
  * VEIL wrapping toggle
  * Per-layer verifier latency under the 23ms NANOZK paper target
  * LayerProofSet hash chain and tamper detection
  * Set-level prove + verify with Fisher selection
  * Set-level wire-format round-trip via to_bytes / from_bytes
  * Backend dispatcher fallback semantics
  * Hash input coercion (bytes vs hex)
"""

from __future__ import annotations

import hashlib

import pytest

from tex.nanozk.fisher_guided import select_layers_to_prove
from tex.nanozk.layerwise_prover import (
    LAYERWISE_BACKEND_ID,
    LAYERWISE_CIRCUIT_VERSION,
    NANOZK_VERIFIER_TARGET_MS,
    LayerCircuit,
    LayerOpKind,
    LayerProof,
    LayerProofSet,
    LayerProofSetVerification,
    LayerProofVerification,
    NanozkBackendUnavailable,
    default_block_circuit,
    get_layerwise_backend,
    prove_layer,
    prove_layer_set,
    verify_layer_proof,
    verify_layer_proof_set,
)


# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #


class TestConstants:
    def test_backend_id_string(self) -> None:
        assert LAYERWISE_BACKEND_ID == "nanozk-layerwise-2026"

    def test_circuit_version_string(self) -> None:
        assert LAYERWISE_CIRCUIT_VERSION == "nanozk-layerwise-v1-2026.05"

    def test_verifier_target_is_paper_value(self) -> None:
        # arxiv 2603.18046 §5.2 reports 23 ms verifier time.
        assert NANOZK_VERIFIER_TARGET_MS == 23.0


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _weights() -> str:
    return _hex(b"some-layer-weights")


# --------------------------------------------------------------------------- #
# LayerCircuit                                                                 #
# --------------------------------------------------------------------------- #


class TestLayerCircuit:
    def test_default_block_has_canonical_ops(self) -> None:
        c = default_block_circuit(layer_index=0)
        # GPT-2/Llama-shape: LayerNorm, MatMul, Softmax, MatMul,
        # Residual, LayerNorm, MatMul, GELU, MatMul, Residual.
        assert LayerOpKind.SOFTMAX in c.op_kinds
        assert LayerOpKind.GELU in c.op_kinds
        assert LayerOpKind.MATMUL in c.op_kinds
        assert LayerOpKind.LAYERNORM in c.op_kinds

    def test_default_block_layer_index(self) -> None:
        for i in range(5):
            assert default_block_circuit(layer_index=i).layer_index == i

    def test_circuit_is_frozen(self) -> None:
        c = default_block_circuit(layer_index=0)
        with pytest.raises(Exception):
            c.layer_index = 1  # type: ignore[misc]

    def test_fingerprint_is_64_hex(self) -> None:
        c = default_block_circuit(layer_index=0)
        fp = c.fingerprint()
        assert len(fp) == 64
        int(fp, 16)

    def test_fingerprint_stable_for_same_index(self) -> None:
        c1 = default_block_circuit(layer_index=3)
        c2 = default_block_circuit(layer_index=3)
        assert c1.fingerprint() == c2.fingerprint()

    def test_fingerprint_varies_by_index(self) -> None:
        c0 = default_block_circuit(layer_index=0)
        c1 = default_block_circuit(layer_index=1)
        assert c0.fingerprint() != c1.fingerprint()

    def test_fusion_factor_positive(self) -> None:
        # zkGPT §5.2 reports 1.6-4.2× fusion. Our estimator returns
        # ~2× so the factor should be > 1.
        c = default_block_circuit(layer_index=0)
        assert c.fusion_factor > 1.0

    def test_fusion_factor_uses_division(self) -> None:
        c = default_block_circuit(layer_index=0)
        assert c.fusion_factor == c.pre_fusion_row_count / c.fused_row_count

    def test_canonical_bytes_deterministic(self) -> None:
        c = default_block_circuit(layer_index=2)
        assert c.canonical_bytes() == c.canonical_bytes()

    def test_extra_field_rejected(self) -> None:
        # Pydantic ConfigDict(extra='forbid') is on every model.
        with pytest.raises(Exception):
            LayerCircuit(
                layer_index=0,
                op_kinds=(LayerOpKind.MATMUL,),
                nonlinearity_gadgets=(),
                fused_row_count=10,
                pre_fusion_row_count=20,
                bogus_field="bad",  # type: ignore[call-arg]
            )


# --------------------------------------------------------------------------- #
# Single-layer prove + verify                                                  #
# --------------------------------------------------------------------------- #


class TestSingleLayerProveVerify:
    def test_prove_returns_layerproof(self) -> None:
        proof = prove_layer(
            layer_index=0,
            layer_inputs=b"in",
            layer_outputs=b"out",
            layer_weights_commitment=_weights(),
        )
        assert isinstance(proof, LayerProof)

    def test_prove_proof_bytes_nonempty(self) -> None:
        proof = prove_layer(
            layer_index=0,
            layer_inputs=b"in",
            layer_outputs=b"out",
            layer_weights_commitment=_weights(),
        )
        assert len(proof.proof_bytes) > 0

    def test_prove_includes_circuit_fingerprint(self) -> None:
        proof = prove_layer(
            layer_index=0,
            layer_inputs=b"in",
            layer_outputs=b"out",
            layer_weights_commitment=_weights(),
        )
        expected = default_block_circuit(0).fingerprint()
        assert proof.circuit_fingerprint == expected

    def test_verify_happy_path(self) -> None:
        inp = b"hello"
        out = b"world"
        w = _weights()
        proof = prove_layer(
            layer_index=0,
            layer_inputs=inp,
            layer_outputs=out,
            layer_weights_commitment=w,
        )
        result = verify_layer_proof(
            proof,
            expected_inputs_hash=_hex(inp),
            expected_outputs_hash=_hex(out),
            expected_weights_commitment=w,
        )
        assert result.is_valid
        assert result.reason is None

    def test_verify_returns_verification_object(self) -> None:
        inp = b"hello"
        out = b"world"
        w = _weights()
        proof = prove_layer(
            layer_index=0,
            layer_inputs=inp,
            layer_outputs=out,
            layer_weights_commitment=w,
        )
        result = verify_layer_proof(
            proof,
            expected_inputs_hash=_hex(inp),
            expected_outputs_hash=_hex(out),
            expected_weights_commitment=w,
        )
        assert isinstance(result, LayerProofVerification)

    def test_verifier_latency_under_paper_target(self) -> None:
        # arxiv 2603.18046 §5.2 — 23ms verifier target. The shim
        # path is sub-millisecond so this is comfortably under.
        inp = b"hello"
        out = b"world"
        w = _weights()
        proof = prove_layer(
            layer_index=0,
            layer_inputs=inp,
            layer_outputs=out,
            layer_weights_commitment=w,
        )
        result = verify_layer_proof(
            proof,
            expected_inputs_hash=_hex(inp),
            expected_outputs_hash=_hex(out),
            expected_weights_commitment=w,
        )
        assert result.verifier_ms < NANOZK_VERIFIER_TARGET_MS

    def test_layer_index_mismatch_in_circuit_rejected(self) -> None:
        # Passing a circuit with the wrong layer_index should raise.
        with pytest.raises(ValueError):
            prove_layer(
                layer_index=0,
                layer_inputs=b"in",
                layer_outputs=b"out",
                layer_weights_commitment=_weights(),
                circuit=default_block_circuit(5),
            )

    def test_invalid_weights_commitment_rejected(self) -> None:
        with pytest.raises(ValueError):
            prove_layer(
                layer_index=0,
                layer_inputs=b"in",
                layer_outputs=b"out",
                layer_weights_commitment="not-64-hex",
            )

    def test_hex_input_passthrough(self) -> None:
        # Passing a 64-char hex string as input — it should pass
        # through without re-hashing.
        h = _hex(b"some bytes")
        proof = prove_layer(
            layer_index=0,
            layer_inputs=h,
            layer_outputs=b"out",
            layer_weights_commitment=_weights(),
        )
        assert proof.input_hash == h

    def test_invalid_hex_input_rejected(self) -> None:
        with pytest.raises(ValueError):
            prove_layer(
                layer_index=0,
                layer_inputs="not-hex-64-chars",
                layer_outputs=b"out",
                layer_weights_commitment=_weights(),
            )


# --------------------------------------------------------------------------- #
# Tamper detection                                                             #
# --------------------------------------------------------------------------- #


class TestSingleLayerTamperDetection:
    def _make_proof(self) -> tuple[LayerProof, bytes, bytes, str]:
        inp = b"the input"
        out = b"the output"
        w = _weights()
        proof = prove_layer(
            layer_index=0,
            layer_inputs=inp,
            layer_outputs=out,
            layer_weights_commitment=w,
        )
        return proof, inp, out, w

    def test_tampered_input_hash_rejected(self) -> None:
        proof, inp, out, w = self._make_proof()
        result = verify_layer_proof(
            proof,
            expected_inputs_hash=_hex(b"different"),
            expected_outputs_hash=_hex(out),
            expected_weights_commitment=w,
        )
        assert not result.is_valid
        assert result.reason == "input_hash_mismatch"

    def test_tampered_output_hash_rejected(self) -> None:
        proof, inp, out, w = self._make_proof()
        result = verify_layer_proof(
            proof,
            expected_inputs_hash=_hex(inp),
            expected_outputs_hash=_hex(b"different"),
            expected_weights_commitment=w,
        )
        assert not result.is_valid
        assert result.reason == "output_hash_mismatch"

    def test_tampered_weights_rejected(self) -> None:
        proof, inp, out, w = self._make_proof()
        result = verify_layer_proof(
            proof,
            expected_inputs_hash=_hex(inp),
            expected_outputs_hash=_hex(out),
            expected_weights_commitment=_hex(b"other-weights"),
        )
        assert not result.is_valid
        assert result.reason == "weights_commitment_mismatch"

    def test_tampered_circuit_rejected(self) -> None:
        # Pass a non-matching expected circuit (different layer
        # index → different fingerprint).
        proof, inp, out, w = self._make_proof()
        result = verify_layer_proof(
            proof,
            expected_inputs_hash=_hex(inp),
            expected_outputs_hash=_hex(out),
            expected_weights_commitment=w,
            expected_circuit=default_block_circuit(layer_index=7),
        )
        assert not result.is_valid
        # Either circuit_fingerprint_mismatch (caught early) or
        # layer_index mismatch path.
        assert result.reason is not None
        assert "circuit" in result.reason or "fingerprint" in result.reason

    def test_tampered_proof_bytes_rejected(self) -> None:
        # Modify the proof_bytes wholesale — VEIL integrity should
        # fire.
        proof, inp, out, w = self._make_proof()
        bad = proof.model_copy(update={"proof_bytes": b"\x00" * 128})
        result = verify_layer_proof(
            bad,
            expected_inputs_hash=_hex(inp),
            expected_outputs_hash=_hex(out),
            expected_weights_commitment=w,
        )
        assert not result.is_valid


# --------------------------------------------------------------------------- #
# VEIL wrap toggle                                                             #
# --------------------------------------------------------------------------- #


class TestVeilWrapToggle:
    def test_default_is_veil_wrapped(self) -> None:
        proof = prove_layer(
            layer_index=0,
            layer_inputs=b"in",
            layer_outputs=b"out",
            layer_weights_commitment=_weights(),
        )
        assert proof.veil_wrapped is True

    def test_unwrapped_path(self) -> None:
        proof = prove_layer(
            layer_index=0,
            layer_inputs=b"in",
            layer_outputs=b"out",
            layer_weights_commitment=_weights(),
            veil_wrap_proof=False,
        )
        assert proof.veil_wrapped is False

    def test_unwrapped_verifies(self) -> None:
        inp = b"in"
        out = b"out"
        w = _weights()
        proof = prove_layer(
            layer_index=0,
            layer_inputs=inp,
            layer_outputs=out,
            layer_weights_commitment=w,
            veil_wrap_proof=False,
        )
        result = verify_layer_proof(
            proof,
            expected_inputs_hash=_hex(inp),
            expected_outputs_hash=_hex(out),
            expected_weights_commitment=w,
        )
        assert result.is_valid

    def test_wrapped_proof_larger_than_unwrapped(self) -> None:
        inp = b"in"
        out = b"out"
        w = _weights()
        wrapped = prove_layer(
            layer_index=0,
            layer_inputs=inp,
            layer_outputs=out,
            layer_weights_commitment=w,
            veil_wrap_proof=True,
        )
        unwrapped = prove_layer(
            layer_index=0,
            layer_inputs=inp,
            layer_outputs=out,
            layer_weights_commitment=w,
            veil_wrap_proof=False,
        )
        # Wrapped adds ~88 bytes of VEIL metadata (32 + 32 + 16 + 8).
        assert len(wrapped.proof_bytes) - len(unwrapped.proof_bytes) >= 88


# --------------------------------------------------------------------------- #
# Backend dispatcher                                                           #
# --------------------------------------------------------------------------- #


class TestBackendDispatcher:
    def test_get_shim_backend(self) -> None:
        backend = get_layerwise_backend("deterministic-shim-v1")
        assert backend.backend_id == "deterministic-shim-v1"

    def test_get_layerwise_backend_falls_back_to_shim(self) -> None:
        # The regulator-grade Rust backend is not bundled; with
        # fallback enabled (default) we get the shim.
        backend = get_layerwise_backend(LAYERWISE_BACKEND_ID)
        assert backend.backend_id == "deterministic-shim-v1"

    def test_get_layerwise_backend_no_fallback_raises(self) -> None:
        with pytest.raises(NanozkBackendUnavailable):
            get_layerwise_backend(
                LAYERWISE_BACKEND_ID, allow_shim_fallback=False
            )

    def test_unknown_backend_raises(self) -> None:
        with pytest.raises(NanozkBackendUnavailable):
            get_layerwise_backend("not-a-real-backend")


# --------------------------------------------------------------------------- #
# LayerProofSet                                                                #
# --------------------------------------------------------------------------- #


def _build_chain(
    *,
    layer_indices: tuple[int, ...],
    seed_input_hex: str,
    final_output_hex: str,
    model_hash_hex: str,
) -> tuple[dict[int, str], dict[int, str], dict[int, str]]:
    """Build per-layer i/o + weights hex maps that chain together."""
    per_in: dict[int, str] = {}
    per_out: dict[int, str] = {}
    per_w: dict[int, str] = {}
    prev = seed_input_hex
    for pos, idx in enumerate(layer_indices):
        is_last = pos == len(layer_indices) - 1
        per_in[idx] = prev
        if is_last:
            out = final_output_hex
        else:
            out = hashlib.sha256(
                b"chain|"
                + bytes.fromhex(prev)
                + b"|"
                + idx.to_bytes(4, "big")
            ).hexdigest()
        per_out[idx] = out
        per_w[idx] = hashlib.sha256(
            b"w|" + bytes.fromhex(model_hash_hex) + b"|"
            + idx.to_bytes(4, "big")
        ).hexdigest()
        prev = out
    return per_in, per_out, per_w


class TestLayerProofSet:
    def test_prove_set_returns_layerproofset(self) -> None:
        sel = (0, 1, 2)
        in_h = _hex(b"env-in")
        out_h = _hex(b"env-out")
        m = _hex(b"model")
        per_in, per_out, per_w = _build_chain(
            layer_indices=sel,
            seed_input_hex=in_h,
            final_output_hex=out_h,
            model_hash_hex=m,
        )
        ps = prove_layer_set(
            selected_indices=sel,
            per_layer_inputs=per_in,
            per_layer_outputs=per_out,
            per_layer_weights_commitments=per_w,
            total_layers=12,
            fisher_captured_information=0.5,
        )
        assert isinstance(ps, LayerProofSet)
        assert len(ps.proofs) == 3

    def test_indices_must_be_ascending(self) -> None:
        with pytest.raises(ValueError):
            prove_layer_set(
                selected_indices=(2, 1, 0),
                per_layer_inputs={0: b"a", 1: b"b", 2: b"c"},
                per_layer_outputs={0: b"a", 1: b"b", 2: b"c"},
                per_layer_weights_commitments={0: _hex(b"w"), 1: _hex(b"w"), 2: _hex(b"w")},
                total_layers=3,
                fisher_captured_information=0.5,
            )

    def test_missing_layer_input_raises(self) -> None:
        with pytest.raises(ValueError, match="missing inputs"):
            prove_layer_set(
                selected_indices=(0, 1),
                per_layer_inputs={0: b"in"},
                per_layer_outputs={0: b"out", 1: b"out"},
                per_layer_weights_commitments={0: _hex(b"w"), 1: _hex(b"w")},
                total_layers=2,
                fisher_captured_information=0.5,
            )

    def test_missing_layer_output_raises(self) -> None:
        with pytest.raises(ValueError, match="missing outputs"):
            prove_layer_set(
                selected_indices=(0, 1),
                per_layer_inputs={0: b"in", 1: b"in"},
                per_layer_outputs={0: b"out"},
                per_layer_weights_commitments={0: _hex(b"w"), 1: _hex(b"w")},
                total_layers=2,
                fisher_captured_information=0.5,
            )

    def test_missing_layer_weights_raises(self) -> None:
        with pytest.raises(ValueError, match="missing weights"):
            prove_layer_set(
                selected_indices=(0,),
                per_layer_inputs={0: b"in"},
                per_layer_outputs={0: b"out"},
                per_layer_weights_commitments={},
                total_layers=1,
                fisher_captured_information=0.5,
            )

    def test_set_root_consistent_after_prove(self) -> None:
        sel = (0, 1, 2)
        in_h = _hex(b"env-in")
        out_h = _hex(b"env-out")
        m = _hex(b"model")
        per_in, per_out, per_w = _build_chain(
            layer_indices=sel,
            seed_input_hex=in_h,
            final_output_hex=out_h,
            model_hash_hex=m,
        )
        ps = prove_layer_set(
            selected_indices=sel,
            per_layer_inputs=per_in,
            per_layer_outputs=per_out,
            per_layer_weights_commitments=per_w,
            total_layers=12,
            fisher_captured_information=0.5,
        )
        # Recomputing the root from the same proofs should match.
        from tex.nanozk.layerwise_prover import _set_root

        root, _kind = _set_root(ps.proofs)
        assert root == ps.set_root


class TestLayerProofSetVerify:
    def _build(
        self,
    ) -> tuple[
        LayerProofSet,
        dict[int, str],
        dict[int, str],
        dict[int, str],
        tuple[int, ...],
    ]:
        sel = (0, 3, 7, 11)
        in_h = _hex(b"env-in")
        out_h = _hex(b"env-out")
        m = _hex(b"model")
        per_in, per_out, per_w = _build_chain(
            layer_indices=sel,
            seed_input_hex=in_h,
            final_output_hex=out_h,
            model_hash_hex=m,
        )
        ps = prove_layer_set(
            selected_indices=sel,
            per_layer_inputs=per_in,
            per_layer_outputs=per_out,
            per_layer_weights_commitments=per_w,
            total_layers=12,
            fisher_captured_information=0.4,
        )
        # The verifier expects expected_per_layer_inputs to be hashes
        # of the actual layer-input *bytes-or-hex* — and since we
        # passed hex strings, the proof stored them as-is. So the
        # expected map mirrors per_in.
        return ps, per_in, per_out, per_w, sel

    def test_verify_set_happy_path(self) -> None:
        ps, per_in, per_out, per_w, sel = self._build()
        result = verify_layer_proof_set(
            ps,
            expected_per_layer_inputs=per_in,
            expected_per_layer_outputs=per_out,
            expected_per_layer_weights=per_w,
        )
        assert isinstance(result, LayerProofSetVerification)
        assert result.is_valid
        assert result.layer_count == 4

    def test_verify_set_root_tampered(self) -> None:
        ps, per_in, per_out, per_w, sel = self._build()
        bad = ps.model_copy(update={"set_root": "0" * 64})
        result = verify_layer_proof_set(
            bad,
            expected_per_layer_inputs=per_in,
            expected_per_layer_outputs=per_out,
            expected_per_layer_weights=per_w,
        )
        assert not result.is_valid
        assert result.reason == "set_root_mismatch"

    def test_verify_set_per_layer_tamper_detected(self) -> None:
        ps, per_in, per_out, per_w, sel = self._build()
        # Tamper the expected i/o for one layer — proof rejects.
        bad_per_in = dict(per_in)
        bad_per_in[sel[1]] = _hex(b"tampered-input")
        result = verify_layer_proof_set(
            ps,
            expected_per_layer_inputs=bad_per_in,
            expected_per_layer_outputs=per_out,
            expected_per_layer_weights=per_w,
        )
        assert not result.is_valid

    def test_verify_set_latency_under_target(self) -> None:
        ps, per_in, per_out, per_w, sel = self._build()
        result = verify_layer_proof_set(
            ps,
            expected_per_layer_inputs=per_in,
            expected_per_layer_outputs=per_out,
            expected_per_layer_weights=per_w,
        )
        # 4-layer set under 23ms total verifier time is the paper
        # target per layer; total budget is generous.
        assert result.total_verifier_ms < 4 * NANOZK_VERIFIER_TARGET_MS


# --------------------------------------------------------------------------- #
# Wire-format round trip                                                       #
# --------------------------------------------------------------------------- #


class TestWireFormat:
    def test_to_bytes_from_bytes_round_trip(self) -> None:
        sel = (0, 1)
        in_h = _hex(b"env-in")
        out_h = _hex(b"env-out")
        m = _hex(b"model")
        per_in, per_out, per_w = _build_chain(
            layer_indices=sel,
            seed_input_hex=in_h,
            final_output_hex=out_h,
            model_hash_hex=m,
        )
        ps = prove_layer_set(
            selected_indices=sel,
            per_layer_inputs=per_in,
            per_layer_outputs=per_out,
            per_layer_weights_commitments=per_w,
            total_layers=2,
            fisher_captured_information=0.5,
        )
        wire = ps.to_bytes()
        restored = LayerProofSet.from_bytes(wire)
        assert restored.set_root == ps.set_root
        assert restored.total_layers == ps.total_layers
        assert len(restored.proofs) == len(ps.proofs)
        for original, recovered in zip(ps.proofs, restored.proofs):
            assert original.layer_index == recovered.layer_index
            assert original.input_hash == recovered.input_hash
            assert original.output_hash == recovered.output_hash
            assert (
                original.weights_commitment
                == recovered.weights_commitment
            )
            assert original.proof_bytes == recovered.proof_bytes
            assert original.backend == recovered.backend
            assert original.veil_wrapped == recovered.veil_wrapped

    def test_round_trip_verifies(self) -> None:
        sel = (0, 1)
        in_h = _hex(b"env-in")
        out_h = _hex(b"env-out")
        m = _hex(b"model")
        per_in, per_out, per_w = _build_chain(
            layer_indices=sel,
            seed_input_hex=in_h,
            final_output_hex=out_h,
            model_hash_hex=m,
        )
        ps = prove_layer_set(
            selected_indices=sel,
            per_layer_inputs=per_in,
            per_layer_outputs=per_out,
            per_layer_weights_commitments=per_w,
            total_layers=2,
            fisher_captured_information=0.5,
        )
        wire = ps.to_bytes()
        restored = LayerProofSet.from_bytes(wire)
        result = verify_layer_proof_set(
            restored,
            expected_per_layer_inputs=per_in,
            expected_per_layer_outputs=per_out,
            expected_per_layer_weights=per_w,
        )
        assert result.is_valid


# --------------------------------------------------------------------------- #
# Fisher-driven selection integration                                          #
# --------------------------------------------------------------------------- #


class TestFisherIntegration:
    def test_select_then_prove(self) -> None:
        """Build a Fisher selection then prove the selected layers."""
        total = 8
        fisher = tuple(0.1 + 0.2 * i for i in range(total))
        sel_result = select_layers_to_prove(
            total_layers=total,
            budget=4,
            fisher_scores=fisher,
        )
        # Top-4 by Fisher: indices 4, 5, 6, 7.
        assert sel_result.selected_indices == (4, 5, 6, 7)

        in_h = _hex(b"env-in")
        out_h = _hex(b"env-out")
        m = _hex(b"model")
        per_in, per_out, per_w = _build_chain(
            layer_indices=sel_result.selected_indices,
            seed_input_hex=in_h,
            final_output_hex=out_h,
            model_hash_hex=m,
        )
        ps = prove_layer_set(
            selected_indices=sel_result.selected_indices,
            per_layer_inputs=per_in,
            per_layer_outputs=per_out,
            per_layer_weights_commitments=per_w,
            total_layers=total,
            fisher_captured_information=sel_result.captured_information,
        )
        result = verify_layer_proof_set(
            ps,
            expected_per_layer_inputs=per_in,
            expected_per_layer_outputs=per_out,
            expected_per_layer_weights=per_w,
        )
        assert result.is_valid
        assert ps.fisher_captured_information == pytest.approx(
            sel_result.captured_information
        )
