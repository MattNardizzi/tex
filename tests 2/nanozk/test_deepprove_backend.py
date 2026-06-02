"""Tests for tex.nanozk.deepprove_backend."""

from __future__ import annotations

import pytest

from tex.nanozk.deepprove_backend import (
    DEEPPROVE_BACKEND_ID,
    DEEPPROVE_BINARY_NAME,
    DEEPPROVE_DEFAULT_TIMEOUT_S,
    DeepProveAvailability,
    DeepProveSubprocessBackend,
    PAPER_PROVER_SPEEDUP_OVER_EZKL,
    PAPER_VERIFIER_SPEEDUP_OVER_EZKL,
    check_deepprove_availability,
    register_deepprove_if_available,
)


class TestConstants:
    def test_backend_id(self) -> None:
        assert DEEPPROVE_BACKEND_ID == "deepprove-2026"

    def test_binary_name(self) -> None:
        assert DEEPPROVE_BINARY_NAME == "deep-prove"

    def test_paper_prover_speedup(self) -> None:
        assert PAPER_PROVER_SPEEDUP_OVER_EZKL == 158.0

    def test_paper_verifier_speedup(self) -> None:
        assert PAPER_VERIFIER_SPEEDUP_OVER_EZKL == 671.0

    def test_default_timeout(self) -> None:
        assert DEEPPROVE_DEFAULT_TIMEOUT_S == 60.0


class TestAvailabilityProbe:
    def test_probe_returns_availability(self) -> None:
        result = check_deepprove_availability()
        assert isinstance(result, DeepProveAvailability)

    def test_probe_reports_absence_in_ci(self) -> None:
        # In CI / sandbox the binary is NOT installed.
        result = check_deepprove_availability()
        if not result.binary_present:
            assert result.binary_path is None
            assert any("not found" in e for e in result.probe_errors)

    def test_availability_frozen(self) -> None:
        result = check_deepprove_availability()
        with pytest.raises(Exception):
            result.binary_present = True  # type: ignore[misc]


class TestRegisterDeepProveIfAvailable:
    def test_returns_availability(self) -> None:
        avail = register_deepprove_if_available()
        assert isinstance(avail, DeepProveAvailability)

    def test_safe_to_call_repeatedly(self) -> None:
        a = register_deepprove_if_available()
        b = register_deepprove_if_available()
        assert a.binary_present == b.binary_present

    def test_does_not_register_when_absent(self) -> None:
        # When the binary isn't on PATH, registration is a no-op.
        from tex.nanozk.layerwise_prover import _REGISTRY

        avail = register_deepprove_if_available()
        if not avail.binary_present:
            # Backend id should NOT be in the registry.
            assert DEEPPROVE_BACKEND_ID not in _REGISTRY


class TestDeepProveSubprocessBackendStructure:
    def test_has_required_attributes(self) -> None:
        backend = DeepProveSubprocessBackend(
            binary_path="/nonexistent/deep-prove",
        )
        assert backend.backend_id == DEEPPROVE_BACKEND_ID

    def test_implements_prove_method(self) -> None:
        backend = DeepProveSubprocessBackend(
            binary_path="/nonexistent/deep-prove",
        )
        assert callable(backend.prove)

    def test_implements_verify_method(self) -> None:
        backend = DeepProveSubprocessBackend(
            binary_path="/nonexistent/deep-prove",
        )
        assert callable(backend.verify)

    def test_prove_raises_when_binary_missing(self) -> None:
        from tex.nanozk.layerwise_prover import (
            NanozkBackendUnavailable,
            default_block_circuit,
        )

        backend = DeepProveSubprocessBackend(
            binary_path="/definitely/does/not/exist/deep-prove",
        )
        circuit = default_block_circuit(layer_index=0)
        with pytest.raises(NanozkBackendUnavailable):
            backend.prove(
                circuit=circuit,
                input_hash="a" * 64,
                output_hash="b" * 64,
                weights_commitment="c" * 64,
            )

    def test_verify_returns_false_when_binary_missing(self) -> None:
        from tex.nanozk.layerwise_prover import default_block_circuit

        backend = DeepProveSubprocessBackend(
            binary_path="/definitely/does/not/exist/deep-prove",
        )
        circuit = default_block_circuit(layer_index=0)
        result = backend.verify(
            circuit=circuit,
            proof_bytes=b"\x00" * 100,
            input_hash="a" * 64,
            output_hash="b" * 64,
            weights_commitment="c" * 64,
        )
        assert result is False

    def test_protocol_match(self) -> None:
        """Confirms the backend matches the NanozkBackend Protocol."""
        from tex.nanozk.layerwise_prover import NanozkBackend

        backend = DeepProveSubprocessBackend(
            binary_path="/nonexistent",
        )
        # Runtime-checkable Protocol — structural match.
        assert isinstance(backend, NanozkBackend)


class TestAvailabilitySerialization:
    def test_availability_can_be_serialised(self) -> None:
        avail = DeepProveAvailability(
            binary_present=False,
            probe_errors=("not found",),
        )
        # Pydantic frozen model — serialise round-trip.
        data = avail.model_dump_json()
        parsed = DeepProveAvailability.model_validate_json(data)
        assert parsed == avail
