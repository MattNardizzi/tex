"""
Regression guard for the NanoZK DEACTIVATION.

NanoZK is a deactivated placeholder: ``verify_layer_proof_set`` is
hard-gated and must fail-closed unless ``TEX_NANOZK_ALLOW_SHIM=1`` is set
explicitly. This file asserts the *default-off* behaviour and would FAIL
if anyone removed the gate, flipped its default, or otherwise re-activated
the HMAC stand-in so that it could be trusted as a real proof.

It is the deliberate counterpart to ``conftest.py`` (which opts the
*scaffold* tests into the shim): here we delete the flag to assert the
production posture.
"""

from __future__ import annotations

import hashlib

import pytest

from tex.nanozk import LayerProofSet, prove_layer_set, verify_layer_proof_set

_DEACTIVATED_REASON = "nanozk_deactivated_placeholder_not_a_real_proof"


def _hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _one_layer_set() -> tuple[LayerProofSet, dict[int, str], dict[int, str], dict[int, str]]:
    """A well-formed single-layer set (so any rejection is the gate, not the set)."""
    per_in = {0: _hex(b"in")}
    per_out = {0: _hex(b"out")}
    per_w = {0: _hex(b"w")}
    ps = prove_layer_set(
        selected_indices=(0,),
        per_layer_inputs=per_in,
        per_layer_outputs=per_out,
        per_layer_weights_commitments=per_w,
        total_layers=1,
        fisher_captured_information=0.5,
    )
    return ps, per_in, per_out, per_w


def test_verify_set_fails_closed_when_deactivated(monkeypatch: pytest.MonkeyPatch) -> None:
    # Production posture: the shim opt-in is NOT set (overrides the conftest autouse).
    monkeypatch.delenv("TEX_NANOZK_ALLOW_SHIM", raising=False)
    ps, per_in, per_out, per_w = _one_layer_set()
    result = verify_layer_proof_set(
        ps,
        expected_per_layer_inputs=per_in,
        expected_per_layer_outputs=per_out,
        expected_per_layer_weights=per_w,
    )
    assert result.is_valid is False
    assert result.reason == _DEACTIVATED_REASON


def test_same_set_verifies_only_when_shim_explicitly_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Sanity: with the shim explicitly enabled, the SAME set verifies — proving
    # the False above is the deactivation gate, not a malformed set.
    monkeypatch.setenv("TEX_NANOZK_ALLOW_SHIM", "1")
    ps, per_in, per_out, per_w = _one_layer_set()
    result = verify_layer_proof_set(
        ps,
        expected_per_layer_inputs=per_in,
        expected_per_layer_outputs=per_out,
        expected_per_layer_weights=per_w,
    )
    assert result.is_valid is True
    assert result.reason != _DEACTIVATED_REASON
