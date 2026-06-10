"""
Shared fixtures for the NanoZK scaffold tests.

NanoZK is a DEACTIVATED placeholder (see the ``src/tex/nanozk`` module
banner): ``verify_layer_proof_set`` is hard-gated and returns
``is_valid=False`` unless ``TEX_NANOZK_ALLOW_SHIM=1`` is set. These tests
exercise the *structural scaffold*, so they opt into the shim explicitly
and unmistakably. The default-OFF (deactivated, fail-closed) behaviour —
the thing that protects production — is asserted separately in
``test_deactivated.py``, which deletes the flag.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _enable_nanozk_shim(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEX_NANOZK_ALLOW_SHIM", "1")
