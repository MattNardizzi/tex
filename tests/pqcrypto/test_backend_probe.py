"""
M0c backend probes — fail-closed truth tables, delegation pins, probe ≠ trust.

Every test here is written to FAIL if the behavior it pins breaks:
  * truth tables: each absent piece independently forces ``available=False``
    and is NAMED in ``missing``; all-present flips available.
  * delegation: the ML-DSA tier is pq_durability.probe_backend() verbatim — a
    divergence breaks the pin.
  * the nanozk trap: a present OpenSSL ML-DSA CLI never raises the tier.
  * probe ≠ trust: monkeypatching every probe to available=True leaves a full
    PDP evaluation byte-identical, and no env flag flips a probe to available.
  * never-raises: broken imports, garbage paths, and exploding checks still
    return a coherent ProbeResult.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

import tex.pqcrypto._backend_probe as _bp
import tex.tee._mode_probe as _mp
from tex.pqcrypto import ml_dsa, pq_durability
from tex.pqcrypto._backend_probe import (
    TIER_NONE,
    ProbeResult,
    probe_ezkl_halo2,
    probe_ml_dsa_backend,
    probe_torch_nli,
)
from tests.factories import make_request

# Env flags that exist elsewhere in the codebase and must NEVER flip a probe.
_FOREIGN_ENV_FLAGS = (
    "TEX_NANOZK_ALLOW_SHIM",
    "TEX_ZKPDP_ALLOW_SHIM",
    "TEX_FRONTIER_NANOZK",
    "TEX_SEAL_DECISIONS",
)


# ── ProbeResult coherence ────────────────────────────────────────────────────


def test_proberesult_rejects_available_with_missing_pieces() -> None:
    with pytest.raises(ValueError):
        ProbeResult(available=True, tier="x", missing=("gap",), detail={})
    with pytest.raises(ValueError):
        ProbeResult(available=True, tier=TIER_NONE, missing=(), detail={})


def test_proberesult_rejects_unavailable_without_named_missing() -> None:
    with pytest.raises(ValueError):
        ProbeResult(available=False, tier=TIER_NONE, missing=(), detail={})
    with pytest.raises(ValueError):
        ProbeResult(available=False, tier="x", missing=("gap",), detail={})


# ── ezkl/Halo2 (L1): fail-closed truth table via injection ──────────────────


def _patch_ezkl_pieces(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    ezkl_ok: bool,
    artifact_ok: bool,
    srs_ok: bool,
) -> None:
    monkeypatch.setattr(_bp, "_ezkl_import_ok", lambda: ezkl_ok)
    if artifact_ok:
        artifact = tmp_path / "zkprov_v1.onnx"
        artifact.write_bytes(b"onnx-bytes")
    else:
        artifact = tmp_path / "absent" / "zkprov_v1.onnx"
    monkeypatch.setattr(_bp, "_zkprov_circuit_path", lambda: artifact)
    monkeypatch.setattr(_bp, "_kzg_srs_present", lambda: srs_ok)


@pytest.mark.parametrize("ezkl_ok", [True, False])
@pytest.mark.parametrize("artifact_ok", [True, False])
@pytest.mark.parametrize("srs_ok", [True, False])
def test_ezkl_truth_table_every_absent_piece_forces_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    ezkl_ok: bool,
    artifact_ok: bool,
    srs_ok: bool,
) -> None:
    _patch_ezkl_pieces(
        monkeypatch, tmp_path, ezkl_ok=ezkl_ok, artifact_ok=artifact_ok, srs_ok=srs_ok
    )
    result = probe_ezkl_halo2()

    expected_missing = set()
    if not ezkl_ok:
        expected_missing.add("ezkl_import")
    if not artifact_ok:
        expected_missing.add("zkprov_circuit_artifact")
    if not srs_ok:
        expected_missing.add("kzg_srs")

    assert set(result.missing) == expected_missing
    assert result.available is (ezkl_ok and artifact_ok and srs_ok)
    assert result.tier == ("pieces-present" if result.available else TIER_NONE)


def test_ezkl_empty_artifact_file_counts_as_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    empty = tmp_path / "zkprov_v1.onnx"
    empty.write_bytes(b"")
    monkeypatch.setattr(_bp, "_ezkl_import_ok", lambda: True)
    monkeypatch.setattr(_bp, "_zkprov_circuit_path", lambda: empty)
    monkeypatch.setattr(_bp, "_kzg_srs_present", lambda: True)
    result = probe_ezkl_halo2()
    assert result.available is False
    assert "zkprov_circuit_artifact" in result.missing


def test_ezkl_srs_env_var_redirects_lookup_but_cannot_fabricate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # EZKL_REPO_PATH pointing at a dir with no SRS yields "missing" — the env
    # var moves WHERE we look, it cannot assert availability...
    monkeypatch.setenv("EZKL_REPO_PATH", str(tmp_path))
    assert _bp._kzg_srs_present() is False
    (tmp_path / "srs").mkdir()
    (tmp_path / "srs" / "kzg14.srs").write_bytes(b"")  # empty file ≠ present
    assert _bp._kzg_srs_present() is False
    # ...and only a real, non-empty kzg*.srs file flips the check.
    (tmp_path / "srs" / "kzg14.srs").write_bytes(b"srs-bytes")
    assert _bp._kzg_srs_present() is True


def test_ezkl_probe_never_raises_on_exploding_or_garbage_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom() -> bool:
        raise RuntimeError("broken import machinery")

    monkeypatch.setattr(_bp, "_ezkl_import_ok", _boom)
    monkeypatch.setattr(_bp, "_zkprov_circuit_path", lambda: 12345)  # garbage
    monkeypatch.setattr(_bp, "_kzg_srs_present", _boom)
    result = probe_ezkl_halo2()
    assert isinstance(result, ProbeResult)
    assert result.available is False
    assert {"ezkl_import", "zkprov_circuit_artifact", "kzg_srs"} <= set(result.missing)


def test_ezkl_probe_internal_bug_degrades_to_named_internal_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _impl_bug() -> ProbeResult:
        raise ValueError("probe impl bug")

    monkeypatch.setattr(_bp, "_probe_ezkl_halo2_impl", _impl_bug)
    result = probe_ezkl_halo2()
    assert result.available is False
    assert result.missing == ("probe_internal_error:ezkl_halo2",)


def test_ezkl_probe_ignores_zkpdp_shim_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    baseline = probe_ezkl_halo2()
    monkeypatch.setenv("TEX_ZKPDP_ALLOW_SHIM", "1")
    assert probe_ezkl_halo2() == baseline


# ── ML-DSA (L10): delegation, never duplication ──────────────────────────────


@pytest.mark.parametrize(
    ("backend_id", "expected_tier", "expected_available"),
    [
        ("pyca-cryptography-native", "durable", True),
        ("liboqs", "research_only", True),
        ("some-future-unreviewed-backend", "none", False),
        ("", "none", False),
        (None, "none", False),
    ],
)
def test_ml_dsa_probe_tier_is_pq_durability_verbatim(
    monkeypatch: pytest.MonkeyPatch,
    backend_id: str | None,
    expected_tier: str,
    expected_available: bool,
) -> None:
    monkeypatch.setattr(ml_dsa, "active_backend_id", lambda: backend_id)
    result = probe_ml_dsa_backend()
    # The delegation pin: tier must equal the L10 oracle's answer exactly.
    assert result.tier == pq_durability.probe_backend().value == expected_tier
    assert result.available is expected_available
    assert result.detail["signer_maturity"] == expected_tier
    assert result.detail["ml_dsa_backend_id"] == (backend_id or "<none>")
    if not expected_available:
        assert result.missing == ("ml_dsa_live_backend",)


def test_ml_dsa_live_divergence_pin_matches_probe_backend_exactly() -> None:
    # Live, unpatched: any drift between this probe and the L10 oracle fails here.
    result = probe_ml_dsa_backend()
    assert result.tier == pq_durability.probe_backend().value
    assert result.available is (
        pq_durability.probe_backend() is not pq_durability.SignerDurability.NONE
    )


def test_ml_dsa_cli_shim_present_never_raises_tier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # THE nanozk trap, probed-edition: a reachable OpenSSL ML-DSA CLI is
    # reported as a separate fact and must not move the tier off "none".
    monkeypatch.setattr(ml_dsa, "active_backend_id", lambda: None)
    monkeypatch.setattr(
        pq_durability, "find_openssl_mldsa", lambda: "/fake/openssl-3.5"
    )
    result = probe_ml_dsa_backend()
    assert result.detail["openssl_mldsa_cli_present"] == "true"
    assert result.tier == "none"
    assert result.available is False


def test_ml_dsa_cli_shim_absent_never_lowers_a_durable_tier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ml_dsa, "active_backend_id", lambda: "pyca-cryptography-native")
    monkeypatch.setattr(pq_durability, "find_openssl_mldsa", lambda: None)
    result = probe_ml_dsa_backend()
    assert result.detail["openssl_mldsa_cli_present"] == "false"
    assert result.tier == "durable"
    assert result.available is True


def test_ml_dsa_probe_never_raises_when_oracle_explodes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom() -> pq_durability.SignerDurability:
        raise RuntimeError("oracle exploded")

    monkeypatch.setattr(pq_durability, "probe_backend", _boom)
    result = probe_ml_dsa_backend()
    assert result.available is False
    assert result.missing == ("probe_internal_error:ml_dsa_backend",)


# ── torch+NLI+GPU (L11): verified load required, imports are not enough ─────


def _patch_nli_pieces(
    monkeypatch: pytest.MonkeyPatch,
    *,
    transformers_ok: bool,
    torch_ok: bool,
    model_ok: bool,
    device: str | None,
) -> None:
    monkeypatch.setattr(_bp, "_transformers_import_ok", lambda: transformers_ok)
    monkeypatch.setattr(_bp, "_torch_import_ok", lambda: torch_ok)
    monkeypatch.setattr(_bp, "_nli_model_verified", lambda: model_ok)
    monkeypatch.setattr(_bp, "_gpu_device", lambda: device)


@pytest.mark.parametrize("transformers_ok", [True, False])
@pytest.mark.parametrize("torch_ok", [True, False])
@pytest.mark.parametrize("model_ok", [True, False])
@pytest.mark.parametrize("device", ["cuda", None])
def test_nli_truth_table_every_absent_piece_forces_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    transformers_ok: bool,
    torch_ok: bool,
    model_ok: bool,
    device: str | None,
) -> None:
    _patch_nli_pieces(
        monkeypatch,
        transformers_ok=transformers_ok,
        torch_ok=torch_ok,
        model_ok=model_ok,
        device=device,
    )
    result = probe_torch_nli()

    expected_missing = set()
    if not transformers_ok:
        expected_missing.add("transformers_import")
    if not torch_ok:
        expected_missing.add("torch_import")
    if not model_ok:
        expected_missing.add("nli_model_verified")
    if device is None:
        expected_missing.add("gpu_device")

    assert set(result.missing) == expected_missing
    assert result.available is (
        transformers_ok and torch_ok and model_ok and device is not None
    )
    assert result.tier == ("verified-load" if result.available else TIER_NONE)


def test_nli_imports_and_gpu_without_verified_load_stay_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The seam's discipline (NeuralNLIScorer.load): import success is NOT
    # availability — only a verified model load is.
    _patch_nli_pieces(
        monkeypatch, transformers_ok=True, torch_ok=True, model_ok=False, device="cuda"
    )
    result = probe_torch_nli()
    assert result.available is False
    assert result.missing == ("nli_model_verified",)
    assert result.detail["transformers_import_ok"] == "true"


def test_nli_probe_never_raises_on_exploding_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom() -> bool:
        raise ImportError("torn-up site-packages")

    for helper in (
        "_transformers_import_ok",
        "_torch_import_ok",
        "_nli_model_verified",
    ):
        monkeypatch.setattr(_bp, helper, _boom)
    monkeypatch.setattr(_bp, "_gpu_device", _boom)
    result = probe_torch_nli()
    assert isinstance(result, ProbeResult)
    assert result.available is False
    assert {
        "transformers_import",
        "torch_import",
        "nli_model_verified",
        "gpu_device",
    } <= set(result.missing)


def test_nli_probe_does_not_enable_the_neural_path() -> None:
    # Running the probe must leave the voice seam exactly as the pinned test
    # test_neural_scorer_is_off_and_honest expects: off and honest.
    from tex.voice.voice_gate import NeuralNLIScorer

    probe_torch_nli()
    scorer = NeuralNLIScorer()
    assert scorer.load() is False
    assert scorer.entails("premise", "hypothesis") is None


# ── live-env smoke: this box reports honestly, no patching ───────────────────


def test_live_smoke_ezkl_reports_this_box_honestly() -> None:
    result = probe_ezkl_halo2()
    # Self-consistent against the real environment rather than hardcoded:
    try:
        import ezkl  # type: ignore[import-not-found]  # noqa: F401

        ezkl_installed = True
    except Exception:  # noqa: BLE001
        ezkl_installed = False
    assert result.detail["ezkl_import_ok"] == str(ezkl_installed).lower()
    # The circuit artifact is out-of-tree by contract, so this box can never
    # report the full backend available.
    assert result.available is False
    assert "zkprov_circuit_artifact" in result.missing


def test_live_smoke_ml_dsa_matches_oracle_and_reports_cli_separately() -> None:
    result = probe_ml_dsa_backend()
    assert result.tier == pq_durability.probe_backend().value
    assert result.detail["openssl_mldsa_cli_present"] == str(
        pq_durability.openssl_mldsa_available()
    ).lower()


def test_live_smoke_nli_unavailable_without_verified_model_load() -> None:
    result = probe_torch_nli()
    # NeuralNLIScorer.load() refuses availability without a verified model
    # load (today: unconditionally False), so this holds even if transformers/
    # torch/GPU appear on the box.
    assert result.available is False
    assert "nli_model_verified" in result.missing


# ── determinism ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "probe", [probe_ezkl_halo2, probe_ml_dsa_backend, probe_torch_nli]
)
def test_probe_is_deterministic_in_a_fixed_environment(probe) -> None:
    assert probe() == probe()


# ── probe ≠ trust: the verdict path is blind to probe results ────────────────


_AVAILABLE_RESULTS = {
    "probe_ezkl_halo2": ProbeResult(
        available=True, tier="pieces-present", missing=(), detail={}
    ),
    "probe_ml_dsa_backend": ProbeResult(
        available=True, tier="durable", missing=(), detail={}
    ),
    "probe_torch_nli": ProbeResult(
        available=True, tier="verified-load", missing=(), detail={}
    ),
    "probe_attestation_mode": ProbeResult(
        available=True, tier="tdx-present", missing=(), detail={}
    ),
}


# Fields that two back-to-back UNPATCHED runs of the identical request already
# differ on (verified in-session): the per-run decision UUID, wall-clock
# timestamps/latency, and evidence_hash (the chain hash binds the per-run
# decision id — its variance is the hash chain working, not a verdict change).
# Everything behavioral — verdict, confidence, final_score,
# determinism_fingerprint, reasons, findings, scores, uncertainty_flags,
# asi_findings, policy_version — stays in the byte-for-byte comparison.
_PER_RUN_VOLATILE_KEYS = frozenset({"decision_id", "evidence_hash", "latency"})


def _scrub(node):
    """Drop per-run identifiers/timestamps; keep every behavioral field."""
    if isinstance(node, dict):
        return {
            key: _scrub(value)
            for key, value in sorted(node.items())
            if key not in _PER_RUN_VOLATILE_KEYS and not key.endswith("_at")
        }
    if isinstance(node, list):
        return [_scrub(value) for value in node]
    return node


def _verdict_projection(result) -> str:
    return json.dumps(_scrub(result.response.model_dump(mode="json")), sort_keys=True)


def _fixed_request():
    return make_request(
        request_id=UUID("00000000-0000-4000-8000-0000000000c1"),
        requested_at=datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC),
    )


def test_probes_reporting_available_change_no_verdict_and_no_gate(
    runtime, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Control: the projection itself is deterministic across runs.
    before_a = _verdict_projection(
        runtime.evaluate_action_command.execute(_fixed_request())
    )
    before_b = _verdict_projection(
        runtime.evaluate_action_command.execute(_fixed_request())
    )
    assert before_a == before_b

    # Force every M0c probe to scream "available" — and prove the PDP is deaf.
    monkeypatch.setattr(
        _bp, "probe_ezkl_halo2", lambda: _AVAILABLE_RESULTS["probe_ezkl_halo2"]
    )
    monkeypatch.setattr(
        _bp,
        "probe_ml_dsa_backend",
        lambda: _AVAILABLE_RESULTS["probe_ml_dsa_backend"],
    )
    monkeypatch.setattr(
        _bp, "probe_torch_nli", lambda: _AVAILABLE_RESULTS["probe_torch_nli"]
    )
    monkeypatch.setattr(
        _mp,
        "probe_attestation_mode",
        lambda: _AVAILABLE_RESULTS["probe_attestation_mode"],
    )
    for flag in _FOREIGN_ENV_FLAGS:
        monkeypatch.setenv(flag, "1")

    after = _verdict_projection(
        runtime.evaluate_action_command.execute(_fixed_request())
    )
    assert after == before_a  # byte-identical: no verdict, gate, score, or flag moved


def test_no_live_module_consumes_the_probes() -> None:
    # The monkeypatch-based PDP pin above catches attr-lookup consumers; this
    # source scan is the stronger structural pin: NO module under src/tex
    # references the probe modules at all (so even an import-time `from ...
    # import probe_x` binding cannot exist). Consumption is each leap's own
    # future opt-in — when a leap wires a probe, it must extend this allowlist
    # consciously.
    import tex

    src_root = Path(tex.__file__).resolve().parent
    offenders = sorted(
        str(py.relative_to(src_root))
        for py in src_root.rglob("*.py")
        if "_backend_probe" in py.read_text(encoding="utf-8", errors="ignore")
        or "_mode_probe" in py.read_text(encoding="utf-8", errors="ignore")
    )
    # Only the probe modules themselves (and _mode_probe's import of the
    # shared ProbeResult) may mention these names.
    assert offenders == ["pqcrypto/_backend_probe.py", "tee/_mode_probe.py"]


@pytest.mark.parametrize(
    "probe", [probe_ezkl_halo2, probe_ml_dsa_backend, probe_torch_nli]
)
def test_no_foreign_env_flag_flips_a_probe_to_available(
    monkeypatch: pytest.MonkeyPatch, probe
) -> None:
    baseline = probe()
    for flag in _FOREIGN_ENV_FLAGS:
        monkeypatch.setenv(flag, "1")
    assert probe() == baseline
    assert probe().available is False  # nothing on this box is actually present
