"""
M0c confidential-VM / TDX mode probe — fail-closed truth table + mode honesty.

Pins that must FAIL if behavior breaks:
  * each absent piece (ITA SDK, quote device) independently forces
    ``available=False`` and is named in ``missing``;
  * the in-tree oracle ``is_tdx_capable`` is conjoined fail-closed — a
    drifted mirror can under-report but never over-report, and the mirrored
    literals are pinned against the oracle's own source;
  * ``TEX_TEE_ATTESTATION_MODE`` is reported, never consulted: no mode value
    moves ``available``/``tier``/``missing``, and ``production`` on a host
    with no hardware still reports honestly absent;
  * the probe never raises and is deterministic.
"""

from __future__ import annotations

import inspect

import pytest

import tex.tee._mode_probe as _mp
from tex.pqcrypto._backend_probe import TIER_NONE, ProbeResult
from tex.tee import tdx_attestation
from tex.tee._mode_probe import probe_attestation_mode

_MODE_ENV = "TEX_TEE_ATTESTATION_MODE"


def _patch_pieces(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sdk_ok: bool,
    device_ok: bool,
    oracle_ok: bool,
) -> None:
    monkeypatch.setattr(_mp, "_ita_sdk_import_ok", lambda: sdk_ok)
    monkeypatch.setattr(_mp, "_tdx_quote_device_present", lambda: device_ok)
    monkeypatch.setattr(tdx_attestation, "is_tdx_capable", lambda: oracle_ok)


# ── fail-closed truth table ──────────────────────────────────────────────────


@pytest.mark.parametrize("sdk_ok", [True, False])
@pytest.mark.parametrize("device_ok", [True, False])
@pytest.mark.parametrize("oracle_ok", [True, False])
def test_truth_table_every_absent_piece_forces_unavailable(
    monkeypatch: pytest.MonkeyPatch, sdk_ok: bool, device_ok: bool, oracle_ok: bool
) -> None:
    _patch_pieces(monkeypatch, sdk_ok=sdk_ok, device_ok=device_ok, oracle_ok=oracle_ok)
    result = probe_attestation_mode()

    expected_missing = set()
    if not sdk_ok:
        expected_missing.add("ita_sdk_import")
    if not device_ok:
        expected_missing.add("tdx_quote_device")
    if sdk_ok and device_ok and not oracle_ok:
        expected_missing.add("tdx_capability_oracle")

    assert set(result.missing) == expected_missing
    assert result.available is (sdk_ok and device_ok and oracle_ok)
    assert result.tier == ("tdx-present" if result.available else TIER_NONE)


def test_oracle_alone_cannot_make_the_probe_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Even an oracle screaming "capable" cannot override absent components —
    # the conjunction is one-directional (closed).
    _patch_pieces(monkeypatch, sdk_ok=False, device_ok=False, oracle_ok=True)
    result = probe_attestation_mode()
    assert result.available is False
    assert {"ita_sdk_import", "tdx_quote_device"} == set(result.missing)


def test_oracle_divergence_is_itself_a_named_missing_piece(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_pieces(monkeypatch, sdk_ok=True, device_ok=True, oracle_ok=False)
    result = probe_attestation_mode()
    assert result.available is False
    assert result.missing == ("tdx_capability_oracle",)


# ── the mode env var: reported, never consulted ──────────────────────────────


@pytest.mark.parametrize("mode", ["test", "production", None])
def test_mode_is_reported_raw_and_changes_no_availability(
    monkeypatch: pytest.MonkeyPatch, mode: str | None
) -> None:
    if mode is None:
        monkeypatch.delenv(_MODE_ENV, raising=False)
    else:
        monkeypatch.setenv(_MODE_ENV, mode)
    result = probe_attestation_mode()
    assert result.detail["attestation_mode"] == (mode or "<unset>")
    # No hardware on this box: every mode value reports the same honest absence.
    assert result.available is False
    assert result.tier == TIER_NONE


def test_production_mode_cannot_conjure_hardware(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_MODE_ENV, "production")
    no_env = probe_attestation_mode()
    monkeypatch.delenv(_MODE_ENV)
    baseline = probe_attestation_mode()
    assert no_env.available is baseline.available is False
    assert no_env.missing == baseline.missing
    assert no_env.tier == baseline.tier


def test_mode_is_orthogonal_to_a_genuinely_capable_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_pieces(monkeypatch, sdk_ok=True, device_ok=True, oracle_ok=True)
    for mode in ("test", "production"):
        monkeypatch.setenv(_MODE_ENV, mode)
        result = probe_attestation_mode()
        assert result.available is True
        assert result.detail["attestation_mode"] == mode


# ── mirror-drift pin against the oracle's own source ─────────────────────────


def test_quote_device_paths_match_oracle_source() -> None:
    # The probe mirrors is_tdx_capable's literals to NAME missing pieces; this
    # pin fails if the oracle's paths or SDK module move without the mirror.
    source = inspect.getsource(tdx_attestation.is_tdx_capable)
    for path in _mp._TDX_QUOTE_DEVICE_PATHS:
        assert path in source
    assert _mp._ITA_SDK_MODULE in source


# ── never raises, live smoke, determinism ────────────────────────────────────


def test_probe_never_raises_on_exploding_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom() -> bool:
        raise OSError("sysfs went away")

    monkeypatch.setattr(_mp, "_ita_sdk_import_ok", _boom)
    monkeypatch.setattr(_mp, "_tdx_quote_device_present", _boom)
    monkeypatch.setattr(tdx_attestation, "is_tdx_capable", _boom)
    result = probe_attestation_mode()
    assert isinstance(result, ProbeResult)
    assert result.available is False
    assert {"ita_sdk_import", "tdx_quote_device"} <= set(result.missing)


def test_probe_internal_bug_degrades_to_named_internal_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _impl_bug() -> ProbeResult:
        raise ValueError("probe impl bug")

    monkeypatch.setattr(_mp, "_probe_attestation_mode_impl", _impl_bug)
    result = probe_attestation_mode()
    assert result.available is False
    assert result.missing == ("probe_internal_error:attestation_mode",)


def test_live_smoke_this_box_reports_honestly_and_matches_oracle() -> None:
    result = probe_attestation_mode()
    assert result.available is tdx_attestation.is_tdx_capable() is False
    assert "ita_sdk_import" in result.missing  # no ITA SDK on this box
    assert result.detail["attestation_mode_env_var"] == _MODE_ENV


def test_probe_is_deterministic_in_a_fixed_environment() -> None:
    assert probe_attestation_mode() == probe_attestation_mode()
