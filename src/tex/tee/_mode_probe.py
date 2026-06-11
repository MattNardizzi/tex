"""
Confidential-VM / TDX mode probe — Wave 2 **M0c** (``track/wave2-probes``).

The narrow claim this module earns (and nothing more)
----------------------------------------------------
One deterministic, never-raising probe that REPORTS (1) which attestation mode
the verifier is configured for (``TEX_TEE_ATTESTATION_MODE``) and (2) whether
REAL Intel TDX quote capability is present on this host. It is the L2 entry of
the M0c probe set; the L1/L10/L11 probes and the shared :class:`ProbeResult`
shape live in ``tex.pqcrypto._backend_probe`` (tee→pqcrypto imports are the
established direction — see ``attestation_client._verify_signature``).

THE ONE RULE (inherited verbatim from ``_backend_probe``)
---------------------------------------------------------
Probes report availability; they never flip behavior, and probe success is not
trust. Specifically here:

  * The mode env var is **reported, never consulted for availability**. Its
    semantics belong to ``attestation_client.verify_attestation`` (production
    rejects unsigned test tokens with reason ``test_mode_in_prod``); the env
    var selects which *verifier rules* apply and can never make this probe
    claim hardware exists. Setting it to ``production`` on a laptop changes
    one ``detail`` string and nothing else.
  * The verifier-only posture of ``tex/tee`` is unchanged: this probe collects
    no evidence, builds no token, and has no consumer on any verdict path.

Fail-closed capability check — oracle conjunction
-------------------------------------------------
``tex.tee.tdx_attestation.is_tdx_capable`` is the in-tree oracle (ITA SDK
importable AND a quote device/evidence path present). To give granular
``missing`` names without forking the truth, this probe mirrors the oracle's
two components *and conjoins the oracle itself*: ``available`` requires the
mirrored components AND ``is_tdx_capable()`` to all pass, so a drifted mirror
can only ever under-report, never over-report. A source-inspection test pins
the mirrored device paths against the oracle's own literals.

Maturity: ``research-solid`` — presence checks over a verified in-tree oracle;
no consumer exists yet.
"""

from __future__ import annotations

import importlib
import os

from tex.pqcrypto._backend_probe import (
    TIER_NONE,
    ProbeResult,
    _guarded,
    _safe_bool,
)
from tex.tee import tdx_attestation
from tex.tee.attestation_client import _ENV_MODE as _ATTESTATION_MODE_ENV

# Mirrors of is_tdx_capable's internals (tdx_attestation.py) — used ONLY to
# name which piece is absent; availability additionally requires the oracle
# itself (conjunction), so a drift here cannot over-report. The test
# test_quote_device_paths_match_oracle_source pins these literals.
_ITA_SDK_MODULE = "inteltrustauthorityclient.tdx.intel"
_TDX_QUOTE_DEVICE_PATHS: tuple[str, ...] = (
    "/sys/kernel/config/tsm/report",
    "/dev/tdx_guest",
)


def _ita_sdk_import_ok() -> bool:
    try:
        importlib.import_module(_ITA_SDK_MODULE)
    except Exception:  # noqa: BLE001 — absent OR broken SDK both mean "no"
        return False
    return True


def _tdx_quote_device_present() -> bool:
    return any(os.path.exists(p) for p in _TDX_QUOTE_DEVICE_PATHS)


def _attestation_mode() -> str:
    """The raw configured verifier mode — a report, never an availability input."""
    return os.environ.get(_ATTESTATION_MODE_ENV) or "<unset>"


def _probe_attestation_mode_impl() -> ProbeResult:
    missing: list[str] = []

    sdk_ok = _safe_bool(_ita_sdk_import_ok)
    if not sdk_ok:
        missing.append("ita_sdk_import")

    device_ok = _safe_bool(_tdx_quote_device_present)
    if not device_ok:
        missing.append("tdx_quote_device")

    # The in-tree oracle, conjoined fail-closed: we can never report available
    # when it says no. If our mirrored components pass but the oracle refuses,
    # the divergence itself is the named missing piece.
    oracle_ok = _safe_bool(tdx_attestation.is_tdx_capable)
    if sdk_ok and device_ok and not oracle_ok:
        missing.append("tdx_capability_oracle")

    available = sdk_ok and device_ok and oracle_ok
    return ProbeResult(
        available=available,
        tier="tdx-present" if available else TIER_NONE,
        missing=tuple(missing),
        detail={
            "attestation_mode": _attestation_mode(),
            "attestation_mode_env_var": _ATTESTATION_MODE_ENV,
            "ita_sdk_import_ok": str(sdk_ok).lower(),
            "tdx_quote_device_present": str(device_ok).lower(),
            "tdx_quote_device_paths": ", ".join(_TDX_QUOTE_DEVICE_PATHS),
        },
    )


def probe_attestation_mode() -> ProbeResult:
    """Probe confidential-VM (Intel TDX) capability + report the verifier mode.

    ``available=True`` proves exactly: the Intel Trust Authority SDK imports, a
    TDX quote device/evidence path exists on this host, AND the in-tree oracle
    ``tdx_attestation.is_tdx_capable()`` agrees. It does **not** prove a TD
    Quote verifies, that measurements match any expected values, or that any
    decision is TEE-bound — verification semantics stay entirely in
    ``attestation_client.verify_attestation``, and consumption is L2's own
    opt-in.

    ``detail["attestation_mode"]`` reports ``TEX_TEE_ATTESTATION_MODE`` raw
    (``<unset>`` when absent). The mode is configuration *about the verifier*,
    not evidence about hardware: no mode value affects ``available``, ``tier``,
    or ``missing``, and ``mode=production`` with no hardware still reports
    ``available=False`` with the absent pieces named.
    """
    return _guarded("attestation_mode", _probe_attestation_mode_impl)


__all__ = ["probe_attestation_mode"]
