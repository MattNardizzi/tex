"""
Fail-closed RUNTIME-DEPENDENT backend probes — Wave 2 **M0c** (``track/wave2-probes``).

The narrow claim this module earns (and nothing more)
----------------------------------------------------
Three deterministic, never-raising probes that REPORT whether an opt-in real
backend is present on this host: ezkl/Halo2 (L1), a real ML-DSA signer backend
(L10), and torch+NLI+GPU (L11). The confidential-VM probe (L2) lives in
``tex.tee._mode_probe`` and shares this module's :class:`ProbeResult` shape.

THE ONE RULE (the nanozk lesson, generalized)
---------------------------------------------
**Probes report availability; they never flip behavior, and probe success is
not trust.**

  * No probe here has ANY consumer on the verdict path. Wiring a probe into a
    leap is that leap's own future opt-in change — this module stays a
    standalone reporter. A regression test pins that monkeypatching every probe
    to ``available=True`` leaves a PDP evaluation byte-identical.
  * Every probe is **closed-world and fail-closed**: only an explicitly
    verified presence counts; anything unrecognized, absent, or *raising*
    resolves to ``available=False`` with the failed piece named in
    ``missing``. No environment variable can make a probe report an
    availability that was not actually verified (env vars may at most redirect
    *where* a check looks, e.g. ezkl's own ``EZKL_REPO_PATH``; the file must
    still really exist).
  * ``available=True`` means *presence*, never *production trust*. The in-tree
    precedent is L10's pinned trap: the OpenSSL ML-DSA CLI being present does
    NOT raise signer maturity (``test_cli_shim_does_not_raise_live_maturity``).
    Each probe's docstring states exactly what its ``available=True`` proves
    and what it does not.

Delegation, not duplication
---------------------------
Where an in-tree fail-closed oracle already exists, the probe delegates to it
instead of re-deriving availability (two copies = two sources of truth that
drift): the ML-DSA probe wraps :func:`tex.pqcrypto.pq_durability.probe_backend`
verbatim, and the NLI probe's "verified model load" fact is
:meth:`tex.voice.voice_gate.NeuralNLIScorer.load` — the seam that refuses to
claim availability without a verified load.

Maturity: ``research-solid`` — pure presence checks over verified in-tree
oracles, fully exercised by injection truth-tables; no consumer exists yet.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from tex.pqcrypto import ml_dsa, pq_durability
from tex.pqcrypto.pq_durability import SignerDurability

# The single fail-closed floor every probe resolves to on anything unverified.
TIER_NONE = "none"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """One probe's honest report. Deterministic, no network, never raised past.

    Coherence is enforced at construction so a probe cannot emit a lying shape:
    ``available=True`` requires an above-floor ``tier`` and an empty ``missing``;
    ``available=False`` requires the floor tier and at least one *named* missing
    piece. ``tier`` is an informational per-probe ladder (each probe documents
    its own); ``available`` is the only availability bit a reader may consume,
    and even that bit asserts presence — **never** production trust.
    """

    available: bool
    tier: str
    missing: tuple[str, ...]
    detail: dict[str, str]

    def __post_init__(self) -> None:
        if self.available and (self.tier == TIER_NONE or self.missing):
            raise ValueError(
                "incoherent ProbeResult: available=True requires tier above "
                f"'{TIER_NONE}' and an empty missing list, got tier={self.tier!r} "
                f"missing={self.missing!r}"
            )
        if not self.available and (self.tier != TIER_NONE or not self.missing):
            raise ValueError(
                "incoherent ProbeResult: available=False requires tier "
                f"'{TIER_NONE}' and at least one named missing piece, got "
                f"tier={self.tier!r} missing={self.missing!r}"
            )


def _safe_bool(check: Callable[[], object]) -> bool:
    """Run a presence check; ANY failure — including an exception — is False.

    This is the closed-world rule in one place: a check that cannot positively
    verify presence reports absence. It never raises.
    """
    try:
        return bool(check())
    except Exception:  # noqa: BLE001 — every failure mode is "not verified"
        return False


def _guarded(probe_name: str, impl: Callable[[], ProbeResult]) -> ProbeResult:
    """Outer never-raise guard shared by every probe.

    A probe bug (including an incoherent :class:`ProbeResult` construction)
    degrades to the fully-failed result with a named internal error — it never
    propagates an exception to a caller and never degrades to a *lying* result.
    """
    try:
        result = impl()
        if not isinstance(result, ProbeResult):
            raise TypeError(f"probe impl returned {type(result).__name__}")
        return result
    except Exception:  # noqa: BLE001 — the probe contract is "never raises"
        return ProbeResult(
            available=False,
            tier=TIER_NONE,
            missing=(f"probe_internal_error:{probe_name}",),
            detail={"probe_internal_error": probe_name},
        )


# ─────────────────────────────────────────────────────────────────────────────
# 1. ezkl / Halo2 (L1) — KZG-only upstream, universal trusted-setup SRS
# ─────────────────────────────────────────────────────────────────────────────

# ezkl >= v23 is KZG-only (IPA removed upstream) and KZG needs a universal
# trusted-setup SRS — see the landed docstrings in tex/zkprov/backends.py
# (Halo2IpaBackend), which are the spec for what "real Halo2 proofs" require.
# The default SRS repo dir mirrors ezkl's own resolution (verified against
# zkonduit/ezkl src/execute.rs this session, 2026-06-11):
#   EZKL_REPO_PATH (default ~/.ezkl) / "srs" / "kzg{logrows}.srs".
# Honoring EZKL_REPO_PATH only redirects where we LOOK — a real, non-empty
# file must still exist, so the env var cannot fabricate availability.
_EZKL_SRS_GLOB = "kzg*.srs"


def _ezkl_import_ok() -> bool:
    try:
        import ezkl  # type: ignore[import-not-found]  # noqa: F401
    except Exception:  # noqa: BLE001 — absent OR broken install both mean "no"
        return False
    return True


def _zkprov_circuit_path() -> Path:
    """The circuit artifact path named by ``Halo2IpaBackend.prove``'s contract:
    ``tex/zkprov/circuits/zkprov_v1.onnx``, resolved against the live package."""
    import tex.zkprov as _zkprov

    return Path(_zkprov.__file__).resolve().parent / "circuits" / "zkprov_v1.onnx"


def _kzg_srs_dir() -> Path:
    repo = os.environ.get("EZKL_REPO_PATH") or str(Path.home() / ".ezkl")
    return Path(repo) / "srs"


def _kzg_srs_present() -> bool:
    srs_dir = _kzg_srs_dir()
    try:
        if not srs_dir.is_dir():
            return False
        return any(
            p.is_file() and p.stat().st_size > 0 for p in srs_dir.glob(_EZKL_SRS_GLOB)
        )
    except OSError:
        return False


def _probe_ezkl_halo2_impl() -> ProbeResult:
    missing: list[str] = []
    detail: dict[str, str] = {}

    ezkl_ok = _safe_bool(_ezkl_import_ok)
    detail["ezkl_import_ok"] = str(ezkl_ok).lower()
    if not ezkl_ok:
        missing.append("ezkl_import")

    try:
        artifact = _zkprov_circuit_path()
        artifact_ok = artifact.is_file() and artifact.stat().st_size > 0
        detail["zkprov_circuit_path"] = str(artifact)
    except Exception:  # noqa: BLE001 — unresolvable path is "absent"
        artifact_ok = False
        detail["zkprov_circuit_path"] = "<unresolvable>"
    if not artifact_ok:
        missing.append("zkprov_circuit_artifact")

    srs_ok = _safe_bool(_kzg_srs_present)
    try:
        detail["kzg_srs_dir"] = str(_kzg_srs_dir())
    except Exception:  # noqa: BLE001
        detail["kzg_srs_dir"] = "<unresolvable>"
    if not srs_ok:
        missing.append("kzg_srs")

    available = ezkl_ok and artifact_ok and srs_ok
    return ProbeResult(
        available=available,
        tier="pieces-present" if available else TIER_NONE,
        missing=tuple(missing),
        detail=detail,
    )


def probe_ezkl_halo2() -> ProbeResult:
    """Probe the ezkl/Halo2 (KZG) proving backend for L1. Reporter only.

    ``available=True`` proves exactly: the ``ezkl`` package imports, the circuit
    artifact ``tex/zkprov/circuits/zkprov_v1.onnx`` exists non-empty, and a
    ``kzg*.srs`` file exists non-empty in ezkl's SRS repo dir. It does **not**
    prove the artifact matches the live ZKPROV statement schema, that the SRS
    hash is valid, that any proof verifies, or that the zkpdp arbiter trusts
    this backend — ``resolve_backend_with_fallback`` deliberately treats
    resolution success as non-evidence of availability, and this probe's
    success is equally non-evidence of trust. Consumption is L1's own opt-in.

    These are the real checks ``Halo2IpaBackend.prove`` would fail without
    (it raises ``BackendUnavailable`` even with ezkl installed when the
    artifact is absent). The probe never reads ``TEX_ZKPDP_ALLOW_SHIM`` and
    never touches arbiter behavior.
    """
    return _guarded("ezkl_halo2", _probe_ezkl_halo2_impl)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Signer ML-DSA maturity (L10) — pure delegation to pq_durability
# ─────────────────────────────────────────────────────────────────────────────

# tier values for this probe are SignerDurability values verbatim:
#   "none" | "research_only" | "durable" — pq_durability owns the ladder.
_ML_DSA_AVAILABLE_TIERS = frozenset(
    {SignerDurability.RESEARCH_ONLY, SignerDurability.DURABLE}
)


def _openssl_mldsa_cli_present() -> bool:
    """Whether an OpenSSL >= 3.5 ML-DSA-87 CLI is reachable — a SEPARATE fact.

    This fact does **not** contribute to the probe's tier or availability and
    never may: the CLI shim is deliberately not the signer the engine
    dispatches to (the pinned nanozk trap,
    ``test_cli_shim_does_not_raise_live_maturity``). It is reported only so an
    operator can see that a feasibility-proof backend exists on the host
    without anyone mistaking it for signer maturity.
    """
    return pq_durability.find_openssl_mldsa() is not None


def _probe_ml_dsa_impl() -> ProbeResult:
    # Single source of truth: the L10 fail-closed allowlist probe. This probe
    # adds NO second maturity computation — a divergence test pins tier ==
    # pq_durability.probe_backend().value exactly.
    maturity = pq_durability.probe_backend()
    backend_id = ml_dsa.active_backend_id()
    cli_present = _safe_bool(_openssl_mldsa_cli_present)

    available = maturity in _ML_DSA_AVAILABLE_TIERS
    return ProbeResult(
        available=available,
        tier=maturity.value,
        missing=() if available else ("ml_dsa_live_backend",),
        detail={
            "signer_maturity": maturity.value,
            "ml_dsa_backend_id": backend_id or "<none>",
            # Separate fact; see _openssl_mldsa_cli_present — NOT maturity input.
            "openssl_mldsa_cli_present": str(cli_present).lower(),
        },
    )


def probe_ml_dsa_backend() -> ProbeResult:
    """Probe the signer's runtime ML-DSA maturity for L10. Reporter only.

    Pure delegation: ``tier`` is :func:`pq_durability.probe_backend`'s
    :class:`SignerDurability` value verbatim — the fail-closed allowlist over
    the id of the backend the ``MlDsaProvider`` dispatches to
    (unknown/empty/``None`` → ``none``). This probe deliberately computes no
    maturity of its own.

    ``available=True`` proves exactly: the dispatch target is a recognized,
    real ML-DSA backend (``research_only`` = liboqs, ``durable`` =
    pyca-native). It does **not** prove production PQ durability (only
    ``tier == "durable"`` carries that), does not honor a PQ-non-repudiation
    claim, and grants nothing — the L10 ABSTAIN signal keys off
    ``pq_durability`` directly and is untouched by this reporter. The
    ``openssl_mldsa_cli_present`` detail is a separate fact that never raises
    the tier (the pinned nanozk trap).
    """
    return _guarded("ml_dsa_backend", _probe_ml_dsa_impl)


# ─────────────────────────────────────────────────────────────────────────────
# 3. torch + NLI + GPU (L11) — verified load required, imports are not enough
# ─────────────────────────────────────────────────────────────────────────────


def _transformers_import_ok() -> bool:
    try:
        import transformers  # type: ignore[import-not-found]  # noqa: F401
    except Exception:  # noqa: BLE001 — in this env the import RAISES (tokenizers pin)
        return False
    return True


def _torch_import_ok() -> bool:
    try:
        import torch  # type: ignore[import-not-found]  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


def _nli_model_verified() -> bool:
    """The seam's own verified-load discipline — never a bare import check.

    Delegates to :meth:`NeuralNLIScorer.load`, which returns ``False`` even
    when the ``transformers`` import succeeds, refusing availability without a
    verified model load. A fresh scorer instance is used so the gate's scorer
    state is never touched — this probe cannot enable the neural path.
    """
    from tex.voice.voice_gate import NeuralNLIScorer

    return NeuralNLIScorer().load() is True


def _gpu_device() -> str | None:
    """Name of a present GPU accelerator ("cuda" or "mps"), else None."""
    try:
        import torch  # type: ignore[import-not-found]

        if torch.cuda.is_available():
            return "cuda"
        mps = getattr(getattr(torch, "backends", None), "mps", None)
        if mps is not None and mps.is_available():
            return "mps"
    except Exception:  # noqa: BLE001 — no torch / broken torch ⇒ no device verified
        return None
    return None


def _probe_torch_nli_impl() -> ProbeResult:
    missing: list[str] = []
    detail: dict[str, str] = {}

    transformers_ok = _safe_bool(_transformers_import_ok)
    detail["transformers_import_ok"] = str(transformers_ok).lower()
    if not transformers_ok:
        missing.append("transformers_import")

    torch_ok = _safe_bool(_torch_import_ok)
    detail["torch_import_ok"] = str(torch_ok).lower()
    if not torch_ok:
        missing.append("torch_import")

    model_ok = _safe_bool(_nli_model_verified)
    detail["nli_model_verified"] = str(model_ok).lower()
    if not model_ok:
        missing.append("nli_model_verified")

    try:
        device = _gpu_device()
    except Exception:  # noqa: BLE001
        device = None
    detail["gpu_device"] = device or "<none>"
    if device is None:
        missing.append("gpu_device")

    available = transformers_ok and torch_ok and model_ok and device is not None
    return ProbeResult(
        available=available,
        tier="verified-load" if available else TIER_NONE,
        missing=tuple(missing),
        detail=detail,
    )


def probe_torch_nli() -> ProbeResult:
    """Probe the torch+NLI+GPU entailment backend for L11. Reporter only.

    ``available=True`` proves exactly: ``transformers`` and ``torch`` import, a
    GPU accelerator is present, AND :meth:`NeuralNLIScorer.load` returned
    ``True`` — the seam's own verified-load bar. Imports alone are reported as
    separate ``detail`` facts and are **never** enough: today ``load()``
    refuses availability without a verified model load even when imports
    succeed, so on this box the probe is ``available=False`` with
    ``nli_model_verified`` named missing regardless of installed packages.

    It does **not** prove entailment quality, calibration, or that the voice
    gate consumes the neural path — the gate's scorer is untouched (the pin
    ``test_neural_scorer_is_off_and_honest`` stays green) and consumption is
    L11's own opt-in.
    """
    return _guarded("torch_nli", _probe_torch_nli_impl)


__all__ = [
    "ProbeResult",
    "TIER_NONE",
    "probe_ezkl_halo2",
    "probe_ml_dsa_backend",
    "probe_torch_nli",
]
