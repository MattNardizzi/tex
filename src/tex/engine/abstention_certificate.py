"""
Builder for the Abstention Certificate (engine layer).

Maps the finalized verdict artifacts — the routed result, the two-sided CRC
certificate, the policy thresholds, and the (already-built) :class:`Hold` — into
the descriptive :class:`AbstentionCertificate` (``domain/abstention_certificate``).

Three hard properties, all enforced here so the PDP wiring stays one call:

  * **Pure and deterministic.** No I/O, no clocks, no randomness — identical
    inputs always produce an identical certificate, so the PDP determinism
    fingerprint is preserved (same posture as ``build_hold``).
  * **ABSTAIN-only.** Returns ``None`` for any non-ABSTAIN verdict, so PERMIT /
    FORBID are structurally unaffected by wiring it in.
  * **Never raises into the verdict path.** Numeric values are clamped before
    model construction so a degenerate score can never raise out of the builder.

The non-weaponization witness reads the permit region the gate ALREADY encodes;
it does not re-run the pipeline on a synthetic variant. Three cases, in order
of evidentiary strength:

  1. CRC gate enabled AND certified → the permit ceiling is the certified
     cutoff ``lambda_hat``; a lower-risk variant scoring <= it is certifiably
     permitted. (source = ``crc_certified_permit_cutoff``)
  2. CRC gate enabled but UNCERTIFIABLE → the gate demotes every PERMIT, so the
     permit region is genuinely empty. The witness says so honestly
     (``permit_reachable=False``) rather than cite a policy threshold the gate
     overrides. (source = ``crc_uncertifiable_fail_closed``)
  3. CRC gate inert / absent (today's default) → the router's policy
     ``permit_threshold`` is the permit ceiling; a lower-risk variant scoring
     <= it is permitted under the same configuration, honestly uncalibrated.
     (source = ``policy_permit_threshold``)
"""

from __future__ import annotations

from typing import Sequence

from tex.domain.abstention_certificate import (
    AbstentionCertificate,
    AbstentionJustification,
    AbstentionTrigger,
    NonWeaponizationWitness,
)
from tex.domain.verdict import Verdict
from tex.engine.crc_gate import CRCCertificate
from tex.engine.hold import _FLAG_PIVOTS, Hold

__all__ = ["build_abstention_certificate"]

# The curated set of recognized uncertainty causes the Hold reasons about
# (engine/hold.py::_FLAG_PIVOTS — every key has a guaranteed live emitter).
# The trigger prefers naming one of these as the cause over the generic
# mechanism-describing flags a fallback analysis raises (``fallback_used``,
# ``specialist_heuristic``, ``no_plan`` …), which say HOW the analysis ran, not
# WHY the verdict was held. ``crc_permit_region_exceeded`` (a CRC demotion) is
# one such recognized cause.
_RECOGNIZED_CAUSES = frozenset(_FLAG_PIVOTS)


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def _round6(x: float) -> float:
    return round(float(x), 6)


def build_abstention_certificate(
    *,
    verdict: Verdict,
    final_score: float,
    uncertainty_flags: Sequence[str],
    permit_threshold: float,
    forbid_threshold: float,
    certificate: CRCCertificate | None,
    hold: Hold | None = None,
) -> AbstentionCertificate | None:
    """Build the descriptive certificate for an ABSTAIN. ``None`` for non-ABSTAIN.

    ``certificate`` is the two-sided CRC certificate attached to this evaluation
    (may be ``None`` when no gate ran). ``hold`` is the already-built
    :class:`Hold` for this same ABSTAIN; when present its pivotal flag enriches
    the trigger. ``permit_threshold`` / ``forbid_threshold`` are the policy
    cutoffs the router used (the uncalibrated decision band).
    """
    if verdict is not Verdict.ABSTAIN:
        return None

    score = _clamp01(final_score)
    flags = tuple(f for f in uncertainty_flags)

    # ── calibration: honest, read from the CRC two-sided certificate ──────
    # band_certified is True only when the gate had real calibration AND this
    # score fell strictly inside its certified hold band — the same signal the
    # Hold reads. Never set True from a synthetic/policy threshold.
    band_certified = bool(certificate is not None and certificate.in_hold_band)

    # ── the effective decision band (what the pipeline actually used) ─────
    if band_certified and certificate is not None:
        band_lower = _round6(certificate.hold_band_lower)
        band_upper = _round6(certificate.hold_band_upper)
        certified_false_permit = _round6(certificate.certified_false_permit_rate)
        certified_false_forbid = _round6(certificate.certified_false_forbid_rate)
    else:
        band_lower = _round6(permit_threshold)
        band_upper = _round6(forbid_threshold)
        certified_false_permit = None
        certified_false_forbid = None

    # ── Part 1: TRIGGER ───────────────────────────────────────────────────
    trigger = _build_trigger(score=score, flags=flags, hold=hold)

    # ── Part 2: JUSTIFICATION ─────────────────────────────────────────────
    if band_certified:
        rationale = (
            f"Fused risk {score:.3f} fell inside the CRC certified hold band "
            f"[{band_lower:.3f}, {band_upper:.3f}]: neither a PERMIT (score "
            f"<= {band_lower:.3f}) nor a FORBID (score >= {band_upper:.3f}) can "
            f"be certified at its risk budget, so abstaining is the calibrated "
            f"choice (false-permit <= {certified_false_permit}, false-forbid "
            f"<= {certified_false_forbid})."
        )
    else:
        rationale = (
            f"Fused risk {score:.3f} fell in the policy abstention band "
            f"[{band_lower:.3f}, {band_upper:.3f}] — above the permit cutoff and "
            f"below the forbid cutoff. The band is the router's real decision "
            f"boundary but is not yet calibrated against a field corpus "
            f"(certified=false), so the hold carries no finite-sample coverage "
            f"statement yet."
        )
    justification = AbstentionJustification(
        risk_score=score,
        band_lower=band_lower,
        band_upper=band_upper,
        band_certified=band_certified,
        calibration="certified" if band_certified else "uncalibrated",
        certified_false_permit_rate=certified_false_permit,
        certified_false_forbid_rate=certified_false_forbid,
        rationale=rationale,
    )

    # ── Part 3: NON-WEAPONIZATION WITNESS ─────────────────────────────────
    witness = _build_witness(
        score=score,
        permit_threshold=permit_threshold,
        certificate=certificate,
        band_certified=band_certified,
    )

    return AbstentionCertificate(
        certified=band_certified,
        trigger=trigger,
        justification=justification,
        witness=witness,
    )


def _build_trigger(
    *,
    score: float,
    flags: tuple[str, ...],
    hold: Hold | None,
) -> AbstentionTrigger:
    """Name the triggering condition and the signal value that tripped it.

    Prefers the Hold's already-chosen pivotal flag (the single fact that would
    resolve the hold); falls back to the first uncertainty flag, then to the
    selective-risk mid-band when no flag is present. The signal value is the
    fused score the verdict region is read from.
    """
    # Priority: the Hold's already-chosen pivotal fact (epistemic, most-
    # resolving) → the first RECOGNIZED uncertainty cause present (over generic
    # mechanism noise) → the first flag → the bare selective-risk band.
    pivotal = hold.pivotal_flag if hold is not None else None
    recognized = next((f for f in flags if f.casefold() in _RECOGNIZED_CAUSES), None)
    chosen = pivotal or recognized or (flags[0] if flags else None)
    if chosen:
        kind = chosen
        signal_name = chosen
        detail = (
            f"Abstention cause '{chosen}'; fused risk score {score:.3f} sits in "
            f"the abstention band."
        )
    else:
        kind = "selective_risk_band"
        signal_name = "fused_score"
        detail = (
            f"No single flag dominated; the fused risk score {score:.3f} fell "
            f"in the selective-risk abstention band (neither clean enough to "
            f"permit nor unsafe enough to forbid)."
        )
    return AbstentionTrigger(
        kind=kind,
        signal_name=signal_name,
        signal_value=score,
        uncertainty_flags=flags,
        detail=detail,
    )


def _build_witness(
    *,
    score: float,
    permit_threshold: float,
    certificate: CRCCertificate | None,
    band_certified: bool,
) -> NonWeaponizationWitness:
    """Derive the permitting counterfactual from the gate's own permit region.

    See the module docstring for the three cases. The ceiling is the highest
    score that PERMITs under THIS configuration; the delta is how far this
    action's score sits above it.
    """
    gate_enabled = certificate is not None and certificate.enabled
    gate_certified = certificate is not None and certificate.certified

    if gate_enabled and not gate_certified:
        # Enabled but uncertifiable: the gate demotes every PERMIT, so the
        # permit region is genuinely empty. Disclose it honestly.
        ceiling = -1.0
        reachable = False
        source = "crc_uncertifiable_fail_closed"
        counterfactual = (
            "This configuration's CRC gate is enabled but cannot certify any "
            "PERMIT on its calibration set, so it routes every action to human "
            "review (fail-closed). No lower-risk variant would be permitted "
            "under this exact configuration until the gate is calibrated — this "
            "is an honest uncalibrated-gate disclosure, not a covert deny."
        )
    elif band_certified and certificate is not None:
        # Certified band: the certified permit cutoff is the permit ceiling.
        ceiling = _round6(certificate.hold_band_lower)
        reachable = ceiling >= 0.0
        source = "crc_certified_permit_cutoff"
        counterfactual = (
            f"Under this exact policy + CRC gate, a lower-risk variant of this "
            f"action scoring <= {ceiling:.3f} would be CERTIFIABLY permitted. "
            f"This action scored {score:.3f}; the abstain is specific to that "
            f"risk, not a blanket deny — the certified permit region is "
            f"non-empty."
        )
    else:
        # Inert / absent gate (today's default): the router's policy
        # permit_threshold governs. The permit region [0, threshold] is the
        # real boundary, honestly uncalibrated.
        ceiling = _round6(_clamp01(permit_threshold))
        reachable = ceiling >= 0.0
        source = "policy_permit_threshold"
        counterfactual = (
            f"Under this exact policy configuration, a lower-risk variant of "
            f"this action scoring <= {ceiling:.3f} (the permit threshold, with "
            f"clean semantics) would be PERMITTED. This action scored "
            f"{score:.3f}; the abstain is specific to that risk, not a blanket "
            f"deny — the permit region is non-empty (threshold uncalibrated)."
        )

    delta = _round6(score - ceiling) if reachable else _round6(score)
    return NonWeaponizationWitness(
        permit_reachable=reachable,
        permit_score_ceiling=ceiling,
        counterfactual_delta=delta,
        source=source,
        counterfactual=counterfactual,
    )
