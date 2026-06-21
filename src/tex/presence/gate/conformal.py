"""DERIVED claims — the conformal correctness floor.

A DERIVED presence claim is an estimate, not a sealed fact, so the gate attaches
a *correctness floor*: the conformal lower bound on coverage (``1 - alpha``) and
an HONEST ``coverage_mode``. We reuse the already-shipped, already-cited
``tex.causal.conformal_attribution`` (Feng et al., arXiv:2605.06788;
Angelopoulos & Bates 2023) rather than re-deriving the math.

The honest edge, surfaced not buried:

  * ``transductive`` (the default here) computes the threshold from the trace's
    OWN score distribution. Coverage is MARGINAL-APPROXIMATE, not a formal
    finite-sample guarantee.
  * ``calibrated`` (only when ``TEX_CONFORMAL_CALIBRATION_PATH`` points at a real
    held-out calibration set) carries the formal guarantee.

``coverage_mode`` is read straight off the ``ConformalPredictionSet`` the library
returns, so the gate can NEVER announce "calibrated" while actually running
transductive — the value is whatever the computation actually did. ``1 - alpha``
without ``calibrated`` is an approximate floor, and the spoken phrasing
(``queries.py``) says "transductive coverage" out loud.

PER-TENANT MODE SELECTION (L1 — the learning flywheel)
------------------------------------------------------
When a ``tenant`` is supplied, this module — not the orchestrator — points the
conformal computation at THAT tenant's calibration file
(``tex.presence.memory.calibration``). So the gate provably *tightens* as a tenant
resolves holds: below ``MIN_CALIBRATION_N`` confirmed labels the file is withheld
and we stay ``transductive`` (and say so); at/above it we switch to ``calibrated``.
Moving the selection into the gate means a forgotten ``tenant_calibration_env``
wrap upstream can no longer silently defeat the flywheel.

Calibration is a CAUTION-ONLY signal (Tex doctrine: a signal may only move a
verdict toward ABSTAIN, never raise it). We compute the transductive *baseline*
AND the tenant-calibrated candidate, then combine monotonically (see
``_monotone_combine``): more labels may *tighten* (DERIVED→ABSTAIN) or *upgrade the
honesty of the floor* (transductive→calibrated at the SAME 1−α), but may NEVER make
the gate speak where the baseline was silent, and never raise the tier or the floor
number. This is structural — it survives a future swap of the CP algorithm, not an
incidental property of two-way filtration. The legacy ``tenant=None`` path is
unchanged (it honours a process-global ``TEX_CONFORMAL_CALIBRATION_PATH``).

The earned floor is SELECTION-CONDITIONAL / within-stratum approximate, NOT i.i.d.
marginal coverage, and degrades under drift — see ``calibration/RESEARCH.md`` and
the ``tex.presence.memory.calibration`` banner. The verdict's ``recomputed_value``
carries the active ``coverage_mode`` and the label count ``calibration_n`` so the
mode is auditable.
"""

from __future__ import annotations

from typing import Any

from tex.causal.conformal_attribution import compute_conformal_prediction_set
from tex.presence.contract import EvidenceRef
from tex.presence.gate import evidence as ev

__all__ = ["derive_root_cause_region"]


def derive_root_cause_region(
    entries: tuple[Any, ...],
    *,
    tenant: str | None = None,
    feed: Any = None,
) -> tuple[dict[str, Any], tuple[EvidenceRef, ...], float, str] | None:
    """Conformal-localize the decisive step across an agent's action trace.

    Each ``ActionLedgerEntry`` is a trajectory step scored by its ``final_score``
    (the fused per-action risk; higher = more anomalous = more likely decisive).
    Returns ``(value, evidence, correctness_floor, coverage_mode)`` or ``None``
    when there is no usable trace, or when calibration tightened the region to
    empty (caller abstains).

    ``value`` is the localized region:
      ``{start_index, end_index, set_size, trace_length, step_ids,
         coverage_mode, calibration_n}``.
    ``correctness_floor`` is the set's ``target_coverage`` (= 1 - alpha).
    ``coverage_mode`` is the set's own mode — never asserted, always observed.

    ``tenant`` (+ optional ``feed``) engage the per-tenant flywheel: the gate points
    the computation at this tenant's calibration file and combines transductive vs
    calibrated monotonically (see module docstring). ``tenant=None`` keeps the
    legacy behaviour (honour a process-global ``TEX_CONFORMAL_CALIBRATION_PATH``).
    """
    if not entries:
        return None

    trace: list[dict[str, object]] = []
    scores: dict[str, float] = {}
    by_step: dict[str, Any] = {}
    for index, entry in enumerate(entries):
        step_id = f"step_{index:04d}"
        trace.append({"step_id": step_id, "agent_id": str(getattr(entry, "agent_id", "unknown"))})
        score = getattr(entry, "final_score", None)
        scores[step_id] = float(score) if score is not None else 0.0
        by_step[step_id] = entry

    cps, calibration_n = _select_mode(trace, scores, tenant=tenant, feed=feed)
    if cps is None:
        # No usable region: a valid computation that localizes nothing, or
        # calibration tightened it to empty — abstain rather than speak.
        return None

    refs = tuple(
        ev.ref_for_action_entry(by_step[sid], field="final_score")
        for sid in cps.step_ids_in_set
        if sid in by_step
    )
    value = {
        "start_index": cps.start_index,
        "end_index": cps.end_index,
        "set_size": cps.set_size,
        "trace_length": cps.trace_length,
        "step_ids": list(cps.step_ids_in_set),
        # Audit surface: the mode the computation ACTUALLY ran, and how many
        # confirmed labels back it (None on the legacy/global path).
        "coverage_mode": cps.coverage_mode,
        "calibration_n": calibration_n,
    }
    return value, refs, float(cps.target_coverage), cps.coverage_mode


def _select_mode(
    trace: list[dict[str, object]],
    scores: dict[str, float],
    *,
    tenant: str | None,
    feed: Any,
) -> tuple[Any | None, int | None]:
    """Pick the conformal mode and return ``(chosen_cps_or_None, calibration_n)``.

    ``tenant is None`` → LEGACY: one computation honouring whatever
    ``TEX_CONFORMAL_CALIBRATION_PATH`` is set (preserves pre-L1 behaviour and its
    test); ``calibration_n`` is None.

    ``tenant`` set → per-tenant, monotone-safe selection: a transductive baseline
    (env cleared so a global path can't leak into a tenant call), and — only if the
    tenant has a calibrated file (writer guarantees n ≥ MIN_CALIBRATION_N) — a
    tenant-calibrated candidate, combined caution-only by :func:`_monotone_combine`.
    """
    if not tenant:
        cps = compute_conformal_prediction_set(trace=trace, screener_confidences=scores)
        return (cps if cps.set_size > 0 else None), None

    # Lazy import keeps the gate decoupled from the memory package at import time
    # and scopes the dependency to where calibration is actually consulted.
    from tex.presence.memory.calibration import (
        MIN_CALIBRATION_N,
        calibration_available,
        calibration_disabled_env,
        default_calibration_feed,
        tenant_calibration_env,
    )

    feed = feed or default_calibration_feed()

    # Transductive baseline — the always-safe reference point.
    with calibration_disabled_env():
        cps_t = compute_conformal_prediction_set(trace=trace, screener_confidences=scores)

    calibration_n = _safe_label_count(feed, tenant)

    # READER-SIDE min_n floor (defence in depth). S5's floor is writer-side only
    # (the feed withholds the scores file below MIN_CALIBRATION_N); on its own that
    # trusts whoever wrote the file. The gate independently refuses to engage a
    # formal floor unless the feed's OWN ledger accounts for ≥ MIN_CALIBRATION_N
    # confirmed labels — so a rogue/stale sub-threshold scores file can never make
    # this gate announce a "calibrated" coverage it has not earned. Both must hold:
    # the ledger count AND a present scores file for the consumer to read.
    floor_met = calibration_n is not None and calibration_n >= MIN_CALIBRATION_N
    if not (floor_met and calibration_available(feed, tenant)):
        # No formal mode to engage — stay honestly transductive (and skip the
        # redundant second compute).
        return (cps_t if cps_t.set_size > 0 else None), calibration_n

    with tenant_calibration_env(feed, tenant):
        cps_c = compute_conformal_prediction_set(trace=trace, screener_confidences=scores)

    return _monotone_combine(cps_t, cps_c), calibration_n


def _monotone_combine(cps_t: Any, cps_c: Any) -> Any | None:
    """Combine the transductive baseline with the tenant-calibrated candidate as a
    CAUTION-ONLY signal. Returns the CPS to report, or ``None`` to ABSTAIN.

      * baseline localizes nothing → ABSTAIN. Calibration may NEVER turn the gate's
        silence into speech ("never loosen the abstain boundary").
      * calibration in force (``cps_c`` ran ``calibrated`` ⇒ n ≥ MIN_CALIBRATION_N):
          - calibrated set empty → ABSTAIN (more labels tightened it — allowed).
          - else → the calibrated set: DERIVED at a now-FORMAL floor (same 1−α).
      * calibration not yet in force → the transductive baseline (approximate).

    The tier never rises and the floor number never changes; only the coverage
    *mode* may upgrade. This holds regardless of which CP algorithm produced the
    sets, so the invariant is structural, not incidental to two-way filtration.
    """
    if cps_t.set_size <= 0:
        return None
    if cps_c.coverage_mode == "calibrated":
        return cps_c if cps_c.set_size > 0 else None
    return cps_t


def _safe_label_count(feed: Any, tenant: str) -> int | None:
    """The tenant's confirmed-label count for the audit surface; never raises into
    the gate (an unreadable ledger must not break a verdict)."""
    try:
        return feed.label_count(tenant)
    except Exception:  # noqa: BLE001 — audit counter only; degrade to unknown
        return None
