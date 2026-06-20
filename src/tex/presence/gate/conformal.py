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
"""

from __future__ import annotations

from typing import Any

from tex.causal.conformal_attribution import compute_conformal_prediction_set
from tex.presence.contract import EvidenceRef
from tex.presence.gate import evidence as ev

__all__ = ["derive_root_cause_region"]


def derive_root_cause_region(
    entries: tuple[Any, ...],
) -> tuple[dict[str, Any], tuple[EvidenceRef, ...], float, str] | None:
    """Conformal-localize the decisive step across an agent's action trace.

    Each ``ActionLedgerEntry`` is a trajectory step scored by its ``final_score``
    (the fused per-action risk; higher = more anomalous = more likely decisive).
    Returns ``(value, evidence, correctness_floor, coverage_mode)`` or ``None``
    when there is no usable trace (caller abstains).

    ``value`` is the localized region:
      ``{start_index, end_index, set_size, trace_length, step_ids}``.
    ``correctness_floor`` is the set's ``target_coverage`` (= 1 - alpha).
    ``coverage_mode`` is the set's own mode — never asserted, always observed.
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

    cps = compute_conformal_prediction_set(trace=trace, screener_confidences=scores)
    if cps.set_size <= 0:
        # A valid computation that localizes nothing — we cannot point anywhere,
        # so abstain rather than speak an empty region.
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
    }
    return value, refs, float(cps.target_coverage), cps.coverage_mode
