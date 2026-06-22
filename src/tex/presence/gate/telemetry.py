"""Presence telemetry — the three numbers that prove the gate behaves.

  * ``abstain_rate``      — share of claims (and of answers) that resolved to
    ABSTAIN. High on adversarial input is GOOD: it is honest refusal.
  * ``grounding_rate``    — share of claims that reached SEALED or DERIVED, i.e.
    were spoken only because the gate recomputed them from rows.
  * ``recompute_mismatch_rate`` — share of claims where the draft span asserted a
    value that disagreed with the gate's recompute. Every one of these was
    lowered to ABSTAIN; a non-zero rate is the gate catching a draft trying to
    lie, not the gate lying.
  * ``over_suppression_rate`` — share of answers where an operator's profile
    CORRECTION lowered at least one claim's tier. This is the metric to WATCH for
    the correction loop: corrections are monotone (``tighten``-only), so the only
    real failure mode is OVER-suppression (a correction quietly muting more than
    intended). Inflation is structurally impossible, so there is no inflation
    counter to keep.

Thread-safe; the live path may observe from multiple worker threads. Pure
counters, no I/O — a metrics exporter can read :meth:`snapshot`.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable

from tex.presence.contract import PresenceTier, PresenceVerdict

__all__ = ["PresenceTelemetry"]

_MISMATCH_MARK = "draft-value-mismatch"


class PresenceTelemetry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.answers_total = 0
        self.answers_abstained = 0  # answers where NO claim was supported
        self.claims_total = 0
        self.claims_sealed = 0
        self.claims_derived = 0
        self.claims_abstained = 0
        self.recompute_mismatches = 0
        # Over-suppression (the correction loop's only real failure mode — inflation
        # is structurally impossible). Counted in run_presence by diffing the gate's
        # tiers against the post-correction tiers.
        self.answers_corrected_down = 0
        self.claims_corrected_down = 0

    def observe_answer(self, verdicts: Iterable[PresenceVerdict], *, claims_lowered: int = 0) -> None:
        """Record one answer's post-correction verdicts, and (atomically, under the
        same lock) how many of its claims a profile CORRECTION lowered. Counting
        both in one critical section means a concurrent :meth:`snapshot` can never
        observe ``answers_corrected_down`` incremented while ``answers_total`` is not
        — so the watch metric ``over_suppression_rate`` is never transiently torn.
        ``claims_lowered`` is monotone by construction (a correction can only
        tighten), so it only ever counts suppression, never inflation."""
        verdicts = tuple(verdicts)
        with self._lock:
            self.answers_total += 1
            if claims_lowered > 0:
                self.answers_corrected_down += 1
                self.claims_corrected_down += claims_lowered
            any_supported = False
            for v in verdicts:
                self.claims_total += 1
                if v.tier is PresenceTier.SEALED:
                    self.claims_sealed += 1
                    any_supported = True
                elif v.tier is PresenceTier.DERIVED:
                    self.claims_derived += 1
                    any_supported = True
                else:
                    self.claims_abstained += 1
                if _MISMATCH_MARK in (v.reason or ""):
                    self.recompute_mismatches += 1
            if not any_supported:
                self.answers_abstained += 1

    # ------------------------------------------------------------------ derived
    @property
    def abstain_rate(self) -> float:
        with self._lock:
            return self.claims_abstained / self.claims_total if self.claims_total else 0.0

    @property
    def grounding_rate(self) -> float:
        with self._lock:
            supported = self.claims_sealed + self.claims_derived
            return supported / self.claims_total if self.claims_total else 0.0

    @property
    def answer_abstain_rate(self) -> float:
        with self._lock:
            return self.answers_abstained / self.answers_total if self.answers_total else 0.0

    @property
    def recompute_mismatch_rate(self) -> float:
        with self._lock:
            return self.recompute_mismatches / self.claims_total if self.claims_total else 0.0

    @property
    def over_suppression_rate(self) -> float:
        """Share of answers where a profile correction lowered ≥1 claim's tier —
        the correction loop's watch metric (inflation is structurally impossible)."""
        with self._lock:
            return self.answers_corrected_down / self.answers_total if self.answers_total else 0.0

    def snapshot(self) -> dict[str, float | int]:
        with self._lock:
            supported = self.claims_sealed + self.claims_derived
            total = self.claims_total
            return {
                "answers_total": self.answers_total,
                "answers_abstained": self.answers_abstained,
                "claims_total": total,
                "claims_sealed": self.claims_sealed,
                "claims_derived": self.claims_derived,
                "claims_abstained": self.claims_abstained,
                "recompute_mismatches": self.recompute_mismatches,
                "answers_corrected_down": self.answers_corrected_down,
                "claims_corrected_down": self.claims_corrected_down,
                "abstain_rate": (self.claims_abstained / total) if total else 0.0,
                "grounding_rate": (supported / total) if total else 0.0,
                "answer_abstain_rate": (
                    self.answers_abstained / self.answers_total if self.answers_total else 0.0
                ),
                "recompute_mismatch_rate": (self.recompute_mismatches / total) if total else 0.0,
                "over_suppression_rate": (
                    self.answers_corrected_down / self.answers_total if self.answers_total else 0.0
                ),
            }
