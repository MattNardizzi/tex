"""Presence telemetry — the three numbers that prove the gate behaves.

  * ``abstain_rate``      — share of claims (and of answers) that resolved to
    ABSTAIN. High on adversarial input is GOOD: it is honest refusal.
  * ``grounding_rate``    — share of claims that reached SEALED or DERIVED, i.e.
    were spoken only because the gate recomputed them from rows.
  * ``recompute_mismatch_rate`` — share of claims where the draft span asserted a
    value that disagreed with the gate's recompute. Every one of these was
    lowered to ABSTAIN; a non-zero rate is the gate catching a draft trying to
    lie, not the gate lying.

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

    def observe_answer(self, verdicts: Iterable[PresenceVerdict]) -> None:
        verdicts = tuple(verdicts)
        with self._lock:
            self.answers_total += 1
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
                "abstain_rate": (self.claims_abstained / total) if total else 0.0,
                "grounding_rate": (supported / total) if total else 0.0,
                "answer_abstain_rate": (
                    self.answers_abstained / self.answers_total if self.answers_total else 0.0
                ),
                "recompute_mismatch_rate": (self.recompute_mismatches / total) if total else 0.0,
            }
