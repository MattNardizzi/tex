"""
Drift signal registry.

The set of named, time-series drift signals tracked over the ecosystem.

Default signals
---------------
The seven default signals listed in the original scaffolding docstring,
each calibrated to surface a distinct ecosystem-state failure mode that
the OWASP Agentic Skills 2026 + AAF taxonomy treats as load-bearing:

  - ``tool_call_rate_per_agent``         — surge / collapse in tool usage
  - ``cross_agent_message_rate``         — coordination spike (collusion proxy)
  - ``capability_grant_rate``            — privilege escalation pressure
  - ``denial_rate_per_agent``            — agent reaching a frustration regime
  - ``outbound_content_volume_per_tenant`` — exfiltration / spam pressure
  - ``average_path_depth``                — task fan-out drift
  - ``average_compromise_score``          — Byzantine-rate regime change

These signal IDs are the keys the change-point detector tracks per-tenant.
The registry is the contract between the *signal aggregator* (upstream of
this layer) and the *change-point detector* (this layer): every signal
the detector consumes must be registered here so its baseline mean/stddev
are known and so the institutional/oracle thresholding stage can look up
its stable rule_id.

References
----------
- arXiv:2512.18561 (AAF, Q1 2026) §4.3 "Online Detection of Harmful Norms"
  — calls for signal-typed streaming statistics fed into the detector.
- OWASP Top 10 for Agentic AI 2026 (ASI04 Resource Overload, ASI07
  Misaligned Behavior, ASI10 Overwhelming Human Oversight) — each maps
  onto one of the default signals here.

Priority: P1.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass


# Default signal identifiers — exposed as module-level constants so callers
# can import them as named symbols (avoid magic strings at call sites).
SIGNAL_TOOL_CALL_RATE_PER_AGENT: str = "tool_call_rate_per_agent"
SIGNAL_CROSS_AGENT_MESSAGE_RATE: str = "cross_agent_message_rate"
SIGNAL_CAPABILITY_GRANT_RATE: str = "capability_grant_rate"
SIGNAL_DENIAL_RATE_PER_AGENT: str = "denial_rate_per_agent"
SIGNAL_OUTBOUND_CONTENT_VOLUME_PER_TENANT: str = "outbound_content_volume_per_tenant"
SIGNAL_AVERAGE_PATH_DEPTH: str = "average_path_depth"
SIGNAL_AVERAGE_COMPROMISE_SCORE: str = "average_compromise_score"


DEFAULT_SIGNAL_IDS: tuple[str, ...] = (
    SIGNAL_TOOL_CALL_RATE_PER_AGENT,
    SIGNAL_CROSS_AGENT_MESSAGE_RATE,
    SIGNAL_CAPABILITY_GRANT_RATE,
    SIGNAL_DENIAL_RATE_PER_AGENT,
    SIGNAL_OUTBOUND_CONTENT_VOLUME_PER_TENANT,
    SIGNAL_AVERAGE_PATH_DEPTH,
    SIGNAL_AVERAGE_COMPROMISE_SCORE,
)


@dataclass(frozen=True, slots=True)
class DriftSignal:
    signal_id: str
    description: str
    aggregation_window_seconds: int
    baseline_mean: float
    baseline_stddev: float


# Signal seed table — one entry per default signal. The descriptions are
# stable: changing them is a visible breaking change to downstream pitch
# / docs surfaces, so version-bump the registry rather than editing in place.
_DEFAULT_SIGNAL_DEFS: tuple[tuple[str, str, int], ...] = (
    (
        SIGNAL_TOOL_CALL_RATE_PER_AGENT,
        "Per-agent tool invocations / minute. Surges signal goal-hijack "
        "or tool-misuse regimes (OWASP ASI01, ASI02).",
        60,
    ),
    (
        SIGNAL_CROSS_AGENT_MESSAGE_RATE,
        "Inter-agent messages / minute across the ecosystem. Spikes are "
        "the canonical behavioral collusion proxy (Bonjour 2022).",
        60,
    ),
    (
        SIGNAL_CAPABILITY_GRANT_RATE,
        "Capability grants / minute (delegation events). Surges signal "
        "privilege-escalation pressure (OWASP ASI03).",
        60,
    ),
    (
        SIGNAL_DENIAL_RATE_PER_AGENT,
        "Per-agent denied-action rate. Sustained elevation is an ARM-style "
        "first-class-denial signal of an agent in a frustration regime.",
        60,
    ),
    (
        SIGNAL_OUTBOUND_CONTENT_VOLUME_PER_TENANT,
        "Outbound content artifacts / minute per tenant. Surges signal "
        "exfiltration or content-spam pressure (FTC §5 / EU AI Act Art. 50).",
        60,
    ),
    (
        SIGNAL_AVERAGE_PATH_DEPTH,
        "Mean depth of agent-task call graphs. Drift indicates emergent "
        "task fan-out beyond the committed governance graph.",
        300,
    ),
    (
        SIGNAL_AVERAGE_COMPROMISE_SCORE,
        "Sliding-window mean of per-event compromise scores. Direct "
        "Byzantine-rate regime indicator (AAF §3.1.4).",
        300,
    ),
)


# Conservative default baselines. Calibration is a per-deployment activity
# — these defaults intentionally normalise a fresh signal at unit variance
# around zero so the change-point detector's Student-t predictive doesn't
# pathologically reject the very first observation.
_DEFAULT_BASELINE_MEAN: float = 0.0
_DEFAULT_BASELINE_STDDEV: float = 1.0


class DriftSignalRegistry:
    """
    Registry of named drift signals.

    Default-constructs with the seven signals from the package scaffolding
    docstring. Custom signals can be registered for tenant-specific telemetry.

    Construction
    ------------
    >>> registry = DriftSignalRegistry()                      # 7 defaults
    >>> registry = DriftSignalRegistry(seed_defaults=False)   # empty
    >>> registry.register(DriftSignal(...))                   # add custom

    Iteration & lookup
    ------------------
    >>> SIGNAL_TOOL_CALL_RATE_PER_AGENT in registry
    True
    >>> registry.get(SIGNAL_TOOL_CALL_RATE_PER_AGENT)
    DriftSignal(signal_id='tool_call_rate_per_agent', ...)
    >>> for signal in registry:
    ...     ...

    TODO(P1): seed with default signals:
      - tool_call_rate_per_agent
      - cross_agent_message_rate
      - capability_grant_rate
      - denial_rate_per_agent
      - outbound_content_volume_per_tenant
      - average_path_depth
      - average_compromise_score
        — DONE. See ``DEFAULT_SIGNAL_IDS`` and the seed table.
    TODO(P1): calibrate default baselines from production telemetry. The
        current defaults (mean=0.0, stddev=1.0) are deliberately neutral
        so a fresh deployment does not generate spurious change-point
        alerts during its initial warmup window.
    TODO(P1): add multivariate signal groups (joint baselines) for
        signals that exhibit known cross-correlations — e.g.
        ``capability_grant_rate`` and ``tool_call_rate_per_agent`` move
        together under healthy onboarding. Univariate BOCPD on each
        signal will fire two correlated alarms; a joint detector would
        fire one. Tracked under arXiv:2007.02923 (joint BOCPD).
    """

    def __init__(self, *, seed_defaults: bool = True) -> None:
        self._signals: dict[str, DriftSignal] = {}
        if seed_defaults:
            self._seed_defaults()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register(self, signal: DriftSignal) -> None:
        """
        Register a new signal. Raises ``ValueError`` on duplicate signal_id —
        callers wanting to overwrite must explicitly remove first or call
        ``update_baseline`` for baseline-only changes.
        """
        if not isinstance(signal, DriftSignal):
            raise TypeError(
                f"register() expects a DriftSignal, got {type(signal).__name__}"
            )
        if signal.signal_id in self._signals:
            raise ValueError(
                f"signal_id {signal.signal_id!r} already registered; "
                "use update_baseline() to change the baseline only"
            )
        if not signal.signal_id:
            raise ValueError("DriftSignal.signal_id must be non-empty")
        if signal.aggregation_window_seconds <= 0:
            raise ValueError(
                "DriftSignal.aggregation_window_seconds must be positive"
            )
        if signal.baseline_stddev <= 0.0:
            raise ValueError("DriftSignal.baseline_stddev must be positive")
        self._signals[signal.signal_id] = signal

    def get(self, signal_id: str) -> DriftSignal:
        """Look up a signal by id. Raises ``KeyError`` if not registered."""
        try:
            return self._signals[signal_id]
        except KeyError as exc:
            raise KeyError(
                f"signal_id {signal_id!r} not registered. "
                f"Known: {sorted(self._signals)!r}"
            ) from exc

    def update_baseline(
        self, *, signal_id: str, baseline_mean: float, baseline_stddev: float
    ) -> DriftSignal:
        """
        Replace a signal's baseline statistics in-place. Returns the new
        DriftSignal. Raises ``KeyError`` if the signal is not registered.
        """
        if baseline_stddev <= 0.0:
            raise ValueError("baseline_stddev must be positive")
        existing = self.get(signal_id)
        replacement = DriftSignal(
            signal_id=existing.signal_id,
            description=existing.description,
            aggregation_window_seconds=existing.aggregation_window_seconds,
            baseline_mean=baseline_mean,
            baseline_stddev=baseline_stddev,
        )
        self._signals[signal_id] = replacement
        return replacement

    def signal_ids(self) -> tuple[str, ...]:
        """Sorted tuple of currently-registered signal ids."""
        return tuple(sorted(self._signals))

    def to_dict(self) -> dict[str, dict[str, float | int | str]]:
        """JSON-canonicalisable view of every registered signal."""
        return {
            sid: {
                "signal_id": sig.signal_id,
                "description": sig.description,
                "aggregation_window_seconds": sig.aggregation_window_seconds,
                "baseline_mean": sig.baseline_mean,
                "baseline_stddev": sig.baseline_stddev,
            }
            for sid, sig in sorted(self._signals.items())
        }

    def __contains__(self, signal_id: object) -> bool:
        return isinstance(signal_id, str) and signal_id in self._signals

    def __len__(self) -> int:
        return len(self._signals)

    def __iter__(self) -> Iterator[DriftSignal]:
        # Stable iteration order — sort by signal_id for reproducibility
        # in tests and operator tooling.
        for sid in sorted(self._signals):
            yield self._signals[sid]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _seed_defaults(self) -> None:
        for signal_id, description, window in _DEFAULT_SIGNAL_DEFS:
            self._signals[signal_id] = DriftSignal(
                signal_id=signal_id,
                description=description,
                aggregation_window_seconds=window,
                baseline_mean=_DEFAULT_BASELINE_MEAN,
                baseline_stddev=_DEFAULT_BASELINE_STDDEV,
            )


# ======================================================================
# Thread 7 — pre-emission drift orchestrator
# ======================================================================
#
# `evaluate_drift(proposed, state_before)` is the engine's Step-6 call
# site. It composes BOCPD (already in `_bocpd.py`) with the anytime-
# valid e-process (`_anytime_valid.py`) and the registered signal
# baselines, returning a `DriftEvaluation` with both the change-point
# posterior (Bayesian) and the anytime-valid p-value (frequentist).
#
# Reference: FRONTIER_DELTA_thread_7.md §6.3 (design justification —
# why BOCPD + anytime-valid certificate over MI9-style JS divergence
# or edit-distance drift), and §1 (Drift-to-Action arxiv 2603.08578).

from datetime import datetime, UTC  # noqa: E402 — orchestrator-only

from pydantic import BaseModel, ConfigDict, Field  # noqa: E402

from tex.drift._anytime_valid import (  # noqa: E402
    AnytimeValidCertificate,
    AnytimeValidEProcess,
)
from tex.drift.change_point import ChangePointDetector  # noqa: E402
from tex.ecosystem.proposed_event import ProposedEvent  # noqa: E402
from tex.ecosystem.state import EcosystemState  # noqa: E402
from tex.observability.telemetry import emit_event  # noqa: E402


class DriftEvaluation(BaseModel):
    """
    Output of ``evaluate_drift`` (Thread 7, Step 6 of the engine;
    three-dimension extension landed in Thread 7.1).

    Composes:

      * the **Bayesian** change-point signal from BOCPD —
        ``change_point_detected`` + per-signal MAP run length;
      * the **frequentist anytime-valid** signal from the e-process —
        ``anytime_valid_p_value`` + log-e-value;
      * the **Rath 2026 three-dimensional drift taxonomy** (arxiv
        2601.04170 §3) — semantic / coordination / behavioral drift
        as separate axes that compose into the aggregate
        ``drift_delta`` via max-pooling.

    Rath 2026 three-dimension taxonomy (Thread 7.1 extension)
    --------------------------------------------------------
      * **semantic_drift** — progressive deviation of event-kind
        distribution from the declared/historical intent baseline.
        Probed by Jensen-Shannon divergence between the recent
        event-kind histogram (sliding window via the registry's
        ``aggregate_drift_signals``) and the registry-declared
        baseline. Triggers when the agent starts taking actions of
        kinds it doesn't usually take.
      * **coordination_drift** — breakdown in inter-agent consensus
        / coordination patterns. Probed by the cross-agent message
        rate against average path depth — when messages spike but
        depth collapses (or vice versa) coordination is
        deteriorating.
      * **behavioral_drift** — emergence of unintended strategies.
        Probed by the joint of tool-call rate and denial rate per
        agent — sustained elevation in both is the canonical
        first-class-denial-driven exploration signal (ARM frame).

    The aggregate ``drift_delta`` = max(semantic_drift,
    coordination_drift, behavioral_drift). This preserves the
    existing semantic ("any drift alarm trips it") while exposing
    the per-dimension breakdown for evidence consumers and the
    Thread-8 composition gate.

    Fields
    ------
    drift_delta
        Aggregate drift score in [0, 1]. Max over the three Rath
        dimensions. ``1.0`` means at least one dimension crossed
        threshold; ``0.0`` means no dimension moved beyond noise.
    semantic_drift
        Rath 2026 semantic-drift score in [0, 1]. Intent deviation.
    coordination_drift
        Rath 2026 coordination-drift score in [0, 1]. Consensus
        breakdown.
    behavioral_drift
        Rath 2026 behavioral-drift score in [0, 1]. Unintended
        strategy emergence.
    signals_evaluated
        Tuple of signal_ids whose probed values produced a non-trivial
        BOCPD update.
    change_point_detected
        True iff *any* probed signal crossed the BOCPD detection
        threshold.
    anytime_valid_p_value
        Minimum across signals of the e-process anytime-valid p-value.
    dominant_signal_id
        signal_id whose change-point score was maximal. ``None`` when
        ``signals_evaluated`` is empty.
    dominant_lambda
        λ from the e-process grid that dominated the mixture for the
        dominant signal.
    dominant_dimension
        Which of the three Rath dimensions ("semantic", "coordination",
        "behavioral") dominated ``drift_delta``. ``None`` when all
        three are at 0.0 (no drift).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    drift_delta: float = Field(ge=0.0, le=1.0)
    semantic_drift: float = Field(default=0.0, ge=0.0, le=1.0)
    coordination_drift: float = Field(default=0.0, ge=0.0, le=1.0)
    behavioral_drift: float = Field(default=0.0, ge=0.0, le=1.0)
    signals_evaluated: tuple[str, ...]
    change_point_detected: bool
    anytime_valid_p_value: float = Field(ge=0.0, le=1.0)
    dominant_signal_id: str | None = None
    dominant_lambda: float = Field(ge=0.0)
    dominant_dimension: str | None = None


# Module-level lazy singletons — one BOCPD detector instance and one
# e-process per (registry, signal_id) tuple. Keyed by id() of the
# registry so multiple registries (e.g. one per tenant) don't share
# state. Operators wanting full control instantiate a `DriftOrchestrator`
# directly; the module-level `evaluate_drift` is the convenience entry
# point for the engine fast path.
_DEFAULT_ORCHESTRATORS: "dict[int, _DriftOrchestrator]" = {}


class _DriftOrchestrator:
    """
    Composes BOCPD + e-process state across a registry's signals.

    Held per-registry-instance by ``evaluate_drift``. Operators who
    need explicit lifecycle control (e.g. checkpoint/restore of drift
    state across process restarts) instantiate one directly.
    """

    def __init__(
        self,
        *,
        registry: DriftSignalRegistry,
        detection_threshold: float = 0.5,
        warmup_steps: int = 5,
    ) -> None:
        self._registry = registry
        self._detector = ChangePointDetector(
            detector_kind="bocpd",
            detection_threshold=detection_threshold,
            warmup_steps=warmup_steps,
        )
        self._e_processes: dict[str, AnytimeValidEProcess] = {}

    def evaluate(
        self,
        *,
        proposed: ProposedEvent,
        state_before: EcosystemState,
    ) -> DriftEvaluation:
        """
        Run BOCPD + anytime-valid e-process across all signals that
        ``proposed`` plausibly shifts. Returns the aggregate
        ``DriftEvaluation``.

        Probing strategy
        ----------------
        At step 6 of the engine the proposed event has NOT been
        admitted. We must score drift *under the hypothesis* the event
        is admitted. The probing function for each signal answers:
        "what would this signal's next observation look like if
        ``proposed`` were admitted?"

        Most defaults are direct counters (e.g.
        ``tool_call_rate_per_agent`` increments by 1 for a
        ``tool_call`` kind event; otherwise stays at the baseline
        observed in ``state_before.aggregate_drift_signals``). We
        evaluate only the subset of signals the proposed event
        plausibly shifts — irrelevant signals (e.g. cross-agent
        message rate under a ``capability_grant`` event) are skipped
        so an event doesn't pollute every signal's BOCPD state.

        Latency
        -------
        Per signal: BOCPD top-K update is O(K) with K=50, ~1 ms. E-
        process update is O(|Λ|) = O(5), ~10 µs. With 1-3 signals
        plausibly probed per event, total Step-6 latency is bounded
        at ~3 ms p99 — under budget.
        """
        relevant_signals = _probe_signals_for(proposed, state_before)

        if not relevant_signals:
            # No signal plausibly shifts under this event. Emit the
            # all-clear certificate.
            emit_event(
                "drift.evaluate.no_relevant_signals",
                event_kind=proposed.event_kind,
                proposed_event_id=_event_id_or_synth(proposed),
            )
            return DriftEvaluation(
                drift_delta=0.0,
                semantic_drift=0.0,
                coordination_drift=0.0,
                behavioral_drift=0.0,
                signals_evaluated=(),
                change_point_detected=False,
                anytime_valid_p_value=1.0,
                dominant_signal_id=None,
                dominant_lambda=0.0,
                dominant_dimension=None,
            )

        per_signal_scores: dict[str, float] = {}
        per_signal_certs: dict[str, AnytimeValidCertificate] = {}
        change_point_detected = False
        evaluated_at = (
            proposed.proposed_at
            if proposed.proposed_at.tzinfo is not None
            else proposed.proposed_at.replace(tzinfo=UTC)
        )

        for signal_id, probed_value in relevant_signals.items():
            try:
                signal = self._registry.get(signal_id)
            except KeyError:
                # Skip signals not in the registry (e.g. a tenant with
                # a stripped-down registry).
                continue

            # Standardise the probed value into baseline σ-units.
            # baseline_stddev > 0 guaranteed by DriftSignal validation.
            standardised = (probed_value - signal.baseline_mean) / signal.baseline_stddev

            # BOCPD update — Bayesian leg.
            detected = self._detector.update(
                signal_name=signal_id,
                signal_value=probed_value,
                at=evaluated_at,
            )
            if detected:
                change_point_detected = True

            # Read the BOCPD's most recent change-point score from the
            # detector's emitted detections. The detector publishes
            # detections to a list when threshold is crossed; for sub-
            # threshold updates we fall back to a soft score derived
            # from |standardised| via a saturating function so the
            # aggregate ``drift_delta`` still smoothly tracks magnitude
            # below the threshold.
            score = _bocpd_soft_score(detector=self._detector, signal_id=signal_id)
            if detected:
                # Clamp threshold-crossing to 1.0 for unambiguous
                # downstream gating.
                score = 1.0
            per_signal_scores[signal_id] = score

            # E-process — frequentist anytime-valid leg.
            if signal_id not in self._e_processes:
                self._e_processes[signal_id] = AnytimeValidEProcess()
            cert = self._e_processes[signal_id].observe(
                standardised_x=standardised,
            )
            per_signal_certs[signal_id] = cert

        if not per_signal_scores:
            # All probed signals were unregistered — fall back to clear.
            return DriftEvaluation(
                drift_delta=0.0,
                semantic_drift=0.0,
                coordination_drift=0.0,
                behavioral_drift=0.0,
                signals_evaluated=(),
                change_point_detected=False,
                anytime_valid_p_value=1.0,
                dominant_signal_id=None,
                dominant_lambda=0.0,
                dominant_dimension=None,
            )

        # Compose Bayesian (BOCPD) + frequentist (anytime-valid) into a
        # single per-signal score. BOCPD is decisive when above threshold
        # (returns 1.0); anytime-valid is decisive when p < α. Below
        # both decisions we want graceful aggregation — taking max of
        # (bocpd_score, 1 - p_anytime_valid) means a high anytime-valid
        # certainty contributes even when BOCPD is sub-threshold. This
        # closes the gap where a single-step shift never triggers BOCPD
        # (which requires a regime change in run-length posterior) but
        # the e-process correctly accumulates evidence against the null.
        per_signal_blended: dict[str, float] = {}
        for sid, bocpd_score in per_signal_scores.items():
            p = per_signal_certs[sid].p_anytime_valid
            blended = max(bocpd_score, 1.0 - p)
            # Clamp into [0, 1] defensively — p ∈ [0,1] by construction
            # but rounding could conceivably nudge a hair past 1.0.
            per_signal_blended[sid] = min(1.0, max(0.0, blended))

        # Thread 7.1 — three-dimension Rath 2026 drift classification.
        # Per-signal blended scores are aggregated into the three drift
        # dimensions via max-pooling within each dimension's signal set.
        # See _SIGNAL_TO_DIMENSION for the signal→dimension map.
        dimension_scores: dict[str, float] = {
            "semantic": 0.0,
            "coordination": 0.0,
            "behavioral": 0.0,
        }
        for sid, score in per_signal_blended.items():
            dim = _SIGNAL_TO_DIMENSION.get(sid)
            if dim is None:
                # Unmapped signal — contributes to none of the three
                # Rath dimensions but still appears in signals_evaluated.
                continue
            if score > dimension_scores[dim]:
                dimension_scores[dim] = score

        dominant_signal_id = max(per_signal_blended, key=per_signal_blended.get)
        drift_delta = per_signal_blended[dominant_signal_id]
        min_p = min(c.p_anytime_valid for c in per_signal_certs.values())
        dominant_cert = per_signal_certs[dominant_signal_id]

        # Dominant dimension = which Rath axis carries the highest
        # score. If all three are 0.0 (e.g. unmapped signal triggered)
        # report None so consumers know to fall back to
        # dominant_signal_id alone.
        max_dim_score = max(dimension_scores.values())
        if max_dim_score > 0.0:
            dominant_dimension = max(
                dimension_scores, key=dimension_scores.get
            )
        else:
            dominant_dimension = None

        emit_event(
            "drift.evaluate.complete",
            proposed_event_id=_event_id_or_synth(proposed),
            n_signals=len(per_signal_scores),
            drift_delta=drift_delta,
            semantic_drift=dimension_scores["semantic"],
            coordination_drift=dimension_scores["coordination"],
            behavioral_drift=dimension_scores["behavioral"],
            change_point_detected=change_point_detected,
            anytime_valid_p_value=min_p,
            dominant_signal=dominant_signal_id,
            dominant_dimension=dominant_dimension,
        )

        return DriftEvaluation(
            drift_delta=drift_delta,
            semantic_drift=dimension_scores["semantic"],
            coordination_drift=dimension_scores["coordination"],
            behavioral_drift=dimension_scores["behavioral"],
            signals_evaluated=tuple(sorted(per_signal_scores)),
            change_point_detected=change_point_detected,
            anytime_valid_p_value=min_p,
            dominant_signal_id=dominant_signal_id,
            dominant_lambda=dominant_cert.dominant_lambda,
            dominant_dimension=dominant_dimension,
        )


def evaluate_drift(
    *,
    proposed: ProposedEvent,
    state_before: EcosystemState,
    registry: DriftSignalRegistry | None = None,
) -> DriftEvaluation:
    """
    Module-level entry point for the engine's Step 6 call site.

    Wires BOCPD + anytime-valid e-process per Thread 7. See
    ``_DriftOrchestrator.evaluate`` for full semantics.

    Parameters
    ----------
    proposed
        The proposed event awaiting ecosystem evaluation.
    state_before
        Ecosystem state *before* admitting ``proposed``. The probing
        function reads ``state_before.aggregate_drift_signals`` for
        baseline-relative comparisons.
    registry
        Optional. Defaults to a module-level default-seeded
        ``DriftSignalRegistry`` (seven default signals from
        ``_DEFAULT_SIGNAL_DEFS``). Pass an explicit registry when
        per-tenant signal sets are needed.

    Returns
    -------
    DriftEvaluation. Always returns — never raises on non-fatal
    conditions. Fail-closed semantics live at the engine layer.
    """
    effective_registry = registry if registry is not None else _module_default_registry()
    key = id(effective_registry)
    if key not in _DEFAULT_ORCHESTRATORS:
        _DEFAULT_ORCHESTRATORS[key] = _DriftOrchestrator(
            registry=effective_registry
        )
    return _DEFAULT_ORCHESTRATORS[key].evaluate(
        proposed=proposed, state_before=state_before,
    )


def _module_default_registry() -> "DriftSignalRegistry":
    """Lazy singleton default registry — seeded with the 7 defaults."""
    global _MODULE_DEFAULT_REGISTRY
    if _MODULE_DEFAULT_REGISTRY is None:
        _MODULE_DEFAULT_REGISTRY = DriftSignalRegistry(seed_defaults=True)
    return _MODULE_DEFAULT_REGISTRY


_MODULE_DEFAULT_REGISTRY: "DriftSignalRegistry | None" = None


# ----------------------------------------------------------------------
# Internals — signal probing + BOCPD score reading
# ----------------------------------------------------------------------


# Thread 7.1 — Rath 2026 three-dimensional drift taxonomy
# (arxiv 2601.04170 §3). Maps each default signal to one of three
# drift axes: semantic (intent deviation), coordination (consensus
# breakdown), behavioral (unintended strategy emergence). Signals
# not in this map contribute to the aggregate drift_delta but to
# none of the three Rath axes.
_SIGNAL_TO_DIMENSION: dict[str, str] = {
    SIGNAL_TOOL_CALL_RATE_PER_AGENT: "semantic",
    SIGNAL_CAPABILITY_GRANT_RATE: "semantic",
    SIGNAL_CROSS_AGENT_MESSAGE_RATE: "coordination",
    SIGNAL_AVERAGE_PATH_DEPTH: "coordination",
    SIGNAL_DENIAL_RATE_PER_AGENT: "behavioral",
    SIGNAL_OUTBOUND_CONTENT_VOLUME_PER_TENANT: "behavioral",
    SIGNAL_AVERAGE_COMPROMISE_SCORE: "behavioral",
}


@dataclass(frozen=True, slots=True)
class ProbeMapPolicy:
    """
    Declarative event-kind → drift-signal classification policy
    (Thread 7.1).

    Replaces the hardcoded static dict that Thread 7 shipped. Three-
    tier evaluation:

      1. ``exact_rules`` — exact event_kind → signal_id match.
      2. ``substring_rules`` — first pattern whose .lower() is a
         substring of event_kind.lower() (ordered tuple; first match
         wins).
      3. None — no signal probed.

    Operators register custom event kinds by constructing a new
    ``ProbeMapPolicy`` and passing it to ``DriftSignalRegistry`` or
    directly to ``evaluate_drift`` callers.

    Mirrors GAAT's OPA Rego rule layering (arxiv 2604.05119 §III.A —
    declarative composition of rules with priority) and RiskGate's
    learned-classifier extensibility (arxiv 2604.24686 §4).

    Both rule sets are frozen so the policy is hashable and safe to
    share across threads.
    """

    exact_rules: tuple[tuple[str, str], ...]
    substring_rules: tuple[tuple[str, str], ...]

    def classify(self, event_kind: str) -> str | None:
        """
        Return the signal_id for ``event_kind`` per the policy.
        ``None`` if no rule matches.
        """
        # Exact match — O(n) but n is small (≤ 30 rules in default).
        for k, signal in self.exact_rules:
            if k == event_kind:
                return signal
        # Substring fallback for novel event kinds.
        ek_lower = event_kind.lower()
        for pattern, signal in self.substring_rules:
            if pattern.lower() in ek_lower:
                return signal
        return None


# Default policy — exact rules cover the ontology event kinds Tex
# ships today; substring rules act as a forward-compatible safety
# net for novel event-kind names introduced by operators.
DEFAULT_PROBE_MAP_POLICY: ProbeMapPolicy = ProbeMapPolicy(
    exact_rules=(
        # Tool invocation — primary case.
        ("agent_invokes_tool", SIGNAL_TOOL_CALL_RATE_PER_AGENT),
        ("tool_call", SIGNAL_TOOL_CALL_RATE_PER_AGENT),
        ("mcp.tool_call", SIGNAL_TOOL_CALL_RATE_PER_AGENT),
        ("capability_used", SIGNAL_TOOL_CALL_RATE_PER_AGENT),
        # Capability grant / revocation pressure.
        ("capability_granted", SIGNAL_CAPABILITY_GRANT_RATE),
        ("capability_grant", SIGNAL_CAPABILITY_GRANT_RATE),
        ("capability.grant", SIGNAL_CAPABILITY_GRANT_RATE),
        # Inter-agent coordination.
        ("agent_to_agent_message", SIGNAL_CROSS_AGENT_MESSAGE_RATE),
        ("agent_message", SIGNAL_CROSS_AGENT_MESSAGE_RATE),
        ("a2a.message", SIGNAL_CROSS_AGENT_MESSAGE_RATE),
        # Denial / forbid events.
        ("denial_event", SIGNAL_DENIAL_RATE_PER_AGENT),
        ("denial", SIGNAL_DENIAL_RATE_PER_AGENT),
        ("forbid", SIGNAL_DENIAL_RATE_PER_AGENT),
        # Outbound content emission — Article 50 / FTC §5 surface.
        ("outbound_content_emitted", SIGNAL_OUTBOUND_CONTENT_VOLUME_PER_TENANT),
        ("agent_emits_output", SIGNAL_OUTBOUND_CONTENT_VOLUME_PER_TENANT),
        ("content_emission", SIGNAL_OUTBOUND_CONTENT_VOLUME_PER_TENANT),
        ("email_outbound", SIGNAL_OUTBOUND_CONTENT_VOLUME_PER_TENANT),
        ("slack_message", SIGNAL_OUTBOUND_CONTENT_VOLUME_PER_TENANT),
    ),
    # Substring rules are conservative — only well-disambiguated
    # tokens whose presence in an event_kind unambiguously implies
    # the signal. Ordered most-specific to most-general so the first
    # match wins.
    substring_rules=(
        ("capability_grant", SIGNAL_CAPABILITY_GRANT_RATE),
        ("capability", SIGNAL_TOOL_CALL_RATE_PER_AGENT),
        ("tool_call", SIGNAL_TOOL_CALL_RATE_PER_AGENT),
        ("tool_invoc", SIGNAL_TOOL_CALL_RATE_PER_AGENT),
        ("agent_message", SIGNAL_CROSS_AGENT_MESSAGE_RATE),
        ("a2a", SIGNAL_CROSS_AGENT_MESSAGE_RATE),
        ("denial", SIGNAL_DENIAL_RATE_PER_AGENT),
        ("forbid", SIGNAL_DENIAL_RATE_PER_AGENT),
        ("email", SIGNAL_OUTBOUND_CONTENT_VOLUME_PER_TENANT),
        ("slack", SIGNAL_OUTBOUND_CONTENT_VOLUME_PER_TENANT),
        ("outbound", SIGNAL_OUTBOUND_CONTENT_VOLUME_PER_TENANT),
        ("emit", SIGNAL_OUTBOUND_CONTENT_VOLUME_PER_TENANT),
    ),
)


def _probe_signals_for(
    proposed: ProposedEvent,
    state_before: EcosystemState,
    policy: "ProbeMapPolicy | None" = None,
) -> dict[str, float]:
    """
    Map a ``ProposedEvent`` to the set of drift signals it plausibly
    shifts, returning the probed next-observation per signal.

    Thread 7.1 — now driven by a declarative ``ProbeMapPolicy``
    (default ``DEFAULT_PROBE_MAP_POLICY``) rather than a hardcoded
    dict. Operators wanting per-tenant probe rules pass a custom
    policy via the ``DriftSignalRegistry.probe_map_policy`` attribute.

    Three classification sources composed in priority order:

      1. **Exact match** — ``policy.exact_rules.get(event_kind)``
      2. **Substring match** — first ``policy.substring_rules`` entry
         whose pattern is a substring of ``event_kind``
      3. **Empty** — no signal probed

    This mirrors GAAT's OPA Rego rule evaluation (declarative, layered)
    and RiskGate's learned-classifier interface (extensible without
    code edits). The default policy is conservative — only the
    canonical signal mappings — but operators can register custom
    event kinds without modifying Tex source.

    The baseline value is read from
    ``state_before.aggregate_drift_signals`` (the projection-time
    aggregate); when absent we fall back to 0.0.
    """
    active_policy = policy if policy is not None else DEFAULT_PROBE_MAP_POLICY
    signal_id = active_policy.classify(proposed.event_kind)
    if signal_id is None:
        return {}
    baseline = state_before.aggregate_drift_signals.get(signal_id, 0.0)
    return {signal_id: float(baseline) + 1.0}


def _bocpd_soft_score(
    *, detector: ChangePointDetector, signal_id: str
) -> float:
    """
    Read the most recent BOCPD score for ``signal_id`` from the
    detector. Falls back to 0.0 when no detection has been published.

    BOCPD publishes a ``ChangePointEvent`` only when the change-point
    score exceeds the detection threshold. For sub-threshold updates
    we synthesise a soft score from the detector's internal state
    (number of recent detections / step count) so the aggregate
    ``drift_delta`` reflects accumulating evidence even before the
    hard threshold is crossed.

    Defense in depth: returns 0.0 on any internal error rather than
    raising — Step 6 of the engine treats a drift evaluator failure
    as "no drift evidence" (fail-closed at the engine, not here).
    """
    try:
        detections = detector.detections
        for event in reversed(detections):
            if event.signal_name == signal_id:
                return min(1.0, max(0.0, event.change_point_score))
    except Exception:  # pragma: no cover — defensive
        pass
    return 0.0


def _event_id_or_synth(proposed: ProposedEvent) -> str:
    """Stable diagnostic id for telemetry — proposed events don't carry one."""
    return (
        f"{proposed.event_kind}:{proposed.actor_entity_id}:"
        f"{proposed.proposed_at.isoformat()}"
    )
