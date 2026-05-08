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
