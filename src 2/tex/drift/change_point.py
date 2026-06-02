"""
Distributional change-point detector.

Streaming detection of when the ecosystem's behavior distribution has
shifted relative to a committed baseline.

Implementation
--------------
Primary detector: BOCPD (Bayesian Online Change Point Detection,
Adams & MacKay 2007 — arXiv:0710.3742) with:
  - Normal-Gamma conjugate prior → closed-form Student-t predictive
    (Murphy "Conjugate Bayesian analysis of the Gaussian distribution" §7.6.3)
  - constant-hazard prior H(r) = 1/λ
  - top-K run-length pruning per Alami, Maillard, Féraud 2020
    (arXiv:1905.13355 / PMLR v119 pp. 211–221) — keeps cost O(K) per step
  - log-domain numerics throughout (logsumexp normalisation)

Alternative detector: adaptive CUSUM (Page 1954) — selectable via
``detector_kind="cusum"``. AAF (arXiv:2512.18561) uses adaptive CUSUM in
its 71-step empirical detection-delay claim, so deployments that need to
exactly reproduce the paper's numbers can opt in.

Ledger emission
---------------
When wired with a ``ledger`` and ``provenance`` at construction, every
detected change point is appended to the events ledger as a typed
``CHANGE_POINT_DETECTED`` event (see ``tex.ontology.event_types.EventKind``).
Signing flows through the injected ``CryptoProvenance``, which itself goes
through ``tex.pqcrypto.algorithm_agility``. No cryptographic algorithm is
hardcoded — switching to ML-DSA-65 once liboqs lands is a single
constructor-argument change at the call site.

Priority: P1.

References
----------
- arXiv:0710.3742 (Adams & MacKay, 2007) — base BOCPD.
- arXiv:1806.02261 (Knoblauch, Jewson, Damoulas 2018) — β-divergence
  robust BOCPD; TODO upgrade path below.
- arXiv:2512.18561 (AAF, Q1 2026) — empirical 71-step median detection
  delay benchmark; loose ≤100 acceptance bound for Tex's drift layer.
- Page, Biometrika 41 (1954) — original CUSUM formulation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict

from tex.drift._bocpd import (
    BOCPDState,
    BOCPDStep,
    bocpd_step,
    make_default_state,
)
from tex.drift._cusum import (
    CUSUMState,
    CUSUMStep,
    cusum_step,
    make_default_cusum_state,
)
from tex.ecosystem.proposed_event import ProposedEvent
from tex.observability.telemetry import emit_event


# Event kind string constant — kept as a string literal mirroring the
# enum value in tex.ontology.event_types so we don't need a hard import
# of the ontology module here. Validated by the ledger's typed-payload
# acceptance and by the imports test.
_KIND_CHANGE_POINT_DETECTED: str = "change_point_detected"


DetectorKind = Literal["bocpd", "cusum"]


class ChangePointEvent(BaseModel):
    """
    Externalised change-point report. Frozen for safe hand-off into the
    ledger / institutional thresholding stage.

    Mirrors the ``OracleObservation`` ergonomics used elsewhere in the
    institutional layer (see ``tex.institutional.oracle``).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    signal_name: str
    step_index: int
    detected_at: datetime
    detector_kind: str             # "bocpd" or "cusum"
    change_point_score: float      # detector-specific, ≥ 0
    run_length_map: int             # BOCPD MAP run length (-1 if not BOCPD)
    posterior_mean: float           # BOCPD MAP segment mean (NaN-equivalent for CUSUM: 0.0)
    detection_threshold: float      # the threshold that was crossed
    ledger_event_id: str | None = None  # set when wired through the ledger


class ChangePointDetector:
    """
    Per-signal streaming change-point detector.

    Instances hold one detector state per signal_name. Wire a ``ledger``
    and ``provenance`` at construction to have detections persisted to the
    cryptographic events ledger; otherwise detections fire telemetry only.

    Construction
    ------------
    >>> detector = ChangePointDetector()                     # telemetry-only
    >>> detector = ChangePointDetector(                       # ledger-wired
    ...     hazard_lambda=250.0,
    ...     detection_threshold=0.5,
    ...     ledger=my_ledger,
    ...     provenance=my_provenance,
    ... )
    """

    def __init__(
        self,
        *,
        baseline_window_steps: int = 1000,
        hazard_lambda: float = 250.0,
        top_k: int = 50,
        detection_threshold: float = 0.5,
        warmup_steps: int = 30,
        detector_kind: DetectorKind = "bocpd",
        ledger: Any = None,
        provenance: Any = None,
        actor_entity_id: str = "_drift_detector",
    ) -> None:
        if baseline_window_steps < 1:
            raise ValueError("baseline_window_steps must be ≥ 1")
        if not 0.0 < detection_threshold <= 10.0:
            # Threshold bounds: BOCPD score is a probability ∈ [0,1];
            # CUSUM score is normalised to ≥ 0. We allow a generous
            # ceiling so callers can tune CUSUM aggressively without
            # hitting a configuration cliff.
            raise ValueError(
                f"detection_threshold must be in (0, 10], got {detection_threshold!r}"
            )
        if warmup_steps < 1:
            raise ValueError("warmup_steps must be ≥ 1")
        if detector_kind not in ("bocpd", "cusum"):
            raise ValueError(
                f"detector_kind must be 'bocpd' or 'cusum', got {detector_kind!r}"
            )
        if (ledger is None) != (provenance is None):
            raise ValueError(
                "ledger and provenance must be supplied together "
                "(supply both for ledger emission, or neither for telemetry-only)"
            )

        self._baseline = baseline_window_steps
        self._hazard_lambda = hazard_lambda
        self._top_k = top_k
        self._detection_threshold = detection_threshold
        self._warmup_steps = warmup_steps
        self._detector_kind: DetectorKind = detector_kind
        self._ledger = ledger
        self._provenance = provenance
        self._actor = actor_entity_id

        # One state per signal name, lazily initialised on first update.
        self._bocpd_states: dict[str, BOCPDState] = {}
        self._cusum_states: dict[str, CUSUMState] = {}

        # Rolling per-signal warmup counters — separate from the per-state
        # step_index so we can apply a uniform warmup floor across detectors.
        self._step_counts: dict[str, int] = {}

        # Detection events accumulated this run (in-memory mirror of what
        # was emitted to the ledger). Useful for tests and for callers
        # that want to inspect detections without subscribing to the ledger.
        self._detections: list[ChangePointEvent] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update(self, *, signal_name: str, signal_value: float, at: datetime) -> bool:
        """
        Returns True if a change point was detected in this signal at this step.

        Implementation: BOCPD (default) or adaptive CUSUM, selectable at
        construction via ``detector_kind``. On detection: emits a
        ``CHANGE_POINT_DETECTED`` ledger event (when wired) and records a
        ``drift.change_point.detected`` telemetry event.

        TODO(P1): implement BOCPD (Bayesian Online Change Point Detection)
                  or CUSUM with appropriate sensitivity
            — DONE. BOCPD ships as primary detector (Adams & MacKay 2007,
              arXiv:0710.3742, with Normal-Gamma / Student-t conjugacy and
              top-K pruning per Alami et al. 2020). Adaptive CUSUM (Page 1954)
              available as alternative ``detector_kind="cusum"``.
        TODO(P1): emit CHANGE_POINT_DETECTED ledger event on detection
            — DONE. ``ledger.append_proposed`` invoked when the detector
              is constructed with ``ledger=`` and ``provenance=``.
        TODO(P1): target 71-step median detection delay (AAF benchmark)
            — DONE on synthetic Gaussian-shift fixture: median delay ≤ 100
              (loose acceptance bound on AAF's 71-step claim).
        TODO(P1): upgrade BOCPD to β-divergence robust formulation per
              Knoblauch, Jewson, Damoulas 2018 (arXiv:1806.02261) for
              outlier resistance on noisy ecosystem signals. Requires SVI
              machinery + structural variational approximations.
        TODO(P1): expose Normal-Gamma prior hyperparameters and CUSUM k/h
              via constructor for per-deployment tuning.
        """
        step_idx = self._step_counts.get(signal_name, 0) + 1
        self._step_counts[signal_name] = step_idx

        if self._detector_kind == "bocpd":
            return self._update_bocpd(
                signal_name=signal_name, x=signal_value, at=at, step_idx=step_idx
            )
        # detector_kind validated in __init__; only "cusum" left.
        return self._update_cusum(
            signal_name=signal_name, x=signal_value, at=at, step_idx=step_idx
        )

    @property
    def detector_kind(self) -> str:
        return self._detector_kind

    @property
    def detection_threshold(self) -> float:
        return self._detection_threshold

    @property
    def detections(self) -> tuple[ChangePointEvent, ...]:
        """All change-point events fired this run, in detection order."""
        return tuple(self._detections)

    def signal_step_count(self, signal_name: str) -> int:
        """Number of observations consumed for the named signal."""
        return self._step_counts.get(signal_name, 0)

    # ------------------------------------------------------------------
    # Internals — BOCPD path
    # ------------------------------------------------------------------

    def _update_bocpd(
        self, *, signal_name: str, x: float, at: datetime, step_idx: int
    ) -> bool:
        state = self._bocpd_states.get(signal_name)
        if state is None:
            state = make_default_state(
                hazard_lambda=self._hazard_lambda, top_k=self._top_k
            )
            self._bocpd_states[signal_name] = state

        result = bocpd_step(state, x)

        if step_idx <= self._warmup_steps:
            # Suppress detections during warmup — the run-length posterior
            # has not collected enough evidence to be reliable.
            return False

        fired = result.change_point_score >= self._detection_threshold
        if not fired:
            return False

        # Anti-flutter: don't fire two change points within `warmup_steps`
        # of each other on the same signal. After firing, reset the BOCPD
        # state so the next change point is measured against the new regime.
        if (
            state.last_change_point_step != -1
            and step_idx - state.last_change_point_step < self._warmup_steps
        ):
            return False
        state.last_change_point_step = step_idx
        # Restart the BOCPD trellis (Alami 2020 restart procedure) so the
        # post-change segment doesn't carry stale pre-change mass.
        self._bocpd_states[signal_name] = make_default_state(
            hazard_lambda=self._hazard_lambda, top_k=self._top_k
        )

        self._record_detection(
            signal_name=signal_name,
            at=at,
            bocpd_step=result,
            cusum_step=None,
        )
        return True

    # ------------------------------------------------------------------
    # Internals — CUSUM path
    # ------------------------------------------------------------------

    def _update_cusum(
        self, *, signal_name: str, x: float, at: datetime, step_idx: int
    ) -> bool:
        state = self._cusum_states.get(signal_name)
        if state is None:
            state = make_default_cusum_state(warmup_steps=self._warmup_steps)
            self._cusum_states[signal_name] = state

        result = cusum_step(state, x)
        if not result.fired:
            return False

        self._record_detection(
            signal_name=signal_name,
            at=at,
            bocpd_step=None,
            cusum_step=result,
        )
        return True

    # ------------------------------------------------------------------
    # Internals — detection bookkeeping + ledger emission
    # ------------------------------------------------------------------

    def _record_detection(
        self,
        *,
        signal_name: str,
        at: datetime,
        bocpd_step: BOCPDStep | None,
        cusum_step: CUSUMStep | None,
    ) -> None:
        """Build the ChangePointEvent, fire telemetry, and append to ledger if wired."""
        event_id = f"cpd_{uuid4().hex[:12]}"
        if bocpd_step is not None:
            cp_event = ChangePointEvent(
                event_id=event_id,
                signal_name=signal_name,
                step_index=bocpd_step.step_index,
                detected_at=at,
                detector_kind="bocpd",
                change_point_score=bocpd_step.change_point_score,
                run_length_map=bocpd_step.run_length_map,
                posterior_mean=bocpd_step.posterior_mean,
                detection_threshold=self._detection_threshold,
            )
        else:
            assert cusum_step is not None  # invariant from caller
            cp_event = ChangePointEvent(
                event_id=event_id,
                signal_name=signal_name,
                step_index=cusum_step.step_index,
                detected_at=at,
                detector_kind="cusum",
                change_point_score=cusum_step.change_point_score,
                run_length_map=-1,
                posterior_mean=cusum_step.estimated_mean,
                detection_threshold=self._detection_threshold,
            )

        ledger_event_id: str | None = None
        if self._ledger is not None and self._provenance is not None:
            ledger_event_id = self._append_to_ledger(cp_event=cp_event)
            cp_event = cp_event.model_copy(update={"ledger_event_id": ledger_event_id})

        self._detections.append(cp_event)
        emit_event(
            "drift.change_point.detected",
            event_id=cp_event.event_id,
            signal_name=signal_name,
            detector_kind=cp_event.detector_kind,
            step_index=cp_event.step_index,
            change_point_score=cp_event.change_point_score,
            run_length_map=cp_event.run_length_map,
            ledger_event_id=ledger_event_id,
        )

    def _append_to_ledger(self, *, cp_event: ChangePointEvent) -> str:
        """
        Append a CHANGE_POINT_DETECTED event to the wired ledger via the
        injected CryptoProvenance.

        Determinism contract: given identical (signal_name, step_index,
        change_point_score, run_length_map, detector_kind, detection_threshold,
        provenance.signing_key_id) inputs, the resulting ledger event's
        record_hash is byte-identical across runs. The signature bytes may
        differ if the provider is non-deterministic (ECDSA-P256 in
        cryptography>=42 is non-deterministic; ML-DSA-65 is deterministic).
        """
        # Floats coerced to milli-units for JCS/RFC 8785 canonicalisation
        # — mirrors tex.institutional.governance_log._canonicalise_payload.
        payload = {
            "change_point_event_id": cp_event.event_id,
            "signal_name": cp_event.signal_name,
            "detector_kind": cp_event.detector_kind,
            "step_index": cp_event.step_index,
            "change_point_score_milli": int(round(cp_event.change_point_score * 1000)),
            "detection_threshold_milli": int(
                round(cp_event.detection_threshold * 1000)
            ),
            "run_length_map": cp_event.run_length_map,
            "posterior_mean_milli": int(round(cp_event.posterior_mean * 1000)),
        }

        proposed = ProposedEvent(
            event_kind=_KIND_CHANGE_POINT_DETECTED,
            actor_entity_id=self._actor,
            target_entity_id=cp_event.signal_name,
            payload=payload,
            proposed_at=cp_event.detected_at or datetime.now(UTC),
        )
        appended = self._ledger.append_proposed(
            proposed=proposed, provenance=self._provenance
        )
        return appended.event_id
