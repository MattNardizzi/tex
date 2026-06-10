"""
L9 — the live multiplicative e-value spine (Wave 2, first-green on-ramp).

What this is
------------
A streaming monitor that holds one ``AnytimeValidEProcess``
(``drift/_anytime_valid.py``, **reused verbatim** — no new primitive) per risk
``stream_id``, multiplicatively composes their per-step e-values into one
Ville-bounded sealed scalar, and raises a **monotone-lowering** hold
(PERMIT → ABSTAIN only) when that composite crosses the anytime-valid action
level. Each step is sealed as a ``SealedFact(DRIFT)`` into the M0
``SealedFactLedger`` (``provenance/decision_seal``-style), so the running
evidence is replayable and signed, not asserted.

The honest scope of THIS wave (read before extending)
-----------------------------------------------------
The brief (ROADMAP L9 / North-Star) asks eventually for ``drift × per-agent ×
voice-error`` as one scalar. We wire **only genuine drift e-processes** now,
and we are explicit about why the rest are excluded:

  * **per-agent deviation** is a heuristic score in ``[0, 1]`` — it is NOT an
    e-process null, so multiplying it in would fabricate a Ville bound it does
    not satisfy (the exact ``nanozk`` failure mode this project exists to never
    repeat). Excluded from the product this wave.
  * **CRC / OPE** are a frozen calibration certificate and a confidence-sequence
    bound respectively (see ``domain/evidence.EvidenceKind``); they are
    fail-closed *gates*, never multipliable e-values. The composer
    (``compose_spine``) drops any non-e-value into ``excluded_ids`` rather than
    inflating the product — a probabilistic signal may only ever *lower* a
    verdict.

So the composite is a product of true drift e-processes, and nothing else.

The two-sided correction — why the action level is ``2^K / α``, not ``1/α``
---------------------------------------------------------------------------
The verbatim e-process is built on ``|S_t|`` (it certifies drift in *either*
direction). For a single λ-component that is
``exp(λ|S_t| − ½λ²t) = max(e^{λS_t−½λ²t}, e^{−λS_t−½λ²t}) ≤ e^{λS_t−½λ²t} +
e^{−λS_t−½λ²t} = 2·[cosh(λS_t)e^{−½λ²t}]``, and ``cosh(λS_t)e^{−½λ²t}`` is a
mean-1 non-negative martingale under H0. Averaging over the λ-grid preserves the
bound, so the per-stream e-value satisfies ``E_t ≤ 2·M_t`` with ``M_t`` a mean-1
martingale. For ``K`` **independent** same-filtration streams the product obeys
``∏E_t ≤ 2^K·∏M_t`` and ``∏M_t`` is itself a mean-1 martingale, so Ville gives::

    P( sup_t  ∏E_t ≥ 2^K/α )  ≤  P( sup_t ∏M_t ≥ 1/α )  ≤  α.

Acting at the naive ``1/α`` level would therefore over-state the guarantee:
measured under H0 with continuous peeking (N=2000, T=500, α=0.05) the realized
false-hold at ``1/α`` is ≈0.060 (> α), while at the corrected ``2^K/α`` level it
is ≈0.028 (single) / ≈0.013 (K=2) — both ≤ α, target < 0.03. We do **not**
modify the verbatim primitive; we choose the *action threshold* honestly. See
``tests/test_risk_spine.py`` for the earning benchmark.

Anytime-valid is a gate, not a label
-------------------------------------
The spine only raises a hold when the composite is genuinely ``anytime_valid``
— every factor a sequentially-predictable e-process sharing **one** filtration,
where Ville's sup-over-time bound carries to the product (``compose_spine`` sets
this from the data, not from a name). Composing across *different* stream
filtrations is sealed honestly but ``anytime_valid=False`` and **never acts**:
the sup-time bound is not licensed without a Choe–Ramdas cross-filtration
adjuster (a later leap). That keeps the monotone-lowering action honest under
continuous peeking.

Where it runs in the PDP (so "each step is sealed" is precise)
--------------------------------------------------------------
The PDP calls :func:`apply_risk_spine` on its **routed branch only** — after the
router/predictive holds, never on the deterministic hard-FORBID short-circuit. So
a request that a structural/deterministic deny already FORBADE bypasses the spine
entirely (no observation consumed, no step sealed). That is by design and loses
nothing: a FORBID is never demotable, and skipping look-steps only restricts the
e-process to the observed sub-filtration, which preserves the martingale (optional
skipping). "Each step is sealed" is therefore *unconditional* for
:meth:`RiskSpine.observe` / :func:`apply_risk_spine`, and PDP-path-conditional
(routed branch) end-to-end.

Fail-closed to today's behaviour
--------------------------------
Opt-in, observation-driven, and inert by default. With no
``request.metadata["risk_spine"]`` (or no spine wired into the PDP) the spine is
a byte-for-byte no-op — no stream advances, nothing is sealed, the verdict is
unchanged. When active it can only ever demote a PERMIT to ABSTAIN. The null's
validity rests on the caller supplying genuinely *standardised* observations
(``x = (raw − baseline_mean) / baseline_stddev``) whose H0 is sub-Gaussian —
the same ``research-early`` caveat ``drift/evidence_adapter.py`` carries; the
math is from verified literature, the production-data validation of the null is
not yet earned.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any, Mapping
from uuid import UUID

from tex.domain.evidence import (
    CombinedEvidence,
    EvidenceMaturity,
    TexEvidence,
    compose_spine,
)
from tex.domain.finding import Finding
from tex.domain.severity import Severity
from tex.domain.verdict import Verdict
from tex.drift._anytime_valid import AnytimeValidEProcess  # reused VERBATIM
from tex.drift.evidence_adapter import certificate_to_tex_evidence
from tex.engine.router import RoutingResult
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind

__all__ = [
    "RiskStreamSpec",
    "RiskSpine",
    "SpineSignal",
    "apply_risk_spine",
    "seal_drift_step",
    "action_log_e_threshold",
    "RISK_SPINE_FLAG",
    "DEFAULT_ALPHA",
    "DRIFT_NULL",
    "DRIFT_FILTRATION",
    "DEFAULT_STREAMS",
]

_logger = logging.getLogger(__name__)

# Opt-in metadata key (mirrors systemic/probguard ``systemic_lookahead``). Shape:
#   request.metadata["risk_spine"] = {"observations": {"<stream_id>": <float>, ...}}
# where each float is a STANDARDISED observation for that stream.
_METADATA_KEY = "risk_spine"

# The uncertainty flag a spine breach raises. Descriptive; ``engine.hold``
# degrades gracefully on a flag it has no tailored pivot for (the verdict is
# still ABSTAIN and a hold is still built), exactly like the systemic flags.
RISK_SPINE_FLAG = "risk_spine_drift_breach"

DEFAULT_ALPHA: float = 0.05

# log of the two-sided correction factor (see module docstring): the verbatim
# ``|S_t|`` e-process obeys E_t <= 2 M_t with M_t a mean-1 martingale.
_ABS_FACTOR_LOG: float = math.log(2.0)

# The single drift stream wired live this wave. One stream ⇒ one filtration ⇒
# the composite is trivially an e-process on one filtration (anytime-valid).
DRIFT_NULL = "drift:no_regime_change"
DRIFT_FILTRATION = "risk:spine_drift"

# The independence/sequential assertion sealed alongside any multi-factor
# product. Honest and attackable: it asserts the composed streams are
# independent e-processes adapted to ONE shared look schedule, so the running
# product is a test (super)martingale under optional continuation (Safe Testing,
# Grünwald–de Heide–Koolen, JRSS-B 86(5) 2024). A single-factor composite
# trivially satisfies it. (The dependence-robust *mean* merge — the spine's
# fallback when independence cannot be defended — is the admissible alternative
# per Wang, Biometrika 112(2) 2025; it is NOT what a product asserts.)
_INDEPENDENCE_JUSTIFICATION = (
    "drift e-processes composed are independent and adapted to one shared "
    "look schedule (filtration); the running product is a test supermartingale "
    "under optional continuation (Safe Testing, Grünwald–de Heide–Koolen, "
    "JRSS-B 2024). Validity of each per-stream sub-Gaussian H0 is research-early "
    "until benchmarked on production data."
)


def action_log_e_threshold(alpha: float, k: int) -> float:
    """The abs-corrected anytime-valid action level in log space: ``log(2^K/α)``.

    The spine raises a hold when the composite ``log_e_value`` reaches this. The
    ``2^K`` factor is the rigorous correction for the verbatim two-sided
    ``|S_t|`` construction (module docstring): it makes the realized false-hold
    provably ``≤ α`` rather than the ``≈2α`` the naive ``1/α`` level yields.
    """
    if not 0.0 < alpha < 1.0:
        raise ValueError(f"alpha must be in (0, 1), got {alpha!r}")
    if k < 1:
        raise ValueError(f"k (number of e-value factors) must be ≥ 1, got {k!r}")
    return k * _ABS_FACTOR_LOG + math.log(1.0 / alpha)


@dataclass(frozen=True, slots=True)
class RiskStreamSpec:
    """One declared risk stream: its id, the null it tests, and its filtration.

    Streams sharing a ``filtration_id`` may be product-composed into an
    anytime-valid scalar; streams on different filtrations are sealed honestly
    but never licensed for the sup-time Ville action (see module docstring).
    """

    stream_id: str
    null_hypothesis_id: str = DRIFT_NULL
    filtration_id: str = DRIFT_FILTRATION


# The live default: a single drift stream. The multiplicative machinery composes
# N same-filtration streams (benchmarked in tests/test_risk_spine.py), but the
# honest minimum wired this wave is one genuine drift e-process.
DEFAULT_STREAMS: tuple[RiskStreamSpec, ...] = (RiskStreamSpec("drift"),)


@dataclass(frozen=True, slots=True)
class SpineSignal:
    """Pure result of one spine step — what was observed, and whether it acts.

    ``acted`` is the e-process action condition ALONE (composite is an
    anytime-valid e-value crossing ``2^K/α``); the PERMIT→ABSTAIN verdict gate
    is applied separately in :func:`apply_risk_spine` so the monotone-lowering
    invariant lives at one guard.
    """

    checked: bool
    acted: bool
    combined: CombinedEvidence | None
    action_log_e_threshold: float
    reason: str


_NEUTRAL_SIGNAL = SpineSignal(
    checked=False,
    acted=False,
    combined=None,
    action_log_e_threshold=0.0,
    reason="",
)


@dataclass(slots=True)
class RiskSpine:
    """Streaming multiplicative e-value spine — one ``AnytimeValidEProcess`` per
    ``stream_id``, composed into one sealed Ville-bounded scalar per step.

    Stateful by design (a *live* monitor accumulates across requests); the state
    lives on this injected instance, never in a module global, so a PDP that
    wires no spine is unaffected and tests construct isolated spines. Mirrors how
    the CRC gate holds calibration state on its instance — and like the CRC gate
    it is a monotone-lowering layer over the deterministic verdict, not part of
    the determinism fingerprint.
    """

    streams: tuple[RiskStreamSpec, ...] = DEFAULT_STREAMS
    alpha: float = DEFAULT_ALPHA
    ledger: SealedFactLedger | None = None
    maturity: EvidenceMaturity = EvidenceMaturity.RESEARCH_EARLY
    _procs: dict[str, AnytimeValidEProcess] = field(default_factory=dict)
    _spec_by_id: dict[str, RiskStreamSpec] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 < self.alpha < 1.0:
            raise ValueError(f"alpha must be in (0, 1), got {self.alpha!r}")
        if not self.streams:
            raise ValueError("RiskSpine requires at least one RiskStreamSpec")
        for spec in self.streams:
            if spec.stream_id in self._spec_by_id:
                raise ValueError(f"duplicate stream_id {spec.stream_id!r}")
            self._spec_by_id[spec.stream_id] = spec

    def observe(
        self,
        observations: Mapping[str, float],
        *,
        decision_id: UUID | None = None,
    ) -> SpineSignal:
        """Advance every known stream that has a fresh standardised observation,
        compose their e-values into one sealed scalar, seal it, and report
        whether it raises a hold.

        Pure of any request coupling; safe to drive directly from a benchmark.
        Unknown stream ids and non-finite observations are dropped fail-closed
        (a monitor must never raise into the request path). With no usable
        observation this is a no-op (nothing advances, nothing is sealed).
        """
        snapshots: list[TexEvidence] = []
        for stream_id, raw in observations.items():
            spec = self._spec_by_id.get(stream_id)
            if spec is None:
                continue
            try:
                x = float(raw)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(x):
                continue
            proc = self._procs.get(stream_id)
            if proc is None:
                proc = AnytimeValidEProcess()
                self._procs[stream_id] = proc
            cert = proc.observe(standardised_x=x)
            snapshots.append(
                certificate_to_tex_evidence(
                    cert,
                    stream_id=stream_id,
                    null_hypothesis_id=spec.null_hypothesis_id,
                    filtration_id=spec.filtration_id,
                    decision_id=decision_id,
                    alpha=self.alpha,
                    maturity=self.maturity,
                )
            )

        if not snapshots:
            return _NEUTRAL_SIGNAL

        # Multiplicative composition (GROW-optimal product of true e-values).
        # ``compose_spine`` drops any non-e-value, sets ``anytime_valid`` from
        # the shared-filtration data, and seals an independence justification.
        combined = compose_spine(
            snapshots,
            decision_id=decision_id,
            prefer_product=True,
            independence_justification=_INDEPENDENCE_JUSTIFICATION,
        )

        k = max(1, combined.n_components)
        threshold = action_log_e_threshold(self.alpha, k)

        # Act ONLY on a genuine anytime-valid e-value crossing the abs-corrected
        # level. anytime_valid=False (e.g. mixed filtration) ⇒ never act — the
        # Ville sup-bound is not licensed, so a continuous-peeking hold would be
        # dishonest. This is the fail-closed honesty gate.
        acted = (
            combined.is_true_e_value
            and combined.anytime_valid
            and combined.log_e_value >= threshold
        )

        self._seal(combined, k=k, threshold=threshold, acted=acted)

        reason = (
            (
                f"risk e-value spine breach: composite E_t={combined.e_value:.3g} "
                f"≥ 2^{k}/α={math.exp(threshold):.3g} (anytime-valid, α={self.alpha}); "
                "drift in a monitored risk stream — holding for review "
                "(PERMIT→ABSTAIN). Ville false-hold ≤ α; NOT a proof of safety."
            )
            if acted
            else ""
        )
        return SpineSignal(
            checked=True,
            acted=acted,
            combined=combined,
            action_log_e_threshold=threshold,
            reason=reason,
        )

    def evaluate(self, request: Any) -> SpineSignal:
        """Read standardised observations off ``request.metadata['risk_spine']``
        and advance the spine. Returns the neutral (no-op) signal when the key
        is absent — the inert, fail-closed default."""
        metadata = getattr(request, "metadata", None)
        if not isinstance(metadata, Mapping):
            return _NEUTRAL_SIGNAL
        raw = metadata.get(_METADATA_KEY)
        if not isinstance(raw, Mapping):
            return _NEUTRAL_SIGNAL
        observations = raw.get("observations")
        if not isinstance(observations, Mapping) or not observations:
            return _NEUTRAL_SIGNAL
        decision_id = getattr(request, "request_id", None)
        if not isinstance(decision_id, UUID):
            decision_id = None
        return self.observe(observations, decision_id=decision_id)

    # ------------------------------------------------------------------ seal
    def _seal(
        self, combined: CombinedEvidence, *, k: int, threshold: float, acted: bool
    ) -> None:
        seal_drift_step(
            self.ledger,
            combined,
            alpha=self.alpha,
            k=k,
            action_log_e_threshold=threshold,
            acted=acted,
            stream_ids=tuple(self._spec_by_id),
            maturity=self.maturity,
        )


def build_drift_fact(
    combined: CombinedEvidence,
    *,
    alpha: float,
    k: int,
    action_log_e_threshold: float,
    acted: bool,
    stream_ids: tuple[str, ...],
    maturity: EvidenceMaturity,
) -> SealedFact:
    """Map one composite e-value step to a canonical ``SealedFact(DRIFT)``.

    Pure. The composite ``CombinedEvidence`` (with its own ``is_true_e_value`` /
    ``anytime_valid`` honesty flags) is embedded as the proof-carrying
    ``evidence``, so the seal records exactly what guarantee held. The ``claim``
    is narrow: it asserts a drift e-value was observed and what its crossing
    would do — never that the action is correct or that safety is proven.
    """
    return SealedFact(
        kind=SealedFactKind.DRIFT,
        subject_id=str(combined.decision_id) if combined.decision_id else None,
        claim=(
            f"drift e-value spine step: composite log_e={combined.log_e_value:.6g} "
            f"over {k} e-process factor(s) {list(stream_ids)} "
            f"(anytime_valid={combined.anytime_valid}); crossing 2^{k}/α "
            f"(α={alpha}) raises a monotone-lowering ABSTAIN with Ville "
            "false-hold ≤ α (abs-corrected for the two-sided |S_t| "
            "construction). Authorship+integrity sealed; NOT a proof of safety."
        ),
        evidence=combined,
        maturity=maturity,
        detail={
            "alpha": alpha,
            "k": k,
            "action_log_e_threshold": action_log_e_threshold,
            "log_e_value": combined.log_e_value,
            "anytime_valid": combined.anytime_valid,
            "is_true_e_value": combined.is_true_e_value,
            "acted": acted,
            "combiner": combined.combiner,
            "stream_ids": list(stream_ids),
            "n_components": combined.n_components,
        },
    )


def seal_drift_step(
    ledger: SealedFactLedger | None,
    combined: CombinedEvidence,
    *,
    alpha: float,
    k: int,
    action_log_e_threshold: float,
    acted: bool,
    stream_ids: tuple[str, ...],
    maturity: EvidenceMaturity,
) -> SealedFact | None:
    """Seal one composite e-value step into ``ledger`` (``decision_seal``-style).

    Fail-closed and observation-only: ``ledger is None`` → no-op returning
    ``None`` (today's behaviour, zero cost); an append failure is logged and
    returns ``None`` — it never propagates into the verdict path. Returns the
    sealed ``SealedFact`` (not the record) so a caller can introspect without a
    ledger.
    """
    fact = build_drift_fact(
        combined,
        alpha=alpha,
        k=k,
        action_log_e_threshold=action_log_e_threshold,
        acted=acted,
        stream_ids=stream_ids,
        maturity=maturity,
    )
    if ledger is None:
        return fact
    try:
        ledger.append(fact)
    except Exception:  # pragma: no cover - defensive; a seal must never break a verdict
        _logger.warning(
            "DRIFT seal failed; verdict unaffected, step not sealed", exc_info=True
        )
    return fact


def apply_risk_spine(
    spine: RiskSpine | None, *, base: RoutingResult, request: Any
) -> RoutingResult:
    """Advance the spine for this request and apply its monotone-lowering hold.

    The single additive call the PDP makes on its routed branch. Fail-closed:
    ``spine is None`` → returns ``base`` unchanged (today's behaviour). The spine
    always advances + seals its monitor when observations are present, but the
    verdict is only ever demoted **PERMIT → ABSTAIN** — never raised, never
    relaxed, and the deterministic structural floor is never fired (a high
    e-value is evidence against a null, not a proof). That single guard below is
    the whole monotonicity invariant.
    """
    if spine is None:
        return base

    signal = spine.evaluate(request)  # advances streams + seals the step
    if not signal.acted:
        return base

    # Monotone-lowering guard: only a PERMIT may be demoted. Everything else is
    # returned untouched — signals lower, never raise.
    if base.verdict is not Verdict.PERMIT:
        return base

    combined = signal.combined
    assert combined is not None  # acted ⇒ combined is set
    reasons = tuple(base.reasons) + (signal.reason,)
    flags = tuple(base.uncertainty_flags) + (RISK_SPINE_FLAG,)
    scores = dict(base.scores)
    # Surface the Ville p-value as a bounded [0,1] score for telemetry (it is a
    # p-value, not a risk magnitude — small means strong evidence of drift).
    p = combined.ville_p_value
    if p is not None:
        scores["risk_spine_ville_p"] = max(0.0, min(1.0, p))
    findings = tuple(base.findings) + (
        Finding(
            source="engine.risk_spine",
            rule_name="risk_spine_drift_breach",
            severity=Severity.WARNING,
            message=signal.reason,
            metadata={
                "log_e_value": round(combined.log_e_value, 6),
                "action_log_e_threshold": round(signal.action_log_e_threshold, 6),
                "anytime_valid": combined.anytime_valid,
                "n_components": combined.n_components,
                "combiner": combined.combiner,
                "tier": "anytime_valid_hold",
            },
        ),
    )

    return RoutingResult(
        verdict=Verdict.ABSTAIN,
        confidence=base.confidence,
        final_score=base.final_score,
        reasons=reasons,
        findings=findings,
        scores=scores,
        uncertainty_flags=flags,
        asi_findings=base.asi_findings,
        semantic_dominance_override_fired=base.semantic_dominance_override_fired,
    )
