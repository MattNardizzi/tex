"""
Wire the existing anytime-valid drift e-process to the sealed evidence type.

``drift/_anytime_valid.py`` is a pure, stdlib-only mixture e-process: feed it
standardised observations and it returns an ``AnytimeValidCertificate`` whose
``log_e_value`` is a true Ville-bounded test-martingale e-value. This module is
the bridge that lifts that certificate into a sealed ``TexEvidence``
(``kind=E_PROCESS``, ``is_true_e_value=True``, ``sequentially_predictable=True``)
so the multiplicative e-value spine can compose it and the ``SealedFactLedger``
can seal it. Keeping the bridge here leaves the e-process core dependency-free
(stdlib-only), which is a real virtue — the math is testable and reusable
without pulling in pydantic.

Two named risk streams the brief calls out (ROADMAP §E):

  * ``false_permit`` — H0: "the false-permit rate is at or below its certified
    budget." A rising e-value is evidence the rate is drifting *above* budget.
  * ``abstain_rate`` — H0: "the abstain rate is at or below baseline." A rising
    e-value is evidence the system is growing more uncertain.

Monotone-lowering, preserved: a large e-value is evidence *against* the stream's
safety null, so it can only ever move a verdict toward caution
(PERMIT→ABSTAIN→FORBID). It can never lower one. **Acting** on a breach —
tightening the verdict/calibration thresholds — is the engine/abstain track's
job; this module only produces the honest, sealed signal and a breach flag.

Maturity is ``RESEARCH_EARLY``, deliberately not ``RESEARCH_SOLID``: the
e-process *construction* is from verified literature (a mixture test
martingale), but the null it tests on these streams — that standardised
risk-stream deviations are sub-Gaussian under H0 — is **not yet validated on
real production data**. No benchmark has earned a stronger tag. The Ville bound
is only as good as that assumption; until a benchmark validates it, the honest
tag is research-early. (Tag honestly; earn the upgrade later.)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

from tex.domain.evidence import EvidenceKind, EvidenceMaturity, TexEvidence
from tex.drift._anytime_valid import (
    AnytimeValidCertificate,
    AnytimeValidEProcess,
)

__all__ = [
    "FALSE_PERMIT_STREAM",
    "ABSTAIN_RATE_STREAM",
    "FALSE_PERMIT_NULL",
    "ABSTAIN_RATE_NULL",
    "FALSE_PERMIT_FILTRATION",
    "ABSTAIN_RATE_FILTRATION",
    "certificate_to_tex_evidence",
    "RiskStreamEProcess",
    "false_permit_monitor",
    "abstain_rate_monitor",
]

# ── Stream identifiers, nulls, filtrations ──────────────────────────────────
FALSE_PERMIT_STREAM = "false_permit"
ABSTAIN_RATE_STREAM = "abstain_rate"

FALSE_PERMIT_NULL = "risk:false_permit_rate_at_or_below_budget"
ABSTAIN_RATE_NULL = "risk:abstain_rate_at_or_below_baseline"

# Distinct per stream on purpose: each is its own filtration, so the spine
# treats a cross-stream merge as mixed-filtration (anytime_valid=False) until a
# Choe–Ramdas adjuster lands — never silently overclaiming the sup-time bound.
FALSE_PERMIT_FILTRATION = "risk:false_permit_stream"
ABSTAIN_RATE_FILTRATION = "risk:abstain_rate_stream"

# Default maturity for a wired risk-stream e-value (see module docstring).
_DEFAULT_MATURITY = EvidenceMaturity.RESEARCH_EARLY


def certificate_to_tex_evidence(
    cert: AnytimeValidCertificate,
    *,
    stream_id: str,
    null_hypothesis_id: str,
    filtration_id: str,
    decision_id: UUID | None = None,
    alpha: float | None = None,
    maturity: EvidenceMaturity = _DEFAULT_MATURITY,
) -> TexEvidence:
    """Lift one drift ``AnytimeValidCertificate`` into a sealed ``TexEvidence``.

    The certificate's ``log_e_value`` is a genuine mixture test-martingale
    e-value, so the snapshot is honestly ``kind=E_PROCESS``,
    ``is_true_e_value=True``, ``sequentially_predictable=True`` (the running
    mixture is an e-variable conditional on its own past at each step). Nothing
    here asserts a property the certificate does not deliver.
    """
    return TexEvidence(
        decision_id=decision_id,
        stream_id=stream_id,
        kind=EvidenceKind.E_PROCESS,
        maturity=maturity,
        is_true_e_value=True,
        log_e_value=cert.log_e_value,
        null_hypothesis_id=null_hypothesis_id,
        filtration_id=filtration_id,
        alpha=alpha,
        sequentially_predictable=True,
        sample_size=cert.sample_size,
    )


@dataclass(slots=True)
class RiskStreamEProcess:
    """An ``AnytimeValidEProcess`` bound to one named risk stream, emitting a
    sealed ``TexEvidence`` per observation.

    One instance per stream. Feed it standardised observations
    (``x = (raw - baseline_mean) / baseline_stddev``); each ``observe`` returns
    the snapshot the spine composes. ``is_breached(alpha)`` reports whether the
    stream currently rejects its safety null at level ``alpha`` with the
    anytime-valid (Ville) guarantee — the breach signal the engine/abstain track
    gates a tightening on.
    """

    stream_id: str
    null_hypothesis_id: str
    filtration_id: str
    alpha: float = 0.05
    maturity: EvidenceMaturity = _DEFAULT_MATURITY
    _ep: AnytimeValidEProcess = field(default_factory=AnytimeValidEProcess)
    _latest: AnytimeValidCertificate | None = field(default=None)

    def __post_init__(self) -> None:
        if not 0.0 < self.alpha < 1.0:
            raise ValueError(f"alpha must be in (0, 1), got {self.alpha!r}")

    def observe(
        self, *, standardised_x: float, decision_id: UUID | None = None
    ) -> TexEvidence:
        """Consume one standardised observation and return the sealed snapshot."""
        cert = self._ep.observe(standardised_x=standardised_x)
        self._latest = cert
        return certificate_to_tex_evidence(
            cert,
            stream_id=self.stream_id,
            null_hypothesis_id=self.null_hypothesis_id,
            filtration_id=self.filtration_id,
            decision_id=decision_id,
            alpha=self.alpha,
            maturity=self.maturity,
        )

    @property
    def latest_certificate(self) -> AnytimeValidCertificate | None:
        """The most recent raw certificate, for auditor sanity-checks."""
        return self._latest

    def is_breached(self, alpha: float | None = None) -> bool:
        """True iff the stream currently rejects its safety null at ``alpha``
        (defaults to the monitor's ``alpha``) with the anytime-valid guarantee.
        False before any observation."""
        if self._latest is None:
            return False
        return self._latest.is_significant_at(self.alpha if alpha is None else alpha)

    def reset(self) -> None:
        """Restart the e-process after a confirmed regime change / a sealed
        human act, beginning certification afresh against the new baseline."""
        self._ep.reset()
        self._latest = None


def false_permit_monitor(*, alpha: float = 0.05) -> RiskStreamEProcess:
    """The false-permit-rate risk-stream monitor (ROADMAP §E)."""
    return RiskStreamEProcess(
        stream_id=FALSE_PERMIT_STREAM,
        null_hypothesis_id=FALSE_PERMIT_NULL,
        filtration_id=FALSE_PERMIT_FILTRATION,
        alpha=alpha,
    )


def abstain_rate_monitor(*, alpha: float = 0.05) -> RiskStreamEProcess:
    """The abstain-rate risk-stream monitor (ROADMAP §E)."""
    return RiskStreamEProcess(
        stream_id=ABSTAIN_RATE_STREAM,
        null_hypothesis_id=ABSTAIN_RATE_NULL,
        filtration_id=ABSTAIN_RATE_FILTRATION,
        alpha=alpha,
    )
