"""
Wave 2 / M0b — the FIELD neighborhood trial (separate entry point, by design).

[Architecture: cross-layer (Engine verdict + Layer 5 Evidence) — bench tooling]

``bench/replay_trial.run_seeded_neighborhood_trial`` hard-codes
``neighborhood_kind="synthetic"`` (replay_trial.py:328) because the family it
samples is one we wrote. This module is the OTHER entry point — the one a
measured field corpus goes through — and it is deliberately separate so the
synthetic trial's label can never be flipped by a parameter:

  * input is a ``LoadedCorpus``, so the kind was EARNED by the loader gate
    (sealed field-collection provenance, pinned authorship, digest binding) —
    a synthetic or unverified corpus is refused here, not downgraded;
  * the certificate's ``family`` string is derived from the corpus's OWN
    sealed provenance (collector, method, window, source) — never
    ``NEIGHBORHOOD_FAMILY``, whose text describes the synthetic ops
    (``_FIELD_CLAIM_SCOPE`` requires the field family to name the measured
    corpus);
  * the statistics are the same in-tree machinery (``stability_p_low`` →
    ``certify_verdict``): a fixed collected sample of n texts, each evaluated
    once through the live runtime, treated as n iid draws from the field
    distribution the provenance describes. That iid-from-the-named-source
    assumption is stated in the family string itself; if the collection was
    adversarially ordered or deduplicated, the claim weakens and the
    provenance record is where an auditor sees how the data was gathered.

NO REAL FIELD CORPUS EXISTS TODAY. Until one is collected and attested, every
path through this module in CI uses simulated-field fixtures (tests attest a
clearly-labelled test collector) — the harness ENABLES field certification;
collecting reality is a separate, human act. That is success, not failure.

Minimum viable field-corpus sizes (alpha = delta = 0.05, verified this
session against the in-tree bound — see ``minimum_field_corpus_size``):

  * L12 robustness: n >= 78 with ZERO observed instability
    (hoeffding_bentkus_ucb(0, 78, 0.05) = 0.04994 <= alpha; n=77 fails at
    0.05057). Any observed instability raises the requirement quickly.
  * L4 action-class: the same arithmetic on the under-classification rate —
    n >= 78 at zero observed misses — PLUS the >=20-genuine-miss holdout
    tripwire, so a real L4 field corpus needs enough must-FORBID mass that
    the floor's misses are observable (zero-miss field data certifies
    vacuously and is refused by ``certify_action_class_corpus``). With any
    calibration misses, n grows: the empirical rate must sit comfortably
    below alpha for the UCB to clear it.
  * L12 QIF: no size gate exists because no certified path exists
    (estimate-only by contract); more samples only shrink the plug-in bias.
  * Clopper-Pearson would need n >= 59 at zero instability (~32% smaller
    than Hoeffding-Bentkus here) — documented for SIZING ONLY; certificates
    use the in-tree Hoeffding-Bentkus bound, and adding a second bound to
    the certificate path is deliberately out of scope.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping
from uuid import uuid4

from tex.bench.replay_trial import STRUCTURAL_METADATA
from tex.bench.wave2_corpus.loaders import LOADED_KIND_FIELD, LoadedCorpus
from tex.domain.evaluation import EvaluationRequest
from tex.domain.verdict import Verdict
from tex.engine.crc_gate import hoeffding_bentkus_ucb
from tex.engine.verdict_certificate import (
    RobustnessObservation,
    VerdictCertificate,
    certify_verdict,
    stability_p_low,
)


def field_family(corpus: LoadedCorpus) -> str:
    """The certificate's named sampling family, from the SEALED provenance.

    A field ``p_low`` is relative to the measured corpus, so the family must
    name that corpus — collector, method, window, source — not the synthetic
    ops. The seed slot in the observation is a corpus-digest prefix: a
    replayable identifier binding certificate to artifact, NOT a PRNG seed
    (no PRNG ran), and the family says so in words.
    """
    p = corpus.provenance
    if p is None:  # unreachable for a field-kind corpus; defensive for callers
        raise ValueError("field family requires sealed provenance")
    return (
        f"field-collected:{p.corpus_id}; collector={p.collector}; "
        f"method={p.collection_method}; window={p.window_start}..{p.window_end}; "
        f"n={p.n_points}; source: {p.source_description}; "
        "fixed collected sample, each text evaluated once (iid-from-source "
        "assumption); seed field = corpus-digest prefix (identifier, not a PRNG seed)"
    )


@dataclass(frozen=True, slots=True)
class FieldNeighborhoodTrialResult:
    """Outcome of one field-corpus robustness trial (L12 field entry point)."""

    family: str
    corpus_id: str
    n_samples: int
    verdicts: tuple[str, ...]
    target_verdict: str
    n_stable: int
    stability_rate: float
    p_low: float
    delta: float
    certificate: VerdictCertificate


def _make_request(content: str, metadata: Mapping[str, Any]) -> EvaluationRequest:
    # Mirrors replay_trial._make_request (private there): same envelope, same
    # structural action graph, so the field texts exercise the identical path.
    return EvaluationRequest(
        request_id=uuid4(),
        action_type="outbound_message",
        content=content,
        recipient="external@example.com",
        channel="email",
        environment="production",
        metadata=dict(metadata),
        policy_id=None,
        requested_at=datetime.now(UTC),
    )


def run_field_neighborhood_trial(
    runtime,
    *,
    corpus: LoadedCorpus,
    delta: float = 0.05,
    alpha: float = 0.05,
    metadata: Mapping[str, Any] = STRUCTURAL_METADATA,
) -> FieldNeighborhoodTrialResult:
    """Run a verified FIELD corpus through the live runtime; certify honestly.

    Refuses anything the loader gate did not mark ``field`` — the synthetic
    path is ``run_seeded_neighborhood_trial`` and stays synthetic-labelled.
    The returned certificate's ``certified`` flag is then decided by
    ``certify_verdict``'s own arithmetic (delta <= alpha and the floored
    STORED p_low >= 1 - alpha) — this function never touches the gate.
    """
    if corpus.consumer != "neighborhood":
        raise ValueError(f"not a neighborhood corpus: {corpus.consumer!r}")
    if corpus.kind != LOADED_KIND_FIELD:
        raise ValueError(
            f"field trial requires a loader-verified field corpus, got kind="
            f"{corpus.kind!r} — the synthetic entry point is "
            "bench.replay_trial.run_seeded_neighborhood_trial"
        )
    if corpus.provenance is None:  # cannot happen post-gate; keep the invariant loud
        raise ValueError("field corpus without provenance cannot be trialled")

    verdicts: list[str] = []
    for text in corpus.points:
        result = runtime.evaluate_action_command.execute(_make_request(text, metadata))
        verdicts.append(result.response.verdict.value)

    target = Verdict.FORBID.value
    n_samples = len(verdicts)
    n_stable = sum(1 for v in verdicts if v == target)
    p_low = stability_p_low(n_stable, n_samples, delta)
    family = field_family(corpus)
    certificate = certify_verdict(
        robustness=RobustnessObservation(
            n_samples=n_samples,
            n_stable=n_stable,
            delta=delta,
            seed=int(corpus.provenance.corpus_sha256[:12], 16),
            family=family,
            neighborhood_kind=LOADED_KIND_FIELD,
            target_verdict=target,
        ),
        alpha=alpha,
    )
    return FieldNeighborhoodTrialResult(
        family=family,
        corpus_id=corpus.corpus_id,
        n_samples=n_samples,
        verdicts=tuple(verdicts),
        target_verdict=target,
        n_stable=n_stable,
        stability_rate=n_stable / n_samples,
        p_low=p_low,
        delta=delta,
        certificate=certificate,
    )


# ── sizing (executable documentation — computed with the in-tree bound) ──────


def minimum_field_corpus_size(
    alpha: float = 0.05, delta: float = 0.05, *, max_n: int = 400
) -> int | None:
    """Smallest n where zero observed failures can clear the certificate gate.

    Searches the IN-TREE ``hoeffding_bentkus_ucb`` (never a re-derivation that
    could drift) for the first n with ``UCB(0, n, delta) <= alpha`` — i.e.
    ``p_low = 1 - UCB >= 1 - alpha`` at perfect stability. Returns None when
    no n <= max_n suffices (max_n respects the exact-``math.comb`` perf
    envelope; at alpha=delta=0.05 the answer is 78, well inside it).
    """
    for n in range(1, max_n + 1):
        if hoeffding_bentkus_ucb(0.0, n, delta) <= alpha:
            return n
    return None


def clopper_pearson_minimum_n(alpha: float = 0.05, delta: float = 0.05) -> int:
    """SIZING REFERENCE ONLY — the exact-binomial minimum at zero failures.

    Solves (1 - alpha)^n <= delta: the smallest n at which observing zero
    failures yields a Clopper-Pearson 1-delta upper bound <= alpha. At
    alpha=delta=0.05 this is 59 (~32% below Hoeffding-Bentkus's 78). The
    certificate path deliberately does NOT use this bound — it would be a
    second concentration-bound implementation that could drift from the
    in-tree spec; this function exists so corpus-collection planning can see
    the gap and is labelled accordingly.
    """
    if not 0.0 < alpha < 1.0 or not 0.0 < delta < 1.0:
        raise ValueError("alpha and delta must be in (0, 1)")
    return math.ceil(math.log(delta) / math.log(1.0 - alpha))


__all__ = [
    "FieldNeighborhoodTrialResult",
    "clopper_pearson_minimum_n",
    "field_family",
    "minimum_field_corpus_size",
    "run_field_neighborhood_trial",
]
