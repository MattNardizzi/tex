"""
Wave 2 / L12 — the verdict certificate: counterfactual robustness + QIF, split & honest.

[Architecture: Engine evidence layer — evidence ABOUT the verdict, never an input to it]

One certificate, two halves, two very different epistemic standings — and the
naming keeps them apart on purpose (the ``nanozk`` lesson: a name that implies
a property must deliver it in the body):

  ROBUSTNESS HALF (genuine finite-sample statistics, named scope).
    A one-sided lower confidence bound ``p_low`` on the verdict-stability rate
    over a SEEDED, NAMED perturbation family (``NEIGHBORHOOD_FAMILY``). The
    claim is DISTRIBUTIONAL: "with confidence 1 - delta, at least p_low of the
    neighborhood distribution maps to the target verdict." It is NOT a
    worst-case / adversarial robustness statement, and the certificate says so
    (``robustness_claim_scope``). Re-running fixed strings through a
    deterministic PDP has zero statistical content; the statistics here come
    from sampling a combinatorially large family, which is exactly the regime
    where a Hoeffding/Bentkus tail is meaningful. The bound reuses
    ``crc_gate.hoeffding_bentkus_ucb`` verbatim on the COMPLEMENT (the
    instability rate) — ``p_low = 1 - UCB(instability)`` — so there is no
    second concentration-bound implementation to drift from the in-tree spec.

  QIF HALF (point estimate ONLY — the word "bound" is contractually banned).
    A data-dependent plug-in estimate of how much information the verdict
    channel leaks about a secret input label. The channel is EXACTLY
    ``VERDICT_CHANNEL`` — the 3-outcome verdict enum. It is NOT
    ``Decision.metadata['pdp']``, which carries scores, latencies and
    summaries and leaks far more; an estimate that did not name its channel
    would be unfalsifiable. Two standard measures are reported (so we cannot
    be accused of picking the flattering one): min-entropy leakage (the
    one-guess-adversary measure) and Shannon mutual information. Both are
    plug-in point estimates over an empirical joint — finite-sample biased,
    with no correction claimed — and both are mathematically capped by the
    channel's capacity ceiling ``log2(3) ~= 1.585`` bits per observation.
    ``qif_certified`` is typed ``Literal[False]`` and ``qif_estimate_only``
    is typed ``Literal[True]``: a "certified QIF guarantee" is structurally
    unconstructible this wave. The genuine finite-sample QIF leakage
    guarantee is the L12 North-Star (ROADMAP) and is explicitly FUTURE work.

Honesty gate (mirrors ``contracts/action_class.certify_action_class``):
``certified`` is True ONLY when the robustness half was measured on a
``field`` neighborhood (real attacker paraphrase distribution, M0b corpus)
AND its ``p_low`` clears ``1 - alpha``. The seeded synthetic family computes
its ``p_low`` honestly but stays ``certified=False`` — the sampling
distribution is one we wrote, not one we measured. With no data at all the
certificate is inert (``enabled=False``), exactly the CRC-gate posture. The
shipped module-level default ``VERDICT_CERT`` is that inert object; M0b (the
field corpus harness) has not landed, so inert is the correct state today.

The runtime verdict path NEVER reads this object. It is evidence about the
verdict, attached to ``Decision.metadata['pdp']['verdict_certificate']`` via
``verdict_certificate_metadata()`` — the same emission pattern as the CRC
certificate's else-branch. No verdict effect, no surfaced hold, no signal.
Maturity: research-early.

References (each re-verified against the primary source, retrieved 2026-06-10):
  - G. Smith, "On the Foundations of Quantitative Information Flow",
    FoSSaCS 2009, LNCS 5504 pp. 288-302 — vulnerability V(X) = max_x P[X=x],
    min-entropy leakage, and why Shannon entropy understates one-guess risk.
  - B. Köpf & G. Smith, "Vulnerability Bounds and Leakage Resilience of
    Blinded Cryptography under Timing Attacks", IEEE CSF 2010, Corollary 2 —
    min-entropy capacity is at most the log of the number of channel
    outputs, for ANY prior (the log2(3) ceiling used here).
  - J. Cohen, E. Rosenfeld, J.Z. Kolter, "Certified Adversarial Robustness
    via Randomized Smoothing", ICML 2019, arXiv:1902.02918 — the precedent
    for certifying a deterministic system by input sampling plus a one-sided
    lower confidence bound on the stable-output rate (they use
    Clopper-Pearson; we reuse the in-tree Hoeffding-Bentkus complement).
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Any, Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field

from tex.domain.verdict import Verdict
from tex.engine.crc_gate import hoeffding_bentkus_ucb

# ── The channel, named exactly (an unnamed channel is unfalsifiable) ─────

# The verdict enum has exactly three outcomes (PERMIT / ABSTAIN / FORBID),
# so one observation of the channel can reveal at most log2(3) bits about
# the input, for ANY prior. This is the output-alphabet capacity ceiling.
VERDICT_ALPHABET: tuple[str, ...] = tuple(v.value for v in Verdict)
CAPACITY_CEILING_BITS: float = math.log2(len(VERDICT_ALPHABET))

VERDICT_CHANNEL = "verdict_enum{PERMIT,ABSTAIN,FORBID}"


# ── The perturbation family, named exactly (an unnamed family is theater) ─

NEIGHBORHOOD_FAMILY = (
    "intent-preserving-paraphrase-v1: base ~ Uniform(base_texts); compose "
    "1-3 ops sampled without replacement from {benign_prefix, benign_suffix, "
    "casing, whitespace, punctuation, synonym_swap}, applied in canonical "
    "order; seeded PRNG; change-guaranteed; plain text only (no encodings, "
    "no homoglyphs, no zero-width — those test sanitization, not paraphrase)"
)

_BENIGN_PREFIXES = (
    "As discussed, ",
    "Quick update: ",
    "Per the ticket, ",
    "Heads up - ",
    "For the record: ",
)
_BENIGN_SUFFIXES = (
    " Thanks!",
    " Much appreciated.",
    " Noting this in the log.",
    " Confirming for the record.",
)
# Domain-preserving swaps only — the rewording must keep the same intent.
_SYNONYM_SWAPS = (
    ("customer", "client"),
    ("refund", "reimbursement"),
    ("immediately", "at once"),
    ("money", "funds"),
    ("right away", "without delay"),
)


def _op_benign_prefix(text: str, rng: random.Random) -> str:
    return rng.choice(_BENIGN_PREFIXES) + text


def _op_benign_suffix(text: str, rng: random.Random) -> str:
    return text + rng.choice(_BENIGN_SUFFIXES)


def _op_casing(text: str, rng: random.Random) -> str:
    words = text.split(" ")
    candidates = [i for i, w in enumerate(words) if any(c.isalpha() for c in w)]
    if not candidates:
        return text
    i = rng.choice(candidates)
    words[i] = words[i].lower() if words[i].isupper() else words[i].upper()
    return " ".join(words)


def _op_whitespace(text: str, rng: random.Random) -> str:
    words = text.split(" ")
    if len(words) < 2:
        return text + " "
    i = rng.randrange(1, len(words))
    return " ".join(words[:i]) + "  " + " ".join(words[i:])


def _op_punctuation(text: str, rng: random.Random) -> str:
    return text[:-1] + "!" if text.endswith(".") else text + "."


def _op_synonym_swap(text: str, rng: random.Random) -> str:
    lowered = text.lower()
    hits = [(a, b) for a, b in _SYNONYM_SWAPS if a in lowered]
    if not hits:
        return text
    a, b = rng.choice(hits)
    i = lowered.index(a)
    return text[:i] + b + text[i + len(a) :]


_NEIGHBORHOOD_OPERATORS: tuple[tuple[str, Any], ...] = (
    ("benign_prefix", _op_benign_prefix),
    ("benign_suffix", _op_benign_suffix),
    ("casing", _op_casing),
    ("whitespace", _op_whitespace),
    ("punctuation", _op_punctuation),
    ("synonym_swap", _op_synonym_swap),
)


def generate_neighborhood(
    *, base_texts: Sequence[str], seed: int, n_samples: int
) -> tuple[str, ...]:
    """Draw ``n_samples`` seeded perturbations from ``NEIGHBORHOOD_FAMILY``.

    Deterministic given (base_texts, seed, n_samples) — same seed, same
    neighborhood, replayable forever. Every sample is guaranteed to differ
    from its base (if every chosen operator no-ops, a benign prefix is
    force-applied), so the trial never silently re-runs a fixed string.
    """
    if not base_texts:
        raise ValueError("base_texts must be non-empty")
    if n_samples <= 0:
        raise ValueError("n_samples must be positive")
    rng = random.Random(seed)
    bases = list(base_texts)
    samples: list[str] = []
    for _ in range(n_samples):
        base = rng.choice(bases)
        k = rng.randint(1, 3)
        chosen = sorted(rng.sample(range(len(_NEIGHBORHOOD_OPERATORS)), k))
        text = base
        for idx in chosen:
            text = _NEIGHBORHOOD_OPERATORS[idx][1](text, rng)
        if text == base:  # change-guaranteed: casing/synonym may no-op
            text = _op_benign_prefix(text, rng)
        samples.append(text)
    return tuple(samples)


# ── Robustness half: a genuine one-sided lower confidence bound ──────────


def stability_p_low(n_stable: int, n: int, delta: float) -> float:
    """1-delta lower confidence bound on the stability rate over the family.

    Method: complement of the in-tree RCPS upper bound — ``p_low = 1 -
    hoeffding_bentkus_ucb(instability_rate, n, delta)`` (crc_gate.py). The
    "unstable" indicator is a [0,1] Bernoulli loss, so a 1-delta UCB on its
    mean is exactly a 1-delta lower bound on stability. Reusing the in-tree
    function means no second concentration-bound implementation can drift.
    Valid under iid draws from the family with the verdict a fixed function
    of the input for the duration of the trial.

    Fail-closed: with no data the only honest lower bound is 0.0 (claims
    nothing), mirroring the action-class inert UCB of 1.0. A degenerate
    ``delta`` is rejected by name (the ``ConformalRiskGate.__init__``
    convention): at ``delta=1.0`` the Hoeffding UCB collapses to ``r_hat``
    and the "bound" would hold with probability zero.
    """
    if not 0.0 < delta < 1.0:
        raise ValueError("delta must be in (0, 1)")
    if n <= 0:
        return 0.0
    if not 0 <= n_stable <= n:
        raise ValueError("n_stable must be in [0, n]")
    r_unstable = (n - n_stable) / n
    return max(0.0, 1.0 - hoeffding_bentkus_ucb(r_unstable, n, delta))


# The claim scope is derived from the neighborhood kind — a 'field'
# certificate must not carry the synthetic disclaimer (it would
# self-contradict), and a synthetic one must never drop it.
_SYNTHETIC_CLAIM_SCOPE = (
    "distributional over the named seeded family; NOT worst-case, "
    "NOT adversarial, NOT a measured field attacker distribution"
)
_FIELD_CLAIM_SCOPE = (
    "distributional over the measured field corpus named in "
    "robustness_family; NOT worst-case, NOT adversarial"
)
_INERT_CLAIM_SCOPE = "no robustness claim (inert)"


@dataclass(frozen=True, slots=True)
class RobustnessObservation:
    """What a neighborhood trial measured — the engine-side input contract.

    Produced by ``bench/replay_trial.run_seeded_neighborhood_trial`` (the
    engine must not import bench, so the contract lives here). The
    ``neighborhood_kind`` follows the action-class corpus discipline:
    'synthetic' = a family we wrote (the seeded paraphrase ops); 'field' = a
    measured real-attacker distribution (M0b — does not exist yet).
    """

    n_samples: int
    n_stable: int
    delta: float
    seed: int
    family: str
    neighborhood_kind: str  # 'synthetic' | 'field'
    target_verdict: str = Verdict.FORBID.value


# ── QIF half: plug-in point estimates, never a guarantee ─────────────────


@dataclass(frozen=True, slots=True)
class QIFSample:
    """One labelled observation of the verdict channel.

    ``secret_label`` is the input-side secret an observer of the verdict
    should not learn (e.g. which policy-sensitive class the request fell
    in); ``verdict`` is the emitted 3-outcome verdict string.
    """

    secret_label: str
    verdict: str


@dataclass(frozen=True, slots=True)
class QIFLeakageEstimate:
    """Plug-in point estimates of the verdict channel's leakage, in bits."""

    n_samples: int
    n_secret_labels: int
    min_entropy_leakage_bits: float
    shannon_mi_bits: float


def estimate_verdict_channel_leakage(
    samples: Sequence[QIFSample],
) -> QIFLeakageEstimate:
    """Estimate leakage of ``VERDICT_CHANNEL`` from a labelled corpus.

    Both measures are computed from the empirical joint distribution:
      - min-entropy leakage  L = log2(V_posterior / V_prior), where
        V_prior = max_x p(x) and V_posterior = sum_y max_x p(x, y) — the
        one-guess-adversary measure of quantitative information flow;
      - Shannon mutual information I(X; Y) in bits.

    Both are plug-in POINT ESTIMATES: finite-sample biased (plug-in MI biases
    upward on small samples), with no correction and no confidence statement
    claimed. Both are mathematically capped by ``CAPACITY_CEILING_BITS``
    because the output alphabet has exactly three letters; the clamp below
    only absorbs float dust. An empty corpus raises — the honest posture for
    "no data" is the inert certificate, not a fabricated zero.
    """
    if not samples:
        raise ValueError("empty corpus estimates nothing — keep the inert certificate")
    for s in samples:
        if s.verdict not in VERDICT_ALPHABET:
            raise ValueError(
                f"verdict {s.verdict!r} is outside the named channel "
                f"{VERDICT_CHANNEL}; the estimate only covers that channel"
            )

    n = len(samples)
    joint: dict[tuple[str, str], int] = {}
    x_marg: dict[str, int] = {}
    y_marg: dict[str, int] = {}
    for s in samples:
        joint[(s.secret_label, s.verdict)] = joint.get((s.secret_label, s.verdict), 0) + 1
        x_marg[s.secret_label] = x_marg.get(s.secret_label, 0) + 1
        y_marg[s.verdict] = y_marg.get(s.verdict, 0) + 1

    v_prior = max(x_marg.values()) / n
    v_post = sum(
        max(joint.get((x, y), 0) for x in x_marg) for y in y_marg
    ) / n
    min_entropy_leakage = math.log2(v_post / v_prior)

    mi = 0.0
    for (x, y), c in joint.items():
        p_xy = c / n
        mi += p_xy * math.log2(p_xy * n * n / (x_marg[x] * y_marg[y]))

    return QIFLeakageEstimate(
        n_samples=n,
        n_secret_labels=len(x_marg),
        min_entropy_leakage_bits=min(CAPACITY_CEILING_BITS, max(0.0, min_entropy_leakage)),
        shannon_mi_bits=min(CAPACITY_CEILING_BITS, max(0.0, mi)),
    )


# ── The certificate ──────────────────────────────────────────────────────


class VerdictCertificate(BaseModel):
    """Auditable robustness + QIF evidence about the verdict channel.

    The runtime floor NEVER reads this object (the ``action_class`` /
    ``crc_gate`` precedent): it is offline evidence attached to decision
    metadata, with no verdict effect and no surfaced hold. Maturity:
    research-early.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(
        description="Whether any measured data backed this certificate."
    )
    certified: bool = Field(
        description=(
            "True ONLY when the robustness half was measured on a 'field' "
            "neighborhood AND its p_low clears 1 - alpha. The synthetic "
            "seeded family computes honestly but stays False. The QIF half "
            "can never set this True this wave (it is estimate-only by "
            "contract)."
        )
    )
    alpha: float = Field(
        ge=0.0,
        le=1.0,
        description="Certification target: require p_low >= 1 - alpha.",
    )

    # ── robustness half (genuine finite-sample lower confidence bound) ──
    robustness_neighborhood_kind: str = Field(
        default="none", description="'none' | 'synthetic' | 'field'."
    )
    robustness_family: str = Field(
        default="",
        description=(
            "The EXACT named perturbation family the p_low is relative to. "
            "A p_low without a named sampling family is theater."
        ),
    )
    robustness_seed: int | None = Field(
        default=None, description="PRNG seed of the sampled neighborhood (replayable)."
    )
    robustness_target_verdict: str = Field(
        default=Verdict.FORBID.value,
        description="The verdict whose stability over the family is measured.",
    )
    robustness_n_samples: int = Field(
        default=0, ge=0, description="Neighborhood samples drawn and evaluated."
    )
    robustness_n_stable: int = Field(
        default=0, ge=0, description="Samples that kept the target verdict."
    )
    robustness_empirical_stability_rate: float = Field(
        default=0.0, ge=0.0, le=1.0, description="n_stable / n_samples on the draw."
    )
    robustness_stability_p_low: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description=(
            "One-sided 1-delta lower confidence bound on the stability rate "
            "OVER THE NAMED FAMILY: 1 - hoeffding_bentkus_ucb(instability, "
            "n, delta), reusing crc_gate verbatim. 0.0 when inert (claims "
            "nothing)."
        ),
    )
    robustness_delta: float = Field(
        default=0.05,
        gt=0.0,
        lt=1.0,
        description="Failure probability of the robustness bound (confidence 1 - delta).",
    )
    robustness_bound_method: str = Field(
        default="hoeffding_bentkus_complement",
        description=(
            "p_low = 1 - hoeffding_bentkus_ucb(instability_rate, n, delta); "
            "valid because 'unstable' is a [0,1] Bernoulli loss."
        ),
    )
    robustness_claim_scope: str = Field(
        default=_INERT_CLAIM_SCOPE,
        description="What the p_low does and does not claim, derived from the kind.",
    )

    # ── QIF half (point estimate ONLY — 'bound' is banned vocabulary) ──
    qif_channel: str = Field(
        default=VERDICT_CHANNEL,
        description=(
            "EXACTLY which channel the estimate covers: the 3-outcome "
            "verdict enum, nothing else. Decision.metadata['pdp'] (scores, "
            "latencies, summaries) leaks far more and is NOT covered."
        ),
    )
    qif_corpus_kind: str = Field(
        default="none", description="'none' | 'synthetic' | 'field'."
    )
    qif_n_samples: int = Field(
        default=0, ge=0, description="Labelled (secret_label, verdict) observations."
    )
    qif_l_bits_point_estimate: float | None = Field(
        default=None,
        description=(
            "Headline L_bits: min-entropy leakage of the verdict channel "
            "(one-guess adversary), plug-in point estimate on the empirical "
            "joint. None when no corpus exists — estimating nothing is the "
            "only honest inert value. Always <= the capacity ceiling. A "
            "point estimate, NOT a finite-sample guarantee."
        ),
    )
    qif_shannon_mi_bits_point_estimate: float | None = Field(
        default=None,
        description=(
            "Shannon mutual information I(secret; verdict) in bits, plug-in "
            "point estimate. Reported alongside the min-entropy measure so "
            "the flattering measure cannot be cherry-picked."
        ),
    )
    qif_capacity_ceiling_bits: float = Field(
        default=CAPACITY_CEILING_BITS,
        description=(
            "Information-theoretic ceiling of the 3-outcome channel: "
            "log2(3) ~= 1.585 bits per observation, for any prior. A fixed "
            "property of the channel alphabet, not a measurement."
        ),
    )
    qif_estimate_only: Literal[True] = Field(
        default=True,
        description=(
            "Structurally pinned True: the QIF half is a data-dependent "
            "point estimate this wave, never a finite-sample guarantee."
        ),
    )
    qif_certified: Literal[False] = Field(
        default=False,
        description=(
            "Structurally pinned False this wave: the finite-sample QIF "
            "leakage guarantee is the L12 North-Star and explicitly FUTURE."
        ),
    )
    qif_estimator: str = Field(
        default="plug-in on the empirical joint; finite-sample biased; no correction claimed",
        description="How the point estimates were computed, stated plainly.",
    )


def certify_verdict(
    *,
    robustness: RobustnessObservation | None = None,
    qif_samples: Sequence[QIFSample] = (),
    qif_corpus_kind: str = "none",
    alpha: float = 0.05,
) -> VerdictCertificate:
    """Build the certificate from whatever was actually measured.

    With nothing measured the certificate is inert (``enabled=False``,
    ``certified=False``) — the CRC no-calibration posture. The honesty gate
    mirrors ``certify_action_class``: only a 'field' neighborhood whose
    p_low clears ``1 - alpha`` certifies; 'synthetic' computes-but-abstains.
    """
    enabled = robustness is not None or len(qif_samples) > 0

    if robustness is not None:
        if robustness.neighborhood_kind not in ("synthetic", "field"):
            raise ValueError("neighborhood_kind must be 'synthetic' or 'field'")
        p_low = stability_p_low(
            robustness.n_stable, robustness.n_samples, robustness.delta
        )
        rate = (
            robustness.n_stable / robustness.n_samples
            if robustness.n_samples
            else 0.0
        )
        # FLOOR, never round: a lower bound must not be displayed above its
        # true value, even by half an ULP of the 6-dp grid.
        p_low_stored = math.floor(p_low * 1e6) / 1e6
        # The gate reads the STORED number (an auditor recomputing
        # `p_low >= 1 - alpha` from the artifact's own fields must agree),
        # and requires delta <= alpha — the certificate's confidence must be
        # at least as strong as the rate it certifies (the RCPS pairing);
        # otherwise a caller could mint `certified` at near-zero confidence.
        certified = (
            robustness.neighborhood_kind == "field"
            and robustness.delta <= alpha
            and p_low_stored >= 1.0 - alpha
        )
        robustness_fields: dict[str, Any] = {
            "robustness_neighborhood_kind": robustness.neighborhood_kind,
            "robustness_family": robustness.family,
            "robustness_seed": robustness.seed,
            "robustness_target_verdict": robustness.target_verdict,
            "robustness_n_samples": robustness.n_samples,
            "robustness_n_stable": robustness.n_stable,
            "robustness_empirical_stability_rate": round(rate, 6),
            "robustness_stability_p_low": p_low_stored,
            "robustness_delta": robustness.delta,
            "robustness_claim_scope": (
                _FIELD_CLAIM_SCOPE
                if robustness.neighborhood_kind == "field"
                else _SYNTHETIC_CLAIM_SCOPE
            ),
        }
    else:
        certified = False
        robustness_fields = {}

    if qif_samples:
        if qif_corpus_kind not in ("synthetic", "field"):
            raise ValueError(
                "qif_corpus_kind must be named ('synthetic' or 'field') when "
                "samples are supplied — an unnamed corpus is unfalsifiable"
            )
        est = estimate_verdict_channel_leakage(qif_samples)
        qif_fields: dict[str, Any] = {
            "qif_corpus_kind": qif_corpus_kind,
            "qif_n_samples": est.n_samples,
            "qif_l_bits_point_estimate": round(est.min_entropy_leakage_bits, 6),
            "qif_shannon_mi_bits_point_estimate": round(est.shannon_mi_bits, 6),
        }
    else:
        qif_fields = {}

    return VerdictCertificate(
        enabled=enabled,
        certified=certified,
        alpha=alpha,
        **robustness_fields,
        **qif_fields,
    )


# The shipped default: inert, certified=False — until M0b lands a field
# corpus, exactly the ACTION_CLASS_CERT / CRC-without-calibration posture.
VERDICT_CERT = certify_verdict()


def verdict_certificate_metadata() -> dict[str, Any]:
    """The stable seam ``pdp.py`` embeds (its single additive line).

    Compact posture while inert — mirroring the CRC else-branch
    ``{"enabled": False, "certified": False}`` — and the full dump once a
    real certificate is built and installed as the module default.
    """
    if not VERDICT_CERT.enabled:
        return {"enabled": False, "certified": False}
    return VERDICT_CERT.model_dump()


__all__ = [
    "CAPACITY_CEILING_BITS",
    "NEIGHBORHOOD_FAMILY",
    "VERDICT_ALPHABET",
    "VERDICT_CHANNEL",
    "QIFLeakageEstimate",
    "QIFSample",
    "RobustnessObservation",
    "VerdictCertificate",
    "VERDICT_CERT",
    "certify_verdict",
    "estimate_verdict_channel_leakage",
    "generate_neighborhood",
    "stability_p_low",
    "verdict_certificate_metadata",
]
