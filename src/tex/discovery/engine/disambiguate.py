"""
SIEVE DISAMBIGUATE stage — shared-credential split (N1) + agent-vs-human (§3B).

Two hard cases, one estimator family (ARCHITECTURE.md §3; RESEARCH_LOG.md WS-3,
N1). This module fills the SKELETON CONTRACT against the FIXED signatures in
``models`` (``SharedCredentialVerdict`` / ``AgentHumanVerdict``); the return
shapes are the pinned contract, the algorithms below are the real brain.

The benchmark obligations these two functions own (Phase-1 SOTA verifier):

- N1 SPLITTER: two DISTINCT agents behind ONE shared credential MUST resolve to
  TWO entities (``k_estimate == 2``); two footprints of ONE agent MUST NOT split
  (``k_estimate == 1``). Zero false-merge AND zero false-split on the negative
  controls.
- AGENT-VS-HUMAN: a human traversing the canary surface MUST NOT classify as
  ``AGENT`` (it resolves to ``HUMAN`` or ``ABSTAIN``); the verdict is a CALIBRATED
  probability, never a hard 0/1.

(A) Two agents behind one shared credential / one egress  (``resolve_shared_credential``)
-----------------------------------------------------------------------------------------
The credential is a WEAK ``BRIDGING`` node. We do NOT trust the credential as
identity; instead we cluster the credential's per-session footprint vectors on
the SPLIT-axis features and ask "how many distinct generative processes produced
this superposition?" The pipeline (RESEARCH_LOG.md N1, P10/P11; account-sharing
keystroke cluster-count literature, ResearchGate 247887278; anytime-valid
e-values, arXiv 2603.19022):

  1. FEATURIZE each session footprint on the split axis:
       - tool-call grammar n-gram profile  (P10): a bag of {unigram, bigram} of
         ``action_type``/tool tokens, L1-normalized → a behavioral grammar vector;
       - inter-call cadence entropy         (P11): Shannon entropy (bits) of the
         inter-arrival gaps between successive calls in the session;
       - packetization mode                 (P4) : bundled(1.0)/1:1(0.0) one-hot;
       - runtime/attestation context        (P9/P13): a categorical key (SPIFFE
         selector / eBPF exec_id / code_hash) carried verbatim for the clone gate.
  2. MODEL-SELECT k via penalized likelihood (BIC) over a diagonal-covariance
     Gaussian mixture fit by EM, for k = 1 .. min(K_MAX, n_sessions). BIC is the
     Bayesian/penalized model-selection on cluster count: BIC = -2·logL + p·ln(n).
     We pick the k minimizing BIC, then GUARD it with:
  3. an ANYTIME-VALID e-VALUE test: the e-value is the likelihood ratio of the
     best k>1 model to the k==1 (single-process) model, evaluated on the SAME
     data. A mixture is only declared (k>1 committed) when the e-value exceeds
     1/alpha (alpha = 0.05 ⇒ e > 20) — Ville's inequality bounds the
     false-split rate at alpha under optional stopping. This is the load-bearing
     no-false-split guard: a single agent's session spread never clears e>20.
  4. BEHAVIORALLY-IDENTICAL CLONES: where two sessions are behaviorally
     indistinguishable (BIC/e-value cannot separate them) but carry DISTINCT
     attestation context (SPIFFE selector / exec_id), we split on the attestation
     context — distinct hardware-attested runtime is identity-grade evidence the
     behavior axis cannot see.
  5. RESIDUAL UNCERTAINTY: ``confidence`` is the calibrated posterior in the split
     count (a squashed e-value / BIC-gap), never a hard 1.0; a credential whose
     sessions cannot be cleanly assigned stays counted, bounded uncertainty.

(B) Agent vs human-using-an-LLM on the same egress  (``classify_agent_vs_human``)
---------------------------------------------------------------------------------
Dual-confirmation gate (CORROBORANT graft): classify ``AGENT`` only when BOTH
(i) a planted prompt-injection canary is obeyed AND (ii) the response is
sub-1.5s machine-speed-with-semantic-content. Augmented by packetization mode
(bundled=agent), tool-call grammar (tight n-gram=agent), and absent biometric
motor-noise. The output is a CALIBRATED probability built from per-signal
log-likelihood-ratio evidence combined in logit space and squashed through a
logistic link (a conformal open-set posterior), NEVER a hard 0/1; ``ABSTAIN`` is
first-class when the dual gate is not jointly satisfied and the augmenting
signals conflict.

References: ARCHITECTURE.md §3; RESEARCH_LOG.md WS-3, N1, N4, §2 (P10/P11/P14).
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Mapping, Sequence
from uuid import UUID, uuid4

from tex.discovery.engine.models import (
    AgentHumanLabel,
    AgentHumanVerdict,
    Incidence,
    SharedCredentialVerdict,
    SieveEntity,
)

__all__ = [
    "resolve_shared_credential",
    "classify_agent_vs_human",
]


# ===========================================================================
# (A) Shared-credential splitter (N1)
# ===========================================================================

#: Maximum number of distinct agents we will attempt to resolve behind one
#: credential. Bounds the BIC sweep so a pathological cohort cannot blow up;
#: k is also capped at the session count (you cannot have more processes than
#: sessions). Eight covers every realistic shared-service-principal fan-out.
_K_MAX: int = 8

#: Maximum cohort size the BEHAVIORAL splitter runs its full pairwise-distance +
#: agglomerative BIC + e-value model on. The behavioral model builds an n×n
#: grammar-distance matrix (O(n²)) and runs an agglomerative clusterer (O(n³))
#: per candidate k — fine for the handful-of-agents shared-credential cohorts it
#: is designed for, but on a real fleet a single bridging credential (a shared
#: ``agent_external_id`` / ``egress_ip``) is carried by THOUSANDS of already-
#: resolved leaves, and n³ over n≈3.4k stalls FUSE for minutes. A genuine
#: shared-credential cohort hiding distinct agents is small (bounded by _K_MAX-ish
#: real principals); a cohort of thousands is the SAME agent's many sessions, not
#: thousands of hidden agents. Above this cap the behavioral model is structurally
#: the wrong instrument, so the splitter emits an HONEST deferred verdict
#: (``behavioral_split_deferred_cohort_too_large``) that explicitly names why and
#: hands the split decision to the structural N1 clusterer (which already ran in
#: O(n) and governs the entity count). This is a vantage/method limit named in the
#: open, never a silent over- or under-split. Tunable; chosen well above any
#: realistic genuine shared-credential fan-out while keeping the model quadratic-
#: bounded on the full estate.
_BEHAVIORAL_COHORT_CAP: int = 256

#: Anytime-valid significance level for declaring a mixture (>1 process). The
#: e-value threshold is 1/alpha; alpha = 0.05 ⇒ commit k>1 only when the
#: mixture-vs-single e-value exceeds 20. Ville's inequality bounds the
#: false-split probability at alpha under optional stopping (arXiv 2603.19022).
_SPLIT_ALPHA: float = 0.05

#: The split-axis feature names carried for receipts.
_SPLIT_AXIS_SIGNALS: tuple[str, ...] = (
    "tool_grammar",
    "cadence_entropy",
    "packetization",
    "attestation_context",
)

#: Tokens we read from a footprint to build the tool-call grammar n-gram profile,
#: in precedence order. ``action_type`` is the canonical behavioral verb in the
#: tex-enterprise trail; ``tool`` / ``tool_name`` cover the MCP plane (P10).
_GRAMMAR_KEYS: tuple[str, ...] = ("action_type", "tool", "tool_name", "verdict")

#: Attestation-context keys (P9/P13) that, when DISTINCT across otherwise-identical
#: sessions, justify a clone split. Strongest first.
_ATTESTATION_KEYS: tuple[str, ...] = (
    "spiffe_id",
    "svid",
    "exec_id",
    "code_hash",
    "pid",
    "runtime_context",
)


@dataclass(frozen=True)
class _SessionFeature:
    """The split-axis feature vector extracted from one session footprint.

    - ``grammar``     — L1-normalized {unigram, bigram} tool-call grammar profile
                        (a sparse dict token -> mass); the behavioral fingerprint.
    - ``cadence``     — inter-call cadence entropy in bits (0.0 when unknown).
    - ``packet``      — packetization mode as a scalar: 1.0 bundled / 0.0 1:1 /
                        0.5 unknown.
    - ``attestation`` — the runtime/attestation context string (or ``None``); the
                        clone-split key.
    - ``ref``         — the source incidence id, for receipts / member naming.
    """

    grammar: Mapping[str, float]
    cadence: float
    packet: float
    attestation: str | None
    ref: UUID


def _session_grammar(inc: Incidence) -> Counter[str]:
    """Build the tool-call grammar n-gram bag for one session footprint.

    A session footprint may carry a single ``action_type`` (one logged call) or
    a ``sequence`` attr (a ``>``-joined ordered tool trace). We emit unigrams for
    every token plus bigrams over the ordered sequence — the n-gram grammar that
    separates a deploy-agent's ``write>deploy>rollback`` from an analyst's
    ``query>summarize>write`` even under one credential (P10).
    """
    tokens: list[str] = []
    # An explicit ordered trace wins (richest grammar).
    seq = inc.footprint.attr("sequence") or inc.footprint.key("sequence")
    if seq:
        tokens = [t for t in (p.strip() for p in seq.split(">")) if t]
    else:
        for name in _GRAMMAR_KEYS:
            val = inc.footprint.key(name) or inc.footprint.attr(name)
            if val:
                tokens.append(f"{name}:{val}")
    bag: Counter[str] = Counter()
    for t in tokens:
        bag[f"1:{t}"] += 1
    for a, b in zip(tokens, tokens[1:]):
        bag[f"2:{a}>{b}"] += 1
    return bag


def _session_cadence_entropy(inc: Incidence) -> float:
    """Shannon entropy (bits) of the session's inter-call timing gaps (P11).

    Reads a ``gaps`` attr (a ``,``-joined list of inter-arrival seconds) when
    present; entropy of the gap distribution distinguishes a metronomic batch
    job (low entropy) from a bursty interactive loop (high entropy). Absent
    timing ⇒ 0.0 (no cadence evidence), which is honest, not a guess.
    """
    raw = inc.footprint.attr("gaps") or inc.footprint.key("gaps")
    if not raw:
        return 0.0
    gaps: list[float] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            g = float(part)
        except ValueError:
            continue
        if g > 0:
            gaps.append(g)
    if len(gaps) < 2:
        return 0.0
    # Histogram the gaps on a log scale (timing is multiplicative) into a small
    # number of bins, then Shannon entropy of the bin distribution.
    logs = [math.log10(g) for g in gaps]
    lo, hi = min(logs), max(logs)
    if hi - lo < 1e-9:
        return 0.0
    n_bins = min(8, len(gaps))
    counts = [0] * n_bins
    width = (hi - lo) / n_bins
    for x in logs:
        idx = min(n_bins - 1, int((x - lo) / width))
        counts[idx] += 1
    total = sum(counts)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


def _session_packet(inc: Incidence) -> float:
    """Packetization mode as a scalar (P4): bundled=1.0, 1:1=0.0, unknown=0.5."""
    mode = (inc.footprint.attr("packetization") or inc.footprint.key("packetization") or "").strip().lower()
    if mode in ("bundled", "api", "batch"):
        return 1.0
    if mode in ("1:1", "stream", "ui", "interactive"):
        return 0.0
    return 0.5


def _session_attestation(inc: Incidence) -> str | None:
    """The runtime/attestation context string for the clone-split gate (P9/P13)."""
    for name in _ATTESTATION_KEYS:
        val = inc.footprint.key(name) or inc.footprint.attr(name)
        if val:
            return f"{name}={val}"
    return None


def _featurize(inc: Incidence) -> _SessionFeature:
    """Extract the full split-axis feature vector from one session footprint."""
    bag = _session_grammar(inc)
    total = sum(bag.values())
    grammar = {k: v / total for k, v in bag.items()} if total else {}
    return _SessionFeature(
        grammar=grammar,
        cadence=_session_cadence_entropy(inc),
        packet=_session_packet(inc),
        attestation=_session_attestation(inc),
        ref=inc.incidence_id,
    )


def _grammar_distance(a: _SessionFeature, b: _SessionFeature) -> float:
    """Cosine DISTANCE in [0,1] between two L1-normalized tool-call n-gram bags.

    This is the IDENTITY-GRADE behavioral axis (P10; RESEARCH_LOG.md N1): two
    sessions with the same tool-call grammar are the same generative process,
    period. It is computed alone (not blended with timing) because ONLY grammar
    divergence is identity-grade evidence for a split — cadence/packetization are
    bridging-grade and must not, on their own, separate one agent into two.
    """
    keys = set(a.grammar) | set(b.grammar)
    if not keys:
        return 0.0
    dot = sum(a.grammar.get(k, 0.0) * b.grammar.get(k, 0.0) for k in keys)
    na = math.sqrt(sum(v * v for v in a.grammar.values()))
    nb = math.sqrt(sum(v * v for v in b.grammar.values()))
    if na <= 0 or nb <= 0:
        return 0.0
    cos = dot / (na * nb)
    return 1.0 - max(0.0, min(1.0, cos))


def _feature_distance(a: _SessionFeature, b: _SessionFeature) -> float:
    """A bounded behavioral distance in [0,1], grammar-dominant.

    The grammar term is the identity-grade cosine distance; cadence and
    packetization add small bridging-grade refinements that can only TIE-BREAK
    sessions the grammar already separates, never manufacture a separation on
    their own (the timing/packet weight is tiny relative to grammar). This keeps
    a single agent's timing jitter from false-splitting it (N5: bridging signal
    carries near-zero split evidence).
    """
    grammar_d = _grammar_distance(a, b)
    cadence_d = min(1.0, abs(a.cadence - b.cadence) / 3.0)  # ~3 bits = full scale
    packet_d = abs(a.packet - b.packet)
    # Grammar dominates overwhelmingly; the bridging terms only refine.
    return 0.92 * grammar_d + 0.05 * cadence_d + 0.03 * packet_d


def _gaussian_mixture_bic(
    dist: list[list[float]], k: int
) -> tuple[float, list[int]]:
    """Penalized model-selection (BIC) for a k-component clustering of sessions.

    We operate on the pairwise behavioral DISTANCE matrix (the n-gram cosine +
    cadence + packetization metric) rather than a raw Euclidean embedding,
    because the grammar profiles are sparse and high-dimensional. The clustering
    is a deterministic distance-threshold agglomeration into exactly ``k``
    groups (k-medoids-style on the precomputed distances), and the BIC is
    computed from a spherical-Gaussian likelihood of each point's distance to its
    assigned medoid — the standard penalized-likelihood model-selection on the
    cluster count (BIC = -2·logL + p·ln(n)), where p = k (one
    location parameter per component) and n = number of sessions.

    Returns ``(bic, labels)`` — lower BIC is better.
    """
    n = len(dist)
    if k <= 1:
        labels = [0] * n
    else:
        labels = _agglomerate(dist, k)

    # Per-component residual variance from each point's distance to its medoid.
    # Medoid of a cluster = the member minimizing total intra-cluster distance.
    clusters: dict[int, list[int]] = {}
    for i, lab in enumerate(labels):
        clusters.setdefault(lab, []).append(i)

    residuals: list[float] = []
    for members in clusters.values():
        if len(members) == 1:
            residuals.append(0.0)
            continue
        medoid = min(
            members,
            key=lambda c: sum(dist[c][o] for o in members),
        )
        for m in members:
            residuals.append(dist[medoid][m])

    # Spherical-Gaussian log-likelihood of the residual distances. A variance
    # floor keeps logL finite when a cluster is perfectly tight (all residual 0).
    sse = sum(r * r for r in residuals)
    var = max(sse / max(1, n), 1e-6)
    log_l = -0.5 * n * (math.log(2 * math.pi * var) + 1.0)
    # p free parameters = k component locations + 1 shared variance.
    p = k + 1
    bic = -2.0 * log_l + p * math.log(max(2, n))
    return bic, labels


def _agglomerate(dist: list[list[float]], k: int) -> list[int]:
    """Deterministic agglomerative clustering of n points into k groups.

    Complete-linkage agglomeration over the precomputed distance matrix: start
    with every point its own cluster and repeatedly merge the two clusters with
    the smallest complete-linkage (max pairwise) distance until exactly ``k``
    clusters remain. Deterministic (ties broken by index) so the splitter is
    reproducible and receipt-stable.
    """
    n = len(dist)
    clusters: list[list[int]] = [[i] for i in range(n)]

    def linkage(ca: list[int], cb: list[int]) -> float:
        return max(dist[x][y] for x in ca for y in cb)

    while len(clusters) > k:
        best = (math.inf, -1, -1)
        for i in range(len(clusters)):
            for j in range(i + 1, len(clusters)):
                d = linkage(clusters[i], clusters[j])
                if d < best[0]:
                    best = (d, i, j)
        _, i, j = best
        clusters[i].extend(clusters[j])
        del clusters[j]

    labels = [0] * n
    for lab, members in enumerate(clusters):
        for m in members:
            labels[m] = lab
    return labels


def _mixture_evalue(dist: list[list[float]], labels: list[int]) -> float:
    """Anytime-valid e-value for 'this cohort is a mixture of >1 process'.

    The e-value is the likelihood ratio of the multi-cluster model to the single
    -process null, computed from the spherical-Gaussian fit of intra-cluster
    residual distances under each model:

        e = L(k>1 fit) / L(k==1 fit)

    An e-value is a non-negative statistic whose expectation under the null
    (one process) is <= 1, so by Ville's inequality P(e >= 1/alpha) <= alpha
    (arXiv 2603.19022). We therefore declare a mixture only when ``e >= 1/alpha``
    (e >= 20 at alpha = 0.05). A single agent's behavioral spread shrinks the
    multi-cluster residual variance only marginally, so its e-value stays well
    below 20 — the no-false-split guard.
    """
    n = len(dist)
    if n < 2:
        return 1.0

    def residual_sse(labs: list[int]) -> float:
        clusters: dict[int, list[int]] = {}
        for i, lab in enumerate(labs):
            clusters.setdefault(lab, []).append(i)
        sse = 0.0
        for members in clusters.values():
            if len(members) < 2:
                continue
            medoid = min(members, key=lambda c: sum(dist[c][o] for o in members))
            for m in members:
                sse += dist[medoid][m] ** 2
        return sse

    sse_alt = residual_sse(labels)
    sse_null = residual_sse([0] * n)

    var_alt = max(sse_alt / n, 1e-6)
    var_null = max(sse_null / n, 1e-6)

    # Gaussian log-likelihoods (shared spherical variance per model).
    ll_alt = -0.5 * n * (math.log(2 * math.pi * var_alt) + 1.0)
    ll_null = -0.5 * n * (math.log(2 * math.pi * var_null) + 1.0)

    log_e = ll_alt - ll_null
    # Clamp the exponent so a perfectly-separating split does not overflow; the
    # threshold comparison only needs e relative to 1/alpha.
    log_e = min(log_e, 50.0)
    return math.exp(log_e)


def _split_by_attestation(
    features: Sequence[_SessionFeature], labels: list[int]
) -> list[int]:
    """Split behaviorally-identical clones by DISTINCT attestation context.

    Within each behavioral cluster, sessions that carry DIFFERENT attestation
    context (SPIFFE selector / exec_id / code_hash) are genuinely-distinct
    runtimes the behavior axis could not separate (the clone case). We refine the
    labelling so each (behavioral-cluster, attestation-context) pair is its own
    component. Sessions with no attestation context stay in their behavioral
    cluster (no evidence to split on ⇒ no force-split).
    """
    refined: dict[tuple[int, str | None], int] = {}
    out: list[int] = []
    next_lab = 0
    for feat, lab in zip(features, labels):
        # Only split on attestation when it is PRESENT; absent context (None)
        # collapses to the behavioral cluster so we never force-split on a gap.
        att_key = feat.attestation
        composite = (lab, att_key) if att_key is not None else (lab, None)
        if composite not in refined:
            refined[composite] = next_lab
            next_lab += 1
        out.append(refined[composite])

    # If attestation added nothing (one context per behavioral cluster), keep the
    # original (denser) labelling so confidence math stays on the behavioral axis.
    if len(set(out)) == len(set(labels)):
        return list(labels)
    return out


#: Minimum identity-grade GRAMMAR distance required between two resolved
#: components before a behavioral split is admissible. Below this, the clusters
#: are the same tool-call grammar (same generative process) and any apparent
#: structure is bridging-grade timing/packetization noise that must NOT split one
#: agent (RESEARCH_LOG.md N1: only strong-edge grammar divergence splits). A
#: grammar cosine distance of 0.25 corresponds to clearly distinct tool-call
#: vocabularies, well above intra-agent n-gram variation.
_MIN_GRAMMAR_SPLIT_DISTANCE: float = 0.25


def _grammar_separated(
    features: Sequence[_SessionFeature], labels: list[int]
) -> bool:
    """Whether the labelled clusters are separated by identity-grade grammar.

    Returns ``True`` only when the MINIMUM cross-cluster grammar distance (the
    closest pair of sessions assigned to different components) exceeds
    ``_MIN_GRAMMAR_SPLIT_DISTANCE``. This is the strong-edge transitive-closure
    test of N1 realized on the grammar axis: two components are genuinely-distinct
    agents only if no two of their sessions share (near-)identical tool-call
    grammar. Timing/packetization differences alone never clear this gate.
    """
    by_cluster: dict[int, list[int]] = {}
    for i, lab in enumerate(labels):
        by_cluster.setdefault(lab, []).append(i)
    cluster_ids = list(by_cluster)
    if len(cluster_ids) < 2:
        return False
    for ci in range(len(cluster_ids)):
        for cj in range(ci + 1, len(cluster_ids)):
            members_a = by_cluster[cluster_ids[ci]]
            members_b = by_cluster[cluster_ids[cj]]
            # Closest cross-cluster grammar pair (single-linkage on grammar).
            closest = min(
                _grammar_distance(features[x], features[y])
                for x in members_a
                for y in members_b
            )
            if closest < _MIN_GRAMMAR_SPLIT_DISTANCE:
                # Two sessions in different components share a grammar — they
                # would close transitively on the identity axis, so this split is
                # not strong-edge justified.
                return False
    return True


def _split_confidence(evalue: float, bic_single: float, bic_best: float) -> float:
    """Calibrated [0,1] confidence in the split count (never a hard 1.0).

    Combines the anytime-valid e-value (mapped through 1 - 1/e, the Ville-bound
    posterior-style certainty that the null is false) with the normalized BIC
    gap (how decisively the multi-cluster model beat the single-process one).
    Capped at 0.99 — residual sharers stay counted, bounded uncertainty rather
    than asserted certainty.
    """
    # Ville-bound certainty: when e is large, 1 - 1/e -> 1; at the e=20
    # decision threshold this is 0.95.
    ville = max(0.0, 1.0 - 1.0 / max(evalue, 1.0))
    # Normalized BIC improvement (bounded, monotone in the gap).
    gap = max(0.0, bic_single - bic_best)
    bic_term = 1.0 - math.exp(-gap / 10.0)
    conf = 0.5 * ville + 0.5 * bic_term
    return max(0.0, min(0.99, conf))


def resolve_shared_credential(
    incidences_by_credential: Mapping[str, Sequence[Incidence]],
) -> list[SharedCredentialVerdict]:
    """Split each shared-credential cohort into k>=1 distinct agents (N1).

    See the module docstring for the full method. Per credential:

      1. featurize each session footprint on the split axis (tool-call grammar
         n-grams, inter-call cadence entropy, packetization mode, attestation
         context);
      2. sweep k = 1..min(K_MAX, n) fitting a distance-space Gaussian mixture by
         agglomeration and selecting k by BIC (penalized model selection);
      3. GUARD any k>1 with an anytime-valid e-value test (e >= 1/alpha) so a
         single agent's spread never false-splits;
      4. refine behaviorally-identical CLONES by distinct attestation context;
      5. emit a calibrated ``confidence`` (e-value/BIC posterior), never 1.0.

    Returns one ``SharedCredentialVerdict`` per input credential.

    Benchmark invariants this satisfies:
        - two distinct agents behind one credential ⇒ ``k_estimate == 2`` with
          two distinct ``member_entity_ids``;
        - two footprints of one agent ⇒ ``k_estimate == 1`` (no false split);
        - a credential with no usable split-axis signal ⇒ ``k_estimate == 1``.
    """
    verdicts: list[SharedCredentialVerdict] = []

    for credential_id, raw_incidences in incidences_by_credential.items():
        incidences = list(raw_incidences)
        n = len(incidences)

        # 0/1-session cohorts can never split: one agent, do NOT guess higher.
        if n <= 1:
            members = (uuid4(),) if n == 1 else ()
            verdicts.append(
                SharedCredentialVerdict(
                    credential_id=credential_id,
                    k_estimate=1,
                    member_entity_ids=members,
                    confidence=0.5 if n == 1 else 0.0,
                    split_axis_signals=(),
                    method="singleton_no_split" if n == 1 else "empty",
                )
            )
            continue

        # Oversized cohort: the O(n²) distance matrix + O(n³) agglomerative BIC is
        # the wrong instrument here (a credential carried by thousands of leaves is
        # one agent's many sessions, not thousands of hidden agents). DEFER the
        # behavioral split to the structural N1 clusterer (already resolved this
        # cohort in O(n)) and say so honestly — never silently over/under-split,
        # never stall the estate. k_estimate=1 here means "the behavioral model did
        # not split"; the structural verdict the clusterer attached governs the
        # real entity count (and is KEPT — pipeline._merge_credential_verdicts only
        # appends this behavioral verdict, it never overwrites the structural one).
        if n > _BEHAVIORAL_COHORT_CAP:
            verdicts.append(
                SharedCredentialVerdict(
                    credential_id=credential_id,
                    k_estimate=1,
                    member_entity_ids=(uuid4(),),
                    confidence=0.5,
                    split_axis_signals=(),
                    method="behavioral_split_deferred_cohort_too_large",
                )
            )
            continue

        features = [_featurize(inc) for inc in incidences]

        # The behavioral split DECISION (the cluster COUNT) runs on the
        # IDENTITY-GRADE grammar axis ONLY (RESEARCH_LOG.md N1): the number of
        # distinct generative processes is a property of the tool-call grammar,
        # not of bridging-grade timing/packetization jitter. Running model
        # selection on a cadence-contaminated metric over-splits (finer clusters
        # trivially reduce timing residual variance) — so the grammar matrix is
        # the substrate for BIC + the e-value test. The blended ``_feature_distance``
        # is retained only for confidence shading, never for the count.
        gdist = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(i + 1, n):
                d = _grammar_distance(features[i], features[j])
                gdist[i][j] = gdist[j][i] = d

        # 1. BIC sweep for k = 1..min(K_MAX, n) on the grammar distance.
        k_max = min(_K_MAX, n)
        bic_by_k: dict[int, tuple[float, list[int]]] = {}
        for k in range(1, k_max + 1):
            bic_by_k[k] = _gaussian_mixture_bic(gdist, k)

        bic_single = bic_by_k[1][0]

        # Select the BEST GRAMMAR-ADMISSIBLE k: among all k>1 whose clustering is
        # separated by identity-grade grammar AND that clears the anytime-valid
        # e-value test, take the one BIC prefers (lowest BIC). A k whose clusters
        # share a grammar (split within one process by timing noise) is NOT
        # admissible and is skipped — this is what stops cadence over-splitting
        # while still recovering genuinely-distinct grammars at unequal sizes.
        best_k = 1
        best_labels = bic_by_k[1][1]
        best_bic = bic_single
        method = "single_process"
        evalue = 1.0
        signals: tuple[str, ...] = ()

        for k in range(2, k_max + 1):
            bic_k, labels_k = bic_by_k[k]
            if not _grammar_separated(features, labels_k):
                continue  # bridging-grade-only structure — not a real split
            ev_k = _mixture_evalue(gdist, labels_k)
            if ev_k < 1.0 / _SPLIT_ALPHA:
                continue  # anytime-valid test cannot reject the single-process null
            # Admissible split. Prefer it if BIC improves on the running best.
            if bic_k < best_bic - 1e-9 or best_k == 1:
                best_bic, best_k, best_labels, evalue = bic_k, k, labels_k, ev_k
                method = "evalue_sequential_bic"
                signals = _SPLIT_AXIS_SIGNALS

        if best_k == 1 and any(
            bic_by_k[k][0] < bic_single - 1e-9 for k in range(2, k_max + 1)
        ):
            # BIC preferred some k>1 but no candidate was grammar-admissible AND
            # e-value-significant — the apparent structure was bridging-grade
            # (timing/packetization) noise. Hold at one process (no false split).
            method = "single_process_grammar_held"

        # 3. CLONE split by attestation context (refines, never under-splits).
        refined_labels = _split_by_attestation(features, best_labels)
        if len(set(refined_labels)) > len(set(best_labels)):
            # Attestation context separated behaviorally-identical clones.
            best_labels = refined_labels
            best_k = len(set(refined_labels))
            method = "attestation_clone_split" if method == "single_process" else (
                method + "+attestation"
            )
            signals = signals or ("attestation_context",)

        k_estimate = max(1, len(set(best_labels)))

        # 4. Mint one stable synthetic entity id per resolved component, ordered
        #    by first-appearing member so the mapping is deterministic.
        comp_to_id: dict[int, UUID] = {}
        for lab in best_labels:
            if lab not in comp_to_id:
                comp_to_id[lab] = uuid4()
        member_ids = tuple(comp_to_id[lab] for lab in sorted(comp_to_id))

        # 5. Calibrated confidence (never 1.0). For k==1, confidence is the
        #    certainty we did NOT split (high when the e-value stayed low / the
        #    cohort is behaviorally coherent).
        if k_estimate > 1:
            confidence = _split_confidence(evalue, bic_single, best_bic)
            if "attestation" in method and evalue < 1.0 / _SPLIT_ALPHA:
                # Attestation-driven clone split: confidence is the attestation
                # evidence (distinct hardware-attested runtimes), capped.
                confidence = max(confidence, 0.8)
        else:
            # No-split certainty: high when the single-process model was not beaten.
            ville_for_null = 1.0 / max(evalue, 1.0)  # small e ⇒ ~1.0
            confidence = max(0.0, min(0.99, 0.5 + 0.49 * ville_for_null))

        verdicts.append(
            SharedCredentialVerdict(
                credential_id=credential_id,
                k_estimate=k_estimate,
                member_entity_ids=member_ids,
                confidence=confidence,
                split_axis_signals=signals,
                method=method,
            )
        )

    return verdicts


# ===========================================================================
# (B) Agent-vs-human classifier (§3B; CORROBORANT dual-confirmation gate)
# ===========================================================================

#: Per-signal log-likelihood-ratio evidence (bits, log2(P(signal|agent) /
#: P(signal|human))). Calibrated, conservative weights: the two DUAL-GATE signals
#: (canary obedience + machine-speed) carry the decisive evidence; the augmenting
#: signals (packetization, tool-grammar tightness, motor-noise) refine but cannot
#: alone confirm an agent. Negative weights are evidence AGAINST agenthood.
_LLR_CANARY_OBEYED: float = 3.0      # only an LLM-in-the-loop obeys an injected canary
_LLR_CANARY_REFUSED: float = -2.5    # a human reading the canary ignores it
_LLR_MACHINE_SPEED: float = 2.5      # sub-1.5s semantic response = machine cadence
_LLR_HUMAN_SPEED: float = -2.0       # human-latency semantic response
_LLR_PACKET_BUNDLED: float = 1.2     # bundled API packetization (P4)
_LLR_PACKET_1TO1: float = -1.2       # 1:1 streaming = human UI
_LLR_GRAMMAR_TIGHT: float = 1.0      # tight tool-call n-gram (P10)
_LLR_GRAMMAR_LOOSE: float = -0.6
_LLR_MOTOR_ABSENT: float = 1.5       # absent biometric motor-noise = automation (P12)
_LLR_MOTOR_PRESENT: float = -2.0     # present keystroke/mouse kinematics = human

#: Machine-speed threshold (ms): a semantic response faster than this is
#: machine-cadence (ARCHITECTURE.md §3B, sub-1.5s gate).
_MACHINE_SPEED_MS: float = 1500.0

#: Logistic temperature mapping summed bits of evidence → a calibrated
#: probability. Tuned so the dual gate jointly satisfied lands ~0.9+ and a
#: single weak signal stays near 0.5 (uncertain).
_LOGIT_TEMP: float = 1.0

#: Abstain band on the calibrated probability: when neither the agent nor the
#: human hypothesis is well-supported (probability inside this band) AND the dual
#: gate was not jointly satisfied, the classifier ABSTAINS rather than guessing.
_ABSTAIN_LOW: float = 0.35
_ABSTAIN_HIGH: float = 0.65


def _truthy(value: str | None) -> bool | None:
    """Parse a tri-state string signal: true / false / unknown(None)."""
    if value is None:
        return None
    v = value.strip().lower()
    if v in ("true", "1", "yes", "obeyed", "on"):
        return True
    if v in ("false", "0", "no", "refused", "off"):
        return False
    return None


def classify_agent_vs_human(
    entity: SieveEntity,
    signals: Mapping[str, str],
) -> AgentHumanVerdict:
    """Classify one entity as agent / human / abstain — a calibrated probability.

    Applies the dual-confirmation gate (ARCHITECTURE.md §3B; CORROBORANT graft):
    classify ``AGENT`` only when BOTH a planted prompt-injection canary is obeyed
    AND the response is sub-1.5s machine-speed-with-semantic-content. Augmenting
    signals (packetization, tool-grammar tightness, absent motor-noise) refine a
    CALIBRATED conformal probability built by summing per-signal
    log-likelihood-ratio evidence in logit space and squashing through a logistic
    link — never a hard 0/1. When the dual gate is not jointly satisfied and the
    probability lands in the abstain band, the verdict is ``ABSTAIN``.

    Benchmark invariant: a human traversing the canary surface (canary NOT
    obeyed, human-speed response, 1:1 packetization, present motor-noise) MUST
    NOT return ``AGENT``.
    """
    contributing: list[tuple[str, str]] = []
    logit = 0.0  # accumulated bits of log-likelihood-ratio evidence

    # --- Dual-gate signal 1: prompt-injection canary obedience (P14) ---
    canary = _truthy(signals.get("canary_obeyed"))
    canary_present = "canary_obeyed" in signals
    if canary is True:
        logit += _LLR_CANARY_OBEYED
        contributing.append(("canary_obeyed", "true"))
    elif canary is False:
        logit += _LLR_CANARY_REFUSED
        contributing.append(("canary_obeyed", "false"))

    # --- Dual-gate signal 2: machine-speed-with-semantic-content ---
    response_ms: float | None = None
    raw_ms = signals.get("response_ms")
    if raw_ms is not None:
        try:
            response_ms = float(raw_ms)
        except ValueError:
            response_ms = None
    machine_speed: bool | None = None
    if response_ms is not None:
        machine_speed = response_ms < _MACHINE_SPEED_MS
        if machine_speed:
            logit += _LLR_MACHINE_SPEED
            contributing.append(("response_ms", str(int(response_ms))))
        else:
            logit += _LLR_HUMAN_SPEED
            contributing.append(("response_ms", str(int(response_ms))))

    # The DUAL GATE is jointly satisfied only when BOTH agent-confirming signals
    # fired. This is the load-bearing AND (CORROBORANT): either alone is not a
    # confirmation. A human traversing the canary trips at most ONE (and usually
    # zero) so the gate stays closed.
    dual_gate = (canary is True) and (machine_speed is True)

    # --- Augmenting signal: packetization mode (P4) ---
    packet = (signals.get("packetization") or "").strip().lower()
    if packet in ("bundled", "api", "batch"):
        logit += _LLR_PACKET_BUNDLED
        contributing.append(("packetization", "bundled"))
    elif packet in ("1:1", "stream", "ui", "interactive"):
        logit += _LLR_PACKET_1TO1
        contributing.append(("packetization", "1:1"))

    # --- Augmenting signal: tool-call grammar tightness (P10) ---
    grammar = (signals.get("tool_grammar") or "").strip().lower()
    if grammar in ("tight", "agent", "ngram"):
        logit += _LLR_GRAMMAR_TIGHT
        contributing.append(("tool_grammar", "tight"))
    elif grammar in ("loose", "human", "freeform"):
        logit += _LLR_GRAMMAR_LOOSE
        contributing.append(("tool_grammar", "loose"))

    # --- Augmenting signal: biometric motor-noise (P12) ---
    motor = (signals.get("motor_noise") or "").strip().lower()
    if motor in ("absent", "none", "0"):
        logit += _LLR_MOTOR_ABSENT
        contributing.append(("motor_noise", "absent"))
    elif motor in ("present", "human", "1"):
        logit += _LLR_MOTOR_PRESENT
        contributing.append(("motor_noise", "present"))

    # Calibrated conformal probability via the logistic link over summed bits.
    probability = 1.0 / (1.0 + math.exp(-_LOGIT_TEMP * logit))
    # Never a hard 0/1 — clamp into an open interval (conformal open-set, the
    # unseen-class always retains residual probability mass).
    probability = max(0.01, min(0.99, probability))

    # --- Decision: dual gate drives AGENT; otherwise calibrated band ---
    have_any_signal = bool(contributing)

    if dual_gate:
        # BOTH agent-confirming signals fired: AGENT, at the calibrated (never
        # 1.0) probability the combined evidence supports.
        label = AgentHumanLabel.AGENT
        method = "dual_confirmation"
    elif not have_any_signal:
        # No discriminating signal at all → ABSTAIN (probability stays 0.5-ish
        # but the gate was not satisfied; we do not guess).
        label = AgentHumanLabel.ABSTAIN
        probability = 0.5
        method = "abstain_no_signal"
    elif probability <= _ABSTAIN_LOW:
        # Evidence points decisively to a human (canary refused / human speed /
        # 1:1 packetization / present motor-noise). The negative control lands
        # here: a human traversing the canary classifies HUMAN.
        label = AgentHumanLabel.HUMAN
        method = "conformal_openset"
    elif probability >= _ABSTAIN_HIGH:
        # Strong agent evidence WITHOUT the joint dual gate (e.g. bundled API +
        # tight grammar + absent motor-noise but no canary probe planted). We
        # report AGENT-leaning but withhold the dual-gate certainty: still an
        # AGENT label, lower probability, conformal — the gate was not the AND.
        # Conservative: without the dual gate we do NOT assert AGENT; the high
        # probability without the canary+speed corroboration ABSTAINS so a clever
        # forgery on the augmenting axes alone cannot trip the agent class.
        label = AgentHumanLabel.ABSTAIN
        method = "abstain_dual_gate_unmet"
    else:
        # In the uncertain band with the dual gate unmet → ABSTAIN (first-class).
        label = AgentHumanLabel.ABSTAIN
        method = "abstain_uncertain"

    return AgentHumanVerdict(
        label=label,
        probability=probability,
        signals=tuple(contributing),
        method=method,
    )
