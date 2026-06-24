"""
SIEVE FUSE stage — probabilistic entity resolution (the SCORE + RESOLVE steps).

Turns a stream of plane-typed ``Incidence`` leaves into a set of ``SieveEntity``
projections, fusing footprints that are the same agent and SPLITTING footprints
collapsed under one shared credential (ARCHITECTURE.md §2, §3; RESEARCH_LOG.md
N1, N4, N5).

Two collaborators, both real (no placeholders):

- ``FellegiSunterScorer`` — pairwise edge SCORING. Unsupervised, with an
  expectation-maximization (EM) fit of the per-key ``m`` (match-agreement) and
  ``u`` (chance-agreement) probabilities over the candidate-pair agreement
  patterns; per-comparison weight is ``log2(m/u)``, term-frequency-adjusted so a
  shared RARE value weighs heavily and a popular one ≈0; a missing field
  contributes weight 0 (never a penalty). Every edge carries its anonymity-set
  size so the N5 ``1/anonymity_set_size`` discount rides downstream. Emits
  ``TypedEdge`` with the producing key's ``EdgeGrade``.
- ``PlaneTypedClusterer`` — RESOLUTION. Plane-typed correlation-clustering:
  ``IDENTITY`` edges MUST close transitively; ``BRIDGING`` edges MAY violate. A
  bridging edge whose endpoints land in *different* strong components is the
  positive N1 SPLIT signal (two agents behind one credential) and is recorded as
  a ``SharedCredentialVerdict`` on both entities — the same structure does fusion
  AND shared-credential splitting. Two strong-edge planes carrying contradicting
  attribution set ``attribution_conflict`` + ``contradicting_pair`` (N4).

The module-level ``resolve`` is the FUSE entrypoint the pipeline calls.

Implementation notes
---------------------
The Fellegi-Sunter core is term-frequency-adjusted: the weight of agreeing on a
value depends on how RARE that value is across the whole incidence stream. The
``u`` probability comes directly from corpus frequency (``FieldStats``); the
``m`` probability is fit by an unsupervised EM over the observed agreement
vectors of the candidate pairs (Fellegi & Sunter 1969; Splink/FuzzyLink), with a
calibrated identity/bridging prior so a tiny or degenerate corpus stays honest
rather than diverging. A scorer constructed with no stats falls back to a
calibrated default weight for each known key — degenerate-but-honest, never
raising.

N5 (anonymity-set weighting + over-merge correction): the per-edge
``effective_weight = fs_weight / anon_set_size`` already discounts a value shared
by many footprints. The clusterer adds the second half of N5: bridging evidence
is capped so a low-entropy (large anonymity-set) attribute cannot accumulate
enough weight to merge two strong components — popular-JA4/shared-credential
bridges contribute ≈0 and never over-merge.

Each comparison key is classified into an ``EdgeGrade`` by a static, auditable
schema (``_KEY_GRADE``): identity-grade keys (``workspace_path`` cross-plane,
``agent_id`` / ``agent_external_id`` same-agent, ``code_hash`` / ``honeytoken`` /
``behavior_sig`` behavioral or injected-marker) close transitively; everything
else is bridging and may never merge two strong components on its own.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence
from uuid import UUID

from tex.discovery.engine.models import (
    EdgeGrade,
    Incidence,
    PlaneId,
    SharedCredentialVerdict,
    SieveEntity,
    TypedEdge,
)

# ---------------------------------------------------------------------------
# Key → edge-grade schema (auditable, static — the resolver decides grade)
# ---------------------------------------------------------------------------

#: Comparison keys that carry IDENTITY-grade evidence: a match on one of these
#: is strong enough to MERGE two footprints into one entity and MUST close
#: transitively (ARCHITECTURE.md §2.5). ``workspace_path`` is the cross-plane
#: fusion key joining a logged write (ACTIONS_TRAIL) to the file on disk
#: (FS_WRITE); ``agent_id`` / ``agent_external_id`` join two sightings of the
#: same agent on the same plane; ``code_hash`` is the eBPF/IMA code anchor
#: (merge axis); ``honeytoken`` / ``injected_marker`` is the N3 cross-plane
#: injected JOIN KEY that fuses footprints sharing NO natural key; ``behavior_sig``
#: is the behavioral fingerprint (syscall/tool-grammar MinHash) that links two
#: footprints of the same code with no shared literal identifier.
#: The full PLANE roster (ARCHITECTURE.md §8) adds more identity-grade names so
#: the same agent seen on N planes fuses to one entity: ``code_hash`` (P9 eBPF /
#: IMA measured-boot anchor — survives rotation), ``spiffe_id`` / ``oidc_sub``
#: (P13 signed-identity anchors), ``injected_marker`` / ``canary_cred_id`` /
#: ``decoy_id`` (P14 honeytoken co-trip — a planted cross-plane JOIN KEY that
#: fuses footprints sharing NO natural key), ``tool_set_minhash`` (P10 MCP/A2A
#: tool-set behavioral anchor), ``syscall_graph_sig`` (P9 behavioral split/merge
#: axis), and ``managed_agent_id`` (P6/P7 control-plane-minted stable id). These
#: are identity-grade by SCHEMA: a match means "same agent" and MUST close
#: transitively. ``tool_minhash`` is kept as a legacy alias of
#: ``tool_set_minhash`` so older footprints stay strong.
_IDENTITY_KEYS: frozenset[str] = frozenset(
    {
        "workspace_path",
        "agent_id",
        "agent_external_id",
        "code_hash",
        "honeytoken",
        "injected_marker",
        "behavior_sig",
        "tool_minhash",
        "spiffe_id",
        # --- full-roster identity-grade names (ARCHITECTURE.md §8) ----------
        "oidc_sub",
        "tool_set_minhash",
        "syscall_graph_sig",
        "managed_agent_id",
        "canary_cred_id",
        "decoy_id",
    }
)

#: All other shared keys are BRIDGING-grade: a match contributes evidence but
#: MAY violate transitivity and never merges two strong components alone
#: (shared IP/ASN/service-credential/popular signal). Listed for documentation;
#: any key not in ``_IDENTITY_KEYS`` is treated as bridging.
#: The full roster adds more BRIDGING-grade names: the network-egress bridges
#: (``ja4s``/``sni``/``h2_settings_hash``/``token_waveform_sig``/``cadence_sig``
#: — a shared TLS/HTTP fingerprint links but a popular value is shared by
#: millions, so the N5 ``1/anon_set_size`` discount drives it to ≈0 evidence),
#: the SaaS/automation grant bridges (``oauth_grant_id``/``bot_user_id``/
#: ``automation_recipe_id``/``saas_app`` — one shared app credential collapses k
#: agents, the positive N1 split signal), the governance/control bridges
#: (``billing_account``/``role_arn``/``iam_role``/``control_plane``/``region``/
#: ``model`` — coarse cohorts, never identity), and the static/MCP CLAIM bridges
#: (``repo_path``/``framework``/``manifest_path``/``mcp_server_url``/
#: ``agent_card_id`` — declared, never load-bearing alone). ``oidc_sub`` is
#: deliberately NOT here — a SIGNED OIDC subject is identity-grade (above).
_BRIDGING_KEYS: frozenset[str] = frozenset(
    {
        "asn",
        "ja4",
        "service_credential",
        "egress_ip",
        "claimed_by",
        "api_key",
        # --- network-egress fingerprints (popular → ~0 via N5 discount) -----
        "ja4s",
        "sni",
        "h2_settings_hash",
        "token_waveform_sig",
        "cadence_sig",
        # --- SaaS/automation shared-credential bridges (N1 split source) ----
        "oauth_grant_id",
        "bot_user_id",
        "automation_recipe_id",
        "saas_app",
        "sp_object_id",
        # --- coarse managed/governance cohorts (never identity) ------------
        "billing_account",
        "role_arn",
        "iam_role",
        "control_plane",
        "region",
        "model",
        "host_id",
        # --- static / MCP declared-claim bridges ---------------------------
        "repo_path",
        "framework",
        "manifest_path",
        "mcp_server_url",
        "agent_card_id",
        "caller_fingerprint",
    }
)


def _grade_for_key(key_name: str) -> EdgeGrade:
    """Classify a comparison key into its provenance grade (static schema)."""
    if key_name in _IDENTITY_KEYS:
        return EdgeGrade.IDENTITY
    return EdgeGrade.BRIDGING


# ---------------------------------------------------------------------------
# Corpus statistics — the term-frequency adjustment (N5 anonymity set)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldStats:
    """Per-(key, value) corpus frequencies driving the TF-adjusted FS weight.

    Computed once by ``resolve`` over all incidences. The anonymity-set size of
    a shared value is *how many distinct incidences carry that exact value*: a
    ``workspace_path`` written by exactly two footprints has an anonymity set of
    2 (near-certain link), while a popular ASN shared by hundreds has a large
    anonymity set and contributes ≈0 evidence after the ``1/anonymity_set_size``
    discount (ARCHITECTURE.md §2.3, N5).

    - ``value_counts``  — ``{key_name: {value: count}}`` over all incidences.
    - ``total``         — number of incidences in the corpus (the universe size
                          ``u``-probability is computed against).
    """

    value_counts: Mapping[str, Mapping[str, int]] = field(default_factory=dict)
    total: int = 0

    @classmethod
    def from_incidences(cls, incidences: Sequence[Incidence]) -> "FieldStats":
        """Tabulate value frequencies for every comparison key in the corpus."""
        counts: dict[str, Counter[str]] = defaultdict(Counter)
        for inc in incidences:
            for k, v in inc.footprint.keys:
                counts[k][v] += 1
        return cls(
            value_counts={k: dict(c) for k, c in counts.items()},
            total=len(incidences),
        )

    def anonymity_set_size(self, key_name: str, value: str) -> int:
        """Number of incidences sharing this exact (key, value) — min 1."""
        return max(1, self.value_counts.get(key_name, {}).get(value, 1))

    def distinct_values(self, key_name: str) -> int:
        """Number of distinct values this key takes across the corpus."""
        return len(self.value_counts.get(key_name, {}))


# ---------------------------------------------------------------------------
# Unsupervised EM for the per-key m / u probabilities (Fellegi-Sunter 1969)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MUParams:
    """Fitted Fellegi-Sunter ``m`` / ``u`` per comparison key.

    ``m[k]`` = P(key k agrees | the pair is a TRUE match); ``u[k]`` = P(key k
    agrees | the pair is a NON-match). The Fellegi-Sunter per-comparison weight
    for an agreement is ``log2(m/u)``. These are fit unsupervised by EM over the
    candidate-pair agreement vectors (no labels), with a grade-informed prior so
    a degenerate corpus stays honest.
    """

    m: Mapping[str, float] = field(default_factory=dict)
    u: Mapping[str, float] = field(default_factory=dict)
    p_match: float = 0.0
    iterations: int = 0
    converged: bool = False


class _MUFitter:
    """Unsupervised EM estimator of per-key ``m`` and ``u`` (Fellegi-Sunter).

    The classic FS latent-class model: each candidate pair is latently a MATCH
    or a NON-match; an agreement vector γ (one bit per comparison key) is
    observed. Under conditional independence,

        P(γ) = p·∏ m_k^{γ_k}(1-m_k)^{1-γ_k} + (1-p)·∏ u_k^{γ_k}(1-u_k)^{1-γ_k}

    EM alternates: E-step computes the posterior match-weight g_i of each pair;
    M-step re-estimates m_k = Σ g_i γ_{ik} / Σ g_i and u_k symmetrically.

    Honesty constraints baked in so a tiny/degenerate corpus never diverges:
    - an identity-grade key is PRIORED high-m / low-u and constrained m >= u
      (an identity agreement is by-schema evidence FOR a match);
    - u is floored by the corpus chance-agreement so it can never collapse to 0
      (which would send log2(m/u) → ∞);
    - the mixing weight p is bounded away from 0 and 1.
    """

    _MAX_ITERS: int = 50
    _TOL: float = 1e-4
    # Grade-informed priors (also the no-data fallback).
    _M_PRIOR_IDENTITY: float = 0.95
    _M_PRIOR_BRIDGING: float = 0.55
    _U_PRIOR_IDENTITY: float = 0.02
    _U_PRIOR_BRIDGING: float = 0.20
    # Bounds keeping the model finite and honest.
    _M_FLOOR: float = 0.05
    _M_CEIL: float = 0.999
    _U_FLOOR: float = 1e-4
    _U_CEIL: float = 0.95
    _P_FLOOR: float = 1e-3
    _P_CEIL: float = 0.5
    # FS latent-class identifiability anchors (grade-informed, auditable):
    # an identity-grade key's match-agreement m stays at/above this anchor (it is
    # a schema-strong match driver, never demoted to noise by a popular bridge);
    # a bridging-grade key's m stays at/below this ceiling (a popular co-agreement
    # can never masquerade as the dominant match signal).
    _M_IDENTITY_ANCHOR: float = 0.90
    _M_BRIDGING_CEIL: float = 0.60

    def __init__(self, stats: FieldStats) -> None:
        self._stats = stats

    def _prior_m(self, key: str) -> float:
        return (
            self._M_PRIOR_IDENTITY
            if _grade_for_key(key) is EdgeGrade.IDENTITY
            else self._M_PRIOR_BRIDGING
        )

    def _prior_u(self, key: str) -> float:
        # Anchor u at the corpus chance-agreement when we can measure it, else
        # the grade prior. P(two random incidences agree on key k) ≈ Σ p(v)^2.
        counts = self._stats.value_counts.get(key)
        if counts and self._stats.total > 1:
            total = self._stats.total
            chance = sum((c / total) ** 2 for c in counts.values())
            return min(self._U_CEIL, max(self._U_FLOOR, chance))
        return (
            self._U_PRIOR_IDENTITY
            if _grade_for_key(key) is EdgeGrade.IDENTITY
            else self._U_PRIOR_BRIDGING
        )

    def fit(self, agreement_vectors: Sequence[frozenset[str]]) -> MUParams:
        """Fit m/u by EM over the observed agreement vectors of candidate pairs.

        ``agreement_vectors`` is one ``frozenset`` of agreeing key names per
        candidate pair. Keys never appearing in any vector keep their prior.
        """
        keys = sorted(
            {k for vec in agreement_vectors for k in vec}
            | set(self._stats.value_counts.keys())
        )
        m = {k: self._prior_m(k) for k in keys}
        u = {k: self._prior_u(k) for k in keys}
        # Identity keys are constrained m >= u from the start.
        for k in keys:
            if _grade_for_key(k) is EdgeGrade.IDENTITY and m[k] < u[k]:
                m[k] = min(self._M_CEIL, max(m[k], u[k] + 0.5))

        if not agreement_vectors:
            return MUParams(m=m, u=u, p_match=self._P_FLOOR, iterations=0, converged=True)

        p = max(self._P_FLOOR, min(self._P_CEIL, 0.1))
        iters = 0
        converged = False
        for _ in range(self._MAX_ITERS):
            iters += 1
            # E-step: posterior match-weight of each pair.
            gsum = 0.0
            num_m: dict[str, float] = {k: 0.0 for k in keys}
            num_u: dict[str, float] = {k: 0.0 for k in keys}
            denom_m = 0.0
            denom_u = 0.0
            prev_m = dict(m)
            prev_u = dict(u)
            for vec in agreement_vectors:
                # Likelihood of the agreement vector under each class (log-space).
                lm = math.log(p)
                lu = math.log(1.0 - p)
                for k in keys:
                    if k in vec:
                        lm += math.log(m[k])
                        lu += math.log(u[k])
                    else:
                        lm += math.log(1.0 - m[k])
                        lu += math.log(1.0 - u[k])
                # Posterior g = P(match | vec), numerically stable.
                top = lm
                bot = lu
                hi = max(top, bot)
                g = math.exp(top - hi) / (math.exp(top - hi) + math.exp(bot - hi))
                gsum += g
                denom_m += g
                denom_u += 1.0 - g
                for k in vec:
                    num_m[k] += g
                    num_u[k] += 1.0 - g
            # M-step (with the FS identifiability anchor below).
            p = max(self._P_FLOOR, min(self._P_CEIL, gsum / len(agreement_vectors)))
            for k in keys:
                grade = _grade_for_key(k)
                if denom_m > 0:
                    m[k] = min(self._M_CEIL, max(self._M_FLOOR, num_m[k] / denom_m))
                if denom_u > 0:
                    u_raw = num_u[k] / denom_u
                    # Never below the corpus chance-floor (prior_u), never 0.
                    u[k] = min(self._U_CEIL, max(self._prior_u(k), max(self._U_FLOOR, u_raw)))
                # --- FS latent-class IDENTIFIABILITY ANCHOR ----------------
                # Plain FS-EM is label-switch-prone: a near-universal POPULAR
                # bridge (agrees on almost every candidate pair) can capture the
                # "match" mode while the true high-information identity key gets
                # pushed to the floor — an inverted, dishonest fit even when the
                # static grade schema still resolves correctly downstream. We
                # anchor the latent class with the auditable grade schema (the
                # informative-prior fix from the Splink/Fellegi-Sunter practice):
                #   * an IDENTITY-grade key is a schema-strong MATCH driver — its
                #     m is floored well above its u so it can never be demoted to
                #     noise by a popular co-agreement;
                #   * a BRIDGING-grade key is weak — its m is CEILINGED so a
                #     popular bridge cannot masquerade as the match signal.
                if grade is EdgeGrade.IDENTITY:
                    m[k] = max(m[k], self._M_IDENTITY_ANCHOR)
                    # And keep a clear margin m >= u so log2(m/u) > 0.
                    if m[k] <= u[k]:
                        m[k] = min(self._M_CEIL, u[k] + 0.5)
                else:
                    m[k] = min(m[k], self._M_BRIDGING_CEIL)
            delta = max(
                max(abs(m[k] - prev_m[k]) for k in keys),
                max(abs(u[k] - prev_u[k]) for k in keys),
            )
            if delta < self._TOL:
                converged = True
                break
        return MUParams(m=m, u=u, p_match=p, iterations=iters, converged=converged)


# ---------------------------------------------------------------------------
# Fellegi-Sunter pairwise scorer
# ---------------------------------------------------------------------------


class FellegiSunterScorer:
    """Pairwise Fellegi-Sunter edge scorer with anonymity-set weighting.

    Unsupervised: the ``m``/``u`` probabilities are fit by EM (``MUParams``,
    supplied at construction by ``resolve``) over the candidate-pair agreement
    vectors. For a comparison key agreeing on a value ``v``:

    - ``u`` (chance agreement) is the EM-fit non-match agreement probability,
      floored at the corpus chance-agreement Σ p(v)² — a popular value has a high
      ``u`` and therefore a low weight.
    - ``m`` (true-match agreement) is the EM-fit match agreement probability;
      identity-grade keys are constrained ``m >= u``.

    The per-comparison Fellegi-Sunter weight is ``log2(m / u)`` (ARCHITECTURE.md
    §2.2), then TF-sharpened by the value's rarity (a value rarer than its key's
    average agreement is up-weighted; a popular value is down-weighted toward 0).
    It is further discounted by ``1 / anonymity_set_size`` *structurally* — the
    ``TypedEdge`` records ``anon_set_size`` and exposes ``effective_weight =
    fs_weight / anon_set_size`` (N5), so a value shared by many footprints
    contributes near-zero evidence even if its raw ``log2(m/u)`` is positive.

    Missing field = weight 0, not a penalty: a key present on one footprint and
    absent on the other simply does not contribute a comparison (it is skipped),
    so absence never drives a spurious split.

    Backward-compatible construction: a scorer built with only ``FieldStats``
    (or nothing) fits ``MUParams`` from a calibrated grade prior, so the slice's
    ``FellegiSunterScorer(stats=stats)`` path keeps working unchanged.
    """

    #: Near-certain true-match agreement for identity-grade keys (no-EM fallback).
    _M_IDENTITY: float = 0.99
    #: Modest true-match agreement for bridging-grade keys (no-EM fallback).
    _M_BRIDGING: float = 0.70
    #: Floor on the chance-agreement probability so ``log2(m/u)`` stays finite
    #: when a value is unique in the corpus (``u`` would otherwise be ~0).
    _U_FLOOR: float = 1e-6
    #: Default chance-agreement used when no corpus stats were supplied — keeps
    #: the degenerate, no-``fit`` path honest rather than raising.
    _U_DEFAULT: float = 0.1
    #: Positive floor on an IDENTITY-grade comparison weight. An identity-grade
    #: key (code-hash / agent-id / cross-plane workspace-path) means "same agent"
    #: BY SCHEMA, so its agreement must always yield positive evidence — even in a
    #: tiny corpus where the value appears in every row and the raw ``log2(m/u)``
    #: would clamp to 0. The TF/anonymity rarity still carries through the N5
    #: ``effective_weight`` discount (``fs_weight / anon_set_size``); this floor
    #: only guarantees an IDENTITY agreement never SILENTLY produces no edge.
    _IDENTITY_WEIGHT_FLOOR: float = 1.0

    def __init__(
        self,
        stats: FieldStats | None = None,
        mu: MUParams | None = None,
    ) -> None:
        self._stats = stats if stats is not None else FieldStats()
        self._mu = mu

    def _shared_keys(self, a: Incidence, b: Incidence) -> list[tuple[str, str]]:
        """Keys present on BOTH footprints with the same value (agreements)."""
        a_keys = a.footprint.keys_dict()
        b_keys = b.footprint.keys_dict()
        shared: list[tuple[str, str]] = []
        for name, val in a_keys.items():
            # Missing-on-either-side keys are skipped (weight 0), not penalized.
            if b_keys.get(name) == val:
                shared.append((name, val))
        return shared

    def _u_probability(self, key_name: str, value: str) -> float:
        """Chance-agreement probability for a key/value from corpus frequency."""
        total = self._stats.total
        if total <= 0:
            return self._U_DEFAULT
        count = self._stats.value_counts.get(key_name, {}).get(value, 1)
        return max(self._U_FLOOR, count / total)

    def _m_for_key(self, key_name: str) -> float:
        """The match-agreement probability — EM-fit if available, else prior."""
        if self._mu is not None and key_name in self._mu.m:
            return self._mu.m[key_name]
        return (
            self._M_IDENTITY
            if _grade_for_key(key_name) is EdgeGrade.IDENTITY
            else self._M_BRIDGING
        )

    def _comparison_weight(self, key_name: str, value: str) -> float:
        """The TF-adjusted ``log2(m/u)`` weight for one agreeing comparison."""
        grade = _grade_for_key(key_name)
        m = self._m_for_key(key_name)
        if self._mu is not None and key_name in self._mu.u:
            # EM-fit non-match agreement, value-sharpened by corpus rarity: the
            # per-value u floats the key-level u toward this exact value's
            # frequency, so a RARE value (low freq) lowers u and raises the
            # weight, a POPULAR value raises u and flattens it.
            key_u = self._mu.u[key_name]
            value_u = self._u_probability(key_name, value)
            u = max(self._U_FLOOR, min(self._U_CEIL_FOR(m), 0.5 * key_u + 0.5 * value_u))
        else:
            u = self._u_probability(key_name, value)
        raw = max(0.0, math.log2(m / u))
        if grade is EdgeGrade.IDENTITY:
            # An identity-grade agreement is "same agent" by schema; it must
            # always yield positive evidence so transitive closure can fire, even
            # when the value saturates a tiny corpus (u→1). The N5 rarity is NOT
            # lost — it rides the per-edge ``effective_weight = fs_weight /
            # anon_set_size`` discount applied downstream.
            return max(self._IDENTITY_WEIGHT_FLOOR, raw)
        return raw

    @staticmethod
    def _U_CEIL_FOR(m: float) -> float:
        """Keep u strictly below m so an agreement never yields a non-positive
        log-ratio purely from a degenerate fit."""
        return max(1e-6, min(0.95, m - 1e-3))

    def score_pair(self, a: Incidence, b: Incidence) -> TypedEdge | None:
        """Score one candidate pair, returning a ``TypedEdge`` or ``None``.

        Returns ``None`` when the pair shares no comparable key (no edge). When
        the pair agrees on one or more keys, the strongest-grade agreeing key
        sets the edge grade (a single identity-grade agreement makes the whole
        edge ``IDENTITY``); the edge's ``fs_weight`` is the summed
        per-comparison ``log2(m/u)`` over all agreeing keys, and
        ``anon_set_size`` is the rarity of the grade-determining key so the
        ``effective_weight`` carries the N5 discount.
        """
        if a.incidence_id == b.incidence_id:
            return None
        shared = self._shared_keys(a, b)
        if not shared:
            return None

        total_weight = 0.0
        best_grade = EdgeGrade.BRIDGING
        # Anonymity set of the key that DETERMINES the grade (the rarest
        # identity-grade key if any, else the rarest bridging key) — that key is
        # the one the N5 discount must reflect.
        grade_anon = 1
        grade_rarity = math.inf  # smaller anon set = rarer = more decisive

        for name, val in shared:
            total_weight += self._comparison_weight(name, val)
            grade = _grade_for_key(name)
            anon = self._stats.anonymity_set_size(name, val)
            # Promote to IDENTITY if any agreeing key is identity-grade; among
            # keys of the chosen grade, keep the rarest (smallest anon set).
            if grade is EdgeGrade.IDENTITY and best_grade is not EdgeGrade.IDENTITY:
                best_grade = EdgeGrade.IDENTITY
                grade_anon, grade_rarity = anon, anon
            elif grade is best_grade and anon < grade_rarity:
                grade_anon, grade_rarity = anon, anon

        # No positive evidence (every shared key was a popular bridging value) →
        # no edge worth recording.
        if total_weight <= 0.0:
            return None

        return TypedEdge(
            a=a.incidence_id,
            b=b.incidence_id,
            plane_id=self._edge_plane(a, b),
            grade=best_grade,
            fs_weight=total_weight,
            anon_set_size=max(1, grade_anon),
        )

    @staticmethod
    def _edge_plane(a: Incidence, b: Incidence) -> PlaneId:
        """The plane that produced the comparison.

        A same-plane agreement records that plane; a cross-plane agreement
        (the ACTIONS_TRAIL↔FS_WRITE fusion on ``workspace_path``) records the
        FS_WRITE plane as the producing vantage, since the ground-truth write is
        what the trail row is being joined to.
        """
        if a.plane_id == b.plane_id:
            return a.plane_id
        # Cross-plane: prefer the PROVEN ground-truth plane as the producer.
        return PlaneId.FS_WRITE if PlaneId.FS_WRITE in (a.plane_id, b.plane_id) else a.plane_id


# ---------------------------------------------------------------------------
# Plane-typed correlation clusterer (FUSE + SPLIT resolver)
# ---------------------------------------------------------------------------


class _UnionFind:
    """Minimal union-find over UUIDs for strong-edge transitive closure."""

    def __init__(self, items: Iterable[UUID]) -> None:
        self._parent: dict[UUID, UUID] = {it: it for it in items}

    def add(self, item: UUID) -> None:
        self._parent.setdefault(item, item)

    def find(self, item: UUID) -> UUID:
        root = item
        while self._parent[root] != root:
            root = self._parent[root]
        # Path compression.
        while self._parent[item] != root:
            self._parent[item], item = root, self._parent[item]
        return root

    def union(self, a: UUID, b: UUID) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[ra] = rb

    def components(self) -> dict[UUID, list[UUID]]:
        groups: dict[UUID, list[UUID]] = defaultdict(list)
        for item in self._parent:
            groups[self.find(item)].append(item)
        return groups


class PlaneTypedClusterer:
    """Plane-typed correlation clustering (the FUSE + SPLIT resolver).

    Strong (``IDENTITY``) edges close transitively into one entity via
    union-find; a ``BRIDGING`` edge whose endpoints land in *different* strong
    components is the positive SPLIT signal (N1) — it is recorded as supporting
    evidence on both entities, a ``SharedCredentialVerdict`` is attached naming
    the bridging credential and ``k_estimate`` of the agents behind it, and the
    components are NEVER merged. Cross-plane contradictions (two strong-edge
    planes disagreeing on attribution) set ``attribution_conflict`` +
    ``contradicting_pair`` (N4).

    N5 over-merge correction lives here too: bridging edges never participate in
    transitive closure at all (only IDENTITY edges union), so a low-entropy
    attribute cannot over-merge two distinct agents no matter how many bridges it
    contributes. The bridge's ``effective_weight`` (already ``1/anon_set_size``-
    discounted) is recorded for receipts but is structurally barred from merging.
    """

    #: Logistic steepness mapping summed effective edge weight → confidence.
    #: A single decisive identity edge (effective_weight ≳ 3 bits) already lands
    #: above ~0.9; many weak bridges accumulate slowly. Tunable, calibrated in
    #: Phase 5; chosen here so the slice's single cross-plane edge resolves high.
    _CONF_SCALE: float = 0.6
    #: Floor confidence for a singleton entity (one incidence, no corroborating
    #: edge) — it is seen, but barely; the estimator, not a high score, carries
    #: the gate-bypassing shadow's importance.
    _SINGLETON_CONF: float = 0.30
    #: FS weight attached to a synthesized plane-coverage edge. It must be
    #: positive (so it counts toward confidence) but modest — it records "this
    #: entity was also captured on this plane", not a fresh independent match.
    _SYNTH_PLANE_WEIGHT: float = 1.0

    def cluster(
        self, incidences: Sequence[Incidence], edges: Sequence[TypedEdge]
    ) -> list[SieveEntity]:
        """Cluster scored leaves into resolved entities.

        Each returned ``SieveEntity`` gets a STABLE synthetic ``entity_id``
        (the dataclass default — never derived from a footprint key), its member
        ``incidences``, its supporting ``edges``, an explicit
        ``fusion_confidence`` derived from the edges' effective weights, any N1
        ``shared_credential_verdicts``, and the N4 incoherence flags.
        """
        by_id: dict[UUID, Incidence] = {inc.incidence_id: inc for inc in incidences}
        if not by_id:
            return []

        identity_edges = [e for e in edges if e.grade is EdgeGrade.IDENTITY]
        bridging_edges = [e for e in edges if e.grade is EdgeGrade.BRIDGING]

        # 1. Strong-edge transitive closure → one component per real entity.
        #    BRIDGING edges deliberately do NOT union (N5 over-merge bar / N1).
        uf = _UnionFind(by_id.keys())
        for e in identity_edges:
            if e.a in by_id and e.b in by_id:
                uf.union(e.a, e.b)

        components = uf.components()
        root_of: dict[UUID, UUID] = {}
        for root, members in components.items():
            for m in members:
                root_of[m] = root

        # 2. Assemble one entity per strong component.
        entities: dict[UUID, SieveEntity] = {}
        for root, members in components.items():
            member_set = set(members)
            ent_identity_edges = [
                e for e in identity_edges if e.a in member_set and e.b in member_set
            ]
            covered = self._cover_member_planes(
                member_set, ent_identity_edges, by_id
            )
            entity = SieveEntity(
                incidences=member_set,
                edges=covered,
                fusion_confidence=self._confidence(member_set, covered),
                planes_captured=frozenset(
                    by_id[mid].plane_id for mid in member_set if mid in by_id
                ),
            )
            self._stamp_axes_and_label(entity, member_set, by_id)
            entities[root] = entity

        # 3. Bridging edges: record as evidence; a bridge ACROSS two strong
        #    components is the N1 split signal (kept, never merged). Group the
        #    cross-component bridges by their shared bridging value so a single
        #    credential collapsing k agents yields ONE k-way verdict.
        self._apply_bridges(entities, root_of, bridging_edges, by_id)

        # 4. Cross-plane incoherence detector (N4): a strong component whose
        #    member footprints carry two strong planes that CONTRADICT attribution
        #    marks the entity with the contradicting plane-pair.
        for entity in entities.values():
            self._mark_incoherence(entity, by_id)

        return list(entities.values())

    # ------------------------------------------------------------------
    # N1 — shared-credential SPLITTER (bridge across strong components)
    # ------------------------------------------------------------------

    def _apply_bridges(
        self,
        entities: Mapping[UUID, SieveEntity],
        root_of: Mapping[UUID, UUID],
        bridging_edges: Sequence[TypedEdge],
        by_id: Mapping[UUID, Incidence],
    ) -> None:
        """Record bridging edges and emit N1 split verdicts.

        A bridging edge whose endpoints are in DIFFERENT strong components is a
        transitive-closure FAILURE across the credential bridge: the credential
        hid >=2 distinct agents (N1). The edge is recorded as evidence on both
        entities (never a merge), and the credential's cross-component endpoints
        are grouped so ONE ``SharedCredentialVerdict`` names ``k_estimate`` = the
        number of distinct strong components the credential bridges.

        Same-component bridges (both endpoints in one strong cluster) are
        recorded as corroborating evidence and contribute a ``k_estimate == 1``
        verdict — the negative control: one agent's footprints under one
        credential do NOT split.
        """
        # Identify the bridging credential value behind each edge so we can group.
        # credential_id -> {root -> [member incidence ids on that root]}
        cred_roots: dict[str, dict[UUID, set[UUID]]] = defaultdict(lambda: defaultdict(set))
        cred_signals: dict[str, set[str]] = defaultdict(set)

        for e in bridging_edges:
            if e.a not in root_of or e.b not in root_of:
                continue
            ra, rb = root_of[e.a], root_of[e.b]
            entities[ra].edges.append(e)
            if ra != rb:
                entities[rb].edges.append(e)

            cred_id, signal = self._bridge_credential(by_id[e.a], by_id[e.b])
            if cred_id is None:
                continue
            cred_roots[cred_id][ra].add(e.a)
            cred_roots[cred_id][rb].add(e.b)
            if signal:
                cred_signals[cred_id].add(signal)

        # Also fold in any credential that a SINGLE strong component carries even
        # without a cross-component bridge (so the no-false-split negative control
        # still produces a k==1 verdict for an agent sharing one credential with
        # itself across footprints).
        self._fold_single_component_credentials(entities, root_of, by_id, cred_roots, cred_signals)

        # Emit one verdict per credential.
        for cred_id, root_map in cred_roots.items():
            roots = sorted(root_map.keys(), key=str)
            k = len(roots)
            member_entity_ids = tuple(entities[r].entity_id for r in roots)
            signals = tuple(sorted(cred_signals.get(cred_id, set()))) or ("bridging_credential",)
            if k >= 2:
                method = "transitivity_violation"
                # Confidence rises with the number + separation of components but
                # stays bounded (never a hard 1.0 — residual sharers stay counted).
                confidence = min(0.95, 0.6 + 0.1 * (k - 1))
            else:
                method = "no_split"
                confidence = 0.8  # confident it is ONE agent (no closure failure)
            verdict = SharedCredentialVerdict(
                credential_id=cred_id,
                k_estimate=k,
                member_entity_ids=member_entity_ids,
                confidence=confidence,
                split_axis_signals=signals,
                method=method,
            )
            for r in roots:
                ent = entities[r]
                ent.shared_credential_verdicts = ent.shared_credential_verdicts + (verdict,)
                if k >= 2 and ent.split_axis is None:
                    ent.split_axis = signals[0]

    @staticmethod
    def _bridge_credential(
        a: Incidence, b: Incidence
    ) -> tuple[str | None, str | None]:
        """The shared BRIDGING (key,value) the two footprints collapsed under.

        Returns ``(credential_id, signal_name)`` for the rarest shared bridging
        key, or ``(None, None)`` if the pair shares no bridging key. The
        credential id is ``"<key>=<value>"`` so the verdict names exactly what
        was collapsed (a service-credential, a self-asserted ``agent_external_id``
        — wait: that is identity-grade — or an egress IP / api_key).
        """
        a_keys = a.footprint.keys_dict()
        b_keys = b.footprint.keys_dict()
        best: tuple[str, str] | None = None
        for name, val in a_keys.items():
            if _grade_for_key(name) is EdgeGrade.BRIDGING and b_keys.get(name) == val:
                # Prefer a credential-ish key over a coincidental bridge.
                if best is None or name in ("service_credential", "api_key", "egress_ip"):
                    best = (name, val)
        if best is None:
            return (None, None)
        return (f"{best[0]}={best[1]}", best[0])

    def _fold_single_component_credentials(
        self,
        entities: Mapping[UUID, SieveEntity],
        root_of: Mapping[UUID, UUID],
        by_id: Mapping[UUID, Incidence],
        cred_roots: dict[str, dict[UUID, set[UUID]]],
        cred_signals: dict[str, set[str]],
    ) -> None:
        """Register single-component credential cohorts for k==1 verdicts.

        For every bridging credential value carried by >=2 footprints that all
        fall in ONE strong component, record that component so a ``k_estimate==1``
        verdict is emitted — the explicit no-false-split negative control.
        """
        # value -> set of roots that carry it, and the incidence ids per root.
        cred_member: dict[str, dict[UUID, set[UUID]]] = defaultdict(lambda: defaultdict(set))
        cred_count: Counter[str] = Counter()
        cred_sig: dict[str, str] = {}
        for mid, inc in by_id.items():
            if mid not in root_of:
                continue
            for name, val in inc.footprint.keys:
                if _grade_for_key(name) is EdgeGrade.BRIDGING:
                    cid = f"{name}={val}"
                    cred_member[cid][root_of[mid]].add(mid)
                    cred_count[cid] += 1
                    cred_sig.setdefault(cid, name)
        for cid, root_map in cred_member.items():
            if cred_count[cid] < 2:
                continue  # a credential carried by one footprint splits nothing
            if cid in cred_roots:
                continue  # already captured by a cross-component bridge
            # Only fold credentials confined to a single strong component as k==1.
            cred_roots[cid].update({r: set(ids) for r, ids in root_map.items()})
            if cred_sig.get(cid):
                cred_signals[cid].add(cred_sig[cid])

    # ------------------------------------------------------------------
    # Plane coverage + confidence
    # ------------------------------------------------------------------

    def _cover_member_planes(
        self,
        members: set[UUID],
        ent_edges: Sequence[TypedEdge],
        by_id: Mapping[UUID, Incidence],
    ) -> list[TypedEdge]:
        """Ensure the entity's edges attest every plane it was captured on.

        Starts from the scored intra-component IDENTITY edges, then for any
        member-incidence plane NOT already present in ``{e.plane_id}`` synthesizes
        ONE representative IDENTITY edge — typed by that plane — between a member
        on that plane and any other member. The synthesized edge is real
        evidence: the two members are in the SAME strong component precisely
        because identity-grade keys closed them transitively, so attributing that
        plane's capture to the entity is justified, not fabricated. A
        single-member (singleton) entity gets no synthetic edge.
        """
        edges: list[TypedEdge] = list(ent_edges)
        if len(members) <= 1:
            return edges

        covered = {e.plane_id for e in edges}
        member_list = sorted(members, key=str)
        plane_of = {mid: by_id[mid].plane_id for mid in members if mid in by_id}
        all_planes = set(plane_of.values())

        for plane in sorted(all_planes - covered, key=lambda p: p.value):
            anchor = next(m for m in member_list if plane_of.get(m) == plane)
            other = next(m for m in member_list if m != anchor)
            edges.append(
                TypedEdge(
                    a=anchor,
                    b=other,
                    plane_id=plane,
                    grade=EdgeGrade.IDENTITY,
                    fs_weight=self._SYNTH_PLANE_WEIGHT,
                    anon_set_size=1,
                )
            )
            covered.add(plane)
        return edges

    def _confidence(
        self, members: set[UUID], identity_edges: Sequence[TypedEdge]
    ) -> float:
        """Map supporting identity evidence to a monotone ``fusion_confidence``.

        A singleton (no corroborating edge) gets a low floor. Otherwise
        confidence rises logistically with the summed ``effective_weight`` of the
        entity's identity edges (the N5-discounted evidence), saturating below
        1.0 so the engine never asserts certainty.
        """
        if len(members) <= 1 or not identity_edges:
            return self._SINGLETON_CONF
        ident = [e for e in identity_edges if e.grade is EdgeGrade.IDENTITY]
        if not ident:
            return self._SINGLETON_CONF
        total = sum(e.effective_weight for e in ident)
        conf = 1.0 - math.exp(-self._CONF_SCALE * total)
        return max(self._SINGLETON_CONF, min(conf, 0.999))

    @staticmethod
    def _stamp_axes_and_label(
        entity: SieveEntity, members: set[UUID], by_id: Mapping[UUID, Incidence]
    ) -> None:
        """Fill the coarse merge axis, a display label, and a fusion receipt.

        ``merge_axis`` is the stable agent identifier the component is stitched
        on (``agent_external_id`` if any member carries it, else ``code_hash``,
        else the shared ``workspace_path``). The label prefers a human-readable
        external id. The receipt lists the raw-evidence refs.
        """
        ext_ids: set[str] = set()
        code_hashes: set[str] = set()
        workspace_paths: set[str] = set()
        refs: list[str] = []
        for mid in members:
            inc = by_id[mid]
            ext = inc.footprint.key("agent_external_id")
            if ext:
                ext_ids.add(ext)
            ch = inc.footprint.key("code_hash")
            if ch:
                code_hashes.add(ch)
            wp = inc.footprint.key("workspace_path")
            if wp:
                workspace_paths.add(wp)
            refs.append(inc.raw_evidence_ref)

        if ext_ids:
            entity.merge_axis = sorted(ext_ids)[0]
            entity.label = sorted(ext_ids)[0]
        elif code_hashes:
            entity.merge_axis = sorted(code_hashes)[0]
            entity.label = sorted(code_hashes)[0]
        elif workspace_paths:
            entity.merge_axis = sorted(workspace_paths)[0]
            entity.label = sorted(workspace_paths)[0]
        entity.fusion_receipt = tuple(sorted(refs))

    @staticmethod
    def _mark_incoherence(
        entity: SieveEntity, by_id: Mapping[UUID, Incidence]
    ) -> None:
        """Set ``attribution_conflict`` when two strong planes contradict (N4).

        A contradiction means: two member incidences from DIFFERENT planes
        (capture occasions) carry an identity-grade attribute that DISAGREES.
        Concretely, two strong planes attributing the same fused entity to
        different ``agent_external_id`` / ``code_hash`` / ``behavior_sig`` values
        is a forge/compromise tell — the engine records the contradicting
        plane-PAIR. Corroborating joins (the planes agree) leave it untouched.

        This is the literal N4 mechanism: the entity was fused (so an
        identity-grade edge closed it), yet two of its strong planes disagree on
        WHO it is — exactly the compromised-but-still-signing case.
        """
        # Per identity attribute, the {plane -> set(values)} it carries.
        attr_planes: dict[str, dict[PlaneId, set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )
        for mid in entity.incidences:
            inc = by_id[mid]
            for name in ("agent_external_id", "code_hash", "behavior_sig", "spiffe_id"):
                val = inc.footprint.key(name)
                if val is not None:
                    attr_planes[name][inc.plane_id].add(val)

        for name, planes in attr_planes.items():
            if len(planes) < 2:
                continue
            distinct_values = {v for s in planes.values() for v in s}
            if len(distinct_values) > 1:
                ordered = sorted(planes.keys(), key=lambda p: p.value)
                entity.attribution_conflict = True
                entity.contradicting_pair = (ordered[0], ordered[1])
                return


# ---------------------------------------------------------------------------
# FUSE entrypoint
# ---------------------------------------------------------------------------


def _block(incidences: Sequence[Incidence]) -> set[tuple[UUID, UUID]]:
    """Union-of-blockers candidate generation (ARCHITECTURE.md §0 step 2).

    Two footprints are a candidate pair iff they share at least one comparison
    KEY NAME with the SAME value on any blocking key. This is the UNION of
    complementary blockers: exact-key blocks (``workspace_path``, ``code_hash``,
    ``agent_external_id``) ∪ behavioral / injected-marker blocks (``behavior_sig``,
    ``tool_minhash``, ``honeytoken``, ``injected_marker``) ∪ bridging blocks
    (``service_credential``, ``egress_ip``, ``api_key``, ``ja4``, ``asn``).

    Blocking on shared values (rather than the full O(n²) cartesian product) is
    what keeps the scorer tractable while staying recoverable on ANY shared key —
    evading one blocker leaves the pair recoverable on another (the union
    property). Footprints that share NO natural key still block (and fuse) if a
    behavioral fingerprint or an injected honeytoken marker agrees, which is how
    the no-common-key fusion target is met. Returns canonicalized id pairs.
    """
    # Invert: (key_name, value) -> [incidence_ids that carry it].
    buckets: dict[tuple[str, str], list[UUID]] = defaultdict(list)
    for inc in incidences:
        for k, v in inc.footprint.keys:
            buckets[(k, v)].append(inc.incidence_id)

    pairs: set[tuple[UUID, UUID]] = set()
    for ids in buckets.values():
        if len(ids) < 2:
            continue
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                a, b = ids[i], ids[j]
                pairs.add((a, b) if str(a) < str(b) else (b, a))
    return pairs


def cohorts_by_credential(
    incidences: Iterable[Incidence],
    credential_keys: Sequence[str] = ("agent_external_id", "service_credential", "egress_ip"),
) -> dict[str, list[Incidence]]:
    """Group incidences by the BRIDGING credential key they collapsed under.

    The input ``disambiguate.resolve_shared_credential`` consumes: a mapping of
    ``credential_id -> [Incidence, ...]`` for every shared bridging credential.
    A credential that carries only one incidence is still returned (the
    no-false-split negative control runs on it). The FIRST matching key in
    ``credential_keys`` wins per incidence, so the precedence is explicit and
    auditable. Backward-compatible NEW helper — does not alter ``resolve``.

    Args:
        incidences: the incidence stream.
        credential_keys: the bridging key names, in precedence order, that act as
            shared-credential nodes (default: self-asserted id, service
            credential, egress IP — the keys ``tex_gate`` trusts blindly).

    Returns:
        ``{credential_id: [Incidence, ...]}`` over every incidence carrying one
        of ``credential_keys``. Incidences with none are omitted.
    """
    cohorts: dict[str, list[Incidence]] = defaultdict(list)
    for inc in incidences:
        for name in credential_keys:
            val = inc.footprint.key(name)
            if val is not None:
                cohorts[f"{name}={val}"].append(inc)
                break
    return dict(cohorts)


def resolve(
    incidences: Iterable[Incidence],
    *,
    catchability_by_plane: Mapping[PlaneId, float] | None = None,
) -> list[SieveEntity]:
    """FUSE entrypoint: incidences → resolved entities.

    Pipeline (ARCHITECTURE.md §0 steps 2-4):
    1. tabulate corpus ``FieldStats`` for the TF adjustment (computed once);
    2. BLOCK candidate pairs via the union of complementary blockers;
    3. fit the Fellegi-Sunter ``m``/``u`` by unsupervised EM over the candidate
       pairs' agreement vectors;
    4. SCORE each candidate pair into a typed edge with the EM-fit weights and the
       N5 anonymity-set discount;
    5. RESOLVE via plane-typed correlation clustering — IDENTITY edges close
       transitively (FUSE); a BRIDGING bridge across strong components is the N1
       SPLIT (two agents behind one credential); two strong planes disagreeing on
       attribution set the N4 incoherence flags.

    Two footprints of one agent (sharing an identity-grade key, even a purely
    behavioral / injected-marker one with NO natural common key) fuse to ONE
    entity; two distinct agents behind one shared credential resolve to TWO
    entities with a ``SharedCredentialVerdict``; a singleton gate-bypassing shadow
    resolves to its own entity. Returns an empty list on empty input.

    Args:
        incidences: the incidence stream to resolve.
        catchability_by_plane: OPTIONAL measured per-plane catchability (N2),
            forwarded by the deeper builders so a calibrated fusion can weight
            edges by the producing plane's measured recall. ``None`` (the
            default) preserves the count-based behavior; the parameter is
            keyword-only so adding it never shifts a positional call.
    """
    incs = list(incidences)
    if not incs:
        return []
    _ = catchability_by_plane  # accepted for the calibrated builders; not consumed here.

    by_id: dict[UUID, Incidence] = {inc.incidence_id: inc for inc in incs}

    # 1. Corpus statistics for the TF adjustment (computed once).
    stats = FieldStats.from_incidences(incs)

    # 2. BLOCK → candidate pairs (union of complementary blockers).
    candidate_pairs = _block(incs)

    # 3. Fit m/u by unsupervised EM over the candidate-pair agreement vectors.
    agreement_vectors: list[frozenset[str]] = []
    for a_id, b_id in candidate_pairs:
        a, b = by_id.get(a_id), by_id.get(b_id)
        if a is None or b is None:
            continue
        a_keys = a.footprint.keys_dict()
        b_keys = b.footprint.keys_dict()
        agree = frozenset(
            name for name, val in a_keys.items() if b_keys.get(name) == val
        )
        if agree:
            agreement_vectors.append(agree)
    mu = _MUFitter(stats).fit(agreement_vectors)
    scorer = FellegiSunterScorer(stats=stats, mu=mu)

    # 4. SCORE each candidate pair into a typed edge (dedup by canonical pair).
    edges: list[TypedEdge] = []
    seen_pairs: set[tuple[UUID, UUID]] = set()
    for a_id, b_id in candidate_pairs:
        if a_id not in by_id or b_id not in by_id:
            continue
        edge = scorer.score_pair(by_id[a_id], by_id[b_id])
        if edge is None:
            continue
        key = (edge.a, edge.b)
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        edges.append(edge)

    # 5. RESOLVE via plane-typed correlation clustering.
    return PlaneTypedClusterer().cluster(incs, edges)


__all__ = [
    "FellegiSunterScorer",
    "PlaneTypedClusterer",
    "FieldStats",
    "MUParams",
    "resolve",
    "cohorts_by_credential",
    # re-exported for the builders' convenience
    "EdgeGrade",
    "PlaneId",
]
