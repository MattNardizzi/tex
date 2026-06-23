"""
SIEVE FUSE stage — probabilistic entity resolution (the SCORE + RESOLVE steps).

Turns a stream of plane-typed ``Incidence`` leaves into a set of ``SieveEntity``
projections, fusing footprints that are the same agent and SPLITTING footprints
collapsed under one shared credential (ARCHITECTURE.md §2, §3; RESEARCH_LOG.md
N1, N5).

Two collaborators, both contracts to fill:

- ``FellegiSunterScorer`` — pairwise edge SCORING. Unsupervised, ``log2(m/u)``
  per-comparison weights, term-frequency-adjusted so a shared RARE key weighs
  heavily and a popular one ≈0; missing field = weight 0, not a penalty. Every
  edge is weighted by ``1/anonymity_set_size`` (N5). Emits ``TypedEdge`` with
  the producing plane's ``EdgeGrade``.
- ``PlaneTypedClusterer`` — RESOLUTION. Plane-typed correlation-clustering:
  ``IDENTITY`` edges MUST close transitively; ``BRIDGING`` edges MAY violate. A
  bridging edge whose endpoints fail strong-edge transitive closure becomes a
  positive SPLIT (N1). Same structure does fusion AND disambiguation.

The module-level ``resolve`` is the FUSE entrypoint the pipeline calls.

Implementation notes
---------------------
The Fellegi-Sunter core needs corpus statistics to be term-frequency-adjusted —
the weight of agreeing on a value depends on how RARE that value is across the
whole incidence stream. The fixed ``score_pair(a, b)`` signature carries no
corpus, so corpus statistics are supplied at construction (``FieldStats``,
computed once by ``resolve`` over all incidences before any pair is scored).
A scorer constructed with no stats falls back to a calibrated default weight for
each known key — degenerate-but-honest, never raising.

Each comparison key is classified into an ``EdgeGrade`` by a static, auditable
schema (``_KEY_GRADE``): identity-grade keys (``workspace_path`` cross-plane,
``agent_id`` / ``agent_external_id`` same-agent) close transitively; everything
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
#: same agent on the same plane.
_IDENTITY_KEYS: frozenset[str] = frozenset(
    {"workspace_path", "agent_id", "agent_external_id", "code_hash", "honeytoken"}
)

#: All other shared keys are BRIDGING-grade: a match contributes evidence but
#: MAY violate transitivity and never merges two strong components alone
#: (shared IP/ASN/service-credential/popular signal). Listed for documentation;
#: any key not in ``_IDENTITY_KEYS`` is treated as bridging.
_BRIDGING_KEYS: frozenset[str] = frozenset(
    {"asn", "ja4", "service_credential", "egress_ip", "oidc_sub"}
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


# ---------------------------------------------------------------------------
# Fellegi-Sunter pairwise scorer
# ---------------------------------------------------------------------------


class FellegiSunterScorer:
    """Pairwise Fellegi-Sunter edge scorer with anonymity-set weighting.

    Unsupervised: rather than assume labelled training data, the m/u
    probabilities are derived from corpus frequencies. For a comparison key
    agreeing on a value ``v``:

    - ``u`` (chance agreement) ≈ probability two random incidences both carry
      ``v`` on this key ≈ ``count(v) / total`` — a popular value has a high
      ``u`` and therefore a low weight.
    - ``m`` (true-match agreement) is taken near-certain for an identity-grade
      key (a matched code-hash / workspace-path is overwhelmingly a true link)
      and modest for a bridging key.

    The per-comparison Fellegi-Sunter weight is ``log2(m / u)`` (ARCHITECTURE.md
    §2.2). It is then discounted by ``1 / anonymity_set_size`` *structurally* —
    the ``TypedEdge`` records ``anon_set_size`` and exposes ``effective_weight =
    fs_weight / anon_set_size`` (N5), so a value shared by many footprints
    contributes near-zero evidence even if its raw ``log2(m/u)`` is positive.

    Missing field = weight 0, not a penalty: a key present on one footprint and
    absent on the other simply does not contribute a comparison (it is skipped),
    so absence never drives a spurious split.
    """

    #: Near-certain true-match agreement for identity-grade keys.
    _M_IDENTITY: float = 0.99
    #: Modest true-match agreement for bridging-grade keys (weak evidence).
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

    def __init__(self, stats: FieldStats | None = None) -> None:
        self._stats = stats if stats is not None else FieldStats()

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

    def _comparison_weight(self, key_name: str, value: str) -> float:
        """The TF-adjusted ``log2(m/u)`` weight for one agreeing comparison."""
        grade = _grade_for_key(key_name)
        m = self._M_IDENTITY if grade is EdgeGrade.IDENTITY else self._M_BRIDGING
        u = self._u_probability(key_name, value)
        # Raw Fellegi-Sunter per-comparison weight. Guard: agreement should never
        # be evidence AGAINST a match — a value so popular that u >= m yields a
        # non-positive raw weight; clamp to 0 so a popular BRIDGING key
        # contributes nothing rather than negative evidence.
        raw = max(0.0, math.log2(m / u))
        if grade is EdgeGrade.IDENTITY:
            # An identity-grade agreement is "same agent" by schema; it must
            # always yield positive evidence so transitive closure can fire, even
            # when the value saturates a tiny corpus (u→1). The N5 rarity is NOT
            # lost — it rides the per-edge ``effective_weight = fs_weight /
            # anon_set_size`` discount applied downstream.
            return max(self._IDENTITY_WEIGHT_FLOOR, raw)
        return raw

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
    evidence on both entities but NEVER merges them. Cross-plane contradictions
    (two strong-edge planes disagreeing) set ``attribution_conflict`` +
    ``contradicting_pair`` (N4).
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

    def cluster(
        self, incidences: Sequence[Incidence], edges: Sequence[TypedEdge]
    ) -> list[SieveEntity]:
        """Cluster scored leaves into resolved entities.

        Each returned ``SieveEntity`` gets a STABLE synthetic ``entity_id``
        (the dataclass default — never derived from a footprint key), its member
        ``incidences``, its supporting ``edges``, and an explicit
        ``fusion_confidence`` derived from the edges' effective weights.
        """
        by_id: dict[UUID, Incidence] = {inc.incidence_id: inc for inc in incidences}
        if not by_id:
            return []

        identity_edges = [e for e in edges if e.grade is EdgeGrade.IDENTITY]
        bridging_edges = [e for e in edges if e.grade is EdgeGrade.BRIDGING]

        # 1. Strong-edge transitive closure → one component per real entity.
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
            # Plane coverage: ``SieveEntity.planes_seen`` reads ``{e.plane_id for
            # e in edges}`` (models.py) and the estimator counts capture
            # occasions from it. A single cross-plane edge carries only ONE
            # plane_id, so a component fused across ACTIONS_TRAIL↔FS_WRITE would
            # otherwise under-report as captured on one occasion only — silently
            # zeroing the recapture overlap. We make the entity's edge set cover
            # every plane its member incidences were actually captured on, so the
            # entity attests each occasion it was genuinely seen on (N5/§6).
            covered = self._cover_member_planes(
                member_set, ent_identity_edges, by_id
            )
            entity = SieveEntity(
                incidences=member_set,
                edges=covered,
                fusion_confidence=self._confidence(member_set, covered),
                # The authoritative capture-occasion record: every plane a member
                # incidence was genuinely seen on. Survives the singleton case
                # (a shadow seen on FS_WRITE alone has no edge but WAS captured),
                # which the edge-derived plane set cannot represent.
                planes_captured=frozenset(
                    by_id[mid].plane_id for mid in member_set if mid in by_id
                ),
            )
            self._stamp_axes_and_label(entity, member_set, by_id)
            entities[root] = entity

        # 3. Bridging edges: record as evidence; a bridge ACROSS two strong
        #    components is the N1 split signal (kept, never merged).
        for e in bridging_edges:
            if e.a not in root_of or e.b not in root_of:
                continue
            ra, rb = root_of[e.a], root_of[e.b]
            entities[ra].edges.append(e)
            if ra != rb:
                # Cross-component bridge → positive split signal; mirror on both.
                entities[rb].edges.append(e)

        # 4. Cross-plane incoherence detector (N4): a strong component whose
        #    member footprints come from two planes that CONTRADICT marks the
        #    entity. In the slice the cross-plane join is corroborating, not
        #    contradicting, so this only fires on a genuine disagreement.
        for entity in entities.values():
            self._mark_incoherence(entity, by_id)

        return list(entities.values())

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
        because identity-grade keys closed them transitively (the cross-plane
        ``workspace_path`` match), so attributing that plane's capture to the
        entity is justified, not fabricated. A single-member (singleton) entity
        gets no synthetic edge — there is no second endpoint and nothing to
        corroborate; its plane is carried by the incidence itself and surfaced by
        the estimator via the member set.
        """
        edges: list[TypedEdge] = list(ent_edges)
        if len(members) <= 1:
            return edges

        covered = {e.plane_id for e in edges}
        member_list = sorted(members, key=str)
        plane_of = {mid: by_id[mid].plane_id for mid in members if mid in by_id}
        all_planes = set(plane_of.values())

        for plane in sorted(all_planes - covered, key=lambda p: p.value):
            # Pick a member ON this plane and any distinct member as the anchor.
            anchor = next(m for m in member_list if plane_of.get(m) == plane)
            other = next(m for m in member_list if m != anchor)
            # Anonymity set of 1: a same-component IDENTITY pairing is decisive.
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

    #: FS weight attached to a synthesized plane-coverage edge. It must be
    #: positive (so it counts toward confidence) but modest — it records "this
    #: entity was also captured on this plane", not a fresh independent match.
    _SYNTH_PLANE_WEIGHT: float = 1.0

    def _confidence(
        self, members: set[UUID], identity_edges: Sequence[TypedEdge]
    ) -> float:
        """Map supporting identity evidence to a monotone ``fusion_confidence``.

        A singleton (no corroborating edge) gets a low floor — it is a single
        sighting, deliberately not over-trusted. Otherwise confidence rises
        logistically with the summed ``effective_weight`` of the entity's
        identity edges (the N5-discounted evidence), saturating below 1.0 so the
        engine never asserts certainty.
        """
        if len(members) <= 1 or not identity_edges:
            return self._SINGLETON_CONF
        total = sum(e.effective_weight for e in identity_edges)
        # Logistic on accumulated bits of evidence; bounded in (0, 1).
        conf = 1.0 - math.exp(-self._CONF_SCALE * total)
        return max(self._SINGLETON_CONF, min(conf, 0.999))

    @staticmethod
    def _stamp_axes_and_label(
        entity: SieveEntity, members: set[UUID], by_id: Mapping[UUID, Incidence]
    ) -> None:
        """Fill the coarse merge axis, a display label, and a fusion receipt.

        ``merge_axis`` is the stable agent identifier the component is stitched
        on (``agent_external_id`` if any member carries it, else the shared
        ``workspace_path``). The label prefers a human-readable external id. The
        receipt lists the raw-evidence refs so the ledger story is complete.
        """
        ext_ids: set[str] = set()
        workspace_paths: set[str] = set()
        refs: list[str] = []
        for mid in members:
            inc = by_id[mid]
            ext = inc.footprint.key("agent_external_id")
            if ext:
                ext_ids.add(ext)
            wp = inc.footprint.key("workspace_path")
            if wp:
                workspace_paths.add(wp)
            refs.append(inc.raw_evidence_ref)

        if ext_ids:
            entity.merge_axis = sorted(ext_ids)[0]
            entity.label = sorted(ext_ids)[0]
        elif workspace_paths:
            entity.merge_axis = sorted(workspace_paths)[0]
            entity.label = sorted(workspace_paths)[0]
        entity.fusion_receipt = tuple(sorted(refs))

    @staticmethod
    def _mark_incoherence(
        entity: SieveEntity, by_id: Mapping[UUID, Incidence]
    ) -> None:
        """Set ``attribution_conflict`` when two strong planes contradict (N4).

        A contradiction in the slice means: members from two different planes
        claim DIFFERENT stable agent identifiers under the same fusion. Since the
        cross-plane join here is by ``workspace_path``, a disagreement on
        ``agent_external_id`` across planes (one trail row attributing the same
        file to agent X while another plane attributes it to agent Y) is the
        positive incoherence signal. Corroborating joins leave it untouched.
        """
        planes_to_ext: dict[PlaneId, set[str]] = defaultdict(set)
        for mid in entity.incidences:
            inc = by_id[mid]
            ext = inc.footprint.key("agent_external_id")
            if ext:
                planes_to_ext[inc.plane_id].add(ext)
        # Collect the distinct external ids seen, by plane.
        all_ext = {e for s in planes_to_ext.values() for e in s}
        if len(all_ext) > 1 and len(planes_to_ext) >= 2:
            planes = sorted(planes_to_ext.keys(), key=lambda p: p.value)
            entity.attribution_conflict = True
            entity.contradicting_pair = (planes[0], planes[1])


# ---------------------------------------------------------------------------
# FUSE entrypoint
# ---------------------------------------------------------------------------


def _block(incidences: Sequence[Incidence]) -> set[tuple[UUID, UUID]]:
    """Union-of-blockers candidate generation (ARCHITECTURE.md §0 step 2).

    Two footprints are a candidate pair iff they share at least one comparison
    KEY NAME with the SAME value on any blocking key. Blocking on shared values
    (rather than the full O(n²) cartesian product) is what keeps the scorer
    tractable while staying recoverable on ANY shared key — evading one blocker
    leaves the pair recoverable on another. Returns canonicalized id pairs.
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


def resolve(incidences: Iterable[Incidence]) -> list[SieveEntity]:
    """FUSE entrypoint: incidences → resolved entities.

    Phase-2 slice contract: with the two-plane input, fuse the
    ``ACTIONS_TRAIL`` footprint and the ``FS_WRITE`` footprint that share a
    ``workspace_path`` into ONE ``SieveEntity`` via a cross-plane IDENTITY edge
    with a calibrated ``fusion_confidence`` and a stable synthetic ``entity_id``;
    an ``FS_WRITE`` footprint with NO matching trail row resolves to its own
    entity (the gate-bypassing shadow). A single agent's two footprints must NOT
    split (negative control).

    Wires ``FellegiSunterScorer`` (over the blocked candidate pairs) into
    ``PlaneTypedClusterer``. Returns an empty list on empty input.
    """
    incs = list(incidences)
    if not incs:
        return []

    by_id: dict[UUID, Incidence] = {inc.incidence_id: inc for inc in incs}

    # 1. Corpus statistics for the TF adjustment (computed once).
    stats = FieldStats.from_incidences(incs)
    scorer = FellegiSunterScorer(stats=stats)

    # 2. BLOCK → candidate pairs (union of complementary blockers).
    candidate_pairs = _block(incs)

    # 3. SCORE each candidate pair into a typed edge (dedup by canonical pair).
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

    # 4. RESOLVE via plane-typed correlation clustering.
    return PlaneTypedClusterer().cluster(incs, edges)


__all__ = [
    "FellegiSunterScorer",
    "PlaneTypedClusterer",
    "FieldStats",
    "resolve",
    # re-exported for the builders' convenience
    "EdgeGrade",
    "PlaneId",
]
