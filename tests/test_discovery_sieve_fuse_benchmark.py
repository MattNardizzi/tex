"""
SIEVE FUSE benchmark — the Phase-1 SOTA verifier targets, on planted ground truth.

These tests measure ``fuse.resolve`` / ``FellegiSunterScorer`` / ``PlaneTypedClusterer``
against the three benchmark obligations the deepened fuse stage must MEET:

1. **Fusion pairwise precision >= 0.95 AND recall >= 0.90** on footprints that
   share NO common natural key — resolved ONLY via behavioral / injected-marker
   identity edges (``behavior_sig`` / ``honeytoken``). Pairwise = over the set of
   (incidence, incidence) co-membership pairs vs the planted ground truth.

2. **N1 SPLITTER:** two DISTINCT agents behind ONE shared credential MUST resolve
   to TWO entities (zero false-merge); two footprints of ONE agent MUST NOT split
   (zero false-split) on the negative controls.

3. **(supporting) N4 INCOHERENCE:** two strong-edge planes contradicting set
   ``attribution_conflict`` + the contradicting plane-pair; a coherent agent does
   NOT trip it (false-positive bound).

Run:
    cd /Users/matthewnardizzi/dev/tex-discovery && \
      PYTHONPATH=/Users/matthewnardizzi/dev/tex-discovery/src \
      /Users/matthewnardizzi/dev/tex/.venv/bin/python -m pytest \
      tests/test_discovery_sieve_fuse_benchmark.py -q
"""

from __future__ import annotations

import itertools
import random
from uuid import UUID

from tex.discovery.engine.fuse import (
    FellegiSunterScorer,
    FieldStats,
    PlaneTypedClusterer,
    resolve,
)
from tex.discovery.engine.models import (
    Admissibility,
    EdgeGrade,
    FootprintVector,
    Incidence,
    PlaneId,
)


# ---------------------------------------------------------------------------
# Planted-ground-truth fixture builders. Each incidence carries a hidden
# ``_truth`` agent label (stamped into the evidence ref) so we can score
# resolution against ground truth without leaking it into the matchable keys.
# ---------------------------------------------------------------------------


def _inc(
    plane: PlaneId,
    *,
    keys: dict[str, str],
    truth: str,
    admissibility: Admissibility = Admissibility.OBSERVED,
) -> Incidence:
    return Incidence(
        plane_id=plane,
        footprint=FootprintVector.of(plane, keys=keys, attrs={}),
        catchability=1.0,
        admissibility=admissibility,
        raw_evidence_ref=f"truth={truth}",
    )


def _truth_of(inc: Incidence) -> str:
    return inc.raw_evidence_ref.split("truth=", 1)[1]


def _ground_truth_pairs(incs: list[Incidence]) -> set[frozenset[UUID]]:
    """The set of incidence-pairs that SHOULD co-resolve (same planted agent)."""
    pairs: set[frozenset[UUID]] = set()
    for a, b in itertools.combinations(incs, 2):
        if _truth_of(a) == _truth_of(b):
            pairs.add(frozenset({a.incidence_id, b.incidence_id}))
    return pairs


def _predicted_pairs(entities) -> set[frozenset[UUID]]:
    """The set of incidence-pairs the resolver placed in the same entity."""
    pairs: set[frozenset[UUID]] = set()
    for e in entities:
        for a, b in itertools.combinations(sorted(e.incidences, key=str), 2):
            pairs.add(frozenset({a, b}))
    return pairs


def _precision_recall(truth: set, pred: set) -> tuple[float, float]:
    tp = len(truth & pred)
    fp = len(pred - truth)
    fn = len(truth - pred)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return precision, recall


# ---------------------------------------------------------------------------
# (1) Fusion precision/recall on footprints sharing NO common natural key.
# ---------------------------------------------------------------------------


def test_no_common_key_fusion_meets_precision_recall_targets() -> None:
    """Footprints with NO shared natural key fuse via behavioral/marker edges.

    Each planted agent is seen on multiple planes that share NO literal key
    (no shared workspace_path, no shared agent id) — they are linkable ONLY by a
    behavioral fingerprint (``behavior_sig``, the syscall/tool-grammar MinHash)
    and an injected honeytoken marker (``honeytoken``). Distinct agents carry
    distinct behavioral sigs/markers. Target: pairwise precision >= 0.95 AND
    recall >= 0.90 against the planted ground truth.
    """
    rng = random.Random(7)
    incs: list[Incidence] = []
    n_agents = 25
    for i in range(n_agents):
        sig = f"behavsig-{i:04d}"          # behavioral fingerprint (identity-grade)
        marker = f"honeytoken-{i:04d}"     # injected cross-plane join key (identity)
        # Plane A: only the behavioral sig + a UNIQUE per-sighting path (no reuse).
        incs.append(
            _inc(
                PlaneId.ACTIONS_TRAIL,
                keys={"behavior_sig": sig, "workspace_path": f"a/{i}-{rng.random():.9f}.md"},
                truth=f"agent-{i}",
            )
        )
        # Plane B: only the honeytoken marker + a different unique path.
        incs.append(
            _inc(
                PlaneId.FS_WRITE,
                keys={"honeytoken": marker, "workspace_path": f"b/{i}-{rng.random():.9f}.md"},
                truth=f"agent-{i}",
            )
        )
        # Plane B again: carries BOTH the marker AND the behavioral sig (the
        # cross-plane join that stitches the A-sighting to the B-sighting with no
        # shared natural key between A and the first B sighting).
        incs.append(
            _inc(
                PlaneId.FS_WRITE,
                keys={"behavior_sig": sig, "honeytoken": marker},
                truth=f"agent-{i}",
            )
        )
    rng.shuffle(incs)

    entities = resolve(incs)
    truth = _ground_truth_pairs(incs)
    pred = _predicted_pairs(entities)
    precision, recall = _precision_recall(truth, pred)

    assert precision >= 0.95, f"fusion precision {precision:.3f} < 0.95"
    assert recall >= 0.90, f"fusion recall {recall:.3f} < 0.90"
    # And the resolver did not collapse everything into one blob.
    assert len(entities) == n_agents, f"expected {n_agents} entities, got {len(entities)}"


def test_popular_bridge_alone_never_over_merges() -> None:
    """N5: a low-entropy (popular) bridge alone never merges distinct agents.

    Many distinct agents share ONE popular service-credential (a low-entropy
    bridging attribute). With no identity-grade edge between them, they MUST stay
    distinct — the popular bridge's effective weight is ≈0 and bridging edges are
    structurally barred from transitive closure (N5 over-merge correction).
    """
    incs: list[Incidence] = []
    n = 30
    for i in range(n):
        incs.append(
            _inc(
                PlaneId.ACTIONS_TRAIL,
                keys={
                    "service_credential": "shared-sa-001",   # popular bridge
                    "behavior_sig": f"sig-{i:04d}",           # distinct identity
                },
                truth=f"agent-{i}",
            )
        )
    entities = resolve(incs)
    # Popular bridge alone must NOT merge the distinct agents.
    assert len(entities) == n, f"popular bridge over-merged: {len(entities)} != {n}"


# ---------------------------------------------------------------------------
# (2) N1 splitter: distinct agents behind one credential split; one agent doesn't.
# ---------------------------------------------------------------------------


def test_n1_two_agents_behind_one_credential_split_to_two() -> None:
    """Two DISTINCT agents under ONE shared credential resolve to TWO entities.

    Both agents share a self-... no — share a BRIDGING ``service_credential``
    (the credential ``tex_gate`` trusts), but carry DISTINCT identity-grade
    behavioral fingerprints. The bridge across the two strong components is the
    N1 transitivity violation: two entities, and a ``SharedCredentialVerdict``
    with ``k_estimate == 2`` naming both. Zero false-merge.
    """
    cred = "service_credential", "svc-shared-42"
    incs = [
        # Agent X: two footprints, linked by a behavioral identity edge.
        _inc(PlaneId.ACTIONS_TRAIL, keys={cred[0]: cred[1], "behavior_sig": "X"}, truth="X"),
        _inc(PlaneId.FS_WRITE, keys={cred[0]: cred[1], "behavior_sig": "X"}, truth="X"),
        # Agent Y: two footprints, distinct behavioral identity.
        _inc(PlaneId.ACTIONS_TRAIL, keys={cred[0]: cred[1], "behavior_sig": "Y"}, truth="Y"),
        _inc(PlaneId.FS_WRITE, keys={cred[0]: cred[1], "behavior_sig": "Y"}, truth="Y"),
    ]
    entities = resolve(incs)

    # Two distinct strong components — the credential did NOT merge them.
    assert len(entities) == 2, f"shared credential over-merged: {len(entities)} != 2"

    # A SharedCredentialVerdict naming k_estimate == 2 is recorded on the split.
    verdicts = [v for e in entities for v in e.shared_credential_verdicts]
    split_verdicts = [v for v in verdicts if v.credential_id == "service_credential=svc-shared-42"]
    assert split_verdicts, "no SharedCredentialVerdict recorded for the shared credential"
    v = split_verdicts[0]
    assert v.k_estimate == 2, f"k_estimate {v.k_estimate} != 2 for two distinct agents"
    assert len(set(v.member_entity_ids)) == 2
    assert 0.0 <= v.confidence <= 1.0 and v.confidence < 1.0  # never a hard 1.0
    assert v.method == "transitivity_violation"


def test_n1_one_agent_does_not_split_negative_control() -> None:
    """Negative control: two footprints of ONE agent do NOT split.

    One agent's two footprints share a credential AND a behavioral identity, so
    they fuse to ONE entity. Any recorded credential verdict is ``k_estimate==1``
    (zero false-split).
    """
    incs = [
        _inc(PlaneId.ACTIONS_TRAIL, keys={"service_credential": "svc-solo", "behavior_sig": "Z"}, truth="Z"),
        _inc(PlaneId.FS_WRITE, keys={"service_credential": "svc-solo", "behavior_sig": "Z"}, truth="Z"),
    ]
    entities = resolve(incs)
    assert len(entities) == 1, "one agent's two footprints must NOT split"
    for v in entities[0].shared_credential_verdicts:
        assert v.k_estimate == 1, f"false split: k_estimate {v.k_estimate} for one agent"


def test_n1_three_agents_behind_one_credential_split_to_three() -> None:
    """k=3 distinct agents behind one credential resolve to THREE entities."""
    cred = "egress_ip", "10.0.0.9"
    incs = []
    for name in ("A", "B", "C"):
        incs.append(_inc(PlaneId.ACTIONS_TRAIL, keys={cred[0]: cred[1], "behavior_sig": name}, truth=name))
        incs.append(_inc(PlaneId.FS_WRITE, keys={cred[0]: cred[1], "behavior_sig": name}, truth=name))
    entities = resolve(incs)
    assert len(entities) == 3
    verdicts = [v for e in entities for v in e.shared_credential_verdicts if v.k_estimate >= 2]
    assert verdicts and verdicts[0].k_estimate == 3


# ---------------------------------------------------------------------------
# (3) N4 incoherence detector: contradicting strong planes flagged; coherent not.
# ---------------------------------------------------------------------------


def test_n4_incoherence_flags_contradicting_strong_planes() -> None:
    """Two strong planes attributing one fused entity to DIFFERENT ids = N4.

    One entity is fused by a shared ``workspace_path`` (identity edge), but its
    two planes carry CONTRADICTING ``agent_external_id`` (ACTIONS_TRAIL says one
    agent, FS_WRITE-side attribution says another) — the compromised/forged tell.
    ``attribution_conflict`` is set with the contradicting plane-pair.
    """
    incs = [
        _inc(
            PlaneId.ACTIONS_TRAIL,
            keys={"workspace_path": "shared/file.md", "agent_external_id": "ResearchAgent"},
            truth="entity",
        ),
        _inc(
            PlaneId.FS_WRITE,
            keys={"workspace_path": "shared/file.md", "agent_external_id": "DeployAgent"},
            truth="entity",
        ),
    ]
    entities = resolve(incs)
    # They fuse on workspace_path (one entity) but the strong planes contradict.
    conflicted = [e for e in entities if e.attribution_conflict]
    assert conflicted, "N4 did not flag contradicting strong-plane attribution"
    e = conflicted[0]
    assert e.contradicting_pair is not None
    assert set(e.contradicting_pair) == {PlaneId.ACTIONS_TRAIL, PlaneId.FS_WRITE}


def test_n4_coherent_agent_does_not_trip_incoherence() -> None:
    """A fully-coherent cross-plane agent must NOT trip N4 (false-positive bound)."""
    incs = [
        _inc(
            PlaneId.ACTIONS_TRAIL,
            keys={"workspace_path": "ok/file.md", "agent_external_id": "Agent"},
            truth="entity",
        ),
        _inc(
            PlaneId.FS_WRITE,
            keys={"workspace_path": "ok/file.md", "agent_external_id": "Agent"},
            truth="entity",
        ),
    ]
    entities = resolve(incs)
    assert len(entities) == 1
    assert not entities[0].attribution_conflict
    assert entities[0].contradicting_pair is None


# ---------------------------------------------------------------------------
# (4) Fellegi-Sunter EM + N5 weight properties (unit-level, not placeholders).
# ---------------------------------------------------------------------------


def test_fs_rare_value_weighs_more_than_popular_value() -> None:
    """TF adjustment: a RARE shared value yields a higher edge weight than a
    POPULAR one (after the N5 anonymity-set discount)."""
    # Corpus: a popular bridging value (shared by many) vs a rare one (shared by 2).
    corpus: list[Incidence] = []
    for i in range(20):
        corpus.append(_inc(PlaneId.ACTIONS_TRAIL, keys={"asn": "AS-popular"}, truth=f"p{i}"))
    rare_a = _inc(PlaneId.ACTIONS_TRAIL, keys={"asn": "AS-rare"}, truth="r")
    rare_b = _inc(PlaneId.FS_WRITE, keys={"asn": "AS-rare"}, truth="r")
    pop_a = corpus[0]
    pop_b = corpus[1]
    all_incs = corpus + [rare_a, rare_b]

    stats = FieldStats.from_incidences(all_incs)
    scorer = FellegiSunterScorer(stats=stats)
    e_rare = scorer.score_pair(rare_a, rare_b)
    e_pop = scorer.score_pair(pop_a, pop_b)
    assert e_rare is not None
    # The popular bridge's effective weight must be ~0 vs the rare bridge.
    pop_eff = e_pop.effective_weight if e_pop else 0.0
    assert e_rare.effective_weight > pop_eff
    assert e_rare.anon_set_size == 2  # rare value shared by exactly two
    if e_pop is not None:
        assert e_pop.anon_set_size >= 20  # popular value's large anonymity set


def test_missing_field_contributes_zero_not_a_penalty() -> None:
    """A key on one footprint but absent on the other is skipped (weight 0)."""
    a = _inc(PlaneId.ACTIONS_TRAIL, keys={"behavior_sig": "S", "workspace_path": "p.md"}, truth="x")
    b = _inc(PlaneId.FS_WRITE, keys={"behavior_sig": "S"}, truth="x")  # no workspace_path
    stats = FieldStats.from_incidences([a, b])
    scorer = FellegiSunterScorer(stats=stats)
    edge = scorer.score_pair(a, b)
    # They still fuse on the shared behavior_sig; the missing workspace_path on b
    # neither blocks the edge nor penalizes it.
    assert edge is not None
    assert edge.grade is EdgeGrade.IDENTITY
    assert edge.fs_weight > 0.0
