"""
SIEVE Layer-A COVERAGE PROOF — the comprehensive discovery+correlation assertion.

Drives the full SIEVE engine over the planting harness
(``tests.discovery_coverage_harness``) and asserts the honesty-gated coverage
contract the brief requires:

* EVERY catchable archetype (a)..(j) maps to a REAL planted agent the engine
  ACTUALLY surfaced — each resolved to its expected entity count.
* The SHARED-CREDENTIAL pair (h) splits to TWO distinct entities, never one.
* The DECOYS (i) — a human-using-an-LLM, a dormant identity, a duplicate signal —
  do NOT inflate the agent count (the human is classified HUMAN, the duplicate
  collapses to one entity).
* The EVASIVE agent (j) is caught and flags the N4 cross-plane incoherence with
  its contradicting plane-PAIR.
* The PHYSICALLY-IRREDUCIBLE agent (k) is NAMED in the blind-spot ledger and is
  NOT fake-found.
* The two-axis identity + cross-plane fusion SURVIVE mutation (rename / restart /
  egress-change / strip-identity / move-to-stdio).
* The REAL fleet (read-only) yields real gate-bypass shadows from the filesystem
  alone — the hard case demonstrated on real data, without touching the fleet.

Run:
    cd /Users/matthewnardizzi/dev/tex-discovery && \
      PYTHONPATH=/Users/matthewnardizzi/dev/tex-discovery/src \
      /Users/matthewnardizzi/dev/tex/.venv/bin/python -m pytest \
      tests/test_discovery_coverage_proof.py -q
"""

from __future__ import annotations

import pytest

from tests.discovery_coverage_harness import (
    archetypes,
    mutate_estate,
    plant_all,
    real_fleet_available,
    run_full_engine,
    run_real_fleet_full_estate,
    run_real_fleet_slice,
)
from tex.discovery.engine.models import AgentHumanLabel, PlaneId


# ===========================================================================
# Fixtures — one planted estate (in-memory) + one with file-sensor fixtures.
# ===========================================================================


@pytest.fixture(scope="module")
def estate():
    return plant_all()


@pytest.fixture(scope="module")
def result(estate):
    return run_full_engine(estate)


@pytest.fixture(scope="module")
def estate_with_fixtures(tmp_path_factory):
    root = tmp_path_factory.mktemp("sieve_coverage_fixtures")
    return plant_all(root)


# ===========================================================================
# 1. EVERY catchable archetype maps to a REAL surfaced agent.
# ===========================================================================


@pytest.mark.parametrize(
    "key", [a.key for a in archetypes() if a.catchable and a.key not in ("h", "i", "m")]
)
def test_catchable_archetype_is_discovered(result, key):
    """Each single-agent catchable archetype resolves to a REAL entity.

    Maps a coverage claim to a planted agent the engine ACTUALLY surfaced — the
    honesty gate: no archetype is "claimed found" without a resolved entity.
    """
    arch = next(a for a in archetypes() if a.key == key)
    ents = result.entities_with_truth(arch.label)
    assert len(ents) == arch.expected_entities, (
        f"archetype ({key}) {arch.label}: expected {arch.expected_entities} "
        f"entity(ies), got {len(ents)} — {arch.description}"
    )
    # The label is genuinely in the engine's surfaced set (not asserted blind).
    assert arch.label in result.found_labels()


def test_all_catchable_labels_present(result):
    """The full catchable roster (a)..(j) is surfaced — no silent coverage gap."""
    found = result.found_labels()
    for arch in archetypes():
        if not arch.catchable:
            continue
        if arch.key == "h":
            assert {"shared-cred-A", "shared-cred-B"} <= found
        elif arch.key == "m":
            # Two distinct agents share the SAME ground-truth label; the per-
            # entity split is asserted in the dedicated over-merge test.
            assert "hostile-shared-ja4" in found
        elif arch.key == "i":
            # Only the DUPLICATE's real agent is a discovered agent; the bait
            # labels exist as their own (non-agent) sightings but are handled by
            # the decoy assertions below.
            assert "decoy-duplicate" in found
        else:
            assert arch.label in found, f"({arch.key}) {arch.label} not surfaced"


# ===========================================================================
# 2. SHARED-CREDENTIAL pair (h) splits to TWO entities, never one.
# ===========================================================================


def test_shared_credential_pair_splits_to_two(result):
    a = result.entities_with_truth("shared-cred-A")
    b = result.entities_with_truth("shared-cred-B")
    assert len(a) == 1, "shared-cred agent A did not resolve to exactly one entity"
    assert len(b) == 1, "shared-cred agent B did not resolve to exactly one entity"
    assert a[0].entity_id != b[0].entity_id, "the two shared-cred agents collapsed to one"

    # No single entity mixes the two distinct agents (zero false-merge).
    for e in result.entities:
        truths = result.truths_of(e)
        assert not ({"shared-cred-A", "shared-cred-B"} <= truths), (
            "false-merge: two distinct agents behind one credential collapsed"
        )

    # The N1 split is recorded as a SharedCredentialVerdict with k_estimate >= 2.
    verdicts = [
        v
        for e in (a + b)
        for v in e.shared_credential_verdicts
        if v.k_estimate >= 2
    ]
    assert verdicts, "no SharedCredentialVerdict recorded the k>=2 split"


# ===========================================================================
# 3. DECOYS (i) do NOT inflate the agent count.
# ===========================================================================


def test_decoy_human_is_not_classified_agent(result):
    """A human-using-an-LLM must NOT be labeled AGENT (HUMAN or ABSTAIN only)."""
    humans = result.entities_with_truth("decoy-human")
    assert len(humans) == 1, "the human bait should be its own single sighting"
    verdict = humans[0].agent_human
    assert verdict is not None, "agent-vs-human classifier did not run on the bait"
    assert verdict.label in (AgentHumanLabel.HUMAN, AgentHumanLabel.ABSTAIN), (
        f"false positive: human-using-an-LLM classified {verdict.label}"
    )


def test_decoy_duplicate_signal_collapses_to_one_entity(result):
    """A duplicate signal of ONE agent must resolve to ONE entity, not two."""
    dup = result.entities_with_truth("decoy-duplicate")
    assert len(dup) == 1, (
        f"duplicate signal of one agent inflated to {len(dup)} entities"
    )
    # And that one entity fused BOTH duplicate sightings.
    assert len(dup[0].incidences) == 2, "the two duplicate sightings did not fuse"


def test_decoy_dormant_identity_is_not_an_exercised_agent(result):
    """A dormant directory identity is a claim with no exercised behavior.

    It must not masquerade as a discovered ACTING agent: its only sighting is a
    PLATFORM_ATTESTED/CLAIMED signed-id leaf with no behavioral corroboration, so
    its entity carries no exercised capability edge.
    """
    dormant = result.entities_with_truth("decoy-dormant")
    assert len(dormant) == 1
    graph = dormant[0].capability_graph
    exercised = [e for e in (graph.edges if graph else ()) if e.exercised]
    assert not exercised, "dormant identity falsely shows exercised capability"


# ===========================================================================
# 4. EVASIVE agent (j) caught + flags N4 cross-plane incoherence.
# ===========================================================================


def test_evasive_agent_caught_and_flags_incoherence(result):
    ev = result.entities_with_truth("evasive-catchable")
    assert len(ev) == 1, "evasive agent did not resolve to one entity"
    entity = ev[0]
    # It was caught via multi-plane corroboration (fused across kernel + gov).
    assert len(entity.incidences) == 2
    assert {PlaneId.KERNEL_EBPF, PlaneId.GOVERNANCE_STREAM} <= entity.planes_seen
    # N4: the signed-vs-observed behavioral contradiction is a positive find.
    assert entity.attribution_conflict, (
        "N4 incoherence not raised on the compromised-but-signing evader"
    )
    assert entity.contradicting_pair is not None
    assert set(entity.contradicting_pair) == {
        PlaneId.KERNEL_EBPF,
        PlaneId.GOVERNANCE_STREAM,
    }


# ===========================================================================
# 4b. HOSTILE over-merge trap (m): two agents sharing one POPULAR JA4 resolve
#     to TWO distinct entities — the N5 anonymity-set bar holds, zero false-merge.
# ===========================================================================


def test_hostile_shared_ja4_resolves_to_two_entities(result):
    """Two DISTINCT agents sharing one popular JA4 must NOT over-merge (N5).

    The popular JA4 is a low-entropy BRIDGING key (its anonymity set is large
    because many crowd footprints carry it), so the ``1/anonymity_set_size``
    discount drives its evidence to ≈0. The two agents agree ONLY on that bridge
    yet each carries its OWN identity-grade ``code_hash`` — the strong components
    fail to close transitively across the popular bridge, so the engine resolves
    TWO distinct entities, never one. This is the over-merge dual of (h).
    """
    hostile = result.entities_with_truth("hostile-shared-ja4")
    assert len(hostile) == 2, (
        f"N5 over-merge bar FAILED: two agents sharing a popular JA4 resolved to "
        f"{len(hostile)} entit(ies), expected 2 (the popular bridge over-merged)"
    )
    # They are genuinely distinct entities (not the same id surfaced twice).
    assert len({e.entity_id for e in hostile}) == 2
    # Each fused its OWN eBPF + egress leaf on its own code-hash anchor.
    for e in hostile:
        assert len(e.incidences) == 2
        assert {PlaneId.KERNEL_EBPF, PlaneId.NETWORK_EGRESS} <= e.planes_seen
    # Zero false-merge: no entity in the whole estate carries BOTH hostile leaves
    # AND no entity merges a hostile agent with a crowd decoy on the popular JA4.
    for e in result.entities:
        truths = result.truths_of(e)
        crowd = {t for t in truths if t.startswith("ja4-crowd-")}
        assert not (("hostile-shared-ja4" in truths) and crowd), (
            "false-merge: a hostile agent over-merged with a popular-JA4 crowd decoy"
        )


# ===========================================================================
# 5. PHYSICALLY-IRREDUCIBLE agent (k) is NAMED, not fake-found.
# ===========================================================================


def test_irreducible_agent_is_named_blind_spot_not_found(result, estate):
    # It was NEVER planted as an observable incidence → it cannot be in results.
    assert estate.irreducible_label not in result.found_labels(), (
        "the physically-irreducible air-gapped agent was FAKE-FOUND"
    )
    # The estimator NAMES the withheld vantages (its missing vantage) in the
    # blind-spot ledger rather than folding the mass into N̂.
    spots = result.blind_spot_planes()
    assert spots, "no named blind spot emitted — the honesty ledger is empty"
    assert PlaneId.WITHHELD_THIRD in spots
    # The estimate is an honest lower bound + CI, never a count, never 100%.
    est = result.unseen
    assert 0.0 <= est.ci_low <= est.lower <= est.ci_high <= 1.0
    assert est.coverage_health != "calibrated"  # the slice never claims this


# ===========================================================================
# 6. Two-axis identity + cross-plane fusion SURVIVE mutation.
# ===========================================================================


def test_mutation_preserves_discovery_and_correlation(estate):
    """Rename / restart / egress-change / strip-identity / to-stdio all applied.

    A naive key-equality matcher would MISS the mutated agents (new exec_id, new
    egress_ip/ja4, dropped oidc_sub, renamed self-asserted name). The two-axis
    identity (code-hash MERGE / behavior SPLIT) and cross-plane fusion must
    survive: the SAME archetypes resolve to the SAME entity counts after mutation.
    """
    base = run_full_engine(estate)
    mutated = run_full_engine(mutate_estate(estate, kind="all"))

    # Same number of resolved entities before and after mutation.
    assert len(mutated.entities) == len(base.entities), (
        "mutation changed the resolved entity count — fusion did not survive"
    )

    # Every catchable label still surfaces; the irreducible still does not.
    for arch in archetypes():
        if arch.catchable and arch.key not in ("h", "i", "m"):
            assert len(mutated.entities_with_truth(arch.label)) == arch.expected_entities, (
                f"({arch.key}) {arch.label} lost/duplicated after mutation"
            )
    # Shared-cred still splits to two.
    assert len(mutated.entities_with_truth("shared-cred-A")) == 1
    assert len(mutated.entities_with_truth("shared-cred-B")) == 1
    # Hostile popular-JA4 pair still resolves to TWO (N5 bar survives mutation).
    assert len(mutated.entities_with_truth("hostile-shared-ja4")) == 2
    # Duplicate still collapses to one.
    assert len(mutated.entities_with_truth("decoy-duplicate")) == 1
    # Irreducible still not fake-found.
    assert estate.irreducible_label not in mutated.found_labels()


# ===========================================================================
# 7. REAL sensors surface planted archetypes through the production path.
# ===========================================================================


def test_real_sensors_surface_planted_archetypes(estate_with_fixtures):
    """``run_planes`` over the file-sensor fixtures (eBPF / network / static)
    surfaces the laptop-local (a), egress-only (d), and static (g) archetypes
    through the REAL production sense path — not just the in-memory incidences."""
    res = run_full_engine(estate_with_fixtures)
    pr = res.planes_result
    assert pr is not None, "file-sensor fixtures were not sensed"
    # The three flag-enabled real planes all genuinely captured.
    assert PlaneId.KERNEL_EBPF in pr.occasions       # laptop-local (a)
    assert PlaneId.NETWORK_EGRESS in pr.occasions    # egress-only (d)
    assert PlaneId.STATIC_SUPPLYCHAIN in pr.occasions  # static (g)
    assert len(pr.entities) >= 3
    # Honest estimate over the live planes with a named blind spot.
    assert pr.unseen is not None
    assert {b.missing_plane for b in pr.unseen.named_blind_spots}


# ===========================================================================
# 8. REAL fleet (read-only) — the hard case on real data.
# ===========================================================================


@pytest.mark.skipif(
    not real_fleet_available(),
    reason="real tex-enterprise fleet not present (read-only demonstration)",
)
def test_real_fleet_surfaces_gate_bypass_shadows_readonly():
    """The engine surfaces REAL gate-bypass shadows from the filesystem alone.

    Runs a BOUNDED read-only resolution over the real tex-enterprise fleet: real
    files written with NO matching trail row (the gate-bypass signal) are
    surfaced from the fs-write plane, with no cooperation from any agent and
    without ever writing to the fleet.
    """
    sl = run_real_fleet_slice()
    # The real fleet has genuine gate-bypass files (files with no trail row).
    assert sl.bypass_count >= 1, "expected >=1 real gate-bypass file in the fleet"
    # The engine surfaced at least one of them as a resolved entity.
    assert sl.bypass_entities, "engine did not surface any real gate-bypass shadow"
    # Sanity: the bounded slice resolved a meaningful population (not empty).
    assert len(sl.entities) >= 1


#: The TIME-TO-FULL-ESTATE @20 target: a COLD full-estate SENSE→FUSE over the
#: whole real fleet must complete within this many seconds. The brief's target is
#: 60s; we assert a comfortable margin against it (the measured cold time is ~9s
#: after the star-blocking + weighted-EM + behavioral-cohort-cap fixes, down from
#: a >9-minute non-completion). A loose ceiling absorbs machine variance without
#: letting a real O(n²) regression slip back in.
_FULL_ESTATE_BUDGET_S: float = 60.0


@pytest.mark.skipif(
    not real_fleet_available(),
    reason="real tex-enterprise fleet not present (read-only demonstration)",
)
def test_time_to_full_estate_real_fleet_cold_under_budget():
    """TIME-TO-FULL-ESTATE @20: the WHOLE real fleet resolves cold under budget.

    Runs SENSE → FUSE (``resolve_full``) over the ENTIRE real tex-enterprise
    footprint (~10⁵ leaf incidences, NOT a bounded sample) and asserts the cold
    wall-clock time is under the 60s target. This is the speed regression guard:
    candidate generation is star-blocked (O(n) not O(Σ bᵢ²)), the FS-EM fit runs
    on DISTINCT weighted agreement vectors (not every pair), and the behavioral
    shared-credential splitter defers oversized cohorts to the structural N1
    clusterer — so the engine scales to the real leaf count instead of stalling
    on a single popular blocking value. Read-only; never writes to the fleet.
    """
    t = run_real_fleet_full_estate()
    # The full estate is genuinely large (this is the hard case, not a sample).
    assert t.incidences >= 10_000, (
        f"expected a large real estate (>=10k leaves), saw {t.incidences}"
    )
    # It resolved a non-empty set of entities.
    assert t.entities >= 1, "full-estate resolution produced no entities"
    # The headline: cold TIME-TO-FULL-ESTATE under the 60s target.
    assert t.total_s < _FULL_ESTATE_BUDGET_S, (
        f"TIME-TO-FULL-ESTATE {t.total_s:.2f}s over budget {_FULL_ESTATE_BUDGET_S}s "
        f"(SENSE {t.sense_s:.2f}s + FUSE {t.fuse_s:.2f}s over {t.incidences} leaves)"
    )
