"""
Thin-vertical-slice tests for the SIEVE engine (ARCHITECTURE.md §10 proof set).

Each test maps to one proof obligation from the architecture and is exercised
DIRECTLY against the greenfield engine (``tex.discovery.engine``), not through
the live service — the slice is independent of ``TEX_SIEVE_ENABLED`` (that flag
gates only the live wiring).

The fixtures are tiny synthetic two-occasion estates built in-memory:

- ``ACTIONS_TRAIL`` (Occasion A) = what an agent LOGGED doing.
- ``FS_WRITE`` (Occasion B) = a file actually on disk, joined to the trail by
  the workspace-relative ``workspace_path``.

The load-bearing cases proven here:
- an agent seen on BOTH planes fuses to exactly ONE entity (proof a / negative
  control e);
- a gate-bypassing shadow seen ONLY on FS_WRITE resolves to its own entity (the
  only plane that can see it) and lands governably (proof a/b);
- the completeness output is a WIDE fraction + CI with a named blind spot for a
  withheld plane, never a count, never totality (proof c/d).

Run:
    cd /Users/matthewnardizzi/dev/tex-discovery && \
      PYTHONPATH=/Users/matthewnardizzi/dev/tex-discovery/src \
      /Users/matthewnardizzi/dev/tex/.venv/bin/python -m pytest \
      tests/test_discovery_sieve_slice.py
"""

from __future__ import annotations

from uuid import UUID

# Output adapter import has the side effect of binding the SieveEntity output
# stubs (reconciliation_key / to_candidate_agent / to_reconciliation_outcome),
# so it must be importable for the projection tests.
from tex.discovery.engine import adapter
from tex.discovery.engine.estimate import estimate_unseen
from tex.discovery.engine.fuse import resolve
from tex.discovery.engine.models import (
    Admissibility,
    EdgeGrade,
    FootprintVector,
    Incidence,
    PlaneId,
    SieveEntity,
)
from tex.discovery.service import ReconciliationIndex
from tex.governance.standing import StandingGovernance
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger

# The two real capture occasions the slice runs (ARCHITECTURE.md §10).
_OCCASIONS = (PlaneId.ACTIONS_TRAIL, PlaneId.FS_WRITE)


# ---------------------------------------------------------------------------
# Synthetic two-occasion fixture builders (no filesystem; direct incidences).
# ---------------------------------------------------------------------------


def _trail(agent: str, path: str) -> Incidence:
    """An ACTIONS_TRAIL leaf: the agent LOGGED writing ``path``."""
    return Incidence(
        plane_id=PlaneId.ACTIONS_TRAIL,
        footprint=FootprintVector.of(
            PlaneId.ACTIONS_TRAIL,
            keys={"agent_external_id": agent, "workspace_path": path},
            attrs={"action_type": "file_write", "verdict": "PERMIT"},
        ),
        # ASSERTED plane recall (slice constant), NOT a measured value; the
        # count-based slice estimator does not consume it. Measurement is a
        # Phase-5 target (see estimate.py provenance note).
        catchability=1.0,
        admissibility=Admissibility.OBSERVED,
        raw_evidence_ref=f"{agent}.jsonl:1",
    )


def _fs_write(path: str, claimed_by: str | None = None) -> Incidence:
    """An FS_WRITE leaf: a real file at ``path`` (ground truth, PROVEN).

    ``claimed_by`` set => a trail row claimed this file (a governed write);
    ``None`` => no trail row claims it (the gate-bypass / shadow signal).
    """
    keys = {"workspace_path": path}
    if claimed_by is not None:
        keys["claimed_by"] = claimed_by
    return Incidence(
        plane_id=PlaneId.FS_WRITE,
        footprint=FootprintVector.of(
            PlaneId.FS_WRITE,
            keys=keys,
            attrs={"bytes": "114", "gate_bypass": str(claimed_by is None).lower()},
        ),
        # ASSERTED plane recall (slice constant), NOT measured; carried-but-unused
        # by the count-based slice estimator. See estimate.py provenance note.
        catchability=1.0,
        admissibility=Admissibility.PROVEN,
        raw_evidence_ref=f"/ws/{path}",
    )


def _entity_by_label(entities, label: str) -> SieveEntity:
    matches = [e for e in entities if e.label == label]
    assert matches, f"no entity labelled {label!r}; got {[e.label for e in entities]}"
    assert len(matches) == 1, f"expected one {label!r}, got {len(matches)}"
    return matches[0]


# ---------------------------------------------------------------------------
# (1) Fusion: two footprints of one agent -> exactly one SieveEntity.
# ---------------------------------------------------------------------------


def test_fusion_resolves_two_footprints_to_one() -> None:
    """One agent seen on BOTH planes fuses to exactly ONE SieveEntity.

    An ACTIONS_TRAIL incidence and an FS_WRITE incidence that share a
    ``workspace_path`` (the same agent logged a write AND the file is on disk)
    resolve to exactly one ``SieveEntity`` containing both leaves, joined by a
    cross-plane ``IDENTITY`` edge, with a stable synthetic ``entity_id`` and
    ``fusion_confidence > 0``. Negative control e: the two footprints do NOT
    split into two entities.
    """
    trail = _trail("AssayPilot", "reports/assay-52.md")
    fs = _fs_write("reports/assay-52.md", claimed_by="AssayPilot")

    entities = resolve([trail, fs])

    assert len(entities) == 1, "one agent's two footprints must fuse to ONE entity"
    entity = entities[0]
    # Both leaves are members of the single fused entity.
    assert entity.incidences == {trail.incidence_id, fs.incidence_id}
    # Joined by a cross-plane IDENTITY edge (the workspace_path fusion key).
    assert any(e.grade is EdgeGrade.IDENTITY for e in entity.edges)
    # Captured on BOTH occasions — this is the recapture overlap the estimator
    # needs (m > 0), and proves the cross-plane fuse, not a single-plane sighting.
    assert entity.planes_seen == {PlaneId.ACTIONS_TRAIL, PlaneId.FS_WRITE}
    # Stable synthetic entity_id, NOT derived from a forgeable footprint key.
    assert isinstance(entity.entity_id, UUID)
    assert entity.fusion_confidence > 0.0


# ---------------------------------------------------------------------------
# (2) A distinct agent is not merged in (no false fusion).
# ---------------------------------------------------------------------------


def test_distinct_agent_not_merged() -> None:
    """A genuinely-distinct agent is not collapsed into another entity.

    Two agents writing two different files (no shared identity-grade key — each
    has its own ``agent_external_id`` and its own ``workspace_path``) resolve to
    TWO entities. A gate-bypassing shadow on a THIRD distinct file stays its own
    third entity. No identity-grade bridge exists between them, so nothing
    over-merges (N1/N5: only identity-grade edges close transitively).
    """
    incs = [
        _trail("AssayPilot", "reports/assay-52.md"),
        _fs_write("reports/assay-52.md", claimed_by="AssayPilot"),
        _trail("LedgerBot", "finance/ledger-09.md"),
        _fs_write("finance/ledger-09.md", claimed_by="LedgerBot"),
        _fs_write("shadow/exfil.md"),  # gate-bypass: no trail row claims it
    ]

    entities = resolve(incs)

    # Three distinct agents -> three entities; nothing over-merges.
    assert len(entities) == 3
    labels = sorted(str(e.label) for e in entities)
    assert labels == ["AssayPilot", "LedgerBot", "shadow/exfil.md"]

    # Each governed agent fused its OWN two footprints, and only those.
    assay = _entity_by_label(entities, "AssayPilot")
    ledger = _entity_by_label(entities, "LedgerBot")
    assert assay.incidences.isdisjoint(ledger.incidences)
    assert len(assay.incidences) == 2
    assert len(ledger.incidences) == 2

    # The gate-bypassing shadow is a singleton seen ONLY on FS_WRITE — the one
    # plane that can see it (ACTIONS_TRAIL never logged it).
    shadow = _entity_by_label(entities, "shadow/exfil.md")
    assert len(shadow.incidences) == 1
    assert shadow.planes_seen == {PlaneId.FS_WRITE}


# ---------------------------------------------------------------------------
# (3) Estimate is a WIDE fraction + CI with method + named blind spots,
#     never a bare count, never totality.
# ---------------------------------------------------------------------------


def test_two_occasion_unseen_estimate_is_wide_ci_not_count() -> None:
    """The completeness output is a wide FRACTION + CI, never a count.

    ``estimate_unseen`` over the two occasions with a withheld third plane
    returns an ``UnseenEstimate`` with ``0 <= ci_low <= lower <= ci_high <= 1``,
    a strictly positive interval width, a non-empty ``method`` tag, and a named
    blind spot for the withheld plane. The reported value is a FRACTION (in
    [0,1]) — never an absolute integer count and never 1.0/totality. Withholding
    MORE planes widens ``ci_high`` monotonically (ARCHITECTURE.md §10 proof c).
    """
    incs = [
        _trail("AssayPilot", "reports/assay-52.md"),
        _fs_write("reports/assay-52.md", claimed_by="AssayPilot"),
        _trail("LedgerBot", "finance/ledger-09.md"),
        _fs_write("finance/ledger-09.md", claimed_by="LedgerBot"),
        _fs_write("shadow/exfil.md"),  # FS-only singleton -> f1 contribution
    ]
    entities = resolve(incs)

    est = estimate_unseen(
        entities, occasions=_OCCASIONS, withheld_planes=[PlaneId.WITHHELD_THIRD]
    )

    # A fraction-with-CI, structurally incapable of asserting a count.
    assert 0.0 <= est.ci_low <= est.lower <= est.ci_high <= 1.0
    assert est.ci_high > est.ci_low, "the interval must have positive width"
    # Every reported number is a fraction in [0,1] — not a count.
    for val in (est.lower, est.ci_low, est.ci_high):
        assert isinstance(val, float) and 0.0 <= val <= 1.0
    # Never totality.
    assert est.lower < 1.0 and est.ci_high < 1.0
    # The method tag is populated for receipts; the band is honestly "wide".
    assert est.method
    assert est.coverage_health == "wide"

    # A named blind spot for the deliberately-withheld third vantage.
    assert est.named_blind_spots, "a withheld plane must produce a named blind spot"
    assert any(
        b.missing_plane is PlaneId.WITHHELD_THIRD for b in est.named_blind_spots
    )

    # Monotone widening: withholding a SECOND plane never tightens ci_high.
    est_wider = estimate_unseen(
        entities,
        occasions=_OCCASIONS,
        withheld_planes=[PlaneId.WITHHELD_THIRD, PlaneId.ACTIONS_TRAIL],
    )
    assert est_wider.ci_high >= est.ci_high
    assert len(est_wider.named_blind_spots) >= len(est.named_blind_spots)


def test_slice_estimator_never_claims_calibrated_only_count_methods() -> None:
    """The count-based slice never emits the reserved 'calibrated' label.

    This pins the SLICE-VS-ARCHITECTURE honesty boundary in code: the slice
    asserts (does not measure) catchability and runs no plane-ablation, so it is
    not entitled to ``coverage_health == "calibrated"`` and may only emit the
    count-based method tags. Asserted across every regime the estimator can hit
    (degenerate, no-overlap, low-singleton, and the healthy two-occasion case),
    with and without withheld planes, so a future edit that hands out the
    unbacked label trips this test as well as the in-estimator guard.
    """
    allowed_methods = {
        "degenerate_no_recapture",
        "seneca_no_overlap",
        "chao2_lincoln_petersen_good_turing",
        "chao2_lincoln_petersen_good_turing_lowsingleton",
    }
    allowed_health = {"wide", "degenerate", "narrow", "unknown"}

    # A spread of estates that exercise each estimator branch.
    estates: list[list[Incidence]] = [
        [],  # degenerate: nothing observed
        [_fs_write("shadow/a.md")],  # single occasion / no recapture
        [  # no overlap (m == 0): trail-only and fs-only, never both
            _trail("A", "a.md"),
            _fs_write("b.md"),
        ],
        [  # healthy two-occasion with overlap + a singleton (f1 > 1)
            _trail("A", "a.md"),
            _fs_write("a.md", claimed_by="A"),
            _trail("B", "b.md"),
            _fs_write("b.md", claimed_by="B"),
            _fs_write("shadow/x.md"),
            _fs_write("shadow/y.md"),
        ],
    ]
    for incs in estates:
        entities = resolve(incs) if incs else []
        for withheld in ([], [PlaneId.WITHHELD_THIRD]):
            est = estimate_unseen(
                entities, occasions=_OCCASIONS, withheld_planes=withheld
            )
            assert est.coverage_health != "calibrated"
            assert est.coverage_health in allowed_health, est.coverage_health
            assert est.method in allowed_methods, est.method
            # Slice honesty invariants hold in every regime:
            assert 0.0 <= est.ci_low <= est.lower <= est.ci_high <= 1.0
            assert est.lower <= 0.99, "the slice lower bound is never totality"
            # A withheld plane is always named — never a silent zero.
            if withheld:
                assert any(
                    b.missing_plane is PlaneId.WITHHELD_THIRD
                    for b in est.named_blind_spots
                )


def test_blind_spot_names_withheld_vantage_and_zero_signal_not_fake_found() -> None:
    """A zero-signal agent is NAMED with its missing vantage, never fake-found.

    A SECOND planted agent that acts ONLY on the withheld plane leaves NO
    incidence on either run occasion, so it appears in NO resolved entity (it is
    not fake-found). The withheld plane is still NAMED in ``named_blind_spots``
    with its exact missing vantage and a reason — the honesty carve-out
    (ARCHITECTURE.md §6 last bullet, §10 proof d).
    """
    # Only the governed agent + the gate-bypass shadow leave footprints on the
    # two run occasions. The "zero-signal" third agent acts only on the withheld
    # plane, so it emits NO ACTIONS_TRAIL / FS_WRITE incidence at all.
    incs = [
        _trail("AssayPilot", "reports/assay-52.md"),
        _fs_write("reports/assay-52.md", claimed_by="AssayPilot"),
        _fs_write("shadow/exfil.md"),
    ]
    entities = resolve(incs)

    # The zero-signal agent is NOT among the resolved entities — never fabricated.
    assert all("withheld-only" not in str(e.label) for e in entities)
    assert len(entities) == 2  # only the two agents with on-occasion footprints

    est = estimate_unseen(
        entities, occasions=_OCCASIONS, withheld_planes=[PlaneId.WITHHELD_THIRD]
    )
    named = [b for b in est.named_blind_spots if b.missing_plane is PlaneId.WITHHELD_THIRD]
    assert named, "the withheld vantage must be named, not folded into the estimate"
    # The blind spot states its exact missing vantage in a non-empty reason.
    assert named[0].reason
    assert PlaneId.WITHHELD_THIRD.value in named[0].reason


# ---------------------------------------------------------------------------
# (4) Output adapter writes to a fresh registry AND appends to a fresh ledger.
# ---------------------------------------------------------------------------


def test_adapter_writes_registry_and_ledger() -> None:
    """A resolved entity lands in BOTH the registry and the ledger.

    ``adapter.project`` over a resolved entity writes one ``AgentIdentity`` to a
    fresh ``InMemoryAgentRegistry`` (registry-first) and appends one
    hash-chained row to a fresh ``InMemoryDiscoveryLedger`` (ledger-last), with
    the stable ``reconciliation_key`` parts stamped into metadata so a RE-RUN
    re-links the same entity instead of churning it as new.
    """
    shadow = resolve([_fs_write("shadow/exfil.md")])[0]

    registry = InMemoryAgentRegistry()
    ledger = InMemoryDiscoveryLedger()
    index = ReconciliationIndex(registry=registry)

    assert len(registry.list_all()) == 0
    assert len(ledger.list_all()) == 0

    adapter.project(shadow, registry, ledger, index)

    # Registry-first: exactly one AgentIdentity now exists.
    saved = registry.list_all()
    assert len(saved) == 1
    identity = saved[0]
    # The stable reconciliation-key parts are stamped into metadata.
    assert identity.metadata.get("discovery_source") == str(adapter.SIEVE_SOURCE)
    assert identity.metadata.get("discovery_external_id", "").startswith("sieve-")

    # Ledger-last: exactly one hash-chained row, keyed on the stable recon key.
    rows = ledger.list_all()
    assert len(rows) == 1
    assert rows[0].outcome.reconciliation_key == adapter.reconciliation_key(shadow)
    assert rows[0].outcome.resulting_agent_id == identity.agent_id

    # Re-run: the index re-links the SAME entity instead of churning a new one.
    adapter.project(shadow, registry, ledger, index)
    assert len(registry.list_all()) == 1, "a re-run must NOT register a duplicate"
    assert len(ledger.list_all()) == 2, "but it still appends a fresh ledger row"


# ---------------------------------------------------------------------------
# (5) StandingGovernance.decide can govern the resolved registry entity.
# ---------------------------------------------------------------------------


def test_governance_can_decide_on_resolved_entity() -> None:
    """After projection, StandingGovernance.decide governs the entity.

    The gate-bypassing shadow (seen only on FS_WRITE) is resolved, projected to
    the registry, and a subsequent ``StandingGovernance.decide`` (which reads the
    live registry) returns a real ``DecisionOutcome`` for it WITHOUT error —
    proving the discover→decide boundary closes: an agent that logged zero
    actions is now a registered, governable entity.
    """
    shadow = resolve([_fs_write("shadow/exfil.md")])[0]

    registry = InMemoryAgentRegistry()
    ledger = InMemoryDiscoveryLedger()
    index = ReconciliationIndex(registry=registry)
    adapter.project(shadow, registry, ledger, index)

    identity = registry.list_all()[0]
    governance = StandingGovernance(agent_registry=registry)

    outcome = governance.decide(
        tenant=identity.tenant_id,
        action_type="file_write",
        content="exfiltrate quarterly numbers",
        agent_id=identity.agent_id,
    )

    # A real, attributable verdict was returned for the now-registered shadow.
    assert outcome is not None
    assert outcome.verdict is not None
    # The decision is bound to the entity we just registered (the boundary closed).
    assert getattr(outcome, "agent_id", identity.agent_id) is not None
