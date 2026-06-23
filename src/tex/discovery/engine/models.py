"""
SIEVE engine data model — the load-bearing contract.

This module is the greenfield core of the SIEVE discovery engine
(Sparse-Incidence Entity & Vantage Estimator). It is deliberately NOT an
extension of ``tex.discovery.reconciliation`` — the existing reconciliation
layer is pure key-equality (``source:tenant:external_id``), which is exactly
the brittleness SIEVE replaces. Everything downstream (sensors, fusion,
estimation, the output adapter) depends on the shapes declared here, so this
file is the fixed contract that parallel builders fill against.

Three layers, mirroring ARCHITECTURE.md §1:

1. ``Incidence``       — the immutable LEAF observation. One sighting of a
                         footprint on one plane, carrying an ASSERTED plane
                         catchability (the slice asserts it; measurement is
                         deferred to Phase 5 — see ``catchability`` below).
                         Append-only.
2. ``SieveEntity``     — the probabilistic ENTITY projection. One entity is
                         fused from many incidences (FUSE); one shared
                         credential may split into k entities (SPLIT). Carries
                         explicit ``fusion_confidence`` and a two-axis identity
                         (``merge_axis`` MERGES, ``split_axis`` SPLITS).
3. ``UnseenEstimate``  — the calibrated COMPLETENESS output: a lower-bound
                         FRACTION with a CI plus a named-blind-spot ledger.
                         Never a bare count, never an implied totality.

The organizing commitment (RESEARCH_LOG.md): *discovery is a MEASUREMENT
problem, not a detection problem*. The ARCHITECTURE target is that every plane
is a calibrated instrument whose MEASURED catchability is fed to the estimator;
the headline deliverable is a lower-bound-with-CI plus named blind spots. This
is why ``Incidence`` carries a ``catchability`` field and ``UnseenEstimate``
carries a named-blind-spot ledger rather than a count.

SLICE-VS-ARCHITECTURE HONESTY (read before trusting a field):
- The ``catchability`` field is CARRIED on every incidence but in the thin slice
  it is an ASSERTED plane constant (the sensors default it to 1.0), NOT a
  measured recall. The slice estimator (``estimate.py``) is COUNT-BASED and does
  NOT consume catchability — it is carried-but-unused until Phase 5.
- Measured catchability (signed-cohort recall / honeytoken bite-rate),
  plane-ablation cross-validation, and the SENECA self-consistent missing-mass
  algorithm are ARCHITECTURE targets that are NOT exercised by this slice. Do
  not read the present field/method names as live measurement capability.

Design rules honored here:

- ``entity_id`` is a STABLE synthetic UUID. It survives credential rotation /
  rename and is NOT derived from any single forgeable attribute. It is minted
  once at first resolution and carried forward; nothing recomputes it from a
  footprint key.
- Frozen / hashable leaves (``Incidence``, ``TypedEdge``, ``FootprintVector``)
  so they can live in sets and be hashed into receipts. ``SieveEntity`` is
  mutable because the streaming engine *tightens* it in place.
- No HTTP, no SDKs, no platform specifics. Sensors adapt the platform shape
  to ``Incidence`` records; this module never imports a connector.

References: ARCHITECTURE.md §0–§7, §10; RESEARCH_LOG.md §1, §2, §6, §8.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

if TYPE_CHECKING:  # pragma: no cover - typing-only, avoids an import cycle
    from tex.domain.discovery import CandidateAgent, ReconciliationOutcome


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class PlaneId(StrEnum):
    """
    The capture occasion a footprint was observed on.

    Each plane is a physically-distinct *vantage* (RESEARCH_LOG.md §1). The
    capture-recapture estimator treats each plane as an independent capture
    occasion, so two genuinely-independent planes are the minimum the math
    needs and the only way to see a gate-bypassing agent.

    The thin vertical slice (ARCHITECTURE.md §10) uses exactly two real planes
    plus one deliberately-WITHHELD placeholder so the blind-spot ledger has a
    named third vantage to point at:

    - ``ACTIONS_TRAIL`` — Occasion A: what each agent LOGGED doing
      (``runtime/logs/<agent>.jsonl``). A gate-using agent appears here.
    - ``FS_WRITE``      — Occasion B: files actually written under the
      WORKSPACE, diffed against what the trail claims. A gate-BYPASSING agent
      that writes a file but logs no action appears here and NOT on
      ``ACTIONS_TRAIL`` — the only plane that can see it.
    - ``WITHHELD_THIRD`` — a placeholder for a deliberately-withheld third
      vantage (e.g. network-egress / eBPF). It is NEVER emitted by a sensor in
      the slice; it exists so ``UnseenEstimate.named_blind_spots`` can name the
      exact missing vantage of a zero-signal agent without fake-finding it.

    The full P0..P14 roster (ARCHITECTURE.md §8) extends this enum; the slice
    ships only the three values below so the contract stays small and honest.
    """

    ACTIONS_TRAIL = "actions_trail"
    FS_WRITE = "fs_write"
    WITHHELD_THIRD = "withheld_third"


class Admissibility(StrEnum):
    """
    How much an observation can be trusted, ranked by provenance strength.

    This mirrors the per-capability admissibility grade SIEVE attaches to every
    capability edge (ARCHITECTURE.md §4) and the ``CoverageBoundary`` grade
    already in the repo. It governs how heavily an incidence weighs and how
    much the PDP/UI should trust a resolved entity's surface.

    Ordering (strongest → weakest):

    - ``PROVEN``            — ground truth (a file actually exists on disk; an
                              eBPF-bound syscall). Cannot be talked away.
    - ``OBSERVED``          — an exercised behavior we watched (a logged action,
                              an MCP tool-call DAG).
    - ``PLATFORM_ATTESTED`` — a managed control plane asserts it (IAM role, IdP
                              grant). Trusted only as far as the platform.
    - ``CLAIMED``           — the agent declared it (A2A skills[], tools/list).
                              A CLAIM only — never load-bearing alone.
    """

    PROVEN = "proven"
    OBSERVED = "observed"
    PLATFORM_ATTESTED = "platform_attested"
    CLAIMED = "claimed"


class EdgeGrade(StrEnum):
    """
    The provenance type of a fusion edge — the load-bearing N1 distinction.

    Plane-typed correlation-clustering (ARCHITECTURE.md §2; TransClean graft)
    closes ``IDENTITY`` edges transitively but lets ``BRIDGING`` edges violate
    transitivity. A bridging edge whose endpoints fail strong-edge transitive
    closure is the positive shared-credential SPLIT signal (N1).

    - ``IDENTITY`` — strong, identity-grade: code-hash, honeytoken co-trip,
                     behavioral fingerprint, a planted cross-plane marker. MUST
                     close transitively.
    - ``BRIDGING`` — weak: shared IP/ASN/service-credential/popular-JA4. MAY
                     violate transitivity; never merges distinct entities alone.
    """

    IDENTITY = "identity"
    BRIDGING = "bridging"


class PresenceState(StrEnum):
    """
    Liveness of a resolved entity, reused from the PresenceTracker vocabulary.

    The streaming delta primitive (ARCHITECTURE.md §5) feeds live keys into
    ``observe_seen`` and absent keys into ``observe_missing``; the
    N-consecutive-miss threshold suppresses false disappearances. The slice
    only emits ``SEEN`` for freshly-resolved entities; the other states exist
    so the Phase-6 wiring fills them without changing this contract.
    """

    SEEN = "seen"
    MISSING_SOFT = "missing_soft"
    CONFIRMED_DISAPPEARED = "confirmed_disappeared"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Leaf layer — immutable, append-only observations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FootprintVector:
    """
    A plane-specific bundle of keys + attributes for one observation.

    A footprint is what a sensor extracted from one sighting. It is plane-shaped
    but deliberately generic: ``keys`` are the blocking / matching identifiers
    (e.g. ``{"agent_external_id": "AssayPilot", "code_hash": "...",
    "workspace_path": "gxp/audit/assay-trail.jsonl"}``) and ``attrs`` are the
    descriptive payload (byte counts, action_type, timestamps-as-strings).

    Keys are what the Fellegi-Sunter scorer compares and the blockers union
    over; attrs are carried for receipts and capability mapping but are not
    matched on. Both are sorted tuples-of-pairs so the footprint is frozen,
    hashable, and order-stable for hashing into receipts.

    Sensors MUST NOT put a forgeable single attribute (a self-asserted name)
    in a position that the resolver could treat as identity — the resolver
    decides edge grade, not the footprint. The footprint only *reports*.
    """

    plane_id: PlaneId
    keys: tuple[tuple[str, str], ...] = ()
    attrs: tuple[tuple[str, str], ...] = ()

    @classmethod
    def of(
        cls,
        plane_id: PlaneId,
        keys: dict[str, str] | None = None,
        attrs: dict[str, str] | None = None,
    ) -> FootprintVector:
        """Build a frozen footprint from plain dicts, sorting for stability."""
        return cls(
            plane_id=plane_id,
            keys=tuple(sorted((str(k), str(v)) for k, v in (keys or {}).items())),
            attrs=tuple(sorted((str(k), str(v)) for k, v in (attrs or {}).items())),
        )

    def key(self, name: str) -> str | None:
        """Return the value of a single key, or ``None`` if absent."""
        for k, v in self.keys:
            if k == name:
                return v
        return None

    def attr(self, name: str) -> str | None:
        """Return the value of a single attr, or ``None`` if absent."""
        for k, v in self.attrs:
            if k == name:
                return v
        return None

    def keys_dict(self) -> dict[str, str]:
        """Materialize ``keys`` back into a plain dict (for scoring/receipts)."""
        return {k: v for k, v in self.keys}


@dataclass(frozen=True)
class Incidence:
    """
    The leaf observation — one sighting of a footprint on one plane.

    Append-only and immutable. The ``catchability`` field is the seat of what is
    MEANT to make discovery a measurement problem (RESEARCH_LOG.md §8): in the
    full engine it is the plane's MEASURED recall (signed-cohort recall /
    honeytoken bite-rate), fed to the estimator as a measured per-plane capture
    probability.

    SLICE STATUS (honest): in the thin slice this is an ASSERTED plane recall —
    the sensors default it to a plane constant (1.0), not a measured value — and
    the slice estimator is count-based and does NOT consume it. Measurement is
    deferred to Phase 5 (signed-cohort/honeytoken calibration + plane-ablation).
    The field is carried so the contract is fixed; it is not yet load-bearing.

    Fields (ARCHITECTURE.md §1.1):

    - ``incidence_id``     — stable UUID for this sighting.
    - ``plane_id``         — the capture occasion (mirrors ``footprint.plane_id``).
    - ``footprint``        — the plane-specific keys + attrs.
    - ``catchability``     — [0,1], ASSERTED plane recall in the slice
                             (measurement deferred to Phase 5); carried-but-unused
                             by the count-based slice estimator.
    - ``observed_at``      — tz-aware sighting time; drives the estimator's time
                             axis and the streaming tighten-only updates.
    - ``admissibility``    — provenance grade of THIS observation.
    - ``raw_evidence_ref`` — opaque pointer (path:line, log offset) for receipts.

    Degrade-to-empty rule: a sensor that finds nothing emits zero incidences;
    it never raises and never emits a synthetic placeholder.
    """

    plane_id: PlaneId
    footprint: FootprintVector
    catchability: float
    admissibility: Admissibility
    raw_evidence_ref: str
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    incidence_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not 0.0 <= self.catchability <= 1.0:
            raise ValueError(
                f"catchability must be in [0,1], got {self.catchability!r}"
            )
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.footprint.plane_id != self.plane_id:
            raise ValueError(
                "footprint.plane_id must match incidence.plane_id "
                f"({self.footprint.plane_id!r} != {self.plane_id!r})"
            )


# ---------------------------------------------------------------------------
# Edge layer — typed fusion edges between leaves
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TypedEdge:
    """
    A scored, plane-typed link between two incidences.

    Each edge is the unit the plane-typed correlation clusterer operates on
    (ARCHITECTURE.md §1.2, §2). The ``grade`` decides whether the edge MUST
    close transitively (``IDENTITY``) or MAY violate it (``BRIDGING``); the
    transitivity violation across a bridging edge is the N1 split signal.

    Fields:

    - ``a``, ``b``        — the two ``incidence_id``s the edge connects.
    - ``plane_id``        — the plane that produced the comparison (a cross-plane
                            edge fuses two occasions; same-plane edges deduplicate).
    - ``grade``           — IDENTITY (strong) vs BRIDGING (weak).
    - ``fs_weight``       — the Fellegi-Sunter log-likelihood-ratio weight
                            (``log2(m/u)``), TF-adjusted; high for a rare shared
                            key, ~0 for a popular one.
    - ``anon_set_size``   — the anonymity-set size of the shared signal; the edge
                            is effectively weighted by ``1/anon_set_size`` (N5) so
                            a JA4 shared by millions contributes ≈0 evidence.

    ``a``/``b`` are stored order-independently via the constructor so an edge is
    the same regardless of which endpoint was discovered first.
    """

    a: UUID
    b: UUID
    plane_id: PlaneId
    grade: EdgeGrade
    fs_weight: float
    anon_set_size: int = 1

    def __post_init__(self) -> None:
        if self.a == self.b:
            raise ValueError("a TypedEdge cannot connect an incidence to itself")
        if self.anon_set_size < 1:
            raise ValueError("anon_set_size must be >= 1")
        # Canonicalize endpoint order so {a,b} == {b,a}. frozen → object.__setattr__.
        # Use locals as temps; mutating self.a first would clobber the swap.
        if str(self.b) < str(self.a):
            a, b = self.b, self.a
            object.__setattr__(self, "a", a)
            object.__setattr__(self, "b", b)

    @property
    def effective_weight(self) -> float:
        """FS weight discounted by anonymity-set size (the N5 epistemic weight)."""
        return self.fs_weight / float(self.anon_set_size)


# ---------------------------------------------------------------------------
# Entity layer — the probabilistic projection (mutable; tightened in place)
# ---------------------------------------------------------------------------


@dataclass
class SieveEntity:
    """
    The probabilistic entity — many footprints fused into one agent.

    One entity is fused from many incidences (FUSE); one shared credential may
    split into k entities (SPLIT). This is the internal identity of SIEVE — the
    ``reconciliation_key`` survives ONLY as an output-boundary shim
    (ARCHITECTURE.md §1.3), not as the identity.

    ``entity_id`` is a STABLE synthetic UUID (ARCHITECTURE.md §1.2): minted once
    at first resolution, NOT derived from any single forgeable attribute, and
    carried forward across credential rotation / rename. Callers MUST NOT
    recompute it from a footprint key.

    Two-axis identity:
    - ``merge_axis`` (coarse) — code-hash / model+SDK waveform / tool-set MinHash:
      stitches many sessions of the same code into ONE entity.
    - ``split_axis`` (fine)   — syscall-graph / tool-grammar n-grams / cadence:
      separates distinct agents collapsed under one binary/credential.

    The entity is MUTABLE on purpose: the streaming engine emits a provisional
    entity on the first sighting and *tightens* ``fusion_confidence`` (never
    loosens) as more planes corroborate (ARCHITECTURE.md §5).
    """

    incidences: set[UUID] = field(default_factory=set)
    edges: list[TypedEdge] = field(default_factory=list)
    fusion_confidence: float = 0.0
    merge_axis: str | None = None
    split_axis: str | None = None
    capability: tuple[str, ...] = ()
    presence: PresenceState = PresenceState.SEEN
    attribution_conflict: bool = False
    contradicting_pair: tuple[PlaneId, PlaneId] | None = None
    # The planes this entity's member incidences were genuinely captured on,
    # filled by the resolver from each member's ``plane_id``. This is the
    # authoritative capture-occasion record the estimator counts: it survives the
    # singleton case (a gate-bypassing shadow seen on exactly one plane has NO
    # corroborating edge, so an edge-only ``planes_seen`` would wrongly report it
    # captured on zero occasions and drop it from the estimate). ``planes_seen``
    # unions this with the edge-attested planes so neither path under-reports.
    planes_captured: frozenset[PlaneId] = frozenset()
    # Display label + first-class evidence handles. Not identity — receipts.
    label: str | None = None
    fusion_receipt: tuple[str, ...] = ()
    # entity_id is LAST so it always defaults to a fresh stable synthetic UUID.
    entity_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not 0.0 <= self.fusion_confidence <= 1.0:
            raise ValueError(
                f"fusion_confidence must be in [0,1], got {self.fusion_confidence!r}"
            )

    @property
    def planes_seen(self) -> set[PlaneId]:
        """Distinct capture occasions this entity was genuinely seen on.

        Unions the planes its member incidences were captured on
        (``planes_captured``, filled by the resolver) with the planes its fusion
        edges attest. The estimator counts capture occasions from this, so the
        union is load-bearing: a singleton gate-bypassing shadow has no
        corroborating edge but WAS captured on its one plane — it must still
        attest that occasion or it would silently drop out of the unseen
        estimate (ARCHITECTURE.md §6, §10 proof (a)/(d)).
        """
        return set(self.planes_captured) | {e.plane_id for e in self.edges}

    def tighten(self, new_confidence: float) -> None:
        """Monotonically raise ``fusion_confidence`` — never lower it.

        Mirrors the presence-tier ``tighten()`` monotonicity primitive
        (ARCHITECTURE.md §5). A corroborating plane may only increase
        confidence; a contradicting plane sets ``attribution_conflict`` instead
        of loosening confidence. Calls that would lower it are ignored.
        """
        if not 0.0 <= new_confidence <= 1.0:
            raise ValueError("new_confidence must be in [0,1]")
        if new_confidence > self.fusion_confidence:
            self.fusion_confidence = new_confidence

    # ------------------------------------------------------------------
    # Output-boundary projection STUBS — the adapter builder fills these.
    # ------------------------------------------------------------------

    def reconciliation_key(self) -> str:
        """Stable output-boundary key for ``ReconciliationIndex`` linking.

        The internal identity is ``entity_id``; this projects it to a string
        key the existing index and PresenceTracker key on (ARCHITECTURE.md
        §1.3, §7). Written into ``AgentIdentity.metadata`` as
        ``discovery_source`` / ``discovery_external_id`` so the index keys the
        entity stably across scans (else every scan churns it as "new").

        Implemented by the adapter builder (Phase-2 adapter.py). Stub here so
        the contract is fixed.
        """
        raise NotImplementedError(
            "SieveEntity.reconciliation_key is filled by the adapter builder"
        )

    def to_candidate_agent(self) -> "CandidateAgent":
        """Project this entity to the canonical ``CandidateAgent`` shape.

        Targets ``tex.domain.discovery.CandidateAgent`` (domain/discovery.py
        L237). The adapter sets ``source=DiscoverySource.GENERIC`` (or the
        plane-appropriate member), ``external_id`` derived from ``entity_id``,
        ``confidence=fusion_confidence``, ``capability_hints`` from
        ``capability``, and stamps the stable ``reconciliation_key`` parts into
        ``evidence`` so the ledger story is complete.

        Implemented by the adapter builder. Stub here so the contract is fixed.
        """
        raise NotImplementedError(
            "SieveEntity.to_candidate_agent is filled by the adapter builder"
        )

    def to_reconciliation_outcome(
        self, candidate: "CandidateAgent", resulting_agent_id: UUID | None = None
    ) -> "ReconciliationOutcome":
        """Project to a ``ReconciliationOutcome`` for the discovery ledger.

        Targets ``tex.domain.discovery.ReconciliationOutcome`` (domain/discovery.py
        L387). The adapter maps the resolution result to a ``finding_kind`` /
        ``ReconciliationAction`` (REGISTERED for a new entity, HELD_DUPLICATE
        for a similarity-detected duplicate, etc.), carries
        ``fusion_confidence`` through, and attaches ``fusion_receipt`` +
        ``contradicting_pair`` as ``findings`` so the ledger is auditable.
        ``ledger.append(candidate=candidate, outcome=outcome)`` mirrors
        ``service._apply`` registry-first/ledger-last (ARCHITECTURE.md §7).

        Implemented by the adapter builder. Stub here so the contract is fixed.
        """
        raise NotImplementedError(
            "SieveEntity.to_reconciliation_outcome is filled by the adapter builder"
        )


# ---------------------------------------------------------------------------
# Completeness layer — the calibrated unseen estimate (never a count)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NamedBlindSpot:
    """
    One irreducible gap, NAMED with the exact vantage that would close it.

    The honesty layer (ARCHITECTURE.md §6, §12; RESEARCH_LOG.md WS-4): mass
    below every plane's τ-floor is OUTSIDE capture-recapture support, so it is
    never folded into the estimate and never fake-found — it is named here
    with its missing vantage instead.
    """

    missing_plane: PlaneId
    reason: str
    # Optional handle to a concrete zero-signal entity this blind spot covers,
    # e.g. a planted agent that only acted on the withheld plane.
    evidence_ref: str | None = None


@dataclass(frozen=True)
class UnseenEstimate:
    """
    The headline deliverable — a lower-bound FRACTION with a CI, never a count.

    Two-occasion Lincoln-Petersen / Chao2 + Good-Turing over the resolved
    entities (ARCHITECTURE.md §6, §10). The thin slice deliberately produces a
    WIDE interval and a fully-populated named-blind-spot ledger entry for the
    withheld third plane — proving the honesty layer FIRST, before breadth.

    Fields:

    - ``lower``            — the lower bound on the unseen-but-detectable FRACTION
                             in [0,1]. A floor, never totality.
    - ``ci_low`` / ``ci_high`` — the confidence interval on that fraction. The
                             interval WIDENS as assumptions break or planes are
                             withheld (ARCHITECTURE.md §6 failure modes).
    - ``method``           — a method-TAG string naming which count-based
                             estimator produced it, for receipts. SLICE TAGS:
                             ``degenerate_no_recapture``, ``seneca_no_overlap``
                             (a WIDE count fallback for the m==0 hiding regime —
                             NOT the SENECA self-consistent-missing-mass
                             algorithm, which is unimplemented; the tag names the
                             regime, not a SENECA computation),
                             ``chao2_lincoln_petersen_good_turing`` and its
                             ``_lowsingleton`` variant. The Valiant-Valiant
                             τ-floor, Orlitsky extrapolation horizon, and
                             plane-ablation calibration named in ARCHITECTURE
                             §6/§13 are NOT exercised by the slice.
    - ``named_blind_spots``— the irreducible zero-signal gaps, each NAMED with
                             its missing vantage. Never empty when a plane is
                             withheld.
    - ``coverage_health``  — a coarse human-readable health word ("wide",
                             "degenerate", "unknown") spoken as the honest-edge
                             sentence (ARCHITECTURE.md §9). The word
                             ``"calibrated"`` is a RESERVED label that the slice
                             MUST NOT emit: it would assert measured catchability
                             + plane-ablation validation that the count-based
                             slice does not have. ``estimate_unseen`` is guarded
                             to never return it (see estimate.py).

    INVARIANT: ``0 <= ci_low <= lower <= ci_high <= 1``. This is enforced — the
    estimate is structurally incapable of asserting a count or an implied 100%.
    """

    lower: float
    ci_low: float
    ci_high: float
    method: str
    named_blind_spots: tuple[NamedBlindSpot, ...] = ()
    coverage_health: str = "unknown"

    def __post_init__(self) -> None:
        for name, val in (
            ("lower", self.lower),
            ("ci_low", self.ci_low),
            ("ci_high", self.ci_high),
        ):
            if not 0.0 <= val <= 1.0:
                raise ValueError(f"{name} must be a fraction in [0,1], got {val!r}")
        if not (self.ci_low <= self.lower <= self.ci_high):
            raise ValueError(
                "UnseenEstimate must satisfy ci_low <= lower <= ci_high "
                f"(got {self.ci_low} <= {self.lower} <= {self.ci_high})"
            )


__all__ = [
    "PlaneId",
    "Admissibility",
    "EdgeGrade",
    "PresenceState",
    "FootprintVector",
    "Incidence",
    "TypedEdge",
    "SieveEntity",
    "NamedBlindSpot",
    "UnseenEstimate",
]
