"""
SIEVE CAPABILITY stage — observed-tool-DAG ∩ IaC-IAM, per-edge graded (§4).

Reconstructs an entity's capability / blast-radius surface from OBSERVED
behavior, not declared cards, computed pre-runtime where possible
(ARCHITECTURE.md §4; RESEARCH_LOG.md §2 P8/P10/P11). Each capability edge carries
a per-claim ``Admissibility`` grade so the PDP/UI knows how much to trust it.

Four fused layers, strongest → weakest provenance:

- ``PROVEN``            — eBPF / fs-write ground truth [P9]: an actual file on
                          disk, a bound syscall. Cannot be talked away.
- ``OBSERVED``          — the exercised tool-call / MCP DAG [P10/P11]. The
                          set+sequence of tools/actions an entity exercised IS its
                          capability profile.
- ``PLATFORM_ATTESTED`` — IaC/serverless attached IAM role / service-account
                          policy [P8] ∩ the tools the agent code statically binds
                          = max reachable resources BEFORE first packet.
- ``CLAIMED``           — A2A ``skills[]`` / MCP ``tools/list`` declaration [P10]:
                          a CLAIM only, never load-bearing alone.

First-class honesty outputs (§4):
- **declared-vs-exercised delta** — ``used_but_undeclared`` (hidden blast radius:
  a capability the entity DID exercise but never declared) and
  ``declared_but_unused`` (dormant latent risk: declared, never exercised).
- **capability DRIFT** — capability tokens whose presence/grade MUTATED
  mid-window (a tools/list or AgentCard change, a code-hash change) — a fast
  attribution event.

This module reconstructs the graph GENERICALLY from whatever capability-bearing
signal each member ``Incidence`` carries; it never hard-codes a fixed action
vocabulary. The reconstructed ``CapabilityGraph`` projects to the existing
``CapabilitySurface`` schema (allowed_action_types / channels / tools /
mcp_servers / data_scopes) so the PDP governs a *measured* surface — see
``project_to_surface``.

Honesty obligation (enforced): a capability is marked ``exercised`` ONLY on
OBSERVED or PROVEN evidence — a ``CLAIMED`` (or ``PLATFORM_ATTESTED``)
declaration alone never sets ``exercised``, so a used-but-undeclared tool always
surfaces in the delta. Symmetrically ``declared`` is set ONLY by a CLAIMED /
PLATFORM_ATTESTED signal, so observed-only edges drive the hidden-blast-radius
delta.

References: ARCHITECTURE.md §4, §7; RESEARCH_LOG.md §2 (P8/P9/P10/P11), §7.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Mapping, Sequence

from tex.discovery.engine.models import (
    Admissibility,
    CapabilityEdge,
    CapabilityGraph,
    Incidence,
    SieveEntity,
)

__all__ = [
    "map_capability",
    "project_to_surface",
    "CapabilityClaim",
    "Dimension",
]


# ---------------------------------------------------------------------------
# Capability-token vocabulary — the CapabilitySurface dimensions (§4)
# ---------------------------------------------------------------------------


class Dimension:
    """The ``CapabilitySurface`` dimensions a capability token projects into.

    A capability token is namespaced ``"<dimension>:<value>"`` so the projector
    can route it back into the right ``CapabilitySurface`` field without losing
    which kind of capability it is. The dimensions mirror the
    ``CapabilitySurface`` schema (domain/agent.py L149) one-for-one.
    """

    ACTION_TYPE = "action_type"
    CHANNEL = "channel"
    TOOL = "tool"
    MCP_SERVER = "mcp_server"
    DATA_SCOPE = "data_scope"

    #: Every dimension, in a stable order, for iteration + projection.
    ALL: tuple[str, ...] = (
        ACTION_TYPE,
        CHANNEL,
        TOOL,
        MCP_SERVER,
        DATA_SCOPE,
    )


def _token(dimension: str, value: str) -> str:
    """Namespace a raw capability value into a ``dimension:value`` token."""
    return f"{dimension}:{value.strip().casefold()}"


def split_token(token: str) -> tuple[str, str]:
    """Split a ``dimension:value`` token back into its parts (value may hold ':')."""
    dim, _, value = token.partition(":")
    return dim, value


# ---------------------------------------------------------------------------
# Per-incidence capability extraction — generic, schema-light
# ---------------------------------------------------------------------------

#: Admissibility grades that count as EXERCISED behaviour (we WATCHED it happen).
#: A claim/attestation alone never sets ``exercised`` — that is the honesty rule
#: that forces a used-but-undeclared token into the delta.
_EXERCISED_GRADES: frozenset[Admissibility] = frozenset(
    {Admissibility.PROVEN, Admissibility.OBSERVED}
)

#: Admissibility grades that count as a DECLARATION (the agent/platform asserted
#: it could, but we have not necessarily watched it). These set ``declared`` and
#: never (on their own) set ``exercised``.
_DECLARED_GRADES: frozenset[Admissibility] = frozenset(
    {Admissibility.CLAIMED, Admissibility.PLATFORM_ATTESTED}
)

#: Footprint ATTR names that carry a DECLARED capability, by dimension. A sensor
#: that has a declared A2A skills[] / tools-list / IaC scope stamps these. Read
#: generically so any plane can contribute a declaration without a code change.
_DECLARED_ATTRS: Mapping[str, str] = {
    "declared_action": Dimension.ACTION_TYPE,
    "declared_channel": Dimension.CHANNEL,
    "declared_tool": Dimension.TOOL,
    "declared_mcp": Dimension.MCP_SERVER,
    "declared_mcp_server": Dimension.MCP_SERVER,
    "declared_scope": Dimension.DATA_SCOPE,
    "declared_data_scope": Dimension.DATA_SCOPE,
    # The IaC / IAM attested reachability (PLATFORM_ATTESTED). Same shape.
    "attested_action": Dimension.ACTION_TYPE,
    "attested_scope": Dimension.DATA_SCOPE,
    "attested_data_scope": Dimension.DATA_SCOPE,
    "attested_channel": Dimension.CHANNEL,
    "attested_tool": Dimension.TOOL,
}

#: Footprint ATTR names that carry an EXERCISED capability, by dimension. The
#: actions-trail / MCP-DAG sensors stamp these from what an agent actually did.
_EXERCISED_ATTRS: Mapping[str, str] = {
    "action_type": Dimension.ACTION_TYPE,
    "channel": Dimension.CHANNEL,
    "tool": Dimension.TOOL,
    "tool_name": Dimension.TOOL,
    "mcp_server": Dimension.MCP_SERVER,
    "data_scope": Dimension.DATA_SCOPE,
}

#: A multi-valued attr packs several values into one string with this separator
#: (e.g. ``declared_scope="payment:vendor;iam/study-data"``). Both ``;`` and
#: ``,`` are accepted so a sensor need not pick one. ``:`` is NOT a separator —
#: it is part of a scope value (``payment:vendor``).
_MULTIVALUE_SEPARATORS: tuple[str, ...] = (";", ",", "|")


def _split_values(raw: str) -> list[str]:
    """Split a possibly-multivalued attr string into individual values."""
    parts = [raw]
    for sep in _MULTIVALUE_SEPARATORS:
        parts = [p for chunk in parts for p in chunk.split(sep)]
    return [p.strip() for p in parts if p.strip()]


@dataclass(frozen=True)
class CapabilityClaim:
    """One per-incidence capability observation BEFORE cross-incidence fusion.

    Each member incidence contributes zero or more claims; ``map_capability``
    fuses claims on the same token into one graded ``CapabilityEdge``, taking the
    strongest grade and OR-ing the declared/exercised flags. Carrying the
    ``observed_at`` ordinal lets the drift detector see a token whose grade
    mutated across the window.
    """

    token: str
    admissibility: Admissibility
    declared: bool
    exercised: bool
    evidence_ref: str | None
    observed_at_ns: int


def _claims_from_incidence(inc: Incidence) -> list[CapabilityClaim]:
    """Extract every capability claim a single incidence carries (generic).

    Reads the footprint's ATTRS for declared/attested/exercised capability
    tokens across all five dimensions, plus two structural fallbacks grounded in
    the real tex-enterprise footprint shape:

    - the ``workspace_path`` KEY is an exercised DATA_SCOPE (the agent touched
      that path — a PROVEN ground-truth scope on the fs plane, an OBSERVED scope
      on the trail plane);
    - a PROVEN/OBSERVED ``action_type`` attr is the exercised action.

    The incidence's ``admissibility`` decides whether a token is exercised
    (PROVEN/OBSERVED) or merely declared (CLAIMED/PLATFORM_ATTESTED). A declared
    attr (``declared_*`` / ``attested_*``) is ALWAYS a declaration regardless of
    the carrying incidence's grade — a sensor may attach an IaC scope to an
    otherwise-observed footprint.
    """
    claims: list[CapabilityClaim] = []
    fp = inc.footprint
    ref = inc.raw_evidence_ref
    ts_ns = _observed_ns(inc)
    grade = inc.admissibility
    incidence_exercised = grade in _EXERCISED_GRADES

    def emit(token: str, *, declared: bool, exercised: bool, edge_grade: Admissibility) -> None:
        claims.append(
            CapabilityClaim(
                token=token,
                admissibility=edge_grade,
                declared=declared,
                exercised=exercised,
                evidence_ref=ref,
                observed_at_ns=ts_ns,
            )
        )

    attrs = fp.attrs

    # 1. DECLARED / ATTESTED tokens — always declarations, grade by the attr.
    for attr_name, value in attrs:
        dim = _DECLARED_ATTRS.get(attr_name)
        if dim is None:
            continue
        # An ``attested_*`` attr is PLATFORM_ATTESTED; a ``declared_*`` is CLAIMED.
        attested = attr_name.startswith("attested_")
        edge_grade = (
            Admissibility.PLATFORM_ATTESTED if attested else Admissibility.CLAIMED
        )
        for raw in _split_values(value):
            emit(
                _token(dim, raw),
                declared=True,
                exercised=False,
                edge_grade=edge_grade,
            )

    # 2. EXERCISED tokens — only when the carrying incidence is PROVEN/OBSERVED.
    if incidence_exercised:
        for attr_name, value in attrs:
            dim = _EXERCISED_ATTRS.get(attr_name)
            if dim is None:
                continue
            for raw in _split_values(value):
                emit(
                    _token(dim, raw),
                    declared=False,
                    exercised=True,
                    edge_grade=grade,
                )

    # 3. Structural fallback: a touched ``workspace_path`` is an exercised scope.
    #    On the PROVEN fs plane this is ground-truth blast radius; on the OBSERVED
    #    trail plane it is a watched scope. Only the directory prefix is the
    #    scope token (a per-file path is too fine to govern on).
    if incidence_exercised:
        wp = fp.key("workspace_path")
        if wp:
            scope = _scope_of_path(wp)
            if scope:
                emit(
                    _token(Dimension.DATA_SCOPE, scope),
                    declared=False,
                    exercised=True,
                    edge_grade=grade,
                )

    return claims


def _scope_of_path(workspace_path: str) -> str | None:
    """The governable DATA_SCOPE prefix of a workspace-relative path.

    A per-file path (``preclinical/study-readouts/52.md``) is too fine to govern
    on; the top directory segment (``preclinical``) is the data scope the PDP
    reasons about. A bare filename with no ``/`` yields no scope (nothing to
    generalize). Mirrors how the registry declares ``scopes`` as path prefixes.
    """
    cleaned = workspace_path.strip().strip("/")
    if "/" not in cleaned:
        return None
    return cleaned.split("/", 1)[0] or None


def _observed_ns(inc: Incidence) -> int:
    """Integer-nanosecond ordinal of an incidence's ``observed_at`` for drift."""
    dt = inc.observed_at
    # ``observed_at`` is enforced tz-aware in Incidence.__post_init__.
    return int(dt.timestamp() * 1_000_000_000)


# ---------------------------------------------------------------------------
# Cross-incidence fusion — claims → graded edges + honesty delta + drift
# ---------------------------------------------------------------------------

#: Strength order on Admissibility (higher = stronger provenance). Used to pick
#: the single grade an edge carries when several incidences claim one token at
#: different grades — the PDP should trust the STRONGEST provenance available.
_GRADE_STRENGTH: Mapping[Admissibility, int] = {
    Admissibility.PROVEN: 4,
    Admissibility.OBSERVED: 3,
    Admissibility.PLATFORM_ATTESTED: 2,
    Admissibility.CLAIMED: 1,
}


def _stronger(a: Admissibility, b: Admissibility) -> Admissibility:
    """The stronger-provenance grade of two."""
    return a if _GRADE_STRENGTH[a] >= _GRADE_STRENGTH[b] else b


@dataclass
class _TokenAccumulator:
    """Folds every claim on ONE token into the fields of its final edge."""

    token: str
    grade: Admissibility
    declared: bool = False
    exercised: bool = False
    evidence_ref: str | None = None
    # Distinct (grade) values seen for this token across the window, with the
    # ordinal of the FIRST sighting at each grade — drives drift detection.
    grades_seen: set[Admissibility] = None  # type: ignore[assignment]
    first_ns: int = 0
    last_ns: int = 0

    def __post_init__(self) -> None:
        if self.grades_seen is None:
            self.grades_seen = set()

    def absorb(self, claim: CapabilityClaim) -> None:
        self.grade = _stronger(self.grade, claim.admissibility)
        self.declared = self.declared or claim.declared
        self.exercised = self.exercised or claim.exercised
        self.grades_seen.add(claim.admissibility)
        # Keep the strongest-provenance evidence ref for the receipt; fall back
        # to the first non-null otherwise.
        if self.evidence_ref is None:
            self.evidence_ref = claim.evidence_ref
        if not self.first_ns or claim.observed_at_ns < self.first_ns:
            self.first_ns = claim.observed_at_ns
        if claim.observed_at_ns > self.last_ns:
            self.last_ns = claim.observed_at_ns


def map_capability(
    entity: SieveEntity,
    incidences: Sequence[Incidence],
) -> CapabilityGraph:
    """Build the entity's graded capability / blast-radius surface (§4).

    Fuses the four capability layers over the entity's member incidences —
    PROVEN/OBSERVED exercised tool/MCP/action DAG, PLATFORM_ATTESTED IaC/IAM
    static reachability, and CLAIMED declarations — into one ``CapabilityGraph``
    whose every ``CapabilityEdge`` carries a per-claim ``Admissibility`` grade.
    Derives the two first-class honesty outputs: the declared-vs-exercised delta
    (``used_but_undeclared`` = hidden blast radius; ``declared_but_unused`` =
    dormant latent risk) and capability ``drift`` (tokens whose grade mutated
    mid-window, e.g. a tools-list/code-hash change that promoted a CLAIMED token
    to an OBSERVED one, or vice versa).

    Args:
        entity: the resolved entity whose capability surface is being measured.
            Only the incidences in ``entity.incidences`` are considered (so a
            shared incidence pool can be passed and this entity sees only its
            members).
        incidences: the entity's member ``Incidence`` records (the raw footprints
            carrying the exercised tool-calls, IaC-attested IAM, and declared
            skills/tools-list this graph is reconstructed from). Incidences not
            in ``entity.incidences`` are ignored.

    Returns:
        A ``CapabilityGraph`` with graded ``edges`` (one per distinct capability
        token), the ``used_but_undeclared`` / ``declared_but_unused`` deltas, and
        ``drift``. An entity with no capability-bearing footprint yields an empty
        graph (no edges, empty deltas) rather than raising.

    Honesty obligation: a capability is marked ``exercised`` only on OBSERVED or
    PROVEN evidence — a ``CLAIMED`` / ``PLATFORM_ATTESTED`` declaration alone
    never sets ``exercised``, so a used-but-undeclared tool always surfaces in
    the delta.
    """
    member_ids = entity.incidences
    members = [inc for inc in incidences if inc.incidence_id in member_ids]

    # 1. Extract every per-incidence capability claim.
    claims: list[CapabilityClaim] = []
    for inc in members:
        claims.extend(_claims_from_incidence(inc))

    if not claims:
        return CapabilityGraph()

    # 2. Fold claims per token into one accumulator (strongest grade wins).
    accs: dict[str, _TokenAccumulator] = {}
    for claim in claims:
        acc = accs.get(claim.token)
        if acc is None:
            acc = _TokenAccumulator(token=claim.token, grade=claim.admissibility)
            accs[claim.token] = acc
        acc.absorb(claim)

    # 3. Materialize graded edges (stable, deterministic order).
    edges: list[CapabilityEdge] = []
    used_but_undeclared: list[str] = []
    declared_but_unused: list[str] = []
    drift: list[str] = []

    for token in sorted(accs):
        acc = accs[token]
        edges.append(
            CapabilityEdge(
                capability=token,
                admissibility=acc.grade,
                declared=acc.declared,
                exercised=acc.exercised,
                evidence_ref=acc.evidence_ref,
            )
        )
        # Honesty delta (§4).
        if acc.exercised and not acc.declared:
            used_but_undeclared.append(token)  # hidden blast radius
        if acc.declared and not acc.exercised:
            declared_but_unused.append(token)  # dormant latent risk
        # Drift (§4/§5): a token whose provenance GRADE mutated across the window
        # — e.g. a capability that was only CLAIMED early and became OBSERVED
        # later, or one that was attested and then exercised. A token seen at a
        # single grade is stable. Requires a real time span so a single instant's
        # multi-grade fold (declared+exercised in one tick) is not called drift.
        if len(acc.grades_seen) >= 2 and acc.last_ns > acc.first_ns:
            drift.append(token)

    return CapabilityGraph(
        edges=tuple(edges),
        used_but_undeclared=tuple(used_but_undeclared),
        declared_but_unused=tuple(declared_but_unused),
        drift=tuple(drift),
    )


# ---------------------------------------------------------------------------
# Projection to the existing CapabilitySurface vocabulary (the PDP boundary)
# ---------------------------------------------------------------------------


def project_to_surface(graph: CapabilityGraph) -> dict[str, tuple[str, ...]]:
    """Project a ``CapabilityGraph`` to the ``CapabilitySurface`` field shape.

    Returns a kwargs dict the existing ``CapabilitySurface`` model can be
    constructed from (``allowed_action_types`` / ``allowed_channels`` /
    ``allowed_tools`` / ``allowed_mcp_servers`` / ``data_scopes``), so the PDP
    governs a *measured* surface (ARCHITECTURE.md §4, §7). Built at the boundary
    rather than inside ``map_capability`` so the rich graded graph stays the
    internal authority and only the coarse surface crosses to the PDP.

    Honesty posture (load-bearing): the projected surface is the MEASURED
    capability — the union of EXERCISED tokens (what the entity actually did,
    PROVEN+OBSERVED) and PLATFORM_ATTESTED reachability (the IaC/IAM ceiling the
    entity provably COULD reach pre-runtime). A merely-CLAIMED-but-never-exercised
    token is deliberately NOT widened into the governed surface — a declaration
    alone must not grant scope; it is surfaced as ``declared_but_unused`` dormant
    risk instead. This keeps the surface a floor of real capability the PDP can
    trust, not a self-asserted wishlist.

    The five returned tuples are sorted + de-duplicated for stable receipts.
    """
    by_dim: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        # Only measured capability enters the governed surface: exercised
        # (we watched it) OR platform-attested (the IaC/IAM ceiling). A
        # claim-only edge is excluded (dormant risk, not granted scope).
        governs = edge.exercised or edge.admissibility is Admissibility.PLATFORM_ATTESTED
        if not governs:
            continue
        dim, value = split_token(edge.capability)
        if value:
            by_dim[dim].add(value)

    return {
        "allowed_action_types": tuple(sorted(by_dim.get(Dimension.ACTION_TYPE, set()))),
        "allowed_channels": tuple(sorted(by_dim.get(Dimension.CHANNEL, set()))),
        "allowed_tools": tuple(sorted(by_dim.get(Dimension.TOOL, set()))),
        "allowed_mcp_servers": tuple(sorted(by_dim.get(Dimension.MCP_SERVER, set()))),
        "data_scopes": tuple(sorted(by_dim.get(Dimension.DATA_SCOPE, set()))),
    }
