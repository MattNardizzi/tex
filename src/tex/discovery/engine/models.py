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
    ships only the first three values below. The PLANE-ROSTER members beneath
    them are the breadth planes (ARCHITECTURE.md §8 P0..P14) that the ten
    flag-gated sensor builders emit on. Each one is FLAG-GATED OFF by default
    (see ``sensors.registry``); adding the enum member here does NOT activate a
    plane — only the env flag does. The slice's two real planes plus
    ``WITHHELD_THIRD`` keep their original values so the slice tests are
    unchanged; the roster members are new, additive, and inert until enabled.
    """

    # --- the thin-slice planes (unchanged; slice tests depend on these) ------
    ACTIONS_TRAIL = "actions_trail"
    FS_WRITE = "fs_write"
    WITHHELD_THIRD = "withheld_third"

    # --- the full PLANE roster (ARCHITECTURE.md §8 P0..P14) ------------------
    #: P13 — identity / signed-cohort plane (OIDC sub, SPIFFE id, SP object id,
    #: OAuth grant id). Calibration-grade identity anchor (PLATFORM_ATTESTED).
    SIGNED_ID = "signed_id"
    #: P1..P4 — passive network-egress plane (JA4/JA4S client+server hello, SNI,
    #: ASN, egress IP, HTTP/2 settings hash, token-waveform / cadence sigs).
    NETWORK_EGRESS = "network_egress"
    #: P9 — kernel / eBPF host plane (code hash, exec id, process lineage,
    #: syscall-graph signature, binary path). The PROVEN ground-truth vantage.
    KERNEL_EBPF = "kernel_ebpf"
    #: P6/P7 — managed cloud control plane (control-plane id, managed-agent id,
    #: model, region, IAM role-arn). PLATFORM_ATTESTED audit/grant signal.
    MANAGED_CONTROL = "managed_control"
    #: P5/P8(part) — SaaS / automation plane (OAuth grant, bot user, automation
    #: recipe id, granted scopes). OBSERVED/PLATFORM_ATTESTED app-side signal.
    SAAS_AUTOMATION = "saas_automation"
    #: P11 — governance-stream plane (PDP agent id, OTel trace id, tool name,
    #: billing account). OBSERVED instrumentation already inside the boundary.
    GOVERNANCE_STREAM = "governance_stream"
    #: P8 — static supply-chain / provenance plane (repo path, agent-def symbol,
    #: framework, manifest path, declared tools, IAM role). CLAIMED, parse-only.
    STATIC_SUPPLYCHAIN = "static_supplychain"
    #: P10 — MCP / A2A tool-graph plane (MCP server url, agent-card id, tool-set
    #: MinHash, A2A skills). OBSERVED tool-DAG ∩ CLAIMED card.
    MCP_TOOLGRAPH = "mcp_toolgraph"
    #: P9(endpoint) — endpoint EDR plane (host id, process name, runtime,
    #: persistence). OBSERVED host-agent telemetry.
    ENDPOINT_EDR = "endpoint_edr"
    #: P14 — active honeytoken / decoy lattice plane (decoy id, canary cred id,
    #: caller fingerprint, injected marker). PROVEN bite = a strong join key.
    HONEYTOKEN = "honeytoken"
    #: P0 — coverage-health meta-plane (governance-stream). Reports per-plane
    #: liveness so the honesty layer can NAME a dark vantage rather than guess.
    COVERAGE_HEALTH = "coverage_health"


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


class AgentHumanLabel(StrEnum):
    """The agent-vs-human classification label (ARCHITECTURE.md §3B).

    ``ABSTAIN`` is first-class (RESEARCH_LOG.md N4 / the abstain doctrine): when
    the dual-confirmation gate is not jointly satisfied and the signals conflict,
    the classifier abstains rather than guessing. The slice negative control is
    that a human traversing the canary surface must resolve to ``HUMAN`` or
    ``ABSTAIN`` — never ``AGENT``.
    """

    AGENT = "agent"
    HUMAN = "human"
    ABSTAIN = "abstain"


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


class FootprintField(StrEnum):
    """The canonical footprint key/attr NAME vocabulary the planes share.

    ``FootprintVector`` itself is a deliberately-generic ``keys``/``attrs`` bag
    (a sorted tuple-of-pairs so it stays frozen + hashable). The discriminating
    power lives in the NAMES of those keys, not in struct fields — so the
    "optional fields the planes need" are defined here as a single shared,
    auditable vocabulary that all ten flag-gated sensor builders emit against.
    Centralizing the names is what lets ``fuse.py`` LINK the same agent across N
    planes (a strong-edge name shared by two planes fuses) and lets
    ``disambiguate.py`` SPLIT (a bridging-grade name shared under one credential
    bridges without merging). Builders MUST use these constants for any
    cross-plane key so the field-grade map in ``fuse.py`` classifies them.

    Grade follows ``fuse._IDENTITY_KEYS`` / ``_BRIDGING_KEYS``:
    - IDENTITY-grade (strong, MUST close transitively): an identity-grade name
      means "same agent" by schema — code hash, SPIFFE id, signed OIDC sub, an
      injected honeytoken marker, a tool-set MinHash, a behavioral signature.
    - BRIDGING-grade (weak, MAY violate transitivity): a shared name that links
      but never merges alone — ASN, egress IP, a popular JA4, an OAuth grant.

    Membership in identity vs bridging is decided in ``fuse.py`` (the single
    shared edit), NOT here; this enum only fixes the NAMES so builders cohere.
    """

    # --- network-egress (P1..P4) -------------------------------------------
    JA4 = "ja4"
    JA4S = "ja4s"
    SNI = "sni"
    ASN = "asn"
    EGRESS_IP = "egress_ip"
    H2_SETTINGS_HASH = "h2_settings_hash"
    TOKEN_WAVEFORM_SIG = "token_waveform_sig"
    CADENCE_SIG = "cadence_sig"

    # --- identity / signed-id (P13) ----------------------------------------
    OIDC_SUB = "oidc_sub"
    SP_OBJECT_ID = "sp_object_id"
    OAUTH_GRANT_ID = "oauth_grant_id"
    SPIFFE_ID = "spiffe_id"

    # --- kernel / eBPF (P9) ------------------------------------------------
    CODE_HASH = "code_hash"
    EXEC_ID = "exec_id"
    PROC_LINEAGE = "proc_lineage"
    SYSCALL_GRAPH_SIG = "syscall_graph_sig"
    BINARY_PATH = "binary_path"

    # --- managed control plane (P6/P7) -------------------------------------
    CONTROL_PLANE = "control_plane"
    MANAGED_AGENT_ID = "managed_agent_id"
    MODEL = "model"
    REGION = "region"
    ROLE_ARN = "role_arn"

    # --- SaaS / automation (P5) --------------------------------------------
    SAAS_APP = "saas_app"
    BOT_USER_ID = "bot_user_id"
    AUTOMATION_RECIPE_ID = "automation_recipe_id"
    SCOPES = "scopes"

    # --- governance-stream (P11) -------------------------------------------
    PDP_AGENT_ID = "pdp_agent_id"
    OTEL_TRACE_ID = "otel_trace_id"
    TOOL_NAME = "tool_name"
    BILLING_ACCOUNT = "billing_account"

    # --- static supply-chain (P8) ------------------------------------------
    REPO_PATH = "repo_path"
    AGENT_DEF_SYMBOL = "agent_def_symbol"
    FRAMEWORK = "framework"
    MANIFEST_PATH = "manifest_path"
    DECLARED_TOOLS = "declared_tools"
    IAM_ROLE = "iam_role"

    # --- MCP / A2A tool-graph (P10) ----------------------------------------
    MCP_SERVER_URL = "mcp_server_url"
    AGENT_CARD_ID = "agent_card_id"
    TOOL_SET_MINHASH = "tool_set_minhash"
    A2A_SKILLS = "a2a_skills"

    # --- endpoint EDR (P9 endpoint) ----------------------------------------
    HOST_ID = "host_id"
    PROCESS_NAME = "process_name"
    RUNTIME = "runtime"
    PERSISTENCE = "persistence"

    # --- honeytoken / decoy lattice (P14) ----------------------------------
    DECOY_ID = "decoy_id"
    CANARY_CRED_ID = "canary_cred_id"
    CALLER_FINGERPRINT = "caller_fingerprint"
    INJECTED_MARKER = "injected_marker"

    # --- behavioral fingerprint (cross-plane merge/split axis) -------------
    BEHAVIOR_SIG = "behavior_sig"


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
    # The measured capability/blast-radius surface (ARCHITECTURE.md §4), filled by
    # ``capability.map_capability``. ``None`` until the capability builder runs;
    # the legacy ``capability`` tuple above stays the coarse token list so the
    # slice + its tests keep passing. When present, the graph is the authoritative
    # per-edge-graded surface that projects to ``CapabilitySurface`` at the
    # boundary, and ``capability`` is a derived view of its exercised edges.
    capability_graph: "CapabilityGraph | None" = None
    # The agent-vs-human classification (ARCHITECTURE.md §3B), filled by
    # ``disambiguate.classify_agent_vs_human``. ``None`` until the classifier runs.
    agent_human: "AgentHumanVerdict | None" = None
    # The shared-credential split verdicts this entity participated in (N1;
    # ARCHITECTURE.md §3A), filled by ``disambiguate.resolve_shared_credential``.
    # Empty when the entity was not collapsed under any shared credential.
    shared_credential_verdicts: tuple["SharedCredentialVerdict", ...] = ()
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
    # Output-boundary projection lives in ``adapter.py`` as free functions
    # (``reconciliation_key`` / ``to_candidate_agent`` / ``to_reconciliation_outcome``
    # over a ``SieveEntity``) — deliberately kept OFF the model to avoid a
    # models→adapter import cycle. See ``engine/adapter.py``.
    # ------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Disambiguation layer — shared-credential split (N1) + agent-vs-human (CORROBORANT)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SharedCredentialVerdict:
    """The N1 shared-credential split result — k distinct agents behind one key.

    The hardest constraint in the field (RESEARCH_LOG.md WS-3): every
    credential-keyed inventory collapses one credential to one identity by
    construction. SIEVE resolves the credential as a WEAK ``BRIDGING`` node and
    clusters its per-session footprint vectors on behavioral split-axis features
    (tool-call grammar n-grams, inter-call cadence entropy, packetization mode,
    runtime/attestation context); a strong-edge transitive-closure FAILURE across
    the credential bridge is the positive split signal (N1; ARCHITECTURE.md §3A).

    This is the fixed RETURN shape of
    ``disambiguate.resolve_shared_credential`` — the disambiguation builder fills
    the algorithm behind it. The two negative-control invariants the benchmark
    enforces (do not over-merge two distinct agents into k==1; do not over-split
    one agent into k>=2) are properties of ``k_estimate`` and ``member_entity_ids``.

    Fields:

    - ``credential_id``      — the shared bridging key (e.g. a service-credential /
                               self-asserted ``agent_external_id`` / egress IP) the
                               footprints were collapsed under.
    - ``k_estimate``         — the Bayesian-model-selected number of DISTINCT
                               generative processes (agents) behind the credential.
                               ``k_estimate == 1`` means "one agent, do NOT split".
    - ``member_entity_ids``  — the resolved ``SieveEntity.entity_id`` of each
                               distinct agent the credential was split into. Its
                               length equals ``k_estimate`` once the split lands.
    - ``confidence``         — calibrated [0,1] confidence in the split count
                               (e-value / mixture model-selection posterior).
                               Never a hard 1.0; residual sharers stay counted,
                               bounded uncertainty rather than force-split.
    - ``split_axis_signals`` — the behavioral features that drove the split, for
                               receipts (e.g. ``("tool_grammar", "cadence")``).
    - ``method``             — a method tag naming how ``k_estimate`` was produced
                               (e.g. ``"transitivity_violation"``, ``"mixture_bic"``,
                               ``"evalue_sequential"``), for auditability.

    INVARIANT (enforced): ``k_estimate >= 1``, ``0 <= confidence <= 1``, and
    ``member_entity_ids`` is empty (pre-resolution) or has exactly ``k_estimate``
    distinct ids. ``k_estimate == 1`` with one-or-zero members is the negative
    control (no false split).
    """

    credential_id: str
    k_estimate: int
    member_entity_ids: tuple[UUID, ...] = ()
    confidence: float = 0.0
    split_axis_signals: tuple[str, ...] = ()
    method: str = "unknown"

    def __post_init__(self) -> None:
        if self.k_estimate < 1:
            raise ValueError(
                f"k_estimate must be >= 1 (one agent never splits to 0), "
                f"got {self.k_estimate!r}"
            )
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"confidence must be in [0,1], got {self.confidence!r}"
            )
        if self.member_entity_ids:
            if len(set(self.member_entity_ids)) != len(self.member_entity_ids):
                raise ValueError("member_entity_ids must be distinct")
            if len(self.member_entity_ids) != self.k_estimate:
                raise ValueError(
                    "member_entity_ids, when populated, must have exactly "
                    f"k_estimate entries ({len(self.member_entity_ids)} != "
                    f"{self.k_estimate})"
                )


@dataclass(frozen=True)
class AgentHumanVerdict:
    """Agent-vs-human-using-an-LLM classification — a CALIBRATED probability.

    The dual-confirmation gate grafted from CORROBORANT (ARCHITECTURE.md §3B):
    an entity is classified ``agent`` only when BOTH a planted prompt-injection
    canary is obeyed AND the response is sub-1.5s machine-speed-with-semantic-
    content, augmented by packetization mode / tool-call grammar / absent motor
    noise. Emitted as a conformal open-set probability, NEVER a hard 100% — and
    the thin-slice negative control is that a human traversing the canary surface
    must NOT trip the agent confirmation.

    Fixed RETURN shape of ``disambiguate.classify_agent_vs_human``.

    Fields:

    - ``label``        — one of ``AgentHumanLabel`` (``AGENT`` / ``HUMAN`` /
                         ``ABSTAIN``). ``ABSTAIN`` is first-class: when the dual
                         gate is not jointly satisfied and signals conflict, the
                         classifier abstains rather than guessing.
    - ``probability``  — calibrated [0,1] probability the entity is an
                         agent-in-the-loop. Conformal, never a hard 0/1.
    - ``signals``      — the contributing signals as ``(name, value)`` pairs for
                         receipts (e.g. ``(("canary_obeyed", "true"),
                         ("response_ms", "640"), ("packetization", "bundled")))``).
    - ``method``       — method tag (e.g. ``"dual_confirmation"``,
                         ``"conformal_openset"``).

    INVARIANT (enforced): ``0 <= probability <= 1``.
    """

    label: "AgentHumanLabel"
    probability: float
    signals: tuple[tuple[str, str], ...] = ()
    method: str = "unknown"

    def __post_init__(self) -> None:
        if not 0.0 <= self.probability <= 1.0:
            raise ValueError(
                f"probability must be in [0,1], got {self.probability!r}"
            )


# ---------------------------------------------------------------------------
# Capability layer — observed tool-DAG ∩ IaC-IAM, per-edge graded (§4)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CapabilityEdge:
    """One graded capability the entity can exercise (ARCHITECTURE.md §4).

    Capability is reconstructed from OBSERVED behavior, not declared cards. Each
    edge carries a per-claim ``admissibility`` grade so the PDP/UI knows how much
    to trust it: ``PROVEN`` (eBPF ground truth) > ``OBSERVED`` (exercised tool/MCP
    DAG) > ``PLATFORM_ATTESTED`` (IaC/IAM static reachability) > ``CLAIMED`` (A2A
    skills[] / tools/list declaration — a claim only).

    Fields:

    - ``capability``   — the canonical capability token, aligned with the existing
                         ``CapabilitySurface`` vocabulary (an allowed action type,
                         channel, tool name, mcp_server, or data_scope).
    - ``admissibility``— the provenance grade of THIS edge (drives trust weight).
    - ``declared``     — the agent DECLARED this capability (A2A/tools-list claim).
    - ``exercised``    — SIEVE OBSERVED this capability actually exercised.
    - ``evidence_ref`` — opaque pointer to the observation (span id, eBPF ref).

    The ``declared`` vs ``exercised`` flags drive the entity-level honesty delta:
    ``exercised and not declared`` = hidden blast radius; ``declared and not
    exercised`` = dormant latent risk (see ``CapabilityGraph``).
    """

    capability: str
    admissibility: Admissibility
    declared: bool = False
    exercised: bool = False
    evidence_ref: str | None = None


@dataclass(frozen=True)
class CapabilityGraph:
    """The measured capability / blast-radius surface for one entity (§4).

    Three fused layers (observed tool-DAG ∩ IaC-IAM ∩ declared cards), each edge
    graded, plus the two first-class honesty outputs SIEVE exists to surface:
    the **declared-vs-exercised delta** and **capability DRIFT**. This is the
    return type of ``capability.map_capability`` and the internal shape
    ``SieveEntity.capability_graph`` carries; it projects to the existing
    ``CapabilitySurface`` at the output boundary so the PDP governs a *measured*
    surface.

    Fields:

    - ``edges``                — the graded capability edges (see ``CapabilityEdge``).
    - ``used_but_undeclared``  — capability tokens exercised but never declared =
                                 HIDDEN blast radius (the dangerous delta).
    - ``declared_but_unused``  — capability tokens declared but never exercised =
                                 dormant latent risk.
    - ``drift``                — capability tokens whose presence/grade MUTATED
                                 mid-window (tools/list or AgentCard change,
                                 code-hash change) — a fast attribution event.

    The three delta tuples are derived views over ``edges`` but materialized so
    the PDP/UI and receipts can read them without recomputing. ``declared_vs_
    exercised_delta`` is the union of the first two (the honesty headline).
    """

    edges: tuple[CapabilityEdge, ...] = ()
    used_but_undeclared: tuple[str, ...] = ()
    declared_but_unused: tuple[str, ...] = ()
    drift: tuple[str, ...] = ()

    @property
    def declared_vs_exercised_delta(self) -> tuple[str, ...]:
        """The honesty headline: every capability where declared != exercised.

        The union of ``used_but_undeclared`` (hidden blast radius) and
        ``declared_but_unused`` (dormant risk), sorted+deduped for receipts.
        """
        return tuple(sorted(set(self.used_but_undeclared) | set(self.declared_but_unused)))


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
    "AgentHumanLabel",
    "PresenceState",
    "FootprintVector",
    "FootprintField",
    "Incidence",
    "TypedEdge",
    "SieveEntity",
    "SharedCredentialVerdict",
    "AgentHumanVerdict",
    "CapabilityEdge",
    "CapabilityGraph",
    "NamedBlindSpot",
    "UnseenEstimate",
]
