"""
ARM — Agentic Reference Monitor (arxiv 2604.04035, Chinaei, April 2026).

Provenance-aware runtime enforcement layer. Treats denied actions as
first-class graph nodes with counterfactual edges to subsequent actions
that may have been causally influenced by them.

Trust propagates through a five-level integrity lattice (§2.3, §5.3):

    ToolDesc < ToolUntrusted < ToolTrusted < UserInput < SysInstr

over:
  - transitive data dependencies (DirectOutput / InputTo / FieldOf edges)
  - field-level provenance (DataField nodes, §5.6)
  - denial-induced counterfactual paths (Counterfactual edges, §3.7)

All policy decisions are computed by deterministic graph traversals and
explicit rules, never delegated back to the LLM under scrutiny
(§4.2 reference monitor properties: complete mediation, tamper-proof,
verifiable).

In Tex, the paper's separate "audit log" (§4.5, hash-chained tamper
evidence) is the existing ``tex.events.ledger.InMemoryLedger`` — which
is already SHA-256 hash-chained and signed via the algorithm-agility
provider abstraction. The provenance graph is internal to ARM
(``tex.causal._provenance_graph``).

Priority: P1.

Reference: arxiv 2604.04035 §3.7, §4.3.2, §5.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Mapping
from uuid import uuid4

from tex.causal._denial_record import DenialRecord
from tex.causal._integrity import (
    DEFAULT_TRUST_THRESHOLD,
    IntegrityLevel,
    lattice_meet,
)
from tex.causal._provenance_graph import (
    CallNode,
    DataFieldNode,
    DataNode,
    DeniedActionNode,
    ProvenanceEdgeLabel,
    ProvenanceGraph,
    ProvenanceNodeKind,
    utc_now,
)
# Import from submodules directly (NOT through tex.events.__init__) to
# avoid the circular import via tex.ecosystem -> tex.events. Concretely:
#
#   tex.events/__init__.py imports tex.events.crypto_provenance, which
#   imports tex.ecosystem.proposed_event, which triggers
#   tex.ecosystem/__init__.py -> tex.ecosystem.bridge ->
#   tex.ecosystem.engine -> tex.events.crypto_provenance again, and
#   the second import finds crypto_provenance only partially
#   initialised.
#
# The other ecosystem-tier modules (tex.ecosystem.engine itself, tests
# under tests/ecosystem/) sidestep this by ensuring `tex.ecosystem` is
# loaded *before* any cold `tex.events.*` import. We mirror that by
# importing tex.ecosystem.proposed_event at the top of this module's
# import block — once ecosystem's package init is done, subsequent
# tex.events.* imports resolve cleanly.
from tex.ecosystem.proposed_event import ProposedEvent  # noqa: F401  (priming)

from tex.events._canonical import canonical_sha256
from tex.events.ledger import InMemoryLedger
from tex.observability.telemetry import emit_event
from tex.ontology.event_types import EventKind

# Type-only import for CryptoProvenance — kept under TYPE_CHECKING so
# tools that statically inspect arm.py see the correct annotation
# without re-tripping the cycle at runtime if some future refactor
# re-routes things.
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tex.events.crypto_provenance import CryptoProvenance


# Integrity-label strings exported on integrity_label_for(); these are
# the legacy public-API labels the scaffolding promised. They map onto
# regions of the formal lattice as follows:
#
#   TRUSTED               — MinTrust ≥ ToolTrusted, no counterfactual
#   UNTRUSTED_INPUT       — MinTrust ≤ ToolUntrusted (originating taint)
#   DERIVED_FROM_TAINTED  — MinTrust ≤ ToolUntrusted (transitive taint)
#   TAINTED_BY_DENIAL     — at least one Counterfactual chain reaches the node
#
# Returning these as strings keeps the public API stable even if the
# underlying lattice grows new levels.
LABEL_TRUSTED: str = "TRUSTED"
LABEL_UNTRUSTED_INPUT: str = "UNTRUSTED_INPUT"
LABEL_DERIVED_FROM_TAINTED: str = "DERIVED_FROM_TAINTED"
LABEL_TAINTED_BY_DENIAL: str = "TAINTED_BY_DENIAL"


class AgenticReferenceMonitor:
    """
    Reference monitor over a provenance graph + a hash-chained ledger.

    Construction is dependency-injected so the same class works in three
    deployment modes:

      1. Pure in-memory (no ledger) — ``ledger=None``. Denials live only
         in the in-memory provenance graph; useful for unit tests and
         for the paper's reference deployment which separates audit log
         from graph.
      2. With ledger — ``ledger`` and ``provenance`` both wired. A
         ``DENIAL_EVENT`` is appended to the ledger on every denial; the
         signing algorithm is whatever the injected ``CryptoProvenance``
         has been configured with (ECDSA today, ML-DSA-65 tomorrow —
         no algorithm hardcoded here).
      3. With external graph — ``provenance_graph=`` lets callers share
         a graph instance with other components (e.g. an EcosystemEngine
         wrapper).

    Reference: arxiv 2604.04035 §4.
    """

    def __init__(
        self,
        *,
        provenance_graph: ProvenanceGraph | None = None,
        ledger: InMemoryLedger | None = None,
        provenance: "CryptoProvenance | None" = None,
        actor_entity_id: str = "tex.causal.arm",
        threshold: IntegrityLevel = DEFAULT_TRUST_THRESHOLD,
    ) -> None:
        if ledger is not None and provenance is None:
            raise ValueError(
                "provenance is required when ledger is wired "
                "(crypto provenance must accompany ledger writes)"
            )
        self._graph = (
            provenance_graph if provenance_graph is not None else ProvenanceGraph()
        )
        self._ledger = ledger
        self._provenance = provenance
        self._actor_entity_id = actor_entity_id
        self._threshold = threshold
        # Track event-id → denial-record so integrity_label_for() can
        # resolve a public event identifier into the underlying
        # provenance-graph node.
        self._event_to_node: dict[str, str] = {}
        # Track the tail of denial counterfactual targets that are still
        # awaiting their next-call. Mirrors the "next tool call" heuristic
        # from §3.7 (Algorithm 1, line 7).
        self._pending_denial_event_ids: list[str] = []

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    @property
    def graph(self) -> ProvenanceGraph:
        """Read-only handle for tests and integrations."""
        return self._graph

    def record_denial(
        self,
        *,
        denied_event_id: str,
        denial_reason: str,
        counterfactual_targets: tuple[str, ...],
    ) -> DenialRecord:
        """
        Record a denied action as a first-class graph node. Subsequent
        actions that may have been causally influenced by the denial
        inherit security-relevant context.

        TODO(P1, arxiv:2604.04035 §4.5): emit DENIAL_EVENT into the ledger
            - DONE: when a ledger is wired, builds a ProposedEvent with
              kind=DENIAL_EVENT and appends it through the existing
              hash-chained, signature-verifying append_proposed path.
              Algorithm comes from the injected CryptoProvenance, never
              hardcoded — flips automatically when ML-DSA-65 lands.
        TODO(P1, arxiv:2604.04035 §3.7): annotate counterfactual edges
                  in the graph
            - DONE: a DeniedAction node is added to the provenance graph;
              the ProvenanceGraph then auto-attaches a Counterfactual
              edge to the *next* CallNode (matching the paper's
              temporally-adjacent-call heuristic). Explicit
              counterfactual_targets passed by callers are also wired
              if they are already in the graph.
        """
        if not denied_event_id or not isinstance(denied_event_id, str):
            raise ValueError("denied_event_id must be a non-empty string")
        if not denial_reason or not isinstance(denial_reason, str):
            raise ValueError("denial_reason must be a non-empty string")

        timestamp = utc_now()
        denial_id = f"denial:{uuid4()}"

        denied_action = DeniedActionNode(
            node_id=denial_id,
            denied_tool_name=denied_event_id,
            timestamp=timestamp,
            denial_reason=denial_reason,
            arguments_digest=_digest({"event_id": denied_event_id}),
        )
        self._graph.add_denied_action(denied_action)

        # If callers pass explicit counterfactual targets (event ids of
        # already-registered calls), wire the edges immediately. The
        # auto-attach-on-next-call logic in ProvenanceGraph.add_call
        # still fires for unknown future calls.
        wired_targets: list[str] = []
        for target in counterfactual_targets:
            if not isinstance(target, str):
                continue
            target_node_id = self._event_to_node.get(target)
            # Allow callers to pass the graph node id directly too.
            if target_node_id is None and self._graph.has(target):
                target_node_id = target
            if target_node_id is not None and self._graph.has(target_node_id):
                self._graph.add_edge(
                    source_id=denial_id,
                    target_id=target_node_id,
                    label=ProvenanceEdgeLabel.COUNTERFACTUAL,
                )
                wired_targets.append(target_node_id)

        ledger_event_id: str | None = None
        if self._ledger is not None and self._provenance is not None:
            ledger_event_id = self._append_denial_event(
                denied_event_id=denied_event_id,
                denial_reason=denial_reason,
                timestamp=timestamp,
                counterfactual_targets=tuple(counterfactual_targets),
                provenance_node_id=denial_id,
            )

        # Track for integrity_label_for resolution by event id.
        self._event_to_node[denied_event_id] = denial_id
        if ledger_event_id is not None:
            self._event_to_node[ledger_event_id] = denial_id

        record = DenialRecord(
            denial_id=denial_id,
            denied_event_id=denied_event_id,
            denied_tool_name=denied_event_id,
            denial_reason=denial_reason,
            timestamp=timestamp,
            counterfactual_target_event_ids=tuple(counterfactual_targets),
            provenance_node_id=denial_id,
            ledger_event_id=ledger_event_id,
        )

        emit_event(
            "causal.arm.denial_recorded",
            denial_id=denial_id,
            denied_event_id=denied_event_id,
            ledger_event_id=ledger_event_id,
            wired_target_count=len(wired_targets),
            pending_target_count=max(
                0, len(counterfactual_targets) - len(wired_targets)
            ),
        )
        return record

    def integrity_label_for(self, event_id: str) -> str:
        """
        Return the integrity-lattice label for an event.

        TODO(P1, arxiv:2604.04035 §5.3): walk transitive dependencies +
                  field-level provenance + denial-induced counterfactual paths
            - DONE: resolves the event_id to a graph node, runs the
              ProvenanceGraph.min_trust query (Definition 4) and the
              has_counterfactual_chain_to query (§5.4 query 2), and maps
              the result onto the public label set.
        TODO(P1, arxiv:2604.04035 §3.7): return one of TRUSTED /
                  TAINTED_BY_DENIAL / UNTRUSTED_INPUT / DERIVED_FROM_TAINTED
            - DONE.
        """
        node_id = self._resolve_node_id(event_id)
        if node_id is None:
            # No trace of this event in the graph — conservative default
            # is UNTRUSTED_INPUT for foreign events. Per ARM's lattice,
            # an unknown source is treated as worst-case low-trust.
            return LABEL_UNTRUSTED_INPUT

        # Counterfactual paths take priority — denial-induced taint is
        # the headline class of attack the paper targets, and treating
        # it as the dominant label keeps the public API decisive.
        if self._graph.has_counterfactual_chain_to(node_id):
            return LABEL_TAINTED_BY_DENIAL

        node_kind = self._graph.kind(node_id)
        if node_kind is ProvenanceNodeKind.DENIED_ACTION:
            # The denial node itself is implicitly tainted-by-denial,
            # but counterfactual chain check above won't fire for the
            # denial's own node (it has no incoming counterfactual edge).
            return LABEL_TAINTED_BY_DENIAL

        # For Data / DataField nodes, the node's own intrinsic trust
        # label is considered alongside MinTrust over its ancestors —
        # MinTrust deliberately excludes the node from its own ancestor
        # set (Definition 4), so a Data node with no upstream Data
        # would otherwise look fully trusted regardless of its own
        # label. The effective label is the meet of the two.
        payload = self._graph.payload(node_id)
        intrinsic_trust: IntegrityLevel | None = None
        if isinstance(payload, (DataNode, DataFieldNode)):
            intrinsic_trust = payload.trust

        ancestor_min = self._graph.min_trust(node_id)
        effective = (
            min(ancestor_min, intrinsic_trust)
            if intrinsic_trust is not None
            else ancestor_min
        )

        if effective >= self._threshold:
            return LABEL_TRUSTED

        # Below threshold — distinguish originating untrusted input from
        # transitive derivation. A Data / DataField node *with no data
        # ancestors* is the originator (the trust label was assigned at
        # ingest); anything else is derived.
        if isinstance(payload, (DataNode, DataFieldNode)):
            # Look for any data ancestor — if present, this node is
            # derived; if absent, it is the originator.
            has_data_ancestor = self._has_data_ancestor(node_id)
            if not has_data_ancestor:
                return LABEL_UNTRUSTED_INPUT
        return LABEL_DERIVED_FROM_TAINTED

    def check_proposed(
        self, *, proposed_event_id: str
    ) -> tuple[bool, str | None]:
        """
        Deterministic graph-traversal check. Never asks the LLM.

        TODO(P1, arxiv:2604.04035 §4.3.2): if any upstream event is
                  TAINTED_BY_DENIAL, deny by default
            - DONE: uses ProvenanceGraph.evaluate which combines
              min_trust < threshold (transitive taint, §5.4 query 1)
              with has_counterfactual_chain_to (causality laundering,
              §5.4 query 2).
        TODO(P1, arxiv:2604.04035 §4.3): apply explicit lattice rules
            - DONE: threshold is ``DEFAULT_TRUST_THRESHOLD`` (ToolTrusted
              per §4.3.2) and configurable per instance.
        """
        node_id = self._resolve_node_id(proposed_event_id)
        if node_id is None:
            # No graph evidence — conservative deny so the call site
            # cannot bypass enforcement by submitting an unregistered
            # event id.
            emit_event(
                "causal.arm.check_unknown_event",
                proposed_event_id=proposed_event_id,
            )
            return False, "unknown_event"

        allow, reason = self._graph.evaluate(
            call_node_id=node_id, threshold=self._threshold
        )
        emit_event(
            "causal.arm.check_proposed",
            proposed_event_id=proposed_event_id,
            node_id=node_id,
            allow=allow,
            deny_reason=reason,
        )
        return allow, reason

    # ------------------------------------------------------------------
    # construction helpers — used by tests + future integrations to
    # populate the graph. Kept on the class (not a separate builder)
    # because they need to share the same ProvenanceGraph instance.
    # ------------------------------------------------------------------

    def register_call(
        self,
        *,
        event_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        timestamp: datetime | None = None,
    ) -> str:
        """Add a CallNode and return its provenance-graph node id."""
        node_id = f"call:{event_id}"
        call = CallNode(
            node_id=node_id,
            tool_name=tool_name,
            timestamp=timestamp or utc_now(),
            arguments_digest=_digest(dict(arguments)),
        )
        self._graph.add_call(call)
        self._event_to_node[event_id] = node_id
        return node_id

    def register_data(
        self,
        *,
        event_id: str,
        producing_call_event_id: str | None,
        trust: IntegrityLevel,
        value_digest: str | None = None,
    ) -> str:
        """Add a DataNode produced by an upstream call."""
        node_id = f"data:{event_id}"
        data = DataNode(
            node_id=node_id,
            trust=trust,
            digest=value_digest or _digest({"event_id": event_id}),
        )
        self._graph.add_data(data)
        self._event_to_node[event_id] = node_id
        if producing_call_event_id is not None:
            producing_node = self._event_to_node.get(producing_call_event_id)
            if producing_node is not None:
                self._graph.add_edge(
                    source_id=producing_node,
                    target_id=node_id,
                    label=ProvenanceEdgeLabel.DIRECT_OUTPUT,
                )
        return node_id

    def register_input(
        self, *, data_event_id: str, call_event_id: str
    ) -> None:
        """Add an InputTo edge (data event was used as argument to call)."""
        data_node = self._event_to_node.get(data_event_id)
        call_node = self._event_to_node.get(call_event_id)
        if data_node is None:
            raise KeyError(f"unknown data event {data_event_id!r}")
        if call_node is None:
            raise KeyError(f"unknown call event {call_event_id!r}")
        self._graph.add_edge(
            source_id=data_node,
            target_id=call_node,
            label=ProvenanceEdgeLabel.INPUT_TO,
        )

    def register_data_field(
        self,
        *,
        event_id: str,
        parent_data_event_id: str,
        field_path: str,
        trust: IntegrityLevel,
    ) -> str:
        """Add a DataField node linked to its parent Data node by FieldOf."""
        parent_node = self._event_to_node.get(parent_data_event_id)
        if parent_node is None:
            raise KeyError(f"unknown parent data event {parent_data_event_id!r}")
        node_id = f"field:{event_id}"
        field = DataFieldNode(
            node_id=node_id,
            field_path=field_path,
            trust=trust,
            digest=_digest({"path": field_path, "event_id": event_id}),
        )
        self._graph.add_data_field(field)
        self._event_to_node[event_id] = node_id
        self._graph.add_edge(
            source_id=node_id,
            target_id=parent_node,
            label=ProvenanceEdgeLabel.FIELD_OF,
        )
        return node_id

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _resolve_node_id(self, event_id: str) -> str | None:
        """Map a public event_id onto a provenance-graph node id."""
        if not isinstance(event_id, str):
            return None
        if event_id in self._event_to_node:
            return self._event_to_node[event_id]
        # Allow callers to pass a graph node id directly.
        if self._graph.has(event_id):
            return event_id
        return None

    def _has_data_ancestor(self, node_id: str) -> bool:
        # min_trust scans data ancestors; we recompute here cheaply by
        # checking whether the node has a non-None data ancestor.
        # A short walk via the ProvenanceGraph's underlying graph would
        # be clearer, but we keep the boundary clean by re-asking
        # min_trust and inferring: if min_trust returned anything other
        # than the empty default (SysInstr), we know data ancestors
        # exist. For the originator distinction we want to know if there
        # is a *strictly* upstream data node — so we test for any
        # predecessors in the underlying graph whose payload is a Data
        # or DataField.
        underlying = self._graph._g  # noqa: SLF001 — intentional friend access
        for ancestor in underlying.predecessors(node_id):
            payload = underlying.nodes[ancestor].get("data")
            if isinstance(payload, (DataNode, DataFieldNode)):
                return True
        # Also walk one more hop; FieldOf edges chain field→data→call.
        for predecessor in underlying.predecessors(node_id):
            for grand_ancestor in underlying.predecessors(predecessor):
                payload = underlying.nodes[grand_ancestor].get("data")
                if isinstance(payload, (DataNode, DataFieldNode)):
                    return True
        return False

    def _append_denial_event(
        self,
        *,
        denied_event_id: str,
        denial_reason: str,
        timestamp: datetime,
        counterfactual_targets: tuple[str, ...],
        provenance_node_id: str,
    ) -> str:
        """
        Append a DENIAL_EVENT to the wired ledger.

        Algorithm agility: the signing algorithm comes from
        ``self._provenance`` (which holds a CryptoProvenance whose
        SignatureKeyPair carries the ``algorithm`` field). Nothing in
        this method names ECDSA, ML-DSA, or any concrete primitive —
        flipping ``CryptoProvenance(signing_key=..., signing_provider=...)``
        at construction is the single switch.
        """
        assert self._ledger is not None and self._provenance is not None
        proposed = ProposedEvent(
            event_kind=EventKind.DENIAL_EVENT.value,
            actor_entity_id=self._actor_entity_id,
            target_entity_id=denied_event_id,
            payload={
                "denied_event_id": denied_event_id,
                "denial_reason": denial_reason,
                "counterfactual_targets": list(counterfactual_targets),
                "provenance_node_id": provenance_node_id,
            },
            proposed_at=timestamp,
        )
        event = self._ledger.append_proposed(
            proposed, provenance=self._provenance
        )
        return event.event_id


# ---- helpers ---------------------------------------------------------


def _digest(value: Mapping[str, Any]) -> str:
    """Stable hex digest for arguments / payload provenance."""
    return canonical_sha256(dict(value))
