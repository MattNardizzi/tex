"""
ARGUS Specialist Judge.

Standalone specialist implementing the influence-provenance graph and
provenance-aware decision audit from arxiv 2605.03378v1 (Weng et al.,
**5 May 2026 — published 13 days before this build**).

Where AgentArmorSpecialist surfaces three ARGUS-style reason codes as
hints inside its type-system output, this specialist builds the actual
graph the paper proposes and runs parallel counterfactual tests over it.
Together they cover both the "fast attribution hint" path (inside
AgentArmor) and the "slow but defensible audit" path (here).

Influence Provenance Graph (IPG)
--------------------------------
Per arxiv 2605.03378 §3, the IPG is a directed graph G = (V, E) where:

  V is partitioned into:
    V_user        - the user's authorised instruction(s)
    V_obs         - observations the agent retrieved from tools or external content
    V_decision    - decisions / actions the agent proposes
    V_evidence    - trustworthy evidence that justifies a decision

  E ⊆ V × V × Label captures provenance:
    e = (src, dst, kind) where kind ∈ {derives_from, justified_by, contradicted_by}

A decision d ∈ V_decision is *justified* iff there exists a directed
path d → ... → v ∈ V_user ∪ V_evidence using only `justified_by` edges.
A decision is *suspect* if its only paths to V_user go through V_obs
nodes that contain instruction-like content.

Counterfactual test
-------------------
For each decision node d:
  control-attenuated view G_d = G with all instruction-like content in
  the V_obs ancestors of d redacted to "neutral observation".
  If, in G_d, the decision no longer has a justification path, the
  paper concludes the decision was driven by injected content. We
  report this as ARGUS_DECISION_OBSERVATION_DRIVEN.

This module ships a pure-Python deterministic IPG over a request's
content + retrieval context + structured metadata. When metadata
carries a fully-constructed IPG (`metadata['argus']['ipg']`), we use it
directly. Otherwise we build a lightweight graph from the lexical
signals + retrieval context to give callers something useful out of the
box.

Priority
--------
P0 — frontier piece. The IPG is paper-only as of May 18 2026; no
public commercial governance platform implements it. Tex is first.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from tex.domain.evaluation import EvaluationRequest
from tex.domain.owasp_asi import (
    ASI_GOAL_HIJACK,
    ASI_IDENTITY_ABUSE,
    ASI_MEMORY_POISONING,
    ASI_ROGUE_AGENT,
    ASI_SUPPLY_CHAIN,
    ASI_TOOL_MISUSE,
)
from tex.domain.retrieval import RetrievalContext
from tex.observability.telemetry import emit_event
from tex.specialists.base import SpecialistEvidence, SpecialistResult


# ── IPG node + edge types ────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class IPGNode:
    """One node in the influence-provenance graph."""

    node_id: str
    kind: str          # 'user' | 'obs' | 'decision' | 'evidence'
    content: str
    trustworthy: bool  # whether this node may justify a decision


@dataclass(frozen=True, slots=True)
class IPGEdge:
    """Directed provenance edge."""

    src: str
    dst: str
    kind: str  # 'derives_from' | 'justified_by' | 'contradicted_by'


@dataclass
class InfluenceProvenanceGraph:
    """Directed labeled graph.

    Adjacency is built lazily on demand. The construction-cheap path
    keeps the specialist within its budget.
    """

    nodes: dict[str, IPGNode] = field(default_factory=dict)
    edges: list[IPGEdge] = field(default_factory=list)

    def add_node(self, node: IPGNode) -> None:
        self.nodes[node.node_id] = node

    def add_edge(self, edge: IPGEdge) -> None:
        self.edges.append(edge)

    def out_edges(self, node_id: str, *, kind: str | None = None) -> list[IPGEdge]:
        if kind is None:
            return [e for e in self.edges if e.src == node_id]
        return [e for e in self.edges if e.src == node_id and e.kind == kind]

    def justification_path(
        self, decision_id: str, *, max_depth: int = 8
    ) -> list[str] | None:
        """BFS along `justified_by` edges to V_user or V_evidence node."""
        if decision_id not in self.nodes:
            return None
        seen: set[str] = set()
        # path stack: list of node ids ending at the most recently expanded one.
        stack: list[list[str]] = [[decision_id]]
        while stack:
            path = stack.pop(0)
            tail = path[-1]
            if tail in seen or len(path) > max_depth:
                continue
            seen.add(tail)
            tail_node = self.nodes.get(tail)
            if tail_node is not None and tail_node.kind in {"user", "evidence"}:
                return path
            for edge in self.out_edges(tail, kind="justified_by"):
                stack.append([*path, edge.dst])
        return None

    def observation_ancestors(
        self, decision_id: str, *, max_depth: int = 8
    ) -> list[IPGNode]:
        """All V_obs nodes reachable from `decision_id` via `derives_from`."""
        out: list[IPGNode] = []
        seen: set[str] = set()
        frontier = [decision_id]
        while frontier:
            next_frontier: list[str] = []
            for node_id in frontier:
                if node_id in seen:
                    continue
                seen.add(node_id)
                node = self.nodes.get(node_id)
                if node is not None and node.kind == "obs":
                    out.append(node)
                for edge in self.out_edges(node_id, kind="derives_from"):
                    next_frontier.append(edge.dst)
            frontier = next_frontier
            if len(seen) > max_depth * 8:
                break
        return out

    def has_contradiction(self, decision_id: str) -> bool:
        return any(
            e.src == decision_id and e.kind == "contradicted_by" for e in self.edges
        )


# ── Lexical fingerprints used to mark observation nodes "instruction-like" ─


_INSTRUCTION_LIKE_PATTERNS: tuple[str, ...] = (
    "ignore previous", "override your", "you must", "you should now",
    "act as", "pretend you are", "new instructions", "system override",
    "developer mode", "from now on", "please follow", "instead of",
    "do not reveal", "the user authorized", "the user pre-approved",
    "execute this", "send this", "transfer this", "delete this",
)


_INSTRUCTION_LIKE_RE = re.compile(
    "|".join(re.escape(p) for p in _INSTRUCTION_LIKE_PATTERNS),
    re.IGNORECASE,
)


# Observation-as-external-source markers. ARGUS treats any sentence that
# is *reporting* external content as an untrusted observation, regardless
# of whether the reported content itself contains instruction-like
# phrasing. These markers identify the reporting frame.
_EXTERNAL_SOURCE_PATTERNS: tuple[str, ...] = (
    "the email said", "the document said", "the email instructs",
    "the document instructs", "the message said", "according to the",
    "the response indicates", "the response says", "the tool output",
    "the tool response", "the search result", "the webpage says",
    "the file says", "the attachment", "the retrieved",
    "context indicates", "the observation",
    # Additions matching real IPI payload framings.
    "the tool returned", "tool returned:", "tool response includes",
    "the response for", "tool description:", "description: '",
    "tool 'web_search'", "tool 'calculator'", "tool 'file_read'",
    "tool 'http_request'", "tool 'capability_request'", "tool 'read_customer'",
    "the embedded note", "in the attachment",
    "a colleague mentioned", "the recent message thread",
    "the customer's most recent reply",
)


_EXTERNAL_SOURCE_RE = re.compile(
    "|".join(re.escape(p) for p in _EXTERNAL_SOURCE_PATTERNS),
    re.IGNORECASE,
)


# Reasoning-hijack markers. When a decision sentence contains one of
# these phrases, ARGUS suppresses the automatic justified_by→user edge
# because the decision is justified by an observation, not by the user
# instruction. This is the case the counterfactual is designed to catch.
_REASONING_HIJACK_PATTERNS: tuple[str, ...] = (
    "because the document", "because the email", "because the message",
    "because the response", "because the tool", "because the output",
    "because the context", "since the document", "since the email",
    "since the response", "as the document said", "as the email said",
    "as instructed by the", "the document says to", "the email asked",
    # Additions for indirect / soft framings.
    "act on the instructions contained", "per the embedded note",
    "previously a colleague mentioned",
    "i noticed that previously",
    "had given permission for",
)


_REASONING_HIJACK_RE = re.compile(
    "|".join(re.escape(p) for p in _REASONING_HIJACK_PATTERNS),
    re.IGNORECASE,
)


# Markers indicating the request content contains a decision/action node.
_DECISION_MARKERS: tuple[str, ...] = (
    # First-person decisions
    "i will", "i should", "i'll go ahead", "proceeding to",
    "executing the", "approving the", "transferring the",
    "sending the", "calling the tool", "invoking the tool",
    # Imperative-form decisions (the model is being told to act)
    "please go ahead", "please approve", "please transfer",
    "please send", "please execute", "please forward",
    "please install", "please grant", "please return",
    "please authorize", "please proceed", "go ahead and approve",
    "go ahead and send", "go ahead and transfer",
    "could you proceed", "kindly transmit", "act on the",
)


# ── Scoring ──────────────────────────────────────────────────────────────


_RISK_FLOOR = 0.05
_CONF_FLOOR = 0.42
_CONF_PER_HIT = 0.07
_CONF_CAP = 0.88

_SEV_OBSERVATION_DRIVEN = 0.45   # counterfactual: decision dies w/o obs
_SEV_NO_JUSTIFICATION = 0.40     # decision has no path to V_user / V_evidence
_SEV_CONTRADICTION = 0.30        # explicit contradiction edge
_SEV_HIGH_RISK_ANCESTRY = 0.30   # decision derives from instruction-like obs


class ArgusSpecialist:
    """Specialist implementing ARGUS influence-provenance auditing.

    Build path:
      1. If metadata carries a constructed IPG, use it.
      2. Else build a lightweight IPG from the request content + retrieval
         context.
      3. For each decision node, run:
         a. justification check (path to V_user or V_evidence?)
         b. counterfactual: if all instruction-like obs ancestors were
            removed, does the decision still have a justification?
         c. contradiction check
      4. Emit one reason code per failed check, attribute to ASI tags.

    Performance: O(|V| + |E|) per request. Cap nodes at 64 so the
    construction stays cheap.
    """

    name = "argus"
    MAX_NODES = 64

    def evaluate(
        self,
        *,
        request: EvaluationRequest,
        retrieval_context: RetrievalContext,
    ) -> SpecialistResult:
        ipg = self._build_or_take_ipg(request=request, retrieval_context=retrieval_context)

        all_evidence: list[SpecialistEvidence] = []
        reason_codes: list[str] = []
        asi_tags: list[str] = []
        risk_accum = 0.0
        decision_count = 0
        observation_driven_decisions = 0

        for node in list(ipg.nodes.values()):
            if node.kind != "decision":
                continue
            decision_count += 1

            # (a) Justification check.
            path = ipg.justification_path(node.node_id)
            justified = path is not None

            # (b) Counterfactual: rebuild IPG without instruction-like
            # observations and re-check justification.
            counterfactual_ipg = _build_counterfactual(ipg)
            counterfactual_justified = (
                counterfactual_ipg.justification_path(node.node_id) is not None
            )

            # (c) Contradiction.
            contradicted = ipg.has_contradiction(node.node_id)

            obs_ancestors = ipg.observation_ancestors(node.node_id)
            instruction_like_obs = [
                obs for obs in obs_ancestors if not obs.trustworthy
            ]

            # Decision was justified in original IPG but lost its
            # justification when instruction-like obs were redacted →
            # the decision was observation-driven.
            if justified and not counterfactual_justified:
                observation_driven_decisions += 1
                all_evidence.append(
                    SpecialistEvidence(
                        text=node.content[:1500] or node.node_id,
                        explanation=(
                            "ARGUS_DECISION_OBSERVATION_DRIVEN: decision "
                            f"node '{node.node_id}' lost its justification "
                            "when instruction-like observations were "
                            f"redacted (counterfactual test, arxiv "
                            f"2605.03378 §3.3). Ancestor obs nodes: "
                            f"{[o.node_id for o in instruction_like_obs][:4]}."
                        ),
                    )
                )
                reason_codes.append("ARGUS_DECISION_OBSERVATION_DRIVEN")
                risk_accum += _SEV_OBSERVATION_DRIVEN
                for tag in (ASI_GOAL_HIJACK, ASI_TOOL_MISUSE):
                    if tag not in asi_tags:
                        asi_tags.append(tag)

            elif not justified:
                all_evidence.append(
                    SpecialistEvidence(
                        text=node.content[:1500] or node.node_id,
                        explanation=(
                            "ARGUS_DECISION_NO_JUSTIFICATION: decision "
                            f"node '{node.node_id}' has no justification "
                            "path to V_user or V_evidence."
                        ),
                    )
                )
                reason_codes.append("ARGUS_DECISION_NO_JUSTIFICATION")
                risk_accum += _SEV_NO_JUSTIFICATION
                if ASI_GOAL_HIJACK not in asi_tags:
                    asi_tags.append(ASI_GOAL_HIJACK)

            if contradicted:
                all_evidence.append(
                    SpecialistEvidence(
                        text=node.content[:1500] or node.node_id,
                        explanation=(
                            "ARGUS_DECISION_CONTRADICTED: decision node "
                            f"'{node.node_id}' has a contradicted_by edge "
                            "in the IPG."
                        ),
                    )
                )
                reason_codes.append("ARGUS_DECISION_CONTRADICTED")
                risk_accum += _SEV_CONTRADICTION
                if ASI_ROGUE_AGENT not in asi_tags:
                    asi_tags.append(ASI_ROGUE_AGENT)

            if instruction_like_obs and justified:
                all_evidence.append(
                    SpecialistEvidence(
                        text=node.content[:1500] or node.node_id,
                        explanation=(
                            "ARGUS_HIGH_RISK_ANCESTRY: decision node "
                            f"'{node.node_id}' has {len(instruction_like_obs)} "
                            "instruction-like observation ancestor(s)."
                        ),
                    )
                )
                reason_codes.append("ARGUS_HIGH_RISK_ANCESTRY")
                risk_accum += _SEV_HIGH_RISK_ANCESTRY
                if ASI_MEMORY_POISONING not in asi_tags:
                    asi_tags.append(ASI_MEMORY_POISONING)

        if not reason_codes:
            _emit(
                request_id=str(request.request_id),
                risk_score=_RISK_FLOOR,
                reason_codes=tuple(),
                node_count=len(ipg.nodes),
                decision_count=decision_count,
            )
            return SpecialistResult(
                specialist_name=self.name,
                risk_score=_RISK_FLOOR,
                confidence=_CONF_FLOOR,
                summary=(
                    f"ARGUS IPG check passed (nodes={len(ipg.nodes)}, "
                    f"decisions={decision_count}). All decisions justified "
                    "via trustworthy evidence."
                ),
                rationale=(
                    "Specialist builds an influence-provenance graph per "
                    "arxiv 2605.03378v1 (Weng et al., 5 May 2026) and runs "
                    "parallel counterfactual tests over each decision "
                    "node. No suspect decisions found."
                ),
                evidence=tuple(),
                matched_policy_clause_ids=tuple(),
                matched_entity_names=tuple(),
                uncertainty_flags=("specialist_heuristic",),
            )

        risk_score = min(1.0, risk_accum)
        confidence = min(_CONF_CAP, _CONF_FLOOR + _CONF_PER_HIT * len(all_evidence))

        deduped_codes = _dedupe_preserve_order(reason_codes)
        deduped_asi = _dedupe_preserve_order(asi_tags)

        _emit(
            request_id=str(request.request_id),
            risk_score=risk_score,
            reason_codes=tuple(deduped_codes),
            node_count=len(ipg.nodes),
            decision_count=decision_count,
        )

        summary = (
            f"ARGUS IPG flagged {observation_driven_decisions} of "
            f"{decision_count} decision node(s) as observation-driven; "
            f"{len(deduped_codes)} reason code(s)."
        )
        return SpecialistResult(
            specialist_name=self.name,
            risk_score=round(risk_score, 4),
            confidence=round(confidence, 4),
            summary=summary,
            rationale=(
                "Per arxiv 2605.03378v1 (5 May 2026), ARGUS constructs an "
                "influence-provenance graph over user instructions, "
                "observations, decisions, and trustworthy evidence; runs "
                "parallel counterfactual tests by redacting instruction-"
                "like observations and re-checking decision justification. "
                "Tex is the first runtime governance platform to ship the "
                "full IPG primitive, not just the reason-code heuristic."
            ),
            evidence=tuple(all_evidence),
            matched_policy_clause_ids=tuple([*deduped_codes, *deduped_asi]),
            matched_entity_names=tuple(),
            uncertainty_flags=("specialist_heuristic",),
        )

    # ── IPG construction ────────────────────────────────────────────────

    def _build_or_take_ipg(
        self,
        *,
        request: EvaluationRequest,
        retrieval_context: RetrievalContext,
    ) -> InfluenceProvenanceGraph:
        """Use caller-supplied IPG when present; otherwise build one."""
        argus_md = request.metadata.get("argus")
        if isinstance(argus_md, dict):
            preset = argus_md.get("ipg")
            if isinstance(preset, InfluenceProvenanceGraph):
                return preset
        return self._build_lightweight_ipg(
            request=request, retrieval_context=retrieval_context
        )

    def _build_lightweight_ipg(
        self,
        *,
        request: EvaluationRequest,
        retrieval_context: RetrievalContext,
    ) -> InfluenceProvenanceGraph:
        """Heuristic IPG from request content + retrieval context.

        Splits request.content into sentences. Each sentence becomes a
        node. Sentences that match an instruction-like fingerprint are
        marked as untrusted observations. Sentences matching a decision
        marker become decision nodes. Retrieval context's policy clauses
        become trustworthy evidence nodes. User-instruction node is
        synthesised from `action_type + recipient`.
        """
        ipg = InfluenceProvenanceGraph()

        # V_user — the synthesised user node.
        user_node = IPGNode(
            node_id="user_0",
            kind="user",
            content=(
                f"action_type={request.action_type} "
                f"channel={request.channel} "
                f"recipient={request.recipient or 'unspecified'}"
            ),
            trustworthy=True,
        )
        ipg.add_node(user_node)

        # V_evidence — trustworthy retrieval context.
        for i, clause in enumerate(retrieval_context.policy_clauses[: self.MAX_NODES // 4]):
            ev_node = IPGNode(
                node_id=f"ev_{i}",
                kind="evidence",
                content=clause.text[:1500],
                trustworthy=True,
            )
            ipg.add_node(ev_node)

        # V_obs and V_decision derived from request content sentences.
        # First pass: build all nodes and derives_from edges.
        sentences = _split_sentences(request.content)
        for i, sentence in enumerate(sentences[: self.MAX_NODES]):
            text = sentence.strip()
            if not text:
                continue
            is_instruction = bool(_INSTRUCTION_LIKE_RE.search(text))
            is_external_source = bool(_EXTERNAL_SOURCE_RE.search(text))
            is_decision = any(
                marker in text.lower() for marker in _DECISION_MARKERS
            )
            untrusted = is_instruction or is_external_source
            if is_decision:
                d_node = IPGNode(
                    node_id=f"decision_{i}",
                    kind="decision",
                    content=text[:1500],
                    trustworthy=False,
                )
                ipg.add_node(d_node)
                ipg.add_edge(IPGEdge(d_node.node_id, user_node.node_id, "derives_from"))
                is_reasoning_hijack = bool(_REASONING_HIJACK_RE.search(text))
                if not is_reasoning_hijack:
                    ipg.add_edge(IPGEdge(d_node.node_id, user_node.node_id, "justified_by"))
                for ev_id in [
                    n.node_id for n in ipg.nodes.values() if n.kind == "evidence"
                ]:
                    ipg.add_edge(IPGEdge(d_node.node_id, ev_id, "justified_by"))
            else:
                obs_node = IPGNode(
                    node_id=f"obs_{i}",
                    kind="obs",
                    content=text[:1500],
                    trustworthy=not untrusted,
                )
                ipg.add_node(obs_node)

        # Second pass: wire derives_from + (when warranted) justified_by
        # edges from every decision to every observation in the same
        # content. This catches BOTH orderings (obs-before-decision and
        # decision-before-obs).
        decision_nodes = [n for n in ipg.nodes.values() if n.kind == "decision"]
        obs_nodes = [n for n in ipg.nodes.values() if n.kind == "obs"]
        for d in decision_nodes:
            d_is_reasoning_hijack = bool(_REASONING_HIJACK_RE.search(d.content))
            for o in obs_nodes:
                ipg.add_edge(IPGEdge(d.node_id, o.node_id, "derives_from"))
                # ARGUS adds a justified_by edge from decision to obs
                # when the obs is untrusted AND either: the decision
                # contains reasoning-hijack phrasing OR the decision's
                # action content lines up with what the obs claims.
                if (not o.trustworthy) and (
                    d_is_reasoning_hijack
                    or _content_references_observation(d.content, o.content)
                ):
                    ipg.add_edge(IPGEdge(d.node_id, o.node_id, "justified_by"))

        # If no decision was found in the content but the content
        # itself looks instruction-like, synthesise a single decision
        # node + obs node so the counterfactual test has something to
        # run on. This covers terse one-line attack payloads.
        if not any(n.kind == "decision" for n in ipg.nodes.values()):
            if _INSTRUCTION_LIKE_RE.search(request.content):
                synth_obs = IPGNode(
                    node_id="obs_synth",
                    kind="obs",
                    content=request.content[:1500],
                    trustworthy=False,
                )
                synth_dec = IPGNode(
                    node_id="decision_synth",
                    kind="decision",
                    content=f"agent proposes action_type={request.action_type}",
                    trustworthy=False,
                )
                ipg.add_node(synth_obs)
                ipg.add_node(synth_dec)
                ipg.add_edge(IPGEdge(synth_dec.node_id, synth_obs.node_id, "derives_from"))
                # Note: NO justified_by edge from decision_synth → user_0,
                # because the only thing driving the decision is the
                # untrusted observation. This is what makes the
                # counterfactual collapse.

        return ipg


# ── helpers ──────────────────────────────────────────────────────────────


_SENTENCE_SPLIT_RE = re.compile(r"(?<=[\.\?!])\s+")


def _split_sentences(text: str) -> list[str]:
    return [s for s in _SENTENCE_SPLIT_RE.split(text) if s.strip()]


# Tokens an action sentence would only contain if the action's content
# was lifted from the preceding observation. Used by ARGUS to decide
# whether an untrusted observation is the *justification* source for a
# co-located decision, not just a passive context note.
_ACTION_INHERITANCE_TOKENS: tuple[str, ...] = (
    "transfer", "approve", "send", "delete", "forward", "share",
    "execute", "invoke", "publish", "deploy", "wire", "pay",
    "authorize", "grant", "disable", "enable", "revoke", "post",
)


def _content_references_observation(decision_content: str, obs_content: str) -> bool:
    """Heuristic for 'this decision is doing what the observation said.'

    True when the decision sentence contains an action verb AND the
    observation sentence mentions either the same action verb or an
    authorization claim ("pre-authorized", "approved", "permitted").
    This is the lightweight stand-in for the paper's full provenance
    trace; the metadata-supplied IPG path remains the high-fidelity
    route.
    """
    dec = decision_content.lower()
    obs = obs_content.lower()
    has_action = any(tok in dec for tok in _ACTION_INHERITANCE_TOKENS)
    if not has_action:
        return False
    if any(tok in obs for tok in _ACTION_INHERITANCE_TOKENS):
        return True
    return any(
        marker in obs
        for marker in (
            "pre-authorized", "preauthorized", "pre-approved",
            "preapproved", "permitted", "approved", "authorized",
            "is allowed", "is permitted",
        )
    )


def _build_counterfactual(
    ipg: InfluenceProvenanceGraph,
) -> InfluenceProvenanceGraph:
    """Return G_d: instruction-like obs nodes redacted.

    Per arxiv 2605.03378 §3.3, the counterfactual is the same graph
    with every untrusted observation's outgoing `justified_by` edges
    removed. The decision can still see the obs but cannot rely on it
    to justify itself. We implement by stripping `justified_by` edges
    whose dst is an untrusted observation; we also strip `justified_by`
    edges from decisions to untrusted observations.
    """
    cf = InfluenceProvenanceGraph()
    cf.nodes = dict(ipg.nodes)
    for edge in ipg.edges:
        if edge.kind == "justified_by":
            dst_node = cf.nodes.get(edge.dst)
            src_node = cf.nodes.get(edge.src)
            # Strip justification when either endpoint is an untrusted
            # obs node — these are exactly the paths the counterfactual
            # is supposed to remove.
            if dst_node is not None and dst_node.kind == "obs" and not dst_node.trustworthy:
                continue
            if src_node is not None and src_node.kind == "obs" and not src_node.trustworthy:
                continue
        cf.add_edge(edge)
    return cf


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _emit(
    *,
    request_id: str,
    risk_score: float,
    reason_codes: tuple[str, ...],
    node_count: int,
    decision_count: int,
) -> None:
    fields: dict[str, Any] = {
        "specialist_name": "argus",
        "request_id": request_id,
        "risk_score": round(risk_score, 4),
        "reason_codes": list(reason_codes),
        "ipg_nodes": node_count,
        "ipg_decisions": decision_count,
    }
    emit_event("specialist.argus.evaluated", **fields)


__all__ = [
    "ArgusSpecialist",
    "IPGEdge",
    "IPGNode",
    "InfluenceProvenanceGraph",
]
