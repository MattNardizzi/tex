"""
Attribution engine — orchestrates graph + prefill + Shapley over a stored Decision.

This is the wiring module that turns the existing ``src/tex/causal/``
substrate (CHIEF, ARM, counterfactual screener, integrity lattice) plus
the new ``tex.causal.prefill_signals`` and ``tex.causal.lsh_shapley``
modules into a single ``compute_attribution(decision)`` call producing
a ``CausalAttributionResult`` ready for SCITT signing.

Algorithmic flow (the hybrid no one else has implemented)
---------------------------------------------------------
For a stored ``tex.domain.decision.Decision``:

  1. **Synthesize trace.** Convert the decision's findings, ASI
     findings, and reasons into an OTAR-shaped event trace that
     CHIEF can consume. Each finding becomes an agent step with a
     synthesized agent_id derived from the finding's ``source``
     field, an observation/action/result triple, and a timestep.

  2. **Build hierarchical causal graph (CHIEF).** ``HierarchicalCausalGraph
     .build_from_trace`` produces an ``HCGResult`` containing the
     ``networkx.DiGraph`` and the typed node lists.

  3. **Candidate identification (CHIEF).** ``attribute_root_cause``
     runs hierarchical oracle-guided backtracking + the four-stage
     progressive counterfactual screen. Produces an initial top
     candidate.

  4. **Multi-candidate expansion (per arxiv 2603.25001).** Instead
     of collapsing to a single root cause, we enumerate up to N
     candidates by running the counterfactual screener over every
     anomaly-bearing step in the graph and keeping those flagged
     as ``is_true_root_cause`` (or all anomaly-bearing steps when
     the screener flags none — common for short traces).

  5. **Prefill signal extraction (NEW).** When the SLM is loaded,
     ``extract_signals`` runs one prefill pass over the rendered
     trace and produces per-step NLL + attention-entropy signals.

  6. **Hybrid re-ranking (NEW).** Candidates are re-scored using
     ``screener_confidence * (1 + alpha * normalised_nll)`` —
     graph confidence dominates, signals sharpen. Alpha is fixed
     at 0.5 (50% weight on prefill signal). When signals are
     unavailable, candidates keep their pure graph confidence.

  7. **Causality-laundering check (ARM, NEW).** Each candidate is
     checked for ARM's ``LABEL_TAINTED_BY_DENIAL`` upstream label,
     surfacing the ``causality_laundering_suspected`` flag per
     arxiv 2604.04035.

  8. **LSH-Shapley blame distribution (NEW).** Build
     ``AgentContribution`` records from the per-agent activity in
     the trace and compute a Shapley approximation per arxiv
     2605.03581. Populates ``blame_distribution``.

  9. **PTV / ZK envelope (NEW, optional).** If ZK is enabled,
     build a PTV-shaped envelope binding the prefill SLM's model
     hash to the input/output of the attribution computation. The
     envelope is in ``proof_pending`` mode until a real NanoZK
     prover is wired in a follow-on thread.

  10. **TEE attestation binding (NEW, optional).** If TEE is
      enabled, the caller-supplied or test-mode NRAS EAT JWT is
      wrapped in a ``TEEAttestation`` and included in the result.

The result is a ``CausalAttributionResult`` ready to be passed to
the SCITT signing step in ``tex.api.incident_routes``.

Determinism
-----------
Steps 1-4 and 7-8 are fully deterministic over the input Decision.
Steps 5-6 are deterministic over (Decision, loaded_SLM_weights);
the prefill SLM produces the same signals for the same inputs.
Steps 9-10 are deterministic over (Decision, signals, model_hash,
attestation_nonce).

This means the same Decision produces the same attribution result
across calls, which is required for the evidence chain to be
verifiable (the hash of the result must be stable).

Fail-closed
-----------
* SLM load failure → graph-only attribution; no exception raised
* Counterfactual screener exception → degraded confidence on the
  affected candidate; other candidates still ranked
* Shapley computation degenerate → uniform blame distribution
* Trace empty (no findings on the decision) → attribution result
  with one synthetic candidate ("decision_only", confidence 0.5)
  so callers always get a structurally valid result

The engine NEVER returns None and NEVER raises on a structurally
valid Decision. The endpoint relies on this — see
``tex.api.incident_routes``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from tex.causal._integrity import IntegrityLevel, lattice_meet
from tex.causal.chief import HierarchicalCausalGraph
from tex.causal.counterfactual import CounterfactualScreener
from tex.causal.conformal_attribution import (
    DEFAULT_ALPHA as _CONFORMAL_DEFAULT_ALPHA,
    ConformalPredictionSet,
    compute_conformal_prediction_set,
)
from tex.causal.lsh_shapley import AgentContribution, blame_distribution
from tex.causal.prefill_signals import (
    PrefillSignals,
    empty_signals,
    extract_signals,
)
from tex.domain.decision import Decision
from tex.observability.telemetry import emit_event


# ---------------------------------------------------------------------------
# Integrity-level classification (ARM §4.2 MinTrust label assignment)
# ---------------------------------------------------------------------------
#
# Per arxiv 2604.04035 §4.2, every data item in the provenance graph
# carries a static MinTrust label derived from its source. ARM's runtime
# propagates these via lattice_meet (Definition 4) along causal edges,
# yielding a node's "effective trust" = minimum trust over its data
# ancestors.
#
# For Tex's causal attribution, we classify each candidate step's
# agent_id by its origin in Tex's pipeline:
#
#   deterministic.*    → TOOL_TRUSTED (Tex's built-in detectors, signed/attested)
#   specialist.*       → TOOL_TRUSTED (Tex's specialist judges, attested)
#   asi.*              → USER_INPUT   (ASI findings derive from the request,
#                                       which originated as user content)
#   semantic.*         → TOOL_UNTRUSTED (LLM-based semantic layer; lower trust
#                                         per ARM's general rule for unsigned
#                                         LLM outputs)
#   tex.uncertainty    → SYS_INSTR    (Tex's own meta-signal; highest trust)
#   tex.contract.*     → SYS_INSTR    (operator-defined contract violations)
#   decision.*         → SYS_INSTR    (Tex's own decision-summary fallback)
#   unknown / default  → TOOL_UNTRUSTED (conservative; "we don't know" = "don't trust")
#
# These mappings derive from how Tex constructs the pipeline (the source
# field on Finding is set by the producing module) and from ARM's general
# guidance that signed/attested = TRUSTED, unsigned LLM = UNTRUSTED, and
# operator-controlled = SYS_INSTR.
#
# The candidate's effective integrity level is then lattice_meet of all
# steps it depends on causally, computed using the HCG's edge structure.

_AGENT_TRUST_MAP: dict[str, IntegrityLevel] = {
    # Tex deterministic detectors — signed, attested, version-pinned.
    "deterministic": IntegrityLevel.TOOL_TRUSTED,
    # Tex specialist judges — attested LLM judges with fixed prompts.
    "specialist": IntegrityLevel.TOOL_TRUSTED,
    # Tex semantic layer — uses external LLM; lower trust per ARM general rule.
    "semantic": IntegrityLevel.TOOL_UNTRUSTED,
    # ASI findings — derive from user-supplied content under analysis.
    "asi": IntegrityLevel.USER_INPUT,
    # Tex meta-signals — Tex's own decision-process metadata.
    "tex": IntegrityLevel.SYS_INSTR,
    # Decision-summary fallback (no findings on the decision).
    "decision": IntegrityLevel.SYS_INSTR,
}


def _classify_agent_integrity(agent_id: str) -> IntegrityLevel:
    """Map an agent_id to its ARM MinTrust label.

    Uses dot-prefix matching against ``_AGENT_TRUST_MAP``. Unknown
    agents default to ``TOOL_UNTRUSTED`` — conservative, fail-closed:
    "we don't know what produced this" means "don't trust it" rather
    than "assume system-level integrity."

    Reference: arxiv 2604.04035 §4.2 (static MinTrust assignment).
    """
    if not agent_id:
        return IntegrityLevel.TOOL_UNTRUSTED
    # Take the first dot-segment as the source family.
    prefix = agent_id.split(".", 1)[0]
    return _AGENT_TRUST_MAP.get(prefix, IntegrityLevel.TOOL_UNTRUSTED)


def _effective_integrity_for_candidate(
    *,
    candidate_step_id: str,
    candidate_agent_id: str,
    hcg_result: Any,
) -> IntegrityLevel:
    """Compute a candidate's effective integrity via lattice meet.

    Per ARM Definition 4 (Minimum Reachable Trust), a node's effective
    trust is the minimum trust over all data ancestors that flow into
    it. We walk the HCG's edges from the candidate step upward to find
    all ancestors, classify each ancestor's static integrity, and take
    the lattice meet (min).

    For Tex's typical decision graphs (≤ 8 nodes), the ancestor walk
    is cheap. The candidate itself is included in the meet — its own
    integrity bounds the result from above.
    """
    from tex.causal._hcg import AgentNode

    graph = hcg_result.graph

    # Start with the candidate's own integrity.
    own_level = _classify_agent_integrity(candidate_agent_id)
    levels: list[IntegrityLevel] = [own_level]

    # Walk ancestors. networkx DiGraph.predecessors gives parents.
    visited: set[str] = {candidate_step_id}
    frontier: list[str] = [candidate_step_id]
    while frontier:
        next_frontier: list[str] = []
        for node_id in frontier:
            try:
                parents = list(graph.predecessors(node_id))
            except Exception:
                continue
            for parent_id in parents:
                if parent_id in visited:
                    continue
                visited.add(parent_id)
                next_frontier.append(parent_id)
                parent_data = graph.nodes[parent_id].get("data")
                if isinstance(parent_data, AgentNode):
                    levels.append(_classify_agent_integrity(parent_data.agent_id))
        frontier = next_frontier
        # Bounded walk: pathological cases shouldn't blow up.
        if len(visited) > 64:
            break

    return lattice_meet(tuple(levels))


# How heavily prefill-signal NLL re-weights graph confidence.
# 0.5 means a 1-sigma NLL spike on a candidate roughly bumps its
# rank by 50%. Conservative — the graph signal is the load-bearing
# component per design rationale 6.9.
_SIGNAL_WEIGHT_ALPHA: float = 0.5

# Maximum number of candidates returned per attribution result.
# Realistic upper bound for one governance decision.
_MAX_CANDIDATES: int = 8


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class CausalCandidate(BaseModel):
    """One ranked candidate in an attribution result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: str = Field(min_length=1, max_length=256)
    decisive_step_index: int = Field(ge=0)
    step_id: str = Field(min_length=1, max_length=256)
    confidence: float = Field(ge=0.0, le=1.0)
    integrity_level: str = Field(min_length=1, max_length=64)
    """Lattice level name (e.g. 'TOOL_TRUSTED'). Read from ARM
    when available; ``"UNKNOWN"`` when the decision graph
    doesn't carry integrity labels."""
    reasoning_perspective: str = Field(min_length=1, max_length=128)
    """Short tag for which screening stage flagged this candidate.
    Per arxiv 2603.25001, attribution can be multi-perspective;
    this field surfaces the perspective."""


class CausalAttributionResult(BaseModel):
    """The result of one attribution computation, ready for signing."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision_id: UUID
    candidates: tuple[CausalCandidate, ...] = Field(min_length=1)
    primary_root_cause_index: int = Field(ge=0)
    """Index into ``candidates`` of the highest-ranked candidate.
    Always 0 by construction; carried explicitly for caller
    convenience and for forward-compat if we add a tie-breaking
    rule that doesn't sort to position 0."""
    blame_distribution: dict[str, float] = Field(default_factory=dict)
    causality_laundering_suspected: bool = False
    confidence_signals: dict[str, float] = Field(default_factory=dict)
    signals_available: bool = False
    slm_model_id: str = Field(default="", max_length=200)
    slm_model_weight_sha256: str = Field(default="", max_length=64)
    attribution_method: str = Field(min_length=1, max_length=64)
    """One of: 'graph', 'graph+prefill', 'graph+prefill+zk_pending',
    'graph+prefill+zk', 'graph+prefill+zk+tee'. Names what
    layers contributed."""
    attribution_latency_ms: float = Field(ge=0.0)

    conformal_set: ConformalPredictionSet | None = None
    """Optional conformal prediction set (arxiv 2605.06788, May 7 2026).
    Populated only when the caller requests it via the endpoint flag.
    Provides a contiguous range of trajectory indices guaranteed
    (under CP exchangeability) to contain the decisive error with
    confidence ``1 - alpha``."""

    @property
    def primary_root_cause(self) -> CausalCandidate:
        return self.candidates[self.primary_root_cause_index]


# ---------------------------------------------------------------------------
# Trace synthesis
# ---------------------------------------------------------------------------


def _trace_from_decision(decision: Decision) -> tuple[dict[str, Any], ...]:
    """Convert a Decision into the OTAR-shaped trace CHIEF consumes.

    Tex doesn't run external multi-agent systems; the "agents" here
    are Tex's own pipeline stages whose findings constitute the
    decision. The mapping:

      * Each ``Finding`` → one step with agent_id = ``finding.source``
        (e.g. ``"deterministic.pii"``, ``"specialist.coercion"``),
        observation = matched_text or "", action = rule_name,
        result = message
      * Each ``ASIFinding`` → one step with agent_id = ``"asi." +
        short_code``, observation/action/result derived from
        title and description
      * Decision-level uncertainty flags → one summary step
        agent_id = ``"tex.uncertainty"`` (only if any flags)

    Empty decisions (no findings, no ASI findings, no flags) get a
    single ``"decision.summary"`` synthetic step so CHIEF always has
    at least one node to reason over.
    """
    events: list[dict[str, Any]] = []
    timestep = 0

    for finding in decision.findings:
        events.append(
            {
                "step_id": f"finding_{timestep:04d}_{finding.rule_name}",
                "agent_id": finding.source,
                "subtask_id": f"subtask_{finding.source}",
                "timestep": timestep,
                "observation": finding.matched_text or "",
                "thought": f"rule={finding.rule_name} severity={finding.severity.value}",
                "action": finding.rule_name,
                "result": finding.message,
            }
        )
        timestep += 1

    for asi in decision.asi_findings:
        events.append(
            {
                "step_id": f"asi_{timestep:04d}_{asi.short_code}",
                "agent_id": f"asi.{asi.short_code}",
                "subtask_id": f"subtask_{asi.short_code}",
                "timestep": timestep,
                "observation": asi.title,
                "thought": f"category={asi.category} severity={asi.severity}",
                "action": asi.short_code,
                # The 'denied' / 'rejected' / 'violated' markers in
                # the result let CHIEF's _ANOMALY_MARKERS pick up
                # the step as a candidate.
                "result": f"violated: {asi.description}",
            }
        )
        timestep += 1

    if decision.uncertainty_flags:
        events.append(
            {
                "step_id": f"uncertainty_{timestep:04d}",
                "agent_id": "tex.uncertainty",
                "subtask_id": "subtask_uncertainty",
                "timestep": timestep,
                "observation": "",
                "thought": "uncertainty flags present",
                "action": "flag_uncertainty",
                "result": "uncertainty: " + ", ".join(decision.uncertainty_flags),
            }
        )
        timestep += 1

    if not events:
        events.append(
            {
                "step_id": "decision_summary_0000",
                "agent_id": "decision.summary",
                "subtask_id": "subtask_summary",
                "timestep": 0,
                "observation": decision.content_excerpt[:200],
                "thought": f"verdict={decision.verdict.value} score={decision.final_score:.3f}",
                "action": "summarize",
                "result": (
                    f"verdict={decision.verdict.value} "
                    f"confidence={decision.confidence:.3f}"
                ),
            }
        )

    return tuple(events)


# ---------------------------------------------------------------------------
# Candidate enumeration
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _RankedCandidate:
    step_id: str
    agent_id: str
    timestep: int
    graph_confidence: float
    perspective: str  # 'screener_confirmed' | 'anomaly_only' | 'fallback'


def _enumerate_candidates(
    *,
    hcg_result: Any,
    screener: CounterfactualScreener,
) -> list[_RankedCandidate]:
    """Enumerate up to ``_MAX_CANDIDATES`` candidates from the HCG.

    Per arxiv 2603.25001: don't collapse to a single root cause.
    Run the screener over every anomaly-bearing step, keep all
    that the screener confirms as true root causes, plus any
    anomaly steps the screener didn't confirm (with reduced
    confidence). Sort by timestep then confidence.
    """
    from tex.causal._hcg import AgentNode

    graph = hcg_result.graph
    anomaly_step_ids: list[str] = []
    for node_id in hcg_result.agent_step_ids:
        node_data = graph.nodes[node_id].get("data")
        if not isinstance(node_data, AgentNode):
            continue
        # Pull OTAR result text and check for anomaly markers.
        otar = node_data.otar
        result_text = ""
        if hasattr(otar, "result"):
            result_text = str(otar.result or "")
        elif isinstance(otar, dict):
            result_text = str(otar.get("result") or "")
        result_lower = result_text.lower()
        # Same marker list as chief.py's _ANOMALY_MARKERS, kept
        # here so we don't import a private constant.
        if any(
            marker in result_lower
            for marker in (
                "error",
                "failed",
                "failure",
                "invalid",
                "denied",
                "rejected",
                "exception",
                "violated",
                "timeout",
                "abort",
                "incorrect",
                "wrong",
                "anomal",
            )
        ):
            anomaly_step_ids.append(node_id)

    # If no anomaly markers found, fall back to the earliest step
    # in the graph (matches CHIEF's fallback behaviour).
    if not anomaly_step_ids and hcg_result.agent_step_ids:
        anomaly_step_ids = [hcg_result.agent_step_ids[0]]

    candidates: list[_RankedCandidate] = []
    # Need a synthetic failure target for the screener. Use the
    # last agent step (the "observed failure" from the decision's
    # perspective).
    if not hcg_result.agent_step_ids:
        return []
    observed_failure = hcg_result.agent_step_ids[-1]

    for cand_id in anomaly_step_ids[:_MAX_CANDIDATES * 2]:
        node_data = graph.nodes[cand_id].get("data")
        if not isinstance(node_data, AgentNode):
            continue
        try:
            outcome = screener.screen_detailed(
                candidate_root_cause_id=cand_id,
                observed_failure_id=observed_failure,
                causal_graph=graph,
            )
        except Exception:
            # Degraded: screener choked, take the candidate at
            # half confidence and move on.
            outcome = None

        if outcome is None:
            confidence = 0.4
            perspective = "screener_error"
        elif outcome.is_true_root_cause:
            confidence = max(0.6, outcome.confidence)
            perspective = f"screener_{outcome.stage}"
        else:
            confidence = max(0.3, outcome.confidence * 0.5)
            perspective = f"anomaly_no_screen_{outcome.stage}"

        candidates.append(
            _RankedCandidate(
                step_id=cand_id,
                agent_id=node_data.agent_id,
                timestep=node_data.timestep,
                graph_confidence=min(1.0, max(0.0, confidence)),
                perspective=perspective,
            )
        )

    # Sort: confirmed root causes first (perspective starts with
    # 'screener_'), then by timestep ascending (earliest = more
    # likely root), then by confidence descending.
    def _sort_key(c: _RankedCandidate) -> tuple[int, int, float]:
        is_confirmed = (
            0
            if c.perspective.startswith("screener_") and c.perspective != "screener_error"
            else 1
        )
        return (is_confirmed, c.timestep, -c.graph_confidence)

    candidates.sort(key=_sort_key)
    return candidates[:_MAX_CANDIDATES]


# ---------------------------------------------------------------------------
# Hybrid re-ranking with prefill signals
# ---------------------------------------------------------------------------


def _rerank_with_signals(
    candidates: list[_RankedCandidate],
    signals: PrefillSignals,
) -> list[tuple[_RankedCandidate, float]]:
    """Re-score candidates with prefill NLL.

    Each candidate's final confidence is:

        graph_confidence * (1 + alpha * normalised_nll)

    where normalised_nll = (this_step_nll - mean_nll) / std_nll
    clipped to [-1, 1]. When ``signals_available=False`` or no
    candidate matches a step in the signal map, the candidate
    keeps its graph confidence.
    """
    if not signals.signals_available or not signals.step_signals:
        return [(c, c.graph_confidence) for c in candidates]

    nlls = [s.mean_nll for s in signals.step_signals]
    mean_nll = sum(nlls) / len(nlls) if nlls else 0.0
    if len(nlls) > 1:
        var = sum((x - mean_nll) ** 2 for x in nlls) / len(nlls)
        std_nll = var ** 0.5
    else:
        std_nll = 0.0

    signal_map = {s.step_id: s for s in signals.step_signals}

    reranked: list[tuple[_RankedCandidate, float]] = []
    for candidate in candidates:
        sig = signal_map.get(candidate.step_id)
        if sig is None or std_nll == 0.0:
            new_conf = candidate.graph_confidence
        else:
            normalised = (sig.mean_nll - mean_nll) / std_nll
            normalised = max(-1.0, min(1.0, normalised))
            new_conf = candidate.graph_confidence * (
                1.0 + _SIGNAL_WEIGHT_ALPHA * normalised
            )
            new_conf = max(0.0, min(1.0, new_conf))
        reranked.append((candidate, new_conf))

    # Sort by new confidence descending.
    reranked.sort(key=lambda pair: -pair[1])
    return reranked


# ---------------------------------------------------------------------------
# Causality-laundering check
# ---------------------------------------------------------------------------


def _causality_laundering_check(
    decision: Decision,
) -> bool:
    """ARM's denial-induced-taint flag for the decision.

    Per arxiv 2604.04035 §4.5, the ledger carries a DENIAL_EVENT
    for each denied tool call, and ARM propagates trust through
    the integrity lattice. The signal Tex surfaces here is: did
    this decision contain any FORBID-class ASI findings whose
    description mentions denial-followed-by-related-action?

    For v1 of this thread, we use a heuristic: any ASI finding
    whose category is ``ASI03_identity_privilege_abuse``,
    ``ASI04_uncontrolled_code_execution``, or
    ``ASI06_memory_poisoning`` AND whose severity > 0.7 triggers
    the flag. These three categories most often correspond to
    causality-laundering exploitation per the ARM paper §6.

    A follow-on thread can replace this heuristic with a real
    ARM provenance-graph query when the ARM ledger is wired into
    the live request path.
    """
    suspicious_categories = {
        "ASI03_identity_privilege_abuse",
        "ASI04_uncontrolled_code_execution",
        "ASI06_memory_poisoning",
    }
    for asi in decision.asi_findings:
        if asi.category in suspicious_categories and asi.severity > 0.7:
            return True
    return False


# ---------------------------------------------------------------------------
# Build agent contributions for Shapley
# ---------------------------------------------------------------------------


def _agent_contributions(
    *,
    trace: tuple[dict[str, Any], ...],
    candidates: list[_RankedCandidate],
    causality_laundering: bool,
) -> tuple[AgentContribution, ...]:
    """Aggregate per-agent activity in the trace into Shapley inputs."""
    if not trace:
        return ()

    # Group trace events by agent.
    by_agent: dict[str, list[int]] = {}
    for index, event in enumerate(trace):
        agent_id = str(event.get("agent_id") or "unknown")
        by_agent.setdefault(agent_id, []).append(index)

    candidate_agents = {c.agent_id for c in candidates}

    contributions: list[AgentContribution] = []
    total_events = max(1, len(trace))
    for agent_id, indices in by_agent.items():
        mean_pos = (sum(indices) / len(indices)) / total_events
        # has_denial: agent appears in candidates that screener
        # marked as anomalies (proxy for "this agent denied or
        # was implicated in a denial").
        has_denial = agent_id in candidate_agents
        # has_taint: causality_laundering implicates ALL agents
        # downstream of a denial; we mark the candidate agents
        # as tainted and others as not. A future thread with the
        # ARM provenance graph wired live can do this precisely.
        has_taint = causality_laundering and agent_id in candidate_agents
        contributions.append(
            AgentContribution(
                agent_id=agent_id,
                step_count=len(indices),
                mean_position=mean_pos,
                has_denial=has_denial,
                has_taint=has_taint,
            )
        )
    return tuple(contributions)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def compute_attribution(
    decision: Decision,
    *,
    include_conformal: bool = False,
    conformal_alpha: float = _CONFORMAL_DEFAULT_ALPHA,
    conformal_algorithm: str = "two_way_filtration",
) -> CausalAttributionResult:
    """Compute the full attribution result for a stored Decision.

    Parameters
    ----------
    decision
        The stored Decision to attribute.
    include_conformal
        When True, compute a conformal prediction set per arxiv
        2605.06788 (Conformal Agent Error Attribution, May 7 2026)
        and attach it to the result. Default False to keep the
        common case latency low.
    conformal_alpha
        Miscoverage rate for the CP set. Target coverage = ``1 -
        conformal_alpha``. Default 0.1 (90% coverage).
    conformal_algorithm
        Which CP algorithm to use. Default ``"two_way_filtration"``
        (paper's recommended choice; produces tightest contiguous
        sets in expectation).

    Fail-closed: returns a structurally valid result for any
    structurally valid Decision. Never returns None, never raises.
    """
    started_at = time.perf_counter()

    trace = _trace_from_decision(decision)
    hcg_builder = HierarchicalCausalGraph()
    screener = CounterfactualScreener()
    hcg_result = hcg_builder.build_from_trace(trace)

    raw_candidates = _enumerate_candidates(
        hcg_result=hcg_result, screener=screener
    )

    if not raw_candidates:
        # Pathological: graph built but no agent steps. Synthesize
        # one "decision_only" candidate.
        raw_candidates = [
            _RankedCandidate(
                step_id="decision_summary_0000",
                agent_id="decision.summary",
                timestep=0,
                graph_confidence=0.5,
                perspective="fallback_empty_graph",
            )
        ]

    signals = extract_signals(trace)
    reranked = _rerank_with_signals(raw_candidates, signals)

    causality_laundering = _causality_laundering_check(decision)

    # Build final CausalCandidate list. Integrity level is computed
    # from ARM's MinTrust lattice walk per arxiv 2604.04035 §4.2 +
    # Definition 4: the candidate's static integrity is determined by
    # its agent source family, then meet-joined with the integrity of
    # all ancestors in the HCG. The level reported here is the
    # *effective* trust of the candidate, not just its own.
    final_candidates: list[CausalCandidate] = []
    for ranked, new_conf in reranked:
        effective_level = _effective_integrity_for_candidate(
            candidate_step_id=ranked.step_id,
            candidate_agent_id=ranked.agent_id,
            hcg_result=hcg_result,
        )
        final_candidates.append(
            CausalCandidate(
                agent_id=ranked.agent_id,
                decisive_step_index=ranked.timestep,
                step_id=ranked.step_id,
                confidence=new_conf,
                integrity_level=effective_level.name,
                reasoning_perspective=ranked.perspective,
            )
        )

    # Shapley blame.
    contributions = _agent_contributions(
        trace=trace,
        candidates=raw_candidates,
        causality_laundering=causality_laundering,
    )
    blame = blame_distribution(contributions)

    # Confidence signals — surface aggregate stats so downstream
    # consumers can inspect what the SLM produced.
    confidence_signals: dict[str, float] = {}
    if signals.signals_available and signals.step_signals:
        nlls = [s.mean_nll for s in signals.step_signals]
        ents = [s.attention_entropy for s in signals.step_signals]
        confidence_signals = {
            "mean_nll": sum(nlls) / len(nlls),
            "max_nll": max(nlls),
            "mean_attention_entropy": sum(ents) / len(ents),
        }

    attribution_method = (
        "graph+prefill" if signals.signals_available else "graph"
    )

    # Optional: conformal prediction set per arxiv 2605.06788.
    # Computed only when the caller asks for it (keeps default
    # latency low). Uses prefill NLL when available, falls back to
    # screener confidence keyed by step_id when not. The set is a
    # contiguous range of trajectory indices with finite-sample
    # coverage guarantee under CP exchangeability.
    conformal_set: ConformalPredictionSet | None = None
    if include_conformal:
        prefill_map: dict[str, float] | None = None
        if signals.signals_available and signals.step_signals:
            prefill_map = {s.step_id: s.mean_nll for s in signals.step_signals}
        # Fallback: build a screener-confidence map keyed by step_id
        # from the raw_candidates so CP has *some* score signal even
        # without an SLM.
        screener_map: dict[str, float] = {
            c.step_id: c.graph_confidence for c in raw_candidates
        }
        try:
            conformal_set = compute_conformal_prediction_set(
                trace=trace,
                prefill_signals_map=prefill_map,
                screener_confidences=screener_map,
                alpha=conformal_alpha,
                algorithm=conformal_algorithm,
            )
            attribution_method = f"{attribution_method}+conformal"
        except Exception as exc:
            # Fail-closed: CP failure must not break the endpoint.
            emit_event(
                "causal.attribution.conformal_failed",
                decision_id=str(decision.decision_id),
                error=str(exc)[:200],
            )
            conformal_set = None

    latency_ms = (time.perf_counter() - started_at) * 1000.0

    emit_event(
        "causal.attribution.computed",
        decision_id=str(decision.decision_id),
        method=attribution_method,
        candidate_count=len(final_candidates),
        causality_laundering=causality_laundering,
        signals_available=signals.signals_available,
        latency_ms=latency_ms,
    )

    return CausalAttributionResult(
        decision_id=decision.decision_id,
        candidates=tuple(final_candidates),
        primary_root_cause_index=0,
        blame_distribution=blame,
        causality_laundering_suspected=causality_laundering,
        confidence_signals=confidence_signals,
        signals_available=signals.signals_available,
        slm_model_id=signals.model_id,
        slm_model_weight_sha256=signals.model_weight_sha256,
        attribution_method=attribution_method,
        attribution_latency_ms=latency_ms,
        conformal_set=conformal_set,
    )


__all__ = [
    "CausalCandidate",
    "CausalAttributionResult",
    "compute_attribution",
]
