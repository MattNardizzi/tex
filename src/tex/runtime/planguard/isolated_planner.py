"""
Isolated Planner.

Runs in a context where ONLY the user instruction is visible. Tool outputs
are masked. The planner emits a reference plan; the agent's actual plan is
later checked for consistency against this reference.

Implementation
--------------
Per arxiv 2604.10134 §IV-B, the planner P is a function P(I, T) -> S_ref
where I is the user instruction, T is the tool set, and S_ref is a set of
zero or more actions a_i = (t_k, v_k). The planner is architecturally
isolated from external retrieved content, so any S_ref it produces is
mathematically uncontaminated by adversarial payloads (paper Eq. 6).

Two backends are supported:
  - LLMPlannerCallable: paper-faithful path. Inject a real LLM (DeepSeek-V3.2
    in the paper's evaluation). The callable receives only (instruction,
    tool_catalog) and must return a list of (tool_name, params) pairs.
  - DeterministicPlanner: training-free, offline default. Walks the tool
    catalog and matches verbs/nouns from the instruction against tool
    descriptions. Used for tests and as a safe fallback when no LLM is
    configured. Necessarily over-permissive on edge cases — the Intent
    Verifier (Stage II) is what catches the rest.

Priority: P1.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tex.observability.telemetry import emit_event, get_logger

LLMPlannerCallable = Callable[[str, "ToolCatalog"], "list[tuple[str, Mapping[str, Any]]]"]


class ToolSpec(BaseModel):
    """Specification of a single tool the planner may emit."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1)
    description: str
    # Verb tokens used by the deterministic planner to match against the
    # user instruction. Lowercase, single-token preferred. Per paper §IV-A
    # the planner is given the tool definitions T; we model the relevant
    # slice here.
    verbs: tuple[str, ...] = Field(default_factory=tuple)
    # Optional regex patterns over the user instruction that, if matched,
    # extract a parameter value. Each match group becomes a candidate
    # parameter binding.
    param_extractors: tuple[tuple[str, str], ...] = Field(default_factory=tuple)


class ToolCatalog(BaseModel):
    """The set of tools the planner is allowed to consider — paper's T."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tools: tuple[ToolSpec, ...]

    def by_name(self, name: str) -> ToolSpec | None:
        for tool in self.tools:
            if tool.name == name:
                return tool
        return None


class Action(BaseModel):
    """One reference action a_i = (t_k, v_k) per paper Eq. 1."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_name: str = Field(min_length=1)
    # Frozen JSON-equivalent params. We use a tuple of sorted (key, value)
    # pairs so Action is hashable, enabling set membership for Stage I
    # exact-match (paper Algorithm 1 line 5: a_act ∈ S_ref).
    params: tuple[tuple[str, Any], ...] = Field(default_factory=tuple)

    @classmethod
    def from_mapping(
        cls, *, tool_name: str, params: Mapping[str, Any]
    ) -> "Action":
        return cls(
            tool_name=tool_name,
            params=tuple(sorted((str(k), v) for k, v in params.items())),
        )

    def params_dict(self) -> dict[str, Any]:
        return dict(self.params)


class ReferencePlan(BaseModel):
    """
    A reference plan derived solely from user instructions.

    Per paper §IV-B, S_ref is a *set* of actions. Membership checks
    (a_act ∈ S_ref) are the foundation of Stage I verification.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    actions: frozenset[Action]
    instruction: str
    backend: str  # "llm" | "deterministic" — for audit

    @property
    def allowed_tools(self) -> frozenset[str]:
        """The tool-name projection {t | (t, v) ∈ S_ref} per paper §IV-C1."""
        return frozenset(a.tool_name for a in self.actions)

    @property
    def parameter_constraints(self) -> dict[str, tuple[dict[str, Any], ...]]:
        """{tool_name -> tuple of allowed param dicts}. Stage I uses this
        to evaluate Case 3 (parameter mismatch)."""
        out: dict[str, list[dict[str, Any]]] = {}
        for action in self.actions:
            out.setdefault(action.tool_name, []).append(action.params_dict())
        return {k: tuple(v) for k, v in out.items()}


_DEFAULT_LOGGER = get_logger("tex.runtime.planguard")


class IsolatedPlanner:
    """
    The Isolated Planner P from arxiv 2604.10134.

    Critical invariant: this class is architecturally forbidden from
    receiving any external context (tool outputs, retrieved documents,
    web pages). Only the user instruction and the tool catalog are valid
    inputs. Callers MUST NOT pass tool outputs into derive_reference_plan.
    """

    def __init__(
        self,
        *,
        catalog: ToolCatalog,
        llm_planner: LLMPlannerCallable | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._catalog = catalog
        self._llm_planner = llm_planner
        self._logger = logger or _DEFAULT_LOGGER

    def derive_reference_plan(self, user_instruction: str) -> ReferencePlan:
        """
        Generate the reference action set S_ref from the user instruction.

        Per arxiv 2604.10134 §IV-B (Eq. 6):
            S_ref = P(I, T) = {a_1, a_2, ..., a_k}, k >= 0

        TODO(P1): run planner LLM with ONLY user instruction
        TODO(P1): emit allowed-tool set + parameter constraints

        Status: implemented. LLM path is pluggable via llm_planner; falls
        back to a deterministic verb/regex matcher when no LLM is
        configured. Both paths only see (instruction, catalog).
        """
        normalized_instruction = (user_instruction or "").strip()
        if not normalized_instruction:
            plan = ReferencePlan(
                actions=frozenset(),
                instruction="",
                backend="deterministic",
            )
            self._emit_derived(plan)
            return plan

        if self._llm_planner is not None:
            try:
                raw = self._llm_planner(normalized_instruction, self._catalog)
                actions = frozenset(
                    Action.from_mapping(tool_name=tn, params=p) for tn, p in raw
                )
                plan = ReferencePlan(
                    actions=actions,
                    instruction=normalized_instruction,
                    backend="llm",
                )
                self._emit_derived(plan)
                return plan
            except Exception as exc:  # noqa: BLE001
                # Conservative fallback: deterministic. Logged for ops.
                emit_event(
                    "planguard.planner.llm_failed",
                    level=logging.WARNING,
                    logger=self._logger,
                    error=str(exc),
                )

        actions = self._deterministic_plan(normalized_instruction)
        plan = ReferencePlan(
            actions=actions,
            instruction=normalized_instruction,
            backend="deterministic",
        )
        self._emit_derived(plan)
        return plan

    def _deterministic_plan(self, instruction: str) -> frozenset[Action]:
        """
        Verb-and-regex matcher over the tool catalog. Necessarily
        over-permissive — the Intent Verifier (Stage II) is what catches
        the residual semantic drift. Used for tests and as a safe
        fallback when no LLM backend is configured.
        """
        instruction_lower = instruction.lower()
        actions: set[Action] = set()
        for tool in self._catalog.tools:
            verb_hit = any(
                self._verb_match(verb, instruction_lower) for verb in tool.verbs
            )
            if not verb_hit:
                continue
            params = self._extract_params(tool, instruction)
            actions.add(Action.from_mapping(tool_name=tool.name, params=params))
        return frozenset(actions)

    @staticmethod
    def _verb_match(verb: str, instruction_lower: str) -> bool:
        if not verb:
            return False
        pattern = r"\b" + re.escape(verb.lower()) + r"\b"
        return re.search(pattern, instruction_lower) is not None

    @staticmethod
    def _extract_params(tool: ToolSpec, instruction: str) -> dict[str, Any]:
        params: dict[str, Any] = {}
        for param_name, regex in tool.param_extractors:
            match = re.search(regex, instruction, flags=re.IGNORECASE)
            if match is None:
                continue
            params[param_name] = match.group(1) if match.groups() else match.group(0)
        return params

    def _emit_derived(self, plan: ReferencePlan) -> None:
        emit_event(
            "planguard.reference_plan.derived",
            logger=self._logger,
            backend=plan.backend,
            allowed_tools=sorted(plan.allowed_tools),
            action_count=len(plan.actions),
            instruction_length=len(plan.instruction),
        )
