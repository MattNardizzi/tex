"""
[Architecture: Layer 4 (Execution Governance)] — CamEL capability-based interpreter invoked by specialists/camel_specialist

See ARCHITECTURE.md for the full six-layer model.

CaMeL — Capabilities for Machine Learning.

Capability-based dual-LLM execution layer that defends against indirect
prompt injection by separating planning from data handling. Implements
the architecture from arxiv 2503.18813 (Debenedetti et al., Google
DeepMind, March 2025) for the PCAS-compatible subset of agent control
flow.

Architecture
------------
- ``Privileged LLM`` (P-LLM): receives only the user prompt; emits a
  plan as a sequence of typed operations over capability-tagged values.
  The P-LLM never sees untrusted content.
- ``Quarantined LLM`` (Q-LLM): processes untrusted content but cannot
  call tools. Its outputs are tagged with capabilities derived from
  their sources.
- ``Capability interpreter``: an AST-walking, capability-tracking
  evaluator that runs the P-LLM's plan. Each value carries a
  ``Capability`` set; tool calls are gated against the union of all
  argument capabilities and policy rules.

Genuine novelty vs. existing implementations
--------------------------------------------
- The Google open-source repo at github.com/google-research/camel-
  prompt-injection ships a research prototype. Microsoft Agent
  Governance Toolkit (April 2026) ships no CaMeL equivalent. Our
  contribution is the **first integration of a CaMeL capability
  interpreter with a Datalog policy frontend (PCAS) over a single
  causal provenance graph**.
- Per CaMeL §5, capability propagation rules are: (1) any value derived
  from an untrusted source inherits the untrusted capability; (2) tool
  calls require *all* argument capabilities to be authorized by policy;
  (3) Q-LLM outputs inherit the union of their input capabilities. We
  implement all three rigorously over a typed AST.

Threat model
------------
- The P-LLM is trusted (per CaMeL §3.1). The Q-LLM is untrusted.
- Tools are typed; tool authors specify the capability requirements per
  tool call. Default is *fail-closed*: a tool with no declared
  requirements cannot consume any capability except ``trusted``.
- Side channels (timing, output length) are out of scope, per the
  SentinelAI Operationalizing-CaMeL paper (arxiv 2505.22852) which
  identifies these as open issues.

Components
----------
- ``capability``   — the capability lattice (TRUSTED ⊑ USER ⊑ UNTRUSTED)
                     with ``join`` for combining capabilities of inputs
- ``value``        — capability-tagged values
- ``plan``         — the AST of plans the P-LLM emits
- ``interpreter``  — capability-tracking executor
- ``q_llm``        — Q-LLM callable interface (pluggable; default returns
                     deterministic stub for testing)
- ``policy``       — tool-call policy: what capabilities each tool requires

Priority: P0 — wired into the PDP via ``CamelSpecialist``.

"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.camel import __layer__, __layer_kind__`.
__layer__: int | None = 4
__layer_kind__: str = 'execution_governance'

from tex.camel.capability import (
    Capability,
    CapabilityLevel,
    CapabilitySet,
)
from tex.camel.interpreter import (
    CamelInterpreter,
    CamelInterpreterError,
    ExecutionTrace,
)
from tex.camel.cfi import (
    CfiLedger,
    CfiLedgerEntry,
    cfi_influence_bits,
    scope_symmetric_difference,
)
from tex.camel.plan import (
    Assign,
    Branch,
    Call,
    Literal,
    Plan,
    PlanError,
    PlanNode,
    QLLM,
    Read,
    Return,
    Var,
)
from tex.camel.policy import (
    ToolPolicy,
    ToolPolicyRegistry,
)
from tex.camel.q_llm import QuarantinedLLM, StubQuarantinedLLM
from tex.camel.value import CapValue

__all__ = [
    "Assign",
    "Branch",
    "Call",
    "Capability",
    "CapabilityLevel",
    "CapabilitySet",
    "CamelInterpreter",
    "CamelInterpreterError",
    "CapValue",
    "CfiLedger",
    "CfiLedgerEntry",
    "ExecutionTrace",
    "Literal",
    "Plan",
    "PlanError",
    "PlanNode",
    "QLLM",
    "QuarantinedLLM",
    "Read",
    "Return",
    "StubQuarantinedLLM",
    "ToolPolicy",
    "ToolPolicyRegistry",
    "Var",
    "cfi_influence_bits",
    "scope_symmetric_difference",
]
