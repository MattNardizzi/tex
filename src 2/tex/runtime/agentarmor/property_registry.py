"""
AgentArmor Property Registry.

Reference: arxiv 2508.01249 (Wang et al.), §III-B.

Two registries plus two scanners:

  ToolRegistry  — declares each known tool's input/output param shapes,
                  side effects, and security labels (confidentiality,
                  integrity, capability class).
  DataRegistry  — declares known data entities' sensitivity (confidentiality
                  level) and trustworthiness (TRUSTED / UNTRUSTED / TAINTED).

  ToolScanner   — for unseen tools, dynamically infer metadata from the tool
                  signature / description (LLM-backed in the paper; offline
                  fallback uses a lexical heuristic over the tool name).
  DataScanner   — for unseen data, infer trust from its source attribution
                  (external-content sources default to UNTRUSTED).

The registry is consumed by ``TypeAssigner`` to bind ``(security_type,
trust_type, rule_type)`` triples to PDG nodes. Per the paper the type
system is built atop this metadata layer.

Priority: P1.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Callable

import networkx as nx
from pydantic import BaseModel, ConfigDict, Field

from tex.observability.telemetry import emit_event, get_logger

_logger = get_logger("tex.runtime.agentarmor.registry")


class TrustLevel(str, Enum):
    """Trust label per AgentArmor.

    Lattice order: TRUSTED < UNTRUSTED < TAINTED.
    Once data is observed from an external source it becomes UNTRUSTED.
    Once it has been mixed with policy-violating content it becomes TAINTED.
    """

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    TAINTED = "tainted"


class Confidentiality(str, Enum):
    """Confidentiality lattice (Bell-LaPadula).

    Order: PUBLIC < INTERNAL < CONFIDENTIAL < SECRET.
    Join (least upper bound): more restrictive wins. SECRET ∨ PUBLIC = SECRET.
    Sensitive data must NOT be downgraded.
    """

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"


class Integrity(str, Enum):
    """Integrity lattice (Biba).

    Order: HIGH > MEDIUM > LOW.
    Meet (greatest lower bound): less trustworthy wins. HIGH ∧ LOW = LOW.
    High-integrity outputs must NOT be influenced by low-integrity inputs.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Capability(str, Enum):
    """Tool capability class. Determines which inter-node checks apply."""

    READ = "read"
    WRITE = "write"
    NETWORK = "network"
    EXEC = "exec"


_CONF_ORDER = {Confidentiality.PUBLIC: 0, Confidentiality.INTERNAL: 1,
               Confidentiality.CONFIDENTIAL: 2, Confidentiality.SECRET: 3}
_INT_ORDER = {Integrity.LOW: 0, Integrity.MEDIUM: 1, Integrity.HIGH: 2}
_TRUST_ORDER = {TrustLevel.TRUSTED: 0, TrustLevel.UNTRUSTED: 1,
                TrustLevel.TAINTED: 2}


def conf_join(a: Confidentiality, b: Confidentiality) -> Confidentiality:
    """Bell-LaPadula join: pick the MORE confidential of the two."""
    return a if _CONF_ORDER[a] >= _CONF_ORDER[b] else b


def int_meet(a: Integrity, b: Integrity) -> Integrity:
    """Biba meet: pick the LOWER integrity of the two."""
    return a if _INT_ORDER[a] <= _INT_ORDER[b] else b


def trust_join(a: TrustLevel, b: TrustLevel) -> TrustLevel:
    """Trust join: TAINTED dominates UNTRUSTED dominates TRUSTED."""
    return a if _TRUST_ORDER[a] >= _TRUST_ORDER[b] else b


class ToolSpec(BaseModel):
    """Security metadata for one tool."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    capability: Capability
    declared_confidentiality: Confidentiality = Confidentiality.PUBLIC
    declared_integrity: Integrity = Integrity.MEDIUM
    side_effects: tuple[str, ...] = ()
    description: str = ""


class DataSpec(BaseModel):
    """Security metadata for one named data entity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    confidentiality: Confidentiality
    trust: TrustLevel = TrustLevel.TRUSTED
    integrity: Integrity = Integrity.HIGH


class ToolRegistry(BaseModel):
    """Append-only registry of known tools."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    tools: dict[str, ToolSpec] = Field(default_factory=dict)

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self.tools:
            raise ValueError(f"tool {spec.name} already registered")
        self.tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self.tools.get(name)


class DataRegistry(BaseModel):
    """Append-only registry of known data entities."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    entries: dict[str, DataSpec] = Field(default_factory=dict)

    def register(self, spec: DataSpec) -> None:
        if spec.name in self.entries:
            raise ValueError(f"data {spec.name} already registered")
        self.entries[spec.name] = spec

    def get(self, name: str) -> DataSpec | None:
        return self.entries.get(name)


def default_tool_scanner(tool_name: str, description: str = "") -> ToolSpec:
    """Heuristic capability inference for unseen tools.

    Paper uses an LLM-backed scanner; offline fallback maps common tool-name
    fragments to capability classes. Conservative defaults are chosen to
    avoid false-negative classification of dangerous tools.
    """
    name = tool_name.lower()
    desc = description.lower()
    blob = f"{name} {desc}"

    if any(tok in blob for tok in ("exec", "shell", "bash", "command",
                                    "subprocess", "system", "eval", "run_code")):
        cap = Capability.EXEC
    elif any(tok in blob for tok in ("http", "url", "fetch", "request",
                                      "send", "post", "api_call", "webhook")):
        cap = Capability.NETWORK
    elif any(tok in blob for tok in ("write", "save", "create", "update",
                                      "insert", "delete", "modify", "patch")):
        cap = Capability.WRITE
    else:
        cap = Capability.READ

    return ToolSpec(
        name=tool_name,
        capability=cap,
        description=description,
    )


def default_data_scanner(node_attrs: dict[str, Any]) -> DataSpec:
    """Heuristic data-attribute inference.

    Anything sourced as ``external`` is treated as UNTRUSTED with PUBLIC
    confidentiality and LOW integrity (worst-case default for the consumer's
    safety). User-sourced is TRUSTED but still external; agent-sourced is
    TRUSTED and HIGH integrity.
    """
    source = node_attrs.get("source", "agent")
    name = str(node_attrs.get("param_name") or node_attrs.get("tool_name") or "data")
    if source == "external":
        return DataSpec(
            name=name,
            confidentiality=Confidentiality.PUBLIC,
            trust=TrustLevel.UNTRUSTED,
            integrity=Integrity.LOW,
        )
    if source == "user":
        return DataSpec(
            name=name,
            confidentiality=Confidentiality.INTERNAL,
            trust=TrustLevel.TRUSTED,
            integrity=Integrity.MEDIUM,
        )
    return DataSpec(
        name=name,
        confidentiality=Confidentiality.PUBLIC,
        trust=TrustLevel.TRUSTED,
        integrity=Integrity.HIGH,
    )


class PropertyRegistry:
    """Annotate a built PDG with security metadata.

    Mutates the PDG in place by adding:
      - ``capability``  on TOOL nodes
      - ``trust``       on every node
      - ``confidentiality`` and ``integrity`` on TOOL_PARAM, OBSERVATION,
        and TOOL nodes (so the type system can propagate)
    """

    def __init__(
        self,
        *,
        tools: ToolRegistry | None = None,
        data: DataRegistry | None = None,
        tool_scanner: Callable[[str, str], ToolSpec] = default_tool_scanner,
        data_scanner: Callable[[dict[str, Any]], DataSpec] = default_data_scanner,
    ) -> None:
        self.tools = tools or ToolRegistry()
        self.data = data or DataRegistry()
        self._tool_scanner = tool_scanner
        self._data_scanner = data_scanner

    def annotate(self, pdg: dict | nx.DiGraph) -> nx.DiGraph:
        """Annotate the PDG. ``pdg`` may be a GraphIR.pdg DiGraph or a
        dict containing it (legacy contract).
        """
        graph = self._coerce(pdg)

        unknown_tools = 0
        for node, attrs in graph.nodes(data=True):
            kind = attrs.get("kind")

            if kind in ("tool", "tool_name"):
                tool_name = attrs.get("tool_name", "")
                spec = self.tools.get(tool_name)
                if spec is None:
                    spec = self._tool_scanner(tool_name, attrs.get("content", ""))
                    unknown_tools += 1
                graph.nodes[node]["capability"] = spec.capability.value
                graph.nodes[node]["declared_confidentiality"] = (
                    spec.declared_confidentiality.value
                )
                graph.nodes[node]["declared_integrity"] = spec.declared_integrity.value

            if kind in ("user", "system", "model", "tool_name", "tool_param",
                        "tool", "observation"):
                ds = self._data_scanner(dict(attrs))
                graph.nodes[node]["trust"] = ds.trust.value
                graph.nodes[node]["confidentiality"] = ds.confidentiality.value
                graph.nodes[node]["integrity"] = ds.integrity.value

        emit_event(
            "agentarmor.registry.annotated",
            logger=_logger,
            unknown_tools=unknown_tools,
            total_nodes=graph.number_of_nodes(),
        )
        return graph

    @staticmethod
    def _coerce(pdg: dict | nx.DiGraph) -> nx.DiGraph:
        if isinstance(pdg, nx.DiGraph):
            return pdg
        if isinstance(pdg, dict) and "pdg" in pdg and isinstance(pdg["pdg"], nx.DiGraph):
            return pdg["pdg"]
        raise TypeError("annotate() requires a networkx DiGraph or {'pdg': DiGraph}")
