"""
AgentArmor: Program Analysis on Agent Runtime Traces.

Reference: arxiv 2508.01249, Wang et al., ByteDance.

Treats agent runtime traces as structured programs. Builds CFG/DFG/PDG
intermediate representations and applies a type system over them.

Performance: 95.75% TPR, 3.66% FPR, 1% utility drop on AgentDojo.

Three components:
  graph_constructor    Reconstructs trace as graph IR with control + data flow
  property_registry    Attaches security metadata to tools and data
  type_system          Static type inference and policy checking over IR

Priority: P1.
"""

from tex.runtime.agentarmor.graph_constructor import (
    EdgeKind,
    GraphConstructor,
    GraphIR,
    NodeKind,
    TraceEvent,
)
from tex.runtime.agentarmor.property_registry import (
    Capability,
    Confidentiality,
    DataRegistry,
    DataSpec,
    Integrity,
    PropertyRegistry,
    ToolRegistry,
    ToolSpec,
    TrustLevel,
    conf_join,
    default_data_scanner,
    default_tool_scanner,
    int_meet,
    trust_join,
)
from tex.runtime.agentarmor.type_system import TypeSystem, TypeViolation

__all__ = [
    "Capability",
    "Confidentiality",
    "DataRegistry",
    "DataSpec",
    "EdgeKind",
    "GraphConstructor",
    "GraphIR",
    "Integrity",
    "NodeKind",
    "PropertyRegistry",
    "ToolRegistry",
    "ToolSpec",
    "TraceEvent",
    "TrustLevel",
    "TypeSystem",
    "TypeViolation",
    "conf_join",
    "default_data_scanner",
    "default_tool_scanner",
    "int_meet",
    "trust_join",
]
