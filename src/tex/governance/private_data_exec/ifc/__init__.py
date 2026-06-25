"""
Information-Flow Control sub-layer for Tex.

This sub-package extends ``tex.governance.private_data_exec`` (GAAP)
with the bleeding-edge May 2026 IFC stack used by the PDP at runtime.

Reference implementations
-------------------------
- ARM provenance graph + counterfactual edges     — arxiv 2604.04035
- FIDES product lattice (label × type capacity)   — arxiv 2505.23643
- NeuroTaint cross-session memory                 — arxiv 2604.23374
- CA-CI six-tuple contextual integrity            — IEEE S&P 2026
- GAAP permission DB + disclosure log (parent)    — arxiv 2604.19657
- Rule of Two corrective check                    — Meta Oct 2025,
                                                    Towards AI Nov 2025

Public API
----------
- IfcEngine                       — main orchestrator (per-request)
- IfcVerdict / IfcViolation       — structured engine output
- IfcLabel / IntegrityLevel       — composite labels & 5-level lattice
- ConfidentialityLevel            — 4-level dual-axis lattice
- CapacityType                    — FIDES output capacity tag
- ProvenanceGraph                 — ARM-style 4-edge graph
- CiNorm / CiNormRegistry         — CA-CI six-tuple norms
- MemoryStream                    — NeuroTaint cross-session store
- ClassifiedSource                — output of the source classifier

Priority: P0 — wired into the live PDP via
``tex.specialists.ifc_specialist.IfcSpecialist``.
"""

from tex.governance.private_data_exec.ifc.ci_norms import (
    CiNorm,
    CiNormRegistry,
    TransmissionPrinciple,
)
from tex.governance.private_data_exec.ifc.classifier import (
    CallSpec,
    ClassifiedSource,
    classify_content,
    classify_request,
    extract_ci_norm,
    extract_proposed_tool_call,
    is_sink_action,
    proposed_recipient,
    SINK_ACTION_TYPES,
)
from tex.governance.private_data_exec.ifc.engine import (
    IfcEngine,
    IfcEvidenceItem,
    IfcVerdict,
    IfcViolation,
)
from tex.governance.private_data_exec.ifc.lattice import (
    CapacityType,
    ConfidentialityLevel,
    IfcLabel,
    IntegrityLevel,
    LABEL_RETRIEVED_DOC,
    LABEL_TOOL_DESCRIPTION,
    LABEL_TOOL_OUTPUT_TRUSTED,
    LABEL_TOOL_OUTPUT_UNTRUSTED,
    LABEL_USER_PROMPT,
    SourceClassification,
)
from tex.governance.private_data_exec.ifc.capability_compat import (
    Capability,
    CapabilitySet,
    FidesLabel,
)
from tex.governance.private_data_exec.ifc.capability_compat import (
    CapabilityLevel as CamelCapabilityLevel,
)
from tex.governance.private_data_exec.ifc.capability_compat import (
    ConfidentialityLevel as CamelConfidentialityLevel,
)
from tex.governance.private_data_exec.ifc.memory import (
    DEFAULT_MEMORY_STREAM,
    MemoryItem,
    MemoryStream,
)
from tex.governance.private_data_exec.ifc.noninterference import (
    DEFAULT_EGRESS_CLEARANCE,
    FlowProof,
    FlowStep,
    FlowWitness,
    NonInterferenceVerdict,
    check_noninterference,
    egress_clearance,
    verify_flow_proof,
)
from tex.governance.private_data_exec.ifc.provenance import (
    EdgeKind,
    NodeKind,
    ProvenanceGraph,
)

__all__ = [
    # Engine
    "IfcEngine",
    "IfcVerdict",
    "IfcEvidenceItem",
    "IfcViolation",
    # Lattice
    "IntegrityLevel",
    "ConfidentialityLevel",
    "CapacityType",
    "IfcLabel",
    "SourceClassification",
    "LABEL_USER_PROMPT",
    "LABEL_RETRIEVED_DOC",
    "LABEL_TOOL_OUTPUT_TRUSTED",
    "LABEL_TOOL_OUTPUT_UNTRUSTED",
    "LABEL_TOOL_DESCRIPTION",
    # CI norms
    "CiNorm",
    "CiNormRegistry",
    "TransmissionPrinciple",
    # Provenance graph
    "ProvenanceGraph",
    "NodeKind",
    "EdgeKind",
    # Non-interference checker (SECRET ↛ EGRESS) + checkable proof
    "check_noninterference",
    "verify_flow_proof",
    "egress_clearance",
    "FlowProof",
    "FlowWitness",
    "FlowStep",
    "NonInterferenceVerdict",
    "DEFAULT_EGRESS_CLEARANCE",
    # NeuroTaint memory
    "MemoryStream",
    "MemoryItem",
    "DEFAULT_MEMORY_STREAM",
    # CaMeL FIDES product lattice — IFC home (decommission of tex.camel).
    # The CaMeL integrity/confidentiality enums are exported under Camel*
    # aliases so they do not collide with this package's own (isomorphic)
    # IntegrityLevel/ConfidentialityLevel from ifc.lattice. The verbatim
    # symbols also live at ifc.capability_compat for direct import.
    "Capability",
    "CapabilitySet",
    "FidesLabel",
    "CamelCapabilityLevel",
    "CamelConfidentialityLevel",
    # Classifier
    "ClassifiedSource",
    "CallSpec",
    "classify_request",
    "classify_content",
    "extract_proposed_tool_call",
    "extract_ci_norm",
    "proposed_recipient",
    "is_sink_action",
    "SINK_ACTION_TYPES",
]
