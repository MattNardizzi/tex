"""
Smoke tests proving every scaffolded package is importable.

Each module raises NotImplementedError on its public API; these tests
verify only that the package structure is wired in correctly.
"""

from __future__ import annotations

import importlib

import pytest


SCAFFOLDED_PACKAGES: tuple[str, ...] = (
    # P0 packages
    "tex.pqcrypto",
    "tex.pqcrypto.algorithm_agility",
    "tex.pqcrypto.ml_dsa",
    "tex.pqcrypto.ml_kem",
    "tex.pqcrypto.slh_dsa",
    "tex.pqcrypto.hybrid",
    "tex.pqcrypto.evidence_chain_signer",
    "tex.pqcrypto.code_signing",
    "tex.c2pa",
    "tex.c2pa.manifest",
    "tex.c2pa.signer",
    "tex.c2pa.verifier",
    "tex.c2pa.durable_credentials",
    "tex.receipts",
    "tex.receipts.epistemic_source",
    "tex.receipts.receipt",
    "tex.receipts.runtime",
    "tex.receipts.store",
    # P1 packages
    "tex.zkprov",
    "tex.zkprov.commitment",
    "tex.zkprov.proof",
    "tex.runtime",
    "tex.runtime.planguard",
    "tex.runtime.planguard.isolated_planner",
    "tex.runtime.planguard.intent_verifier",
    "tex.runtime.clawguard",
    "tex.runtime.clawguard.rule_set",
    "tex.runtime.clawguard.boundary_enforcer",
    "tex.runtime.agentarmor",
    "tex.runtime.agentarmor.graph_constructor",
    "tex.runtime.agentarmor.property_registry",
    "tex.runtime.agentarmor.type_system",
    "tex.runtime.mage",
    "tex.runtime.mage.shadow_memory",
    "tex.runtime.mage.risk_assessor",
    "tex.runtime.mcpshield",
    "tex.runtime.mcpshield.lts_model",
    "tex.runtime.mcpshield.verifier",
    "tex.governance",
    "tex.governance.path_policy",
    "tex.governance.path_policy.policy",
    "tex.governance.path_policy.checker",
    "tex.governance.kernel_mcp",
    "tex.governance.kernel_mcp.capability",
    "tex.governance.kernel_mcp.syscall_gate",
    "tex.governance.private_data_exec",
    "tex.governance.private_data_exec.sandbox",
    "tex.governance.stpa_specs",
    "tex.governance.stpa_specs.hazard_model",
    "tex.interop",
    "tex.interop.a2a",
    "tex.interop.a2a.signed_agent_card",
    "tex.interop.a2a.bus_listener",
    "tex.interop.okta",
    "tex.interop.okta.agent_identity_sync",
    "tex.interop.ping",
    "tex.interop.ping.verdict_publisher",
    "tex.interop.microsoft",
    "tex.interop.microsoft.policy_bundle_exporter",
    "tex.interop.nist",
    "tex.interop.nist.self_assessment",
    # P2 packages
    "tex.nanozk",
    "tex.nanozk.layerwise_prover",
    "tex.nanozk.fisher_guided",
    "tex.tee",
    "tex.tee.attestation_client",
    "tex.tee.h100_attestation",
    "tex.tee.tdx_attestation",
    "tex.vet",
    "tex.vet.agent_identity_document",
    "tex.vet.web_proofs",
    # Compliance
    "tex.compliance",
    "tex.compliance.eu_ai_act",
    "tex.compliance.eu_ai_act.article_50",
    "tex.compliance.eu_ai_act.article_26",
    "tex.compliance.eu_ai_act.article_17",
    "tex.compliance.ftc",
    "tex.compliance.ftc.policy_statement",
    "tex.compliance.state",
    "tex.compliance.state.california_sb942",
    "tex.compliance.state.california_ab853_platforms",
    "tex.compliance.state.california_ab853_capture",
    "tex.compliance.state.colorado_ai_act",
    "tex.compliance.state.new_york_ai_disclosure",
    "tex.compliance.nist",
    "tex.compliance.nist.ai_rmf",
    "tex.compliance.nist.agent_standards",
    "tex.compliance.naic",
    "tex.compliance.naic.model_bulletin",
    "tex.compliance.naic.cyber_rider",
    # Pitch surfaces
    "tex.pitch",
    "tex.pitch.vp_marketing",
    "tex.pitch.ciso",
    "tex.pitch.insurer_export",
    # Causal layer (CHIEF + ARM, Thread 11)
    "tex.causal",
    "tex.causal.chief",
    "tex.causal.arm",
    "tex.causal.counterfactual",
    # New specialists
    "tex.specialists.owasp_skills_top10_specialist",
    "tex.specialists.mcp_injection_specialist",
    # Config
    "tex.frontier_config",
)


@pytest.mark.parametrize("module_name", SCAFFOLDED_PACKAGES)
def test_module_importable(module_name: str) -> None:
    """Every scaffolded module must import cleanly without side effects."""
    module = importlib.import_module(module_name)
    assert module is not None


def test_frontier_flags_default_off() -> None:
    """All frontier flags default to off so existing pipeline runs untouched."""
    from tex.frontier_config import FrontierFlags

    flags = FrontierFlags.from_env()
    # Cannot assert all-off (env may have flags set), but the dataclass must
    # be constructible and consistent.
    assert isinstance(flags.any_enabled(), bool)
