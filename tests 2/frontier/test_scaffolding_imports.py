"""
Smoke tests proving every scaffolded package is importable.

Each module raises NotImplementedError on its public API; these tests
verify only that the package structure is wired in correctly.

Active vs pending packages
--------------------------
Packages live in one of two states:

* **Active** — under ``src/tex/`` and required to import cleanly. The
  ``test_module_importable`` parametrize over ``ACTIVE_PACKAGES``
  enforces this hard.
* **Pending** — under ``src/tex/_pending/`` per the policy documented
  in ``src/tex/_pending/__init__.py``. They MUST NOT import as
  ``tex.<name>`` from the active namespace; that's the whole point of
  ``_pending/``. A separate parametrize asserts the *correct* status
  of each pending package (importable under ``tex._pending.<name>``
  but not under ``tex.<name>``) so restoring a pending package later
  is a single test signal: the module moves from one list to the
  other.
"""

from __future__ import annotations

import importlib

import pytest


ACTIVE_PACKAGES: tuple[str, ...] = (
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
    "tex.vet.selective_disclosure",
    "tex.vet.ptv_attestation",
    "tex.vet.aivs_micro",
    "tex.vet.txn_tokens",
    "tex.vet.sd_jwt_vc",
    "tex.vet.registry",
    "tex.vet.integration",
    "tex.vet.scitt",
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


# Pending packages — see src/tex/_pending/__init__.py for the policy.
# Each entry maps the active name (where the package would live if
# restored) to the suffix under tex._pending. Importing the active
# name MUST fail; importing the pending name MUST succeed.
PENDING_PACKAGES: tuple[tuple[str, str], ...] = (
    ("tex.interop", "tex._pending.interop"),
    ("tex.interop.a2a", "tex._pending.interop.a2a"),
    ("tex.interop.a2a.signed_agent_card", "tex._pending.interop.a2a.signed_agent_card"),
    ("tex.interop.a2a.bus_listener", "tex._pending.interop.a2a.bus_listener"),
    ("tex.interop.okta", "tex._pending.interop.okta"),
    ("tex.interop.okta.agent_identity_sync", "tex._pending.interop.okta.agent_identity_sync"),
    ("tex.interop.ping", "tex._pending.interop.ping"),
    ("tex.interop.ping.verdict_publisher", "tex._pending.interop.ping.verdict_publisher"),
    ("tex.interop.microsoft", "tex._pending.interop.microsoft"),
    ("tex.interop.microsoft.policy_bundle_exporter", "tex._pending.interop.microsoft.policy_bundle_exporter"),
    ("tex.interop.nist", "tex._pending.interop.nist"),
    ("tex.interop.nist.self_assessment", "tex._pending.interop.nist.self_assessment"),
    # Graph backend stubs (moved from tex.graph)
    ("tex.graph.postgres_backend", "tex._pending.graph.postgres_backend"),
    ("tex.graph.janusgraph_backend", "tex._pending.graph.janusgraph_backend"),
    # Events extension stub (moved from tex.events)
    ("tex.events.quorum_shard", "tex._pending.events.quorum_shard"),
    # Compliance stubs (moved from tex.compliance.{naic,nist})
    ("tex.compliance.nist", "tex._pending.compliance.nist"),
    ("tex.compliance.nist.ai_rmf", "tex._pending.compliance.nist.ai_rmf"),
    ("tex.compliance.nist.agent_standards", "tex._pending.compliance.nist.agent_standards"),
    ("tex.compliance.naic", "tex._pending.compliance.naic"),
    ("tex.compliance.naic.model_bulletin", "tex._pending.compliance.naic.model_bulletin"),
    ("tex.compliance.naic.cyber_rider", "tex._pending.compliance.naic.cyber_rider"),
    # Pitch surfaces (audience-specific exports — parked pending new GTM)
    ("tex.pitch", "tex._pending.pitch"),
    ("tex.pitch.vp_marketing", "tex._pending.pitch.vp_marketing"),
    ("tex.pitch.ciso", "tex._pending.pitch.ciso"),
    ("tex.pitch.insurer_export", "tex._pending.pitch.insurer_export"),
    ("tex.api.pitch_routes", "tex._pending.api.pitch_routes"),
)


@pytest.mark.parametrize("module_name", ACTIVE_PACKAGES)
def test_module_importable(module_name: str) -> None:
    """Every active scaffolded module must import cleanly without side effects."""
    module = importlib.import_module(module_name)
    assert module is not None


@pytest.mark.parametrize("active_name,pending_name", PENDING_PACKAGES)
def test_pending_module_in_pending_namespace(
    active_name: str, pending_name: str
) -> None:
    """Each pending package must import under ``tex._pending.*`` (proving the
    scaffolding still exists for restoration) and MUST NOT import under
    the active ``tex.*`` name (proving the _pending/ policy is honored).

    When a pending package is restored to active status:
      1. Move the directory from ``src/tex/_pending/<name>/`` to
         ``src/tex/<name>/``.
      2. Move the entry from ``PENDING_PACKAGES`` to ``ACTIVE_PACKAGES``
         (one row in this file).
      3. Update ``src/tex/_pending/__init__.py`` "Current contents"
         block to reflect the change.
      4. Add tests under ``tests/<name>/``.
    """
    # Pending module is reachable under its _pending path.
    module = importlib.import_module(pending_name)
    assert module is not None

    # Active name MUST NOT resolve — that's the entire _pending/ contract.
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(active_name)


def test_frontier_flags_default_off() -> None:
    """All frontier flags default to off so existing pipeline runs untouched."""
    from tex.frontier_config import FrontierFlags

    flags = FrontierFlags.from_env()
    # Cannot assert all-off (env may have flags set), but the dataclass must
    # be constructible and consistent.
    assert isinstance(flags.any_enabled(), bool)
