"""
iter-6 ACTIVATION — the evolved CaMeL specialist fires the metered (CFI/CHOKE-X)
interpreter on the REAL PDP path, and the static plan-ahead specialist is retired.

DoD-4 (fires on real traffic) + the anti-theater contract, proven END-TO-END through
``EvaluateActionCommand.execute()`` (the real composition root):

 (A) FAITHFUL EMISSION — a request that declares a GENUINE untrusted-read-then-branch
     flow (``camel_branch_flow``, real untrusted content in the request, a real finite
     domain, a real irreversible sink) compiles to a metered CaMeL plan whose CHOKE-X
     certificate fires on the live path → the verdict is demoted to ABSTAIN.
 (B) NO THEATER — a request with NO ``camel_branch_flow`` (no real untrusted branch)
     compiles to NOTHING: no plan is stamped, the specialist abstains, and the metered
     branch mechanism does NOT fire. (Rigging a plan to make the mechanism fire is the
     failed build; this proves the plan derives from the request's real structure.)
 (C) PLAN-FROM-REAL-DATA — the untrusted content in the emitted plan IS the request's
     real content (not synthesized), and a request that declares a branch but whose
     untrusted location holds no real content emits NOTHING.
 (D) DEFAULT-OFF — with ``TEX_CAMEL_EMIT_ENABLED`` unset the seam never compiles a
     plan and behaviour is unchanged.
 (E) VALUE-BUDGET FROM GRANT — the LEDGERED value-budget ceiling reads from the SIGNED
     token grant when a verified capability token is present.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from tex.camel.plan import Branch, Plan
from tex.camel.plan_emission import compile_branch_flow, plan_emission_enabled
from tex.domain.evaluation import EvaluationRequest
from tex.domain.verdict import Verdict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _request(content: str, *, metadata: dict | None = None) -> EvaluationRequest:
    return EvaluationRequest(
        request_id=uuid4(),
        action_type="send_email",
        content=content,
        recipient="ops@example.com",
        channel="email",
        environment="production",
        policy_id=None,
        metadata=metadata or {},
    )


def _high_stakes_flow_block() -> dict:
    """A REAL untrusted-read-then-branch declaration: project the request's real
    untrusted content into {refund, no_refund}, and on 'refund' take an IRREVERSIBLE
    sink (issue_refund). budget_bits=0 + irreversible => high-stakes => CHOKE-X
    certifies log2(2)=1 bit of attacker leverage > 0 => ABSTAIN before any sink."""
    return {
        "untrusted_source": "ticket_body",
        "untrusted_from": "content",
        "domain": ["refund", "no_refund"],
        "match_value": "refund",
        "then_tool": "issue_refund",
        "else_tool": "close_ticket",
        "effect_class": "irreversible",
        "budget_bits": 0,
    }


# ---------------------------------------------------------------------------
# (A)/(B)/(C) Faithful compiler unit-level: real structure in, plan or nothing out
# ---------------------------------------------------------------------------


def test_compile_emits_plan_for_genuine_branch_flow():
    req = _request("refund please", metadata={"camel_branch_flow": _high_stakes_flow_block()})
    emitted = compile_branch_flow(req)
    assert emitted is not None
    # The untrusted content in the plan IS the request's real content — NOT synthesized.
    assert emitted.untrusted_env["ticket_body"] == "refund please"
    assert emitted.user_prompt == "refund please"
    # The plan contains a genuine metered Branch over the declared finite domain.
    branches = [n for n in emitted.plan.nodes if isinstance(n, Branch)]
    assert len(branches) == 1
    assert branches[0].is_high_stakes  # budget_bits=0 + irreversible
    assert emitted.provenance["untrusted_from"] == "content"


def test_compile_emits_nothing_without_branch_flow():
    # No camel_branch_flow at all → NO plan (the anti-theater core: a straight-line
    # request gets no fabricated branch).
    req = _request("just a normal email, no branching")
    assert compile_branch_flow(req) is None


def test_compile_emits_nothing_when_untrusted_location_empty():
    # Declares a branch but points untrusted_from at a metadata key with no real
    # content → NOTHING (never invent untrusted bytes).
    block = dict(_high_stakes_flow_block())
    block["untrusted_from"] = "metadata:nonexistent_field"
    req = _request("x", metadata={"camel_branch_flow": block})
    assert compile_branch_flow(req) is None


def test_compile_emits_nothing_for_empty_domain():
    block = dict(_high_stakes_flow_block())
    block["domain"] = []
    req = _request("refund please", metadata={"camel_branch_flow": block})
    assert compile_branch_flow(req) is None


def test_compile_emits_nothing_without_sink_action():
    block = dict(_high_stakes_flow_block())
    block.pop("then_tool")
    req = _request("refund please", metadata={"camel_branch_flow": block})
    assert compile_branch_flow(req) is None


def test_plan_emission_flag_default_off(monkeypatch):
    monkeypatch.delenv("TEX_CAMEL_EMIT_ENABLED", raising=False)
    assert plan_emission_enabled() is False
    monkeypatch.setenv("TEX_CAMEL_EMIT_ENABLED", "1")
    assert plan_emission_enabled() is True


# ---------------------------------------------------------------------------
# DoD-4 — the GENUINE end-to-end scenario through EvaluateActionCommand
# ---------------------------------------------------------------------------


@pytest.fixture
def runtime():
    from tex.main import build_runtime

    return build_runtime()


def test_dod4_real_path_chokex_abstains_on_genuine_untrusted_branch(runtime, monkeypatch):
    """A REAL request that genuinely branches over untrusted data, driven through the
    actual ``EvaluateActionCommand.execute()`` → pdp path, produces a CHOKE-X verdict
    on the real path (the metered branch mechanism FIRES), demoting to ABSTAIN."""
    monkeypatch.setenv("TEX_CAMEL_EMIT_ENABLED", "1")

    req = _request(
        # The REAL untrusted ticket content — this IS the attacker-controlled channel.
        "refund",
        metadata={"camel_branch_flow": _high_stakes_flow_block()},
    )
    result = runtime.evaluate_action_command.execute(req)

    # The metered CaMeL specialist ran on the real path and the CHOKE-X branch
    # certificate fired (high-stakes branch, 1 bit leverage > 0 budget → ABSTAIN).
    camel = next(
        r for r in result.pdp_result.specialist_bundle.results
        if r.specialist_name == "camel"
    )
    assert "camel.branch_leverage_abstain" in camel.matched_policy_clause_ids
    # The hold demoted the routed verdict: a genuine branch-leverage ABSTAIN, never
    # a silent PERMIT. (FORBID is also acceptable if some other floor fired, but it
    # must NOT be a PERMIT — the high-stakes arm was not bounded.)
    assert result.decision.verdict is Verdict.ABSTAIN
    # The branch-leverage hold fired on the real path (PERMIT→ABSTAIN demotion).
    assert "branch_leverage_abstain" in result.response.uncertainty_flags
    # And the plan was COMPILED from the request's real structure — the specialist
    # evidence shows a metered Branch ran (not a static straight-line plan), and the
    # provenance marker confirms the untrusted content came from request.content.
    assert any("Branch" in e.text for e in camel.evidence)
    assert result.pdp_result is not None


def test_dod4_no_branch_flow_does_not_fire_mechanism(runtime, monkeypatch):
    """The control: the SAME real path, a request with NO untrusted-branch structure,
    produces NO plan and the metered mechanism does NOT fire (proves the plan was not
    hardcoded — it derives from the request's real structure)."""
    monkeypatch.setenv("TEX_CAMEL_EMIT_ENABLED", "1")

    req = _request("Hi team, the Q3 review is Tuesday at 2pm. Agenda attached.")
    result = runtime.evaluate_action_command.execute(req)

    camel = next(
        r for r in result.pdp_result.specialist_bundle.results
        if r.specialist_name == "camel"
    )
    # No plan was compiled → the specialist abstained with no_plan, NOT a branch verdict.
    assert "camel.branch_leverage_abstain" not in camel.matched_policy_clause_ids
    assert "no_plan" in camel.uncertainty_flags


def test_dod4_default_off_inert(runtime, monkeypatch):
    """With the emission flag UNSET, a request that DECLARES a branch flow still gets
    NO plan compiled at the seam — default-OFF means the activation is dormant."""
    monkeypatch.delenv("TEX_CAMEL_EMIT_ENABLED", raising=False)

    req = _request("refund", metadata={"camel_branch_flow": _high_stakes_flow_block()})
    result = runtime.evaluate_action_command.execute(req)

    camel = next(
        r for r in result.pdp_result.specialist_bundle.results
        if r.specialist_name == "camel"
    )
    # No plan stamped (flag off) → specialist abstains, no metered branch fired.
    assert "no_plan" in camel.uncertainty_flags
    assert "camel.branch_leverage_abstain" not in camel.matched_policy_clause_ids


def test_dod4_in_budget_branch_does_not_abstain(runtime, monkeypatch):
    """Faithfulness both ways: a REAL branch flow that is WITHIN budget (reversible,
    leverage tolerated) runs the metered interpreter on the real path but does NOT
    ABSTAIN on CHOKE-X — proving the mechanism is genuinely measuring leverage, not
    rubber-stamping every branch to ABSTAIN."""
    monkeypatch.setenv("TEX_CAMEL_EMIT_ENABLED", "1")

    block = dict(_high_stakes_flow_block())
    # Reversible + a leverage budget that admits the 1-bit branch → not high-stakes
    # via CHOKE-X over-budget. (It may still HALT on the empty tool policy, which is a
    # FORBID, not a branch-leverage ABSTAIN — that is fine; the point is the CHOKE-X
    # over-budget ABSTAIN signal specifically does NOT fire.)
    block["effect_class"] = "reversible"
    block["budget_bits"] = 4
    req = _request("refund", metadata={"camel_branch_flow": block})
    result = runtime.evaluate_action_command.execute(req)

    camel = next(
        r for r in result.pdp_result.specialist_bundle.results
        if r.specialist_name == "camel"
    )
    assert "camel.branch_leverage_abstain" not in camel.matched_policy_clause_ids


# ---------------------------------------------------------------------------
# (E) VALUE-BUDGET CEILING reads FROM the signed token grant
# ---------------------------------------------------------------------------


def test_value_budget_ceiling_reads_from_signed_grant(monkeypatch):
    """The LEDGERED value-budget ceiling reads from the SIGNED ``value_budget`` claim
    in a verified capability token (the iter-5 carried-but-unconsumed budget, now
    consumed). A token whose signed value_budget is tighter than the config default
    lowers the ceiling; verify-before means an unverifiable/absent token falls back to
    the config default."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from tex.camel.capability_token import (
        CapabilityGrant,
        make_use_proof,
        mint_capability_token,
    )
    from tex.deterministic.value_budget import BudgetConfig, resolve_budget_ceiling
    from tex.identity.agent_credential import AttestedIdentity

    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", "captoken-test-secret")
    monkeypatch.setenv("TEX_PERMIT_SIGNING_SECRET", "captoken-test-secret")
    monkeypatch.setenv("TEX_APP_ENV", "test")
    monkeypatch.setenv("TEX_CAP_TOKEN_ENABLED", "1")

    holder = Ed25519PrivateKey.generate()
    att = AttestedIdentity(
        verified=True, status="verified", issuer="entra://contoso",
        claimed_agent_id="agent-budget",
    )
    grant = CapabilityGrant(
        steer_budget=3.0,
        branch_leverage_budget=2,
        value_budget=5,  # a TIGHT signed ceiling, well below the config default
        audience="tex.camel.interpreter",
        lineage="default",
    )
    minted = mint_capability_token(
        att, grant=grant, cnf_public_key=holder.public_key(),
    )
    assert minted is not None
    pop = make_use_proof(holder, minted.token)

    config = BudgetConfig(enabled=True, max_confidential=32)
    req = _request(
        "x",
        metadata={
            "camel_capability_token": minted.token,
            "camel_capability_pop_proof": pop,
        },
    )
    # The verified grant's signed value_budget (5) is the effective ceiling, NOT the
    # config default (32).
    assert resolve_budget_ceiling(req, config) == 5

    # Verify-before: drop the PoP proof → the cnf-bound token cannot verify → no
    # grant → fall back to the config default (no widening from an unverified claim).
    req_no_pop = _request(
        "x", metadata={"camel_capability_token": minted.token}
    )
    assert resolve_budget_ceiling(req_no_pop, config) == 32

    # Default-OFF: with the cap-token flag unset, the grant is never consulted.
    monkeypatch.delenv("TEX_CAP_TOKEN_ENABLED", raising=False)
    assert resolve_budget_ceiling(req, config) == 32
