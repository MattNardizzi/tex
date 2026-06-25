"""UNIFIED BROKER CAPABILITY-TOKEN — one proof-carrying capability-future carrying
all three execution budgets (CFI steer / CHOKE-X branch leverage / LEDGERED value),
verified BEFORE a branch commits, sender-constrained, offline-attenuable, sealed.

Falsifiable per the iteration spec (real crypto — the broker's HMAC over canonical
JSON; no theater):

 (1) mint+verify         — a minted token verifies and decodes the three budgets.
 (2) tamper              — mutate ANY budget claim -> the broker signature check
                           FAILS (real HMAC), verify returns no grant.
 (3) token-budget        — an interpreter run under a token whose steer_budget == 0
                           ABSTAINs at the first metered branch (the budget came
                           from the SIGNED token, not the constructor).
 (4) sender-constraint   — a token presented WITHOUT the matching cnf/DPoP PoP
                           proof is REJECTED (no grant) before any commit.
 (5) attenuation         — a strictly-narrower sub-token verifies; a sub-token that
                           attempts to WIDEN a budget (or broaden the audience) is
                           REJECTED.
 (6) ledger-seal         — the CFI total + branch certs seal into the SealedFactLedger
                           via append_sequenced; a gap/replay makes verify_no_gaps
                           fail -> trust_sealed_run is False (-> ABSTAIN, not trusted).
 (7) default-OFF inert   — flag unset => the helper is False and the interpreter run
                           with NO grant is bit-for-bit the iter-3/4 behavior.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tex.camel import (
    Assign,
    Branch,
    Call,
    CamelInterpreter,
    CapabilityGrant,
    CapValue,
    CapabilityLevel,
    Literal,
    Plan,
    QLLM,
    Read,
    Return,
    ToolPolicy,
    ToolPolicyRegistry,
    Var,
    attenuate,
    capability_tokens_enabled,
    make_use_proof,
    mint_capability_token,
    seal_run,
    trust_sealed_run,
    verify_capability_token,
)
from tex.camel.capability_token import (
    AttenuationError,
    _budget_scope,
    _parse_budget_scope,
)
from tex.enforcement.permit import _b64url_decode, _canonical
from tex.identity.agent_credential import AttestedIdentity
from tex.provenance.ledger import SealedFactLedger

_AUD = "tex.camel.interpreter"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    """Hermetic broker signing secret so mint/verify agree (same discipline as the
    authority-plane conftest)."""
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", "captoken-test-secret")
    monkeypatch.setenv("TEX_PERMIT_SIGNING_SECRET", "captoken-test-secret")
    monkeypatch.setenv("TEX_APP_ENV", "test")
    yield


@pytest.fixture
def holder() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _att(agent_id="agent-7", issuer="entra://contoso") -> AttestedIdentity:
    return AttestedIdentity(
        verified=True, status="verified", issuer=issuer, claimed_agent_id=agent_id
    )


def _grant(steer=3.0, leverage=2, value=32, lineage="lin-1") -> CapabilityGrant:
    return CapabilityGrant(
        steer_budget=steer,
        branch_leverage_budget=leverage,
        value_budget=value,
        audience=_AUD,
        lineage=lineage,
    )


def _frozen_registry(*policies: ToolPolicy) -> ToolPolicyRegistry:
    reg = ToolPolicyRegistry()
    for p in policies:
        reg.register(p)
    return reg.freeze()


class _FixedQLLM:
    def __init__(self, answer: str) -> None:
        self._answer = answer

    def answer(self, query: str, inputs):  # noqa: ARG002
        return self._answer


def _metered_branch_plan() -> Plan:
    """A QLLM('yes' over yes/no) feeding a Branch whose disjoint arms reach
    send_email vs archive (sink weight 2) -> a 1*2 = 2-bit metered branch."""
    # ``r`` is pre-bound so that if the metered Branch ABSTAINs (is skipped), the
    # final Return still resolves a bound var (the ABSTAIN does not cascade into an
    # unbound-var HALT). When the branch DOES run, its Call rebinds ``r``.
    return Plan(
        nodes=(
            Assign(name="msg", expr=Read(source="email_body")),
            Assign(name="r", expr=Literal(value="unrun")),
            QLLM(
                query="urgent?",
                inputs=(Var(name="msg"),),
                result_var="decision",
                output_domain=("yes", "no"),
            ),
            Branch(
                cond_var="decision",
                then_nodes=(
                    Call(tool="send_email", args=(Var(name="msg"),), result_var="r"),
                ),
                else_nodes=(
                    Call(tool="archive", args=(Var(name="msg"),), result_var="r"),
                ),
            ),
            Return(expr=Var(name="r")),
        )
    )


def _interp(steer_budget=float("inf")) -> CamelInterpreter:
    reg = _frozen_registry(
        ToolPolicy(tool_name="send_email", max_arg_levels=(CapabilityLevel.UNTRUSTED,)),
        ToolPolicy(tool_name="archive", max_arg_levels=(CapabilityLevel.UNTRUSTED,)),
    )
    return CamelInterpreter(
        tool_policies=reg,
        tool_impls={
            "send_email": lambda *a: CapValue.derived("emailed", from_values=a),
            "archive": lambda *a: CapValue.derived("archived", from_values=a),
        },
        q_llm=_FixedQLLM("yes"),
        untrusted_env={"email_body": "please decide"},
        steer_budget=steer_budget,
    )


# ---------------------------------------------------------------------------
# (1) mint + verify
# ---------------------------------------------------------------------------


def test_mint_then_verify_decodes_three_budgets(holder):
    tok = mint_capability_token(
        _att(), grant=_grant(), cnf_public_key=holder.public_key(), now=1000.0
    )
    assert tok is not None
    assert tok.cnf_jkt is not None  # PoP sender-constrained
    proof = make_use_proof(holder, tok.token, now=1001.0)
    grant = verify_capability_token(
        tok.token, expected_audience=_AUD, pop_proof=proof, lineage="lin-1", now=1001.0
    )
    assert grant is not None
    assert grant.steer_budget == 3.0
    assert grant.branch_leverage_budget == 2
    assert grant.value_budget == 32


def test_scope_codec_roundtrip():
    g = _grant(steer=1.5, leverage=4, value=8)
    scope = _budget_scope(g)
    assert _parse_budget_scope(scope) == (1.5, 4, 8)


def test_unverified_identity_mints_nothing(holder):
    bad = AttestedIdentity(
        verified=False, status="untrusted_issuer", issuer=None, claimed_agent_id="x"
    )
    assert (
        mint_capability_token(
            bad, grant=_grant(), cnf_public_key=holder.public_key(), now=1000.0
        )
        is None
    )


# ---------------------------------------------------------------------------
# (2) tamper a budget claim -> real HMAC verification FAILS
# ---------------------------------------------------------------------------


def _tamper_budgets(token: str, *, steer, leverage, value) -> str:
    """Rewrite the signed body's scope to widen the budgets, KEEPING the original
    signature. The broker re-signs the body and compares — so a mutated budget
    must fail the signature check. This is the real-HMAC falsification."""
    import json

    body, _, sig = token.partition(".")
    claims = json.loads(_b64url_decode(body))
    claims["scope"] = [
        f"cap:steer_budget={steer!r}",
        f"cap:branch_leverage_budget={leverage:d}",
        f"cap:value_budget={value:d}",
    ]
    return f"{_canonical(claims)}.{sig}"


def test_tampered_budget_fails_signature(holder):
    tok = mint_capability_token(
        _att(), grant=_grant(steer=1.0, leverage=1, value=4),
        cnf_public_key=holder.public_key(), now=1000.0,
    )
    assert tok is not None
    tampered = _tamper_budgets(tok.token, steer=999.0, leverage=99, value=9999)
    proof = make_use_proof(holder, tampered, now=1001.0)
    grant = verify_capability_token(
        tampered, expected_audience=_AUD, pop_proof=proof, lineage="lin-1", now=1001.0
    )
    assert grant is None  # bad signature -> no grant -> fail-closed


def test_tamper_detected_directly_by_broker_verify(holder):
    """Belt-and-braces: the broker's own verify reports 'bad signature' on the
    tampered token (proves the rejection is the HMAC, not a parse quirk)."""
    from tex.authority.broker import CredentialBroker

    tok = mint_capability_token(
        _att(), grant=_grant(), cnf_public_key=holder.public_key(), now=1000.0
    )
    tampered = _tamper_budgets(tok.token, steer=999.0, leverage=99, value=9999)
    proof = make_use_proof(holder, tampered, now=1001.0)
    check = CredentialBroker().verify(
        tampered, expected_audience=_AUD, expected_action="execute_plan",
        pop_proof=proof, now=1001.0,
    )
    assert not check.ok and check.reason == "bad signature"


# ---------------------------------------------------------------------------
# (3) interpreter consumes the SIGNED steer_budget (== 0 -> first branch ABSTAINs)
# ---------------------------------------------------------------------------


def test_interpreter_uses_token_steer_budget_zero_abstains(holder):
    # Mint a token whose SIGNED steer_budget is 0. The interpreter is built with an
    # UNBOUNDED constructor budget — so if it ABSTAINs, the 0 came from the token.
    tok = mint_capability_token(
        _att(), grant=_grant(steer=0.0, leverage=8, value=32),
        cnf_public_key=holder.public_key(), now=1000.0,
    )
    proof = make_use_proof(holder, tok.token, now=1001.0)
    grant = verify_capability_token(
        tok.token, expected_audience=_AUD, pop_proof=proof, lineage="lin-1", now=1001.0
    )
    assert grant is not None and grant.steer_budget == 0.0

    interp = _interp(steer_budget=float("inf"))  # generous constructor default
    value, trace = interp.run(_metered_branch_plan(), capability_grant=grant)
    # The metered branch debits 2 bits > the SIGNED 0 budget -> ABSTAIN, no halt.
    assert trace.abstained is True
    assert not trace.halted
    assert "steer budget exhausted" in (trace.abstain_reason or "")
    # The branch was skipped: neither arm ran, so ``r`` keeps its pre-branch value.
    assert value.value == "unrun"


def test_interpreter_token_budget_generous_executes(holder):
    # A generous SIGNED budget (>= 2) lets the same branch execute.
    tok = mint_capability_token(
        _att(), grant=_grant(steer=4.0, leverage=8, value=32),
        cnf_public_key=holder.public_key(), now=1000.0,
    )
    proof = make_use_proof(holder, tok.token, now=1001.0)
    grant = verify_capability_token(
        tok.token, expected_audience=_AUD, pop_proof=proof, lineage="lin-1", now=1001.0
    )
    interp = _interp(steer_budget=0.0)  # STINGY constructor — token must override it
    value, trace = interp.run(_metered_branch_plan(), capability_grant=grant)
    # If the constructor's 0 had governed, this would ABSTAIN. The SIGNED 4 governs.
    assert not trace.abstained
    assert trace.cfi_bits_spent == 2.0
    assert value.value == "emailed"


# ---------------------------------------------------------------------------
# (4) sender-constraint — missing / wrong PoP rejected
# ---------------------------------------------------------------------------


def test_missing_pop_proof_rejected(holder):
    tok = mint_capability_token(
        _att(), grant=_grant(), cnf_public_key=holder.public_key(), now=1000.0
    )
    grant = verify_capability_token(
        tok.token, expected_audience=_AUD, pop_proof=None, lineage="lin-1", now=1001.0
    )
    assert grant is None  # cnf-bound token requires a PoP proof


def test_wrong_key_pop_proof_rejected(holder):
    tok = mint_capability_token(
        _att(), grant=_grant(), cnf_public_key=holder.public_key(), now=1000.0
    )
    thief = Ed25519PrivateKey.generate()  # a different key than the bound cnf
    bad_proof = make_use_proof(thief, tok.token, now=1001.0)
    grant = verify_capability_token(
        tok.token, expected_audience=_AUD, pop_proof=bad_proof, lineage="lin-1", now=1001.0
    )
    assert grant is None  # thumbprint mismatch -> rejected


# ---------------------------------------------------------------------------
# (5) attenuation — narrower verifies; widening rejected
# ---------------------------------------------------------------------------


def test_attenuation_narrower_verifies(holder):
    tok = mint_capability_token(
        _att(), grant=_grant(steer=4.0, leverage=4, value=32),
        cnf_public_key=holder.public_key(), now=1000.0,
    )
    sub = attenuate(
        tok, _att(),
        sub_grant=_grant(steer=1.0, leverage=1, value=8),
        cnf_public_key=holder.public_key(), now=1000.0,
    )
    proof = make_use_proof(holder, sub.token, now=1001.0)
    grant = verify_capability_token(
        sub.token, expected_audience=_AUD, pop_proof=proof, lineage="lin-1", now=1001.0
    )
    assert grant is not None
    assert grant.steer_budget == 1.0
    assert grant.branch_leverage_budget == 1
    assert grant.value_budget == 8


@pytest.mark.parametrize(
    "wide",
    [
        dict(steer=99.0, leverage=1, value=8),   # widen steer
        dict(steer=1.0, leverage=99, value=8),   # widen leverage
        dict(steer=1.0, leverage=1, value=999),  # widen value
    ],
)
def test_attenuation_widening_rejected(holder, wide):
    tok = mint_capability_token(
        _att(), grant=_grant(steer=4.0, leverage=4, value=32),
        cnf_public_key=holder.public_key(), now=1000.0,
    )
    with pytest.raises(AttenuationError):
        attenuate(
            tok, _att(),
            sub_grant=_grant(**wide),
            cnf_public_key=holder.public_key(), now=1000.0,
        )


def test_attenuation_audience_broadening_rejected(holder):
    tok = mint_capability_token(
        _att(), grant=_grant(), cnf_public_key=holder.public_key(), now=1000.0
    )
    broader = CapabilityGrant(
        steer_budget=1.0, branch_leverage_budget=1, value_budget=8,
        audience="tex.everything", lineage="lin-1",
    )
    with pytest.raises(AttenuationError):
        attenuate(
            tok, _att(), sub_grant=broader,
            cnf_public_key=holder.public_key(), now=1000.0,
        )


# ---------------------------------------------------------------------------
# (6) ledger-seal — seals into the chain; gap/replay -> not trusted -> ABSTAIN
# ---------------------------------------------------------------------------


def test_seal_run_into_chain_and_trusted():
    led = SealedFactLedger()
    sealed = seal_run(
        led,
        lineage="lin-1",
        cfi_total_bits=2.0,
        steer_budget=4.0,
        branch_certificates=(("decision", 1.0, 0),),
    )
    assert sealed.cfi_record_hash
    assert len(sealed.branch_record_hashes) == 1
    # The chain is intact and this lineage has no gap -> trusted.
    assert led.verify_chain()["intact"] is True
    assert trust_sealed_run(led, lineage="lin-1") is True


def test_seal_run_replay_breaks_no_gaps_so_not_trusted():
    led = SealedFactLedger()
    seal_run(led, lineage="lin-1", cfi_total_bits=2.0, steer_budget=4.0)
    # Forge a REPLAY: re-append the same lineage's first record under a DUPLICATE
    # identity_seq. verify_no_gaps then reports a duplicate for this lineage.
    first = led.list_for_identity("lin-1")[0]
    from tex.provenance.models import SealedFact

    replayed = first.fact.model_copy(
        update={"detail": {**first.fact.detail, "identity_key": "lin-1", "identity_seq": 0}}
    )
    led.append(replayed)  # plain append keeps the chain intact but duplicates seq 0
    assert led.verify_chain()["intact"] is True
    gaps = led.verify_no_gaps()
    assert "lin-1" in gaps["duplicates"]
    # Budget can no longer be trusted -> caller ABSTAINs.
    assert trust_sealed_run(led, lineage="lin-1") is False


def test_seal_run_tamper_breaks_chain_so_not_trusted():
    led = SealedFactLedger()
    seal_run(led, lineage="lin-1", cfi_total_bits=2.0, steer_budget=4.0)
    # Tamper a sealed record in place -> verify_chain breaks -> not trusted.
    rec = led._entries[0]
    bad_fact = rec.fact.model_copy(update={"claim": "TAMPERED cumulative budget claim"})
    led._entries[0] = rec.model_copy(update={"fact": bad_fact})
    assert led.verify_chain()["intact"] is False
    assert trust_sealed_run(led, lineage="lin-1") is False


# ---------------------------------------------------------------------------
# (7) default-OFF inert
# ---------------------------------------------------------------------------


def test_flag_default_off(monkeypatch):
    monkeypatch.delenv("TEX_CAP_TOKEN_ENABLED", raising=False)
    assert capability_tokens_enabled() is False
    assert capability_tokens_enabled({}) is False


def test_flag_on_truthy():
    assert capability_tokens_enabled({"TEX_CAP_TOKEN_ENABLED": "1"}) is True
    assert capability_tokens_enabled({"TEX_CAP_TOKEN_ENABLED": "true"}) is True
    assert capability_tokens_enabled({"TEX_CAP_TOKEN_ENABLED": "off"}) is False


def test_interpreter_no_grant_is_iter3_behavior():
    """With NO capability_grant the interpreter is bit-for-bit the iter-3/4 path:
    the constructor steer_budget governs, exactly as before this iteration."""
    # Stingy constructor budget 0 -> the metered branch ABSTAINs (iter-3 behavior),
    # and NO grant is supplied (the default-OFF call shape).
    interp = _interp(steer_budget=0.0)
    _v, trace = interp.run(_metered_branch_plan())
    assert trace.abstained is True
    # Generous constructor budget -> executes, exactly as iter-3.
    interp2 = _interp(steer_budget=float("inf"))
    v2, trace2 = interp2.run(_metered_branch_plan())
    assert not trace2.abstained and v2.value == "emailed"
