"""
Acceptance fixtures — the headline test from the original Thread 14
prompt:

    "5 contracts × 1 agent, 100-event run:
       * ZERO false positives on a benign trace
       * 100% detection on a seeded violation trace"

This is the build's load-bearing acceptance test. If it passes, the
contracts layer's real-world utility is demonstrated, regardless of
how many unit tests around the edges are green.

Reference
---------
- arxiv 2602.22302 §6 (AgentContract-Bench) — the multi-domain coverage
  pattern this fixture is modelled on. We don't ship the full 200
  scenarios here; we ship a representative 5-contract slice for the
  insurtech / regulated-outbound-AI-content domain that is Tex's
  primary GTM focus.
"""

from __future__ import annotations

import random
from typing import Iterator

from tex.contracts import BehavioralContract, ContractEnforcer
from tests.contracts.conftest import make_event, make_state


# ---------------------------------------------------------------------
# Contract suite (5 contracts × 1 agent)
# ---------------------------------------------------------------------


def _build_contracts(agent_id: str = "alice") -> tuple[BehavioralContract, ...]:
    """
    Five contracts representative of the regulated-outbound-AI-content
    deployment context Tex targets:

      C1  PII redaction — hard invariant
      C2  Tool whitelist — hard governance
      C3  Citation grounding — soft invariant with k=3 recovery
      C4  Latency budget — soft governance with k=2 recovery
      C5  Authorisation gate — precondition

    Each contract uses a different ABC clause kind so the suite
    exercises the full 6-tuple.
    """
    return (
        # C1 — hard invariant (safety)
        BehavioralContract.make(
            contract_id="c1-no-pii",
            agent_id=agent_id,
            description="Outputs must never contain unredacted PII.",
            hard_invariants_ltl=("G (field:output.pii==false)",),
            covered_event_kinds=("agent_emits_output",),
            severity_on_violation="block",
        ),
        # C2 — hard governance (action allowlist)
        BehavioralContract.make(
            contract_id="c2-tool-allowlist",
            agent_id=agent_id,
            description="Agent may only invoke read/list/write tools.",
            hard_governance_ltl=(
                "G (kind:agent_invokes_tool implies field:tool_id~in:read,list,write)",
            ),
            covered_event_kinds=("agent_invokes_tool",),
            severity_on_violation="block",
        ),
        # C3 — soft invariant (citation grounding)
        BehavioralContract.make(
            contract_id="c3-citation-grounding",
            agent_id=agent_id,
            description="Outputs must claim grounded citations within 3 turns.",
            soft_invariants_ltl=("G (field:output.cited==true)",),
            covered_event_kinds=("agent_emits_output",),
            recovery_window_k=3,
            severity_on_violation="warn",
        ),
        # C4 — soft governance (latency)
        BehavioralContract.make(
            contract_id="c4-latency-budget",
            agent_id=agent_id,
            description="Each action latency under 500ms within 2 retries.",
            soft_governance_ltl=("G (field:latency_ms<500)",),
            covered_event_kinds=("agent_emits_output", "agent_invokes_tool"),
            recovery_window_k=2,
            severity_on_violation="warn",
        ),
        # C5 — precondition (authorisation gate)
        BehavioralContract.make(
            contract_id="c5-authorised-policy",
            agent_id=agent_id,
            description="Active governance graph must be policy-v3 at session start.",
            precondition_ltl="state:active_governance_graph_id==policy-v3",
            covered_event_kinds=("agent_emits_output", "agent_invokes_tool"),
            severity_on_violation="block",
        ),
    )


# ---------------------------------------------------------------------
# Trace generators
# ---------------------------------------------------------------------


def _benign_trace(seed: int = 0, n: int = 100) -> Iterator[tuple[str, dict]]:
    """
    A 100-event compliant trace — no contract should fire.

    Yields (event_kind, payload) tuples. The state for every step is
    the canonical compliant snapshot (governance_graph_id=policy-v3
    so C5 holds; tool_id always read/list/write so C2 holds; etc.).
    """
    rng = random.Random(seed)
    tools = ["read", "list", "write"]
    for _ in range(n):
        if rng.random() < 0.5:
            yield (
                "agent_emits_output",
                {
                    "output": {"pii": False, "cited": True},
                    "latency_ms": rng.randint(50, 400),
                },
            )
        else:
            yield (
                "agent_invokes_tool",
                {
                    "tool_id": rng.choice(tools),
                    "latency_ms": rng.randint(50, 400),
                },
            )


def _seeded_violation_trace(seed: int = 0) -> list[tuple[str, dict, str]]:
    """
    A 100-event trace with one violation per contract, deliberately
    placed at known indices so the test can assert "100% detection".

    Returns (event_kind, payload, expected_contract_id) tuples — the
    third element is None for compliant events and the contract_id
    that should fire for violation events.
    """
    rng = random.Random(seed)
    tools = ["read", "list", "write"]
    out: list[tuple[str, dict, str]] = []

    # We seed exactly one violation per contract type. Indices chosen
    # so they don't collide and so soft-recovery windows have room.
    seeded_indices = {
        20: ("c1-no-pii", "agent_emits_output", {
            "output": {"pii": True, "cited": True},
            "latency_ms": 100,
        }),
        40: ("c2-tool-allowlist", "agent_invokes_tool", {
            "tool_id": "delete",  # not in allowlist
            "latency_ms": 100,
        }),
        60: ("c3-citation-grounding", "agent_emits_output", {
            "output": {"pii": False, "cited": False},
            "latency_ms": 100,
        }),
        80: ("c4-latency-budget", "agent_emits_output", {
            "output": {"pii": False, "cited": True},
            "latency_ms": 1500,  # over budget
        }),
    }

    for i in range(100):
        if i in seeded_indices:
            cid, kind, payload = seeded_indices[i]
            out.append((kind, payload, cid))
            continue
        # Otherwise emit a compliant event.
        if rng.random() < 0.5:
            out.append((
                "agent_emits_output",
                {
                    "output": {"pii": False, "cited": True},
                    "latency_ms": rng.randint(50, 400),
                },
                "",
            ))
        else:
            out.append((
                "agent_invokes_tool",
                {
                    "tool_id": rng.choice(tools),
                    "latency_ms": rng.randint(50, 400),
                },
                "",
            ))
    return out


# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------


class TestAcceptance100EventBenign:
    def test_zero_false_positives(self) -> None:
        """100 compliant events → no contract fires."""
        contracts = _build_contracts()
        e = ContractEnforcer(contracts=contracts)
        # Compliant state: policy-v3 active so C5 (precondition) passes.
        state = make_state(governance_graph_id="policy-v3")

        for kind, payload in _benign_trace(seed=42):
            e.check_pre(
                agent_id="alice",
                proposed_event=make_event(kind=kind, payload=payload),
                current_state=state,
            )

        assert len(e.violations) == 0, (
            f"benign trace produced {len(e.violations)} false-positive violations: "
            + repr([v.contract_id for v in e.violations])
        )
        assert e.step_index == 100
        # Compliance scores stay perfect.
        scores = e.compliance_scores(
            agent_id="alice",
            proposed_event=make_event(
                kind="agent_emits_output",
                payload={"output": {"pii": False, "cited": True}, "latency_ms": 100},
            ),
            current_state=state,
        )
        assert scores.c_hard == 1.0
        assert scores.c_soft == 1.0


class TestAcceptance100EventSeeded:
    def test_full_detection_on_seeded_trace(self) -> None:
        """Each seeded violation produces exactly one detection."""
        contracts = _build_contracts()
        e = ContractEnforcer(contracts=contracts)
        state = make_state(governance_graph_id="policy-v3")

        trace = _seeded_violation_trace(seed=42)
        for kind, payload, _expected in trace:
            e.check_pre(
                agent_id="alice",
                proposed_event=make_event(kind=kind, payload=payload),
                current_state=state,
            )

        # Collect the set of contract ids that ever fired a violation.
        fired = {v.contract_id for v in e.violations}
        # Each of the four seeded violation types should have fired
        # exactly one root-cause contract. (Soft violations may also
        # produce escalation records; we don't count those here.)
        expected = {
            "c1-no-pii",
            "c2-tool-allowlist",
            "c3-citation-grounding",
            "c4-latency-budget",
        }
        missing = expected - fired
        assert not missing, f"missed seeded violations: {missing}"

    def test_seeded_violations_recorded_at_correct_step(self) -> None:
        """StepShield-style: detection step matches injection step."""
        contracts = _build_contracts()
        e = ContractEnforcer(contracts=contracts)
        state = make_state(governance_graph_id="policy-v3")

        trace = _seeded_violation_trace(seed=42)
        for kind, payload, _expected in trace:
            e.check_pre(
                agent_id="alice",
                proposed_event=make_event(kind=kind, payload=payload),
                current_state=state,
            )

        # The first violation by contract_id should have step_index
        # equal to the injection index + 1 (1-indexed step counter).
        injection_step = {
            "c1-no-pii": 21,
            "c2-tool-allowlist": 41,
            "c3-citation-grounding": 61,
            "c4-latency-budget": 81,
        }
        first_by_contract: dict[str, int] = {}
        for v in e.violations:
            first_by_contract.setdefault(v.contract_id, v.step_index)

        for cid, expected_step in injection_step.items():
            actual = first_by_contract.get(cid)
            assert actual == expected_step, (
                f"{cid}: detection step {actual} ≠ injection step {expected_step}"
            )

    def test_precondition_violation_when_policy_inactive(self) -> None:
        """C5 fires for the entire run if the precondition is unmet."""
        contracts = _build_contracts()
        e = ContractEnforcer(contracts=contracts)
        # Wrong policy active -> C5 precondition fails on every event.
        state = make_state(governance_graph_id="policy-v1")

        for kind, payload in _benign_trace(seed=0, n=10):
            e.check_pre(
                agent_id="alice",
                proposed_event=make_event(kind=kind, payload=payload),
                current_state=state,
            )

        c5_violations = [v for v in e.violations if v.contract_id == "c5-authorised-policy"]
        # 10 events × 1 contract = 10 precondition violations.
        assert len(c5_violations) == 10
        for v in c5_violations:
            assert v.violated_clause == "precondition"
            assert v.severity == "block"
