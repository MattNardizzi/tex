"""Thread 12: AgentDojo eval harness — smoke + integration tests."""

from __future__ import annotations

import json
from pathlib import Path

from tex.bench.agentdojo import (
    AgentDojoHarness,
    HarnessConfig,
    PdpVerdict,
    StubAgentModel,
    TaskOutcome,
    TexPipelineDefense,
)
from tex.bench.agentdojo.harness import BUNDLED_TASKS


def _pdp_permissive(_candidate):
    return PdpVerdict.PERMIT, ()


def _pdp_block_injections(candidate):
    tool = candidate.get("tool", "")
    if tool in {"transfer", "send_dm"}:
        return PdpVerdict.FORBID, (f"irreversible:{tool}",)
    return PdpVerdict.PERMIT, ()


def test_harness_runs_smoke_with_stub_model():
    harness = AgentDojoHarness(
        config=HarnessConfig(max_steps=4, smoke=True),
        defense=TexPipelineDefense(pdp_callable=_pdp_permissive),
    )
    outcomes = harness.run(StubAgentModel())
    assert len(outcomes) == 2
    assert all(isinstance(o, TaskOutcome) for o in outcomes)


def test_harness_summary_reports_asr():
    harness = AgentDojoHarness(
        config=HarnessConfig(max_steps=4),
        defense=TexPipelineDefense(pdp_callable=_pdp_permissive),
    )
    outcomes = harness.run(StubAgentModel())
    summary = AgentDojoHarness.summarize(outcomes)
    # asr should be > 0 with permissive PDP and injection-case tasks present
    assert summary["asr"] > 0.0


def test_harness_strict_pdp_blocks_injections():
    harness = AgentDojoHarness(
        config=HarnessConfig(max_steps=4),
        defense=TexPipelineDefense(pdp_callable=_pdp_block_injections),
    )
    outcomes = harness.run(StubAgentModel())
    summary = AgentDojoHarness.summarize(outcomes)
    # strict PDP should drive ASR to 0
    assert summary["asr"] == 0.0
    # at least one FORBID was emitted
    total_forbids = sum(o.pdp_forbids for o in outcomes)
    assert total_forbids >= 1


def test_evidence_chain_links_outcomes():
    harness = AgentDojoHarness(
        config=HarnessConfig(max_steps=4),
        defense=TexPipelineDefense(pdp_callable=_pdp_permissive),
    )
    outcomes = harness.run(StubAgentModel())
    assert outcomes[0].prev_hash == "0" * 64
    for i in range(1, len(outcomes)):
        assert outcomes[i].prev_hash == outcomes[i - 1].evidence_hash


def test_harness_writes_jsonl(tmp_path: Path):
    out_dir = tmp_path / "agentdojo"
    harness = AgentDojoHarness(
        config=HarnessConfig(max_steps=4, output_dir=str(out_dir)),
        defense=TexPipelineDefense(pdp_callable=_pdp_permissive),
    )
    harness.run(StubAgentModel())
    out_file = out_dir / "outcomes.jsonl"
    assert out_file.exists()
    lines = [l for l in out_file.read_text().splitlines() if l.strip()]
    assert len(lines) >= 1
    for line in lines:
        parsed = json.loads(line)
        assert "task_id" in parsed
        assert "evidence_hash" in parsed


def test_filter_by_suite():
    harness = AgentDojoHarness(
        config=HarnessConfig(suite="banking", max_steps=4),
        defense=TexPipelineDefense(pdp_callable=_pdp_permissive),
    )
    outcomes = harness.run(StubAgentModel())
    assert all(o.suite == "banking" for o in outcomes)


def test_defense_refuses_with_message():
    defense = TexPipelineDefense(
        pdp_callable=lambda c: (PdpVerdict.FORBID, ("policy_X",))
    )
    decision = defense.adjudicate({"tool": "send_email", "args": {}})
    assert decision.permitted_tool_call is False
    assert "FORBID" in (decision.refusal_message or "")
    assert "policy_X" in (decision.refusal_message or "")


def test_defense_passes_permit():
    defense = TexPipelineDefense(
        pdp_callable=lambda c: (PdpVerdict.PERMIT, ())
    )
    decision = defense.adjudicate({"tool": "read", "args": {}})
    assert decision.permitted_tool_call is True
    assert decision.refusal_message is None


def test_defense_abstain_passes_with_note():
    defense = TexPipelineDefense(
        pdp_callable=lambda c: (PdpVerdict.ABSTAIN, ())
    )
    decision = defense.adjudicate({"tool": "read", "args": {}})
    assert decision.permitted_tool_call is True
    assert "pdp_abstain" in decision.notes
