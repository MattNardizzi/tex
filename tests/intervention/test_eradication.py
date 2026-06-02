"""
Tests for tex.intervention.eradication — AIR §3 eradication rule synthesis.

Coverage:
- IncidentContext + SynthesizedRule shape (frozen, slots)
- Deterministic-mode synthesis (severity escalation, rule_id determinism,
  predicate/depth count)
- LLM-mode synthesis with a stub client (parses JSON, falls back on error)
- Plan-level checks: schema, safety, cost
- InMemoryRuleRegistry: idempotent register, active_rules, matches
- Integration with InterventionEngine.apply() (FAIL-CLOSED when missing
  context / synth not wired; happy-path embeds rule in audit record)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from tex.intervention.eradication import (
    DEFAULT_MAX_LTLF_DEPTH,
    DEFAULT_MAX_PREDICATE_COUNT,
    EradicationRuleSynthesizer,
    IncidentContext,
    InMemoryRuleRegistry,
    SynthesizedRule,
)


# ----------------------------------------------------------------- fixtures


def _ctx(
    *,
    incident_id: str = "inc_001",
    actor: str = "agent_X",
    event_kind: str = "agent_invokes_tool",
    severity: float = 0.6,
    drift: float = 0.4,
    fingerprint: str = "abc123def456789",
    notes: str = "",
) -> IncidentContext:
    return IncidentContext(
        incident_id=incident_id,
        actor_entity_id=actor,
        event_kind=event_kind,
        target_entity_id="tool_Y",
        contract_violation_severity=severity,
        drift_delta=drift,
        payload_fingerprint=fingerprint,
        observed_at=datetime.now(UTC),
        notes=notes,
    )


# ------------------------------------------------------------------- shape


class TestIncidentContextShape:
    def test_is_frozen(self) -> None:
        ctx = _ctx()
        with pytest.raises((AttributeError, TypeError)):
            ctx.incident_id = "changed"  # type: ignore[misc]

    def test_required_fields_present(self) -> None:
        ctx = _ctx()
        assert ctx.incident_id == "inc_001"
        assert ctx.actor_entity_id == "agent_X"
        assert ctx.event_kind == "agent_invokes_tool"


class TestSynthesizedRuleShape:
    def test_is_frozen(self) -> None:
        synth = EradicationRuleSynthesizer()
        rule = synth.synthesise(_ctx())
        assert rule is not None
        with pytest.raises((AttributeError, TypeError)):
            rule.rule_id = "changed"  # type: ignore[misc]


# --------------------------------------------------------- deterministic mode


class TestDeterministicMode:
    def test_synthesises_a_rule(self) -> None:
        synth = EradicationRuleSynthesizer()
        rule = synth.synthesise(_ctx())
        assert rule is not None
        assert rule.synthesiser_mode == "deterministic"

    def test_severity_block_when_violation_high(self) -> None:
        synth = EradicationRuleSynthesizer()
        rule = synth.synthesise(_ctx(severity=0.9))
        assert rule is not None
        assert rule.severity == "block"

    def test_severity_warn_when_violation_low(self) -> None:
        synth = EradicationRuleSynthesizer()
        rule = synth.synthesise(_ctx(severity=0.3))
        assert rule is not None
        assert rule.severity == "warn"

    def test_rule_id_deterministic_for_same_incident(self) -> None:
        """Two synthesisers called on the same incident produce the
        same rule_id (so retries are idempotent)."""
        synth = EradicationRuleSynthesizer()
        r1 = synth.synthesise(_ctx())
        r2 = synth.synthesise(_ctx())
        assert r1 is not None and r2 is not None
        assert r1.rule_id == r2.rule_id

    def test_rule_id_differs_for_different_incidents(self) -> None:
        synth = EradicationRuleSynthesizer()
        r1 = synth.synthesise(_ctx(actor="agent_A"))
        r2 = synth.synthesise(_ctx(actor="agent_B"))
        assert r1 is not None and r2 is not None
        assert r1.rule_id != r2.rule_id

    def test_predicate_count_matches_components(self) -> None:
        synth = EradicationRuleSynthesizer()
        rule = synth.synthesise(_ctx())
        assert rule is not None
        # 1 actor pattern + 1 forbidden_kind + 1 forbidden_substring = 3
        assert rule.predicate_count == 3

    def test_forbidden_kinds_include_originating_event(self) -> None:
        synth = EradicationRuleSynthesizer()
        rule = synth.synthesise(_ctx(event_kind="some_kind"))
        assert rule is not None
        assert "some_kind" in rule.forbidden_event_kinds


# ------------------------------------------------------------------ LLM mode


class TestLLMMode:
    def test_llm_mode_used_when_client_wired(self) -> None:
        client = MagicMock()
        client.generate_rule_json.return_value = json.dumps({
            "description": "LLM-generated rule",
            "applies_to_actor_pattern": "agent_X",
            "forbidden_event_kinds": ["agent_invokes_tool"],
            "forbidden_payload_substrings": ["secret_pattern"],
            "severity": "block",
        })
        synth = EradicationRuleSynthesizer(llm_client=client)
        rule = synth.synthesise(_ctx())
        assert rule is not None
        assert rule.synthesiser_mode == "llm"
        assert rule.description == "LLM-generated rule"
        assert rule.severity == "block"
        assert "secret_pattern" in rule.forbidden_payload_substrings

    def test_llm_failure_falls_back_to_deterministic(self) -> None:
        client = MagicMock()
        client.generate_rule_json.side_effect = RuntimeError("LLM down")
        synth = EradicationRuleSynthesizer(llm_client=client)
        rule = synth.synthesise(_ctx())
        # Synthesis still succeeds via deterministic fallback.
        assert rule is not None
        assert rule.synthesiser_mode == "deterministic"

    def test_llm_returns_invalid_json_falls_back(self) -> None:
        client = MagicMock()
        client.generate_rule_json.return_value = "not valid json {{"
        synth = EradicationRuleSynthesizer(llm_client=client)
        rule = synth.synthesise(_ctx())
        assert rule is not None
        assert rule.synthesiser_mode == "deterministic"

    def test_llm_returns_non_string_falls_back(self) -> None:
        client = MagicMock()
        client.generate_rule_json.return_value = 12345  # not a string
        synth = EradicationRuleSynthesizer(llm_client=client)
        rule = synth.synthesise(_ctx())
        assert rule is not None
        assert rule.synthesiser_mode == "deterministic"


# ------------------------------------------------------ plan-level checks


class TestPlanLevelChecks:
    def test_cost_ceiling_rejects_overcomplex_llm_rule(self) -> None:
        client = MagicMock()
        # 15 substrings > default ceiling of 10.
        client.generate_rule_json.return_value = json.dumps({
            "description": "wide rule",
            "applies_to_actor_pattern": "agent_X",
            "forbidden_event_kinds": ["kind_a", "kind_b"],
            "forbidden_payload_substrings": [f"sub_{i}" for i in range(15)],
            "severity": "warn",
        })
        synth = EradicationRuleSynthesizer(llm_client=client)
        rule = synth.synthesise(_ctx())
        # Cost check failed, so LLM path returned None; deterministic
        # fallback produced a small rule.
        assert rule is not None
        # The big LLM rule was rejected; we got the deterministic one.
        assert rule.predicate_count <= DEFAULT_MAX_PREDICATE_COUNT

    def test_default_predicate_ceiling_is_ten(self) -> None:
        assert DEFAULT_MAX_PREDICATE_COUNT == 10

    def test_default_ltlf_depth_ceiling_is_six(self) -> None:
        assert DEFAULT_MAX_LTLF_DEPTH == 6

    def test_input_validation_rejects_non_incident(self) -> None:
        synth = EradicationRuleSynthesizer()
        with pytest.raises(TypeError, match="IncidentContext"):
            synth.synthesise({"not": "an_incident"})  # type: ignore[arg-type]


# -------------------------------------------------------------- rule registry


class TestInMemoryRuleRegistry:
    def test_register_returns_true_on_new_rule(self) -> None:
        synth = EradicationRuleSynthesizer()
        rule = synth.synthesise(_ctx())
        assert rule is not None
        reg = InMemoryRuleRegistry()
        assert reg.register(rule) is True

    def test_register_returns_false_on_duplicate(self) -> None:
        synth = EradicationRuleSynthesizer()
        rule = synth.synthesise(_ctx())
        assert rule is not None
        reg = InMemoryRuleRegistry()
        reg.register(rule)
        assert reg.register(rule) is False  # idempotent

    def test_active_rules_lists_all(self) -> None:
        synth = EradicationRuleSynthesizer()
        r1 = synth.synthesise(_ctx(incident_id="i1", actor="A"))
        r2 = synth.synthesise(_ctx(incident_id="i2", actor="B"))
        reg = InMemoryRuleRegistry()
        reg.register(r1)  # type: ignore[arg-type]
        reg.register(r2)  # type: ignore[arg-type]
        assert len(reg.active_rules()) == 2

    def test_matches_when_actor_and_kind_match(self) -> None:
        synth = EradicationRuleSynthesizer()
        rule = synth.synthesise(_ctx(actor="agent_X", event_kind="kind_K"))
        assert rule is not None
        reg = InMemoryRuleRegistry()
        reg.register(rule)
        # Recurrence: same actor, same kind, payload includes the
        # fingerprint substring.
        matches = reg.matches(
            actor_entity_id="agent_X",
            event_kind="kind_K",
            payload_text="prefix_" + rule.forbidden_payload_substrings[0] + "_suffix",
        )
        assert len(matches) == 1

    def test_matches_zero_when_different_actor(self) -> None:
        synth = EradicationRuleSynthesizer()
        rule = synth.synthesise(_ctx(actor="agent_X"))
        assert rule is not None
        reg = InMemoryRuleRegistry()
        reg.register(rule)
        matches = reg.matches(
            actor_entity_id="agent_Y",
            event_kind=rule.forbidden_event_kinds[0],
            payload_text=rule.forbidden_payload_substrings[0],
        )
        assert len(matches) == 0

    def test_matches_zero_when_different_kind(self) -> None:
        synth = EradicationRuleSynthesizer()
        rule = synth.synthesise(_ctx(event_kind="kind_K"))
        assert rule is not None
        reg = InMemoryRuleRegistry()
        reg.register(rule)
        matches = reg.matches(
            actor_entity_id=rule.applies_to_actor_pattern,
            event_kind="other_kind",
            payload_text="anything",
        )
        assert len(matches) == 0

    def test_wildcard_actor_matches_anyone(self) -> None:
        # Manually build a wildcard rule.
        rule = SynthesizedRule(
            rule_id="rule_wild",
            derived_from_incident_id="inc_x",
            description="wild",
            applies_to_actor_pattern="*",
            forbidden_event_kinds=("kind_K",),
            forbidden_payload_substrings=(),
            severity="warn",
            synthesised_at=datetime.now(UTC),
            synthesiser_mode="deterministic",
            synthesiser_metadata={},
            predicate_count=1,
            ltlf_depth=2,
        )
        reg = InMemoryRuleRegistry()
        reg.register(rule)
        matches = reg.matches(
            actor_entity_id="any_actor",
            event_kind="kind_K",
            payload_text="anything",
        )
        assert len(matches) == 1


# ---------------------------------------- integration with InterventionEngine


class TestEngineEradicationIntegration:
    def test_engine_apply_eradication_fails_closed_without_synthesiser(
        self,
    ) -> None:
        from tex.intervention.bounded_compromise import BoundedCompromiseCalculator
        from tex.intervention.engine import (
            InterventionApplyError,
            InterventionEngine,
        )
        from tex.intervention.kinds import Intervention, InterventionKind

        eng = InterventionEngine(
            bounded_compromise_calc=BoundedCompromiseCalculator(),
            ledger=None,
        )
        iv = Intervention(
            intervention_id="iv_erad",
            kind=InterventionKind.ERADICATION_RULE_SYNTHESIS,
            target_entity_id="agent_X",
            parameters={"incident_context": {
                "incident_id": "inc_001",
                "actor_entity_id": "agent_X",
                "event_kind": "k",
                "contract_violation_severity": 0.5,
                "drift_delta": 0.5,
                "payload_fingerprint": "fp",
            }},
            expected_cost_to_system=0.05,
            expected_cost_to_adversary=15.0,
            rationale="test eradication",
        )
        with pytest.raises(InterventionApplyError, match="eradication"):
            eng.apply(iv)

    def test_engine_apply_eradication_succeeds_with_synthesiser(self) -> None:
        from tex.intervention.bounded_compromise import BoundedCompromiseCalculator
        from tex.intervention.engine import InterventionEngine
        from tex.intervention.kinds import Intervention, InterventionKind

        synth = EradicationRuleSynthesizer()
        reg = InMemoryRuleRegistry()
        eng = InterventionEngine(
            bounded_compromise_calc=BoundedCompromiseCalculator(),
            ledger=None,
            eradication_synthesizer=synth,
            rule_registry=reg,
        )
        iv = Intervention(
            intervention_id="iv_erad_ok",
            kind=InterventionKind.ERADICATION_RULE_SYNTHESIS,
            target_entity_id="agent_X",
            parameters={"incident_context": {
                "incident_id": "inc_002",
                "actor_entity_id": "agent_X",
                "event_kind": "agent_invokes_tool",
                "contract_violation_severity": 0.85,
                "drift_delta": 0.5,
                "payload_fingerprint": "fp_abc",
            }},
            expected_cost_to_system=0.05,
            expected_cost_to_adversary=15.0,
            rationale="test eradication happy",
        )
        # No ledger wired -> returns None but doesn't raise; rule is
        # in the registry.
        result = eng.apply(iv)
        assert result is None  # no ledger
        assert len(reg.active_rules()) == 1
        rule = reg.active_rules()[0]
        assert rule.severity == "block"  # severity=0.85 >= 0.7
        assert "agent_invokes_tool" in rule.forbidden_event_kinds

    def test_engine_apply_eradication_with_ledger_embeds_rule(self) -> None:
        from tex.intervention.bounded_compromise import BoundedCompromiseCalculator
        from tex.intervention.engine import InterventionEngine
        from tex.intervention.kinds import Intervention, InterventionKind

        captured: dict = {}

        class CapturingLedger:
            def record_observation(self, *, oracle_observation):
                captured.update(oracle_observation)
                return "evt_captured"

        synth = EradicationRuleSynthesizer()
        reg = InMemoryRuleRegistry()
        eng = InterventionEngine(
            bounded_compromise_calc=BoundedCompromiseCalculator(),
            ledger=CapturingLedger(),
            eradication_synthesizer=synth,
            rule_registry=reg,
        )
        iv = Intervention(
            intervention_id="iv_with_ledger",
            kind=InterventionKind.ERADICATION_RULE_SYNTHESIS,
            target_entity_id="agent_X",
            parameters={"incident_context": {
                "incident_id": "inc_003",
                "actor_entity_id": "agent_X",
                "event_kind": "agent_invokes_tool",
                "contract_violation_severity": 0.85,
                "drift_delta": 0.5,
                "payload_fingerprint": "fp_xyz",
            }},
            expected_cost_to_system=0.05,
            expected_cost_to_adversary=15.0,
            rationale="ledger test",
        )
        eid = eng.apply(iv)
        assert eid == "evt_captured"
        # The audit record carries the synthesised rule.
        assert "synthesised_rule" in captured
        rule_dict = captured["synthesised_rule"]
        assert rule_dict["severity"] == "block"
        assert rule_dict["synthesiser_mode"] == "deterministic"
        assert "agent_invokes_tool" in rule_dict["forbidden_event_kinds"]
        # AIR phase is "eradicate".
        assert captured["air_phase"] == "eradicate"

    def test_engine_apply_eradication_bad_context_fails_closed(self) -> None:
        from tex.intervention.bounded_compromise import BoundedCompromiseCalculator
        from tex.intervention.engine import (
            InterventionApplyError,
            InterventionEngine,
        )
        from tex.intervention.kinds import Intervention, InterventionKind

        synth = EradicationRuleSynthesizer()
        reg = InMemoryRuleRegistry()
        eng = InterventionEngine(
            bounded_compromise_calc=BoundedCompromiseCalculator(),
            ledger=None,
            eradication_synthesizer=synth,
            rule_registry=reg,
        )
        # Missing required incident_context fields.
        iv = Intervention(
            intervention_id="iv_bad_ctx",
            kind=InterventionKind.ERADICATION_RULE_SYNTHESIS,
            target_entity_id="agent_X",
            parameters={"incident_context": {"incomplete": True}},
            expected_cost_to_system=0.05,
            expected_cost_to_adversary=15.0,
            rationale="bad",
        )
        with pytest.raises(InterventionApplyError):
            eng.apply(iv)


# ----------------------------------------------------------- AIR phase map


class TestAirPhaseEradicate:
    def test_eradication_kind_maps_to_eradicate_phase(self) -> None:
        from tex.intervention.engine import air_phase_for
        from tex.intervention.kinds import InterventionKind

        assert (
            air_phase_for(InterventionKind.ERADICATION_RULE_SYNTHESIS)
            == "eradicate"
        )
