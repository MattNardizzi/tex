"""
Tests for tex.drift.emergent_norm — collusion + shared-target detection.

Acceptance: flag coordinated patterns on a 10-agent collusion fixture.
References:
  - arXiv:2604.01151 (multi-agent interpretability) — informs the
    detection approach; we ship the side-channel (action-stream) path.
  - PMLR v180 pp. 223–232 (Bonjour et al. 2022) — pairwise mutual
    information as the action-lockstep signal.
"""

from __future__ import annotations

import logging
import math
import random

import pytest

from tex.drift import (
    PATTERN_ACTION_LOCKSTEP,
    PATTERN_SHARED_TARGET_CONVERGENCE,
    EmergentNormTracer,
    EmergentPattern,
)
from tex.drift.emergent_norm import (
    _connected_components,
    _mutual_information_nats,
)


@pytest.fixture(autouse=True)
def _silence_telemetry():
    logging.getLogger("tex").setLevel(logging.CRITICAL)


# ---------------------------------------------------------------------
# Fixtures: 10-agent collusion scenarios
# ---------------------------------------------------------------------


def _build_collusion_fixture(
    *,
    seed: int = 42,
    n_steps: int = 100,
    colluding: tuple[str, ...] = ("agent_0", "agent_1", "agent_2", "agent_3"),
    honest: tuple[str, ...] = (
        "agent_4",
        "agent_5",
        "agent_6",
        "agent_7",
        "agent_8",
        "agent_9",
    ),
    shared_target: str = "shared_target",
) -> tuple[dict, ...]:
    """
    10-agent fixture: 4 colluding agents act in lockstep on a shared target,
    6 honest agents act independently on randomly-distributed targets.

    Joint action picked once per step for the colluding cluster, randomly
    per-agent for the honest cluster — this is the AAF "Byzantine
    coalition" pattern from §7 (resource-sharing coalition issuing
    near-maximal requests).
    """
    rng = random.Random(seed)
    actions = ("A", "B", "C", "D")
    events: list[dict] = []
    for step in range(n_steps):
        synced = rng.choice(actions)
        for a in colluding:
            events.append(
                {
                    "actor_entity_id": a,
                    "event_kind": synced,
                    "target_entity_id": shared_target,
                    "step_id": step,
                }
            )
        for a in honest:
            events.append(
                {
                    "actor_entity_id": a,
                    "event_kind": rng.choice(actions),
                    "target_entity_id": f"target_{rng.randint(0, 5)}",
                    "step_id": step,
                }
            )
    return tuple(events)


def _build_independent_fixture(
    *, seed: int = 1, n_steps: int = 100, n_agents: int = 10
) -> tuple[dict, ...]:
    """All agents act independently — no collusion signal."""
    rng = random.Random(seed)
    actions = ("A", "B", "C", "D")
    events: list[dict] = []
    for step in range(n_steps):
        for i in range(n_agents):
            events.append(
                {
                    "actor_entity_id": f"agent_{i}",
                    "event_kind": rng.choice(actions),
                    "target_entity_id": f"target_{rng.randint(0, 5)}",
                    "step_id": step,
                }
            )
    return tuple(events)


# ---------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------


class TestConstruction:
    def test_default_constructs(self) -> None:
        tracer = EmergentNormTracer()
        assert tracer is not None

    def test_rejects_invalid_window_size(self) -> None:
        with pytest.raises(ValueError):
            EmergentNormTracer(window_size=1)

    def test_rejects_invalid_mi_threshold(self) -> None:
        with pytest.raises(ValueError):
            EmergentNormTracer(mi_threshold_nats=0.0)

    def test_rejects_invalid_target_threshold(self) -> None:
        with pytest.raises(ValueError):
            EmergentNormTracer(target_convergence_threshold=-1.0)

    def test_rejects_invalid_min_cluster(self) -> None:
        with pytest.raises(ValueError):
            EmergentNormTracer(min_cluster_size=1)

    def test_rejects_empty_action_field(self) -> None:
        with pytest.raises(ValueError):
            EmergentNormTracer(action_field="")

    def test_rejects_empty_bucket_field(self) -> None:
        with pytest.raises(ValueError):
            EmergentNormTracer(bucket_field="")


# ---------------------------------------------------------------------
# Acceptance: flag coordinated patterns on a 10-agent collusion fixture
# ---------------------------------------------------------------------


class TestCollusionDetection:
    def test_flags_colluding_cluster_via_lockstep(self) -> None:
        events = _build_collusion_fixture()
        tracer = EmergentNormTracer(window_size=2000)
        patterns = tracer.trace_norms(recent_event_window=events)
        lockstep = [p for p in patterns if p.kind == PATTERN_ACTION_LOCKSTEP]
        assert len(lockstep) >= 1, "expected an action_lockstep pattern"
        cluster = lockstep[0]
        # Colluding agents must be present.
        assert {"agent_0", "agent_1", "agent_2", "agent_3"} <= set(cluster.agent_ids)
        # Honest agents must NOT be in the lockstep cluster.
        for honest in ("agent_4", "agent_5", "agent_6", "agent_7", "agent_8", "agent_9"):
            assert honest not in cluster.agent_ids

    def test_flags_colluding_cluster_via_shared_target(self) -> None:
        events = _build_collusion_fixture()
        tracer = EmergentNormTracer(window_size=2000)
        patterns = tracer.trace_norms(recent_event_window=events)
        target_conv = [
            p for p in patterns if p.kind == PATTERN_SHARED_TARGET_CONVERGENCE
        ]
        assert len(target_conv) >= 1
        # Shared-target detector must identify the target the colluders converge on.
        assert any(p.target_entity_id == "shared_target" for p in target_conv)

    def test_no_false_positive_on_independent_agents(self) -> None:
        events = _build_independent_fixture(seed=1)
        tracer = EmergentNormTracer(window_size=2000)
        patterns = tracer.trace_norms(recent_event_window=events)
        # No lockstep cluster should fire on truly independent agents.
        # (The shared-target detector may fire by chance on heavy targets;
        #  it's MI we're guarding against false positives on here.)
        lockstep = [p for p in patterns if p.kind == PATTERN_ACTION_LOCKSTEP]
        assert lockstep == [], (
            f"expected no lockstep on independent agents; got {lockstep}"
        )


# ---------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_window_returns_empty(self) -> None:
        tracer = EmergentNormTracer()
        assert tracer.trace_norms(recent_event_window=()) == ()

    def test_single_event_returns_empty(self) -> None:
        tracer = EmergentNormTracer()
        events = (
            {"actor_entity_id": "a", "event_kind": "X", "step_id": 1},
        )
        assert tracer.trace_norms(recent_event_window=events) == ()

    def test_missing_actor_skipped(self) -> None:
        tracer = EmergentNormTracer()
        events = (
            {"event_kind": "X", "step_id": 1},  # no actor — skipped
            {"actor_entity_id": "a", "step_id": 1},  # no event_kind — skipped
        )
        # No errors, no patterns.
        assert tracer.trace_norms(recent_event_window=events) == ()

    def test_below_min_cluster_does_not_fire(self) -> None:
        # Only 2 agents colluding < min_cluster_size of 3.
        rng = random.Random(0)
        events: list[dict] = []
        for step in range(50):
            synced = rng.choice(("A", "B"))
            for a in ("agent_0", "agent_1"):
                events.append(
                    {
                        "actor_entity_id": a,
                        "event_kind": synced,
                        "target_entity_id": "T",
                        "step_id": step,
                    }
                )
            for a in ("agent_2", "agent_3", "agent_4"):
                events.append(
                    {
                        "actor_entity_id": a,
                        "event_kind": rng.choice(("A", "B", "C", "D")),
                        "target_entity_id": f"target_{rng.randint(0, 3)}",
                        "step_id": step,
                    }
                )
        tracer = EmergentNormTracer(window_size=1000, min_cluster_size=3)
        patterns = tracer.trace_norms(recent_event_window=tuple(events))
        # Lockstep cluster of 2 must not be reported.
        lockstep = [p for p in patterns if p.kind == PATTERN_ACTION_LOCKSTEP]
        for p in lockstep:
            assert len(p.agent_ids) >= 3


class TestPatternIsFrozen:
    def test_pattern_attributes_immutable(self) -> None:
        events = _build_collusion_fixture()
        tracer = EmergentNormTracer(window_size=2000)
        patterns = tracer.trace_norms(recent_event_window=events)
        assert patterns
        with pytest.raises((ValueError, TypeError)):
            patterns[0].severity = -1.0  # type: ignore[misc]


# ---------------------------------------------------------------------
# Pure-helper unit tests
# ---------------------------------------------------------------------


class TestMutualInformationHelper:
    def test_independent_streams_have_zero_mi(self) -> None:
        rng = random.Random(0)
        joint = [
            (rng.choice(("A", "B")), rng.choice(("X", "Y"))) for _ in range(2000)
        ]
        mi = _mutual_information_nats(joint)
        assert mi < 0.05  # asymptotically zero

    def test_perfectly_correlated_streams_have_high_mi(self) -> None:
        # X = Y for every sample.
        joint = [("A", "A"), ("B", "B"), ("A", "A"), ("B", "B")] * 50
        mi = _mutual_information_nats(joint)
        # Entropy of binary uniform = log(2) ≈ 0.693 nats.
        assert mi > 0.5
        assert mi <= math.log(2) + 1e-9

    def test_empty_joint_returns_zero(self) -> None:
        assert _mutual_information_nats([]) == 0.0

    def test_single_sample_returns_zero(self) -> None:
        assert _mutual_information_nats([("A", "B")]) == 0.0


class TestConnectedComponents:
    def test_disconnected_singletons(self) -> None:
        comps = _connected_components(nodes=["a", "b", "c"], edges=[])
        # Three singletons.
        sizes = sorted(len(c) for c in comps)
        assert sizes == [1, 1, 1]

    def test_chain_forms_single_component(self) -> None:
        comps = _connected_components(
            nodes=["a", "b", "c", "d"],
            edges=[("a", "b"), ("b", "c"), ("c", "d")],
        )
        assert len(comps) == 1
        assert comps[0] == {"a", "b", "c", "d"}

    def test_two_components(self) -> None:
        comps = _connected_components(
            nodes=["a", "b", "c", "d"],
            edges=[("a", "b"), ("c", "d")],
        )
        sizes = sorted(len(c) for c in comps)
        assert sizes == [2, 2]
