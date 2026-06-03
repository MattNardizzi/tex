"""
Tests for tex.intervention.restorative — restorative-path executor.

Coverage:
- Path lookup (missing graph, unknown path, lookup error)
- Argument validation
- Header + per-event record emission to the governance log
- State transition + post-execution verification
- No-ledger path (test mode)
- Ledger failures during header / per-event append
- The full happy-path success contract: returns True iff
  (a) path exists, (b) all events emitted in order,
  (c) actor's state matches target_legal_state_id.
"""

from __future__ import annotations

import pytest

from tex.institutional.sanctions import RestorativePath
from tex.intervention.restorative import RestorativePathExecutor


# ---------------------------------------------------------- fake collaborators


class FakeGraph:
    """Minimal stand-in for GovernanceGraph.lookup_restorative_path."""

    def __init__(self, paths: dict[str, RestorativePath]) -> None:
        self._paths = paths

    def lookup_restorative_path(self, path_id: str) -> RestorativePath:
        if path_id in self._paths:
            return self._paths[path_id]
        raise KeyError(f"no RestorativePath with path_id={path_id!r}")


class RecordingLedger:
    """In-memory stand-in for GovernanceLog.record_observation."""

    def __init__(self) -> None:
        self.records: list[dict] = []
        self._counter = 0

    def record_observation(self, *, oracle_observation: dict) -> str:
        self._counter += 1
        self.records.append(oracle_observation)
        return f"evt_{self._counter:08x}"


class FailingLedger:
    """Ledger that always fails on append."""

    def __init__(self, *, fail_at: int = 0) -> None:
        self._fail_at = fail_at
        self._calls = 0

    def record_observation(self, *, oracle_observation: dict) -> str:
        self._calls += 1
        if self._calls > self._fail_at:
            raise RuntimeError(f"simulated ledger failure on call {self._calls}")
        return f"evt_pre_fail_{self._calls}"


# ------------------------------------------------------------------ fixtures


def make_path(
    *,
    path_id: str = "p_expiry_default",
    kinds: tuple[str, ...] = ("warning_expired",),
    target_state: str = "active",
    restoration_kind: str = "expiry",
) -> RestorativePath:
    return RestorativePath(
        path_id=path_id,
        description="test restorative path",
        restorative_event_kinds=kinds,
        target_legal_state_id=target_state,
        restoration_kind=restoration_kind,
    )


# ----------------------------------------------------------------- argument val


class TestArgumentValidation:
    def test_invalid_path_id_returns_false(self) -> None:
        ex = RestorativePathExecutor(governance_graph=None, ledger=None)
        assert ex.execute(path_id="", target_entity_id="X") is False
        assert ex.execute(path_id=None, target_entity_id="X") is False  # type: ignore[arg-type]

    def test_invalid_target_returns_false(self) -> None:
        ex = RestorativePathExecutor(governance_graph=None, ledger=None)
        assert ex.execute(path_id="p1", target_entity_id="") is False
        assert ex.execute(path_id="p1", target_entity_id=None) is False  # type: ignore[arg-type]


# ----------------------------------------------------------------- path lookup


class TestPathLookup:
    def test_no_graph_returns_false(self) -> None:
        ex = RestorativePathExecutor(governance_graph=None, ledger=None)
        assert ex.execute(path_id="p1", target_entity_id="X") is False

    def test_unknown_path_returns_false(self) -> None:
        graph = FakeGraph(paths={})
        ex = RestorativePathExecutor(governance_graph=graph, ledger=None)
        assert ex.execute(path_id="missing", target_entity_id="X") is False

    def test_graph_lookup_error_returns_false(self) -> None:
        class ExplodingGraph:
            def lookup_restorative_path(self, path_id: str):  # type: ignore[no-untyped-def]
                raise RuntimeError("graph corrupted")

        ex = RestorativePathExecutor(
            governance_graph=ExplodingGraph(), ledger=None
        )
        assert ex.execute(path_id="any", target_entity_id="X") is False


# ----------------------------------------------------------------- happy path


class TestHappyPath:
    def test_full_success_no_ledger(self) -> None:
        path = make_path(
            path_id="p_warn_expiry",
            kinds=("warning_expired", "trust_restored"),
            target_state="active",
        )
        graph = FakeGraph(paths={"p_warn_expiry": path})
        states: dict[str, str] = {"agent_X": "warning"}
        ex = RestorativePathExecutor(
            governance_graph=graph,
            ledger=None,
            institutional_states=states,
        )
        ok = ex.execute(path_id="p_warn_expiry", target_entity_id="agent_X")
        assert ok is True
        assert states["agent_X"] == "active"

    def test_full_success_with_ledger(self) -> None:
        path = make_path(
            path_id="p_credit",
            kinds=("credit_earned_a", "credit_earned_b", "credit_redeemed"),
            target_state="active",
            restoration_kind="credit_relief",
        )
        graph = FakeGraph(paths={"p_credit": path})
        ledger = RecordingLedger()
        states: dict[str, str] = {"agent_Y": "credited"}
        ex = RestorativePathExecutor(
            governance_graph=graph,
            ledger=ledger,
            institutional_states=states,
        )
        ok = ex.execute(path_id="p_credit", target_entity_id="agent_Y")
        assert ok is True
        # Header + 3 per-event records.
        assert len(ledger.records) == 4
        header = ledger.records[0]
        assert header["kind"] == "restorative_path_executed"
        assert header["restorative_path_id"] == "p_credit"
        assert header["target_legal_state_id"] == "active"
        assert header["restoration_kind"] == "credit_relief"
        # Per-event order preserved.
        for index, kind in enumerate(
            ["credit_earned_a", "credit_earned_b", "credit_redeemed"]
        ):
            rec = ledger.records[1 + index]
            assert rec["kind"] == "restorative_event_emitted"
            assert rec["restorative_event_kind"] == kind
            assert rec["sequence_index"] == index
        assert states["agent_Y"] == "active"

    def test_empty_event_kinds_still_succeeds(self) -> None:
        # Time-driven expiry paths may have empty restorative_event_kinds.
        path = make_path(path_id="p_silent", kinds=(), target_state="active")
        graph = FakeGraph(paths={"p_silent": path})
        ledger = RecordingLedger()
        states: dict[str, str] = {"agent_Z": "warning"}
        ex = RestorativePathExecutor(
            governance_graph=graph,
            ledger=ledger,
            institutional_states=states,
        )
        ok = ex.execute(path_id="p_silent", target_entity_id="agent_Z")
        assert ok is True
        # Just the header.
        assert len(ledger.records) == 1
        assert states["agent_Z"] == "active"

    def test_state_map_not_provided_does_not_block_success(self) -> None:
        path = make_path()
        graph = FakeGraph(paths={"p_expiry_default": path})
        ex = RestorativePathExecutor(
            governance_graph=graph, ledger=None, institutional_states=None,
        )
        ok = ex.execute(path_id="p_expiry_default", target_entity_id="X")
        assert ok is True


# ----------------------------------------------------------------- ledger fails


class TestLedgerFailures:
    def test_header_failure_returns_false(self) -> None:
        path = make_path(kinds=("evt_a",))
        graph = FakeGraph(paths={"p_expiry_default": path})
        ex = RestorativePathExecutor(
            governance_graph=graph,
            ledger=FailingLedger(fail_at=0),  # fail immediately
            institutional_states={"X": "warning"},
        )
        ok = ex.execute(path_id="p_expiry_default", target_entity_id="X")
        assert ok is False

    def test_per_event_failure_returns_false(self) -> None:
        # Header succeeds; first per-event fails.
        path = make_path(kinds=("evt_a", "evt_b"))
        graph = FakeGraph(paths={"p_expiry_default": path})
        ex = RestorativePathExecutor(
            governance_graph=graph,
            ledger=FailingLedger(fail_at=1),  # header ok, first event fails
            institutional_states={"X": "warning"},
        )
        ok = ex.execute(path_id="p_expiry_default", target_entity_id="X")
        assert ok is False
