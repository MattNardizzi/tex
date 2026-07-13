"""
Regression tests for the 2026-07-13 production incident.

The Render Postgres died and EVERY /v1/govern/decide failed closed to
FORBID for 9+ hours: ``MemorySystem.record_decision_with_policy`` opened
a fresh psycopg transaction per call with no degraded-mode guard, the
``OperationalError`` propagated to ``StandingGovernance._adjudicate_deep``,
and its broad ``except Exception`` FORBID-ed with zero logging.

What this file guarantees:

  - Dead database (connection refused) at boot → the memory system enters
    degraded mode, ``record_decision_with_policy`` persists through the
    same in-memory path the legacy EvaluateActionCommand branch uses, and
    ONE loud structured error is logged (rate-limited, not per-call spam).
  - Database dying AFTER a healthy boot → the first failing call degrades;
    subsequent calls never dial the dead database again (no per-call
    connect-timeout stall on the decide hot path).
  - Dead database end-to-end → ``build_runtime()`` still adjudicates and
    returns REAL verdicts driven by content, not the FORBID floor.
  - ``TEX_REQUIRE_DURABLE=1`` → strict write-through is preserved: the
    persistence failure raises exactly as before the fix.
  - Healthy database → the durable transactional path is unchanged.
  - ``StandingGovernance._adjudicate_deep`` logs the traceback before
    returning the forbid floor (the outage produced no error lines).

No secrets: every DSN below points at a closed local port or an invalid
hostname; nothing ever reaches a real database.
"""

from __future__ import annotations

import logging
import socket
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest

import tex.memory._db as memory_db
from tex.domain.decision import Decision
from tex.domain.evaluation import EvaluationRequest
from tex.domain.verdict import Verdict
from tex.governance.standing import StandingGovernance
from tex.memory import MemorySystem
from tex.policies.defaults import build_default_policy

MEMORY_LOGGER = "tex.memory.system"
STANDING_LOGGER = "tex.governance.standing"


@pytest.fixture(autouse=True)
def _fresh_migration_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Reset the process-level migration memo so each test reproduces a real
    boot: a dead database must FAIL schema bootstrap (as prod did), not
    ride a success memoized by an earlier test's fake connection.
    """
    monkeypatch.setattr(memory_db, "_migrations_applied", set())


def _dead_db_url() -> str:
    """
    A DSN pointing at a local port with nothing listening, so psycopg gets
    connection-refused instantly. The port is grabbed from the OS and then
    released; the race window is negligible and a stray listener would
    still fail the postgres handshake.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    return f"postgresql://tex:tex@127.0.0.1:{port}/tex"


def _decision(*, verdict: Verdict = Verdict.PERMIT) -> Decision:
    return Decision(
        request_id=uuid4(),
        verdict=verdict,
        confidence=0.95,
        final_score=0.1,
        action_type="sales_email",
        channel="email",
        environment="production",
        recipient="alice@example.com",
        content_excerpt="hi alice",
        content_sha256="b" * 64,
        policy_version="default-v1",
        scores={"semantic": 0.1},
        reasons=[] if verdict is not Verdict.FORBID else ["risk"],
        uncertainty_flags=[] if verdict is not Verdict.ABSTAIN else ["uncertain"],
        determinism_fingerprint="a" * 64,
    )


def _record(memory: MemorySystem, decision: Decision):
    return memory.record_decision_with_policy(
        decision=decision,
        full_input={"content": "hi alice", "action_type": "sales_email"},
        policy=build_default_policy(),
    )


def _degraded_entry_logs(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.name == MEMORY_LOGGER and "event=memory_degraded " in r.getMessage()
    ]


# ── dead database at boot ──────────────────────────────────────────────────


def test_dead_db_at_boot_degrades_and_still_records(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv("DATABASE_URL", _dead_db_url())
    monkeypatch.delenv("TEX_REQUIRE_DURABLE", raising=False)

    with caplog.at_level(logging.ERROR, logger=MEMORY_LOGGER):
        memory = MemorySystem(evidence_path=tmp_path / "evidence.jsonl")
        decision = _decision()
        evidence = _record(memory, decision)

    # The write landed in-memory and returned a real evidence record —
    # the exact write shape the legacy memory_system=None path produces.
    assert evidence is not None
    assert evidence.record_hash
    assert memory.decisions.get(decision.decision_id) == decision
    assert memory.inputs.get(decision.request_id) is not None

    # Degraded is visible to operators: the flag, /health, and ONE loud log.
    assert memory.degraded is True
    assert memory.health().durable is False
    assert len(_degraded_entry_logs(caplog)) == 1


def test_degraded_logging_is_rate_limited_not_per_call(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv("DATABASE_URL", _dead_db_url())
    monkeypatch.delenv("TEX_REQUIRE_DURABLE", raising=False)

    with caplog.at_level(logging.ERROR, logger=MEMORY_LOGGER):
        memory = MemorySystem(evidence_path=tmp_path / "evidence.jsonl")
        for _ in range(5):
            _record(memory, _decision())

    # One entry log; the per-call reminder stays silent inside the window.
    assert len(_degraded_entry_logs(caplog)) == 1
    reminders = [
        r
        for r in caplog.records
        if r.name == MEMORY_LOGGER and "event=memory_degraded_write" in r.getMessage()
    ]
    assert reminders == []

    # Once the interval elapses the reminder fires again — exactly once.
    memory._degraded_log_at -= 301.0
    with caplog.at_level(logging.ERROR, logger=MEMORY_LOGGER):
        _record(memory, _decision())
        _record(memory, _decision())
    reminders = [
        r
        for r in caplog.records
        if r.name == MEMORY_LOGGER and "event=memory_degraded_write" in r.getMessage()
    ]
    assert len(reminders) == 1


def test_require_durable_keeps_strict_fail_closed_behavior(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("DATABASE_URL", _dead_db_url())
    monkeypatch.setenv("TEX_REQUIRE_DURABLE", "1")

    memory = MemorySystem(evidence_path=tmp_path / "evidence.jsonl")
    assert memory.degraded is False

    with pytest.raises(psycopg.OperationalError):
        _record(memory, _decision())
    assert memory.degraded is False


# ── database dies after a healthy boot ─────────────────────────────────────


class _FakeCursor:
    def __init__(self, executed: list[str]) -> None:
        self._executed = executed
        self.itersize = 0

    def __enter__(self) -> "_FakeCursor":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, sql: object, params: object = None) -> None:
        self._executed.append(str(sql))

    def fetchone(self) -> None:
        return None

    def fetchall(self) -> list:
        return []

    def __iter__(self):
        return iter(())


class _FakeConnection:
    def __init__(self, executed: list[str]) -> None:
        self._executed = executed
        self.commits = 0

    def cursor(self, name: str | None = None) -> _FakeCursor:
        return _FakeCursor(self._executed)

    def transaction(self):
        return nullcontext()

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        return None

    def close(self) -> None:
        return None


class _FakePostgres:
    """Stands in for ``psycopg.connect``; can be killed mid-test."""

    def __init__(self) -> None:
        self.executed: list[str] = []
        self.connections: list[_FakeConnection] = []
        self.attempts = 0
        self.alive = True

    def __call__(self, url: str, **kwargs: object) -> _FakeConnection:
        self.attempts += 1
        if not self.alive:
            raise psycopg.OperationalError("connection refused (simulated death)")
        conn = _FakeConnection(self.executed)
        self.connections.append(conn)
        return conn


@pytest.fixture
def fake_postgres(monkeypatch: pytest.MonkeyPatch) -> _FakePostgres:
    fake = _FakePostgres()
    monkeypatch.setenv("DATABASE_URL", "postgresql://tex:tex@db.invalid:5432/tex")
    monkeypatch.delenv("TEX_REQUIRE_DURABLE", raising=False)
    monkeypatch.setattr(memory_db.psycopg, "connect", fake)
    return fake


def test_db_death_after_boot_degrades_on_first_call_then_stops_dialing(
    fake_postgres: _FakePostgres,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    memory = MemorySystem(evidence_path=tmp_path / "evidence.jsonl")
    assert memory.health().durable is True
    assert memory.degraded is False

    fake_postgres.alive = False
    with caplog.at_level(logging.ERROR, logger=MEMORY_LOGGER):
        decision = _decision()
        evidence = _record(memory, decision)

    assert evidence is not None
    assert memory.decisions.get(decision.decision_id) == decision
    assert memory.degraded is True
    assert len(_degraded_entry_logs(caplog)) == 1
    # The entry log carries the captured traceback (structured evidence).
    assert _degraded_entry_logs(caplog)[0].exc_info is not None

    # Subsequent calls must NOT dial the dead database again — every dial
    # costs a connect timeout on the single-worker decide hot path.
    attempts_after_death = fake_postgres.attempts
    _record(memory, _decision())
    _record(memory, _decision())
    assert fake_postgres.attempts == attempts_after_death


def test_healthy_db_durable_path_unchanged(
    fake_postgres: _FakePostgres,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.ERROR, logger=MEMORY_LOGGER):
        memory = MemorySystem(evidence_path=tmp_path / "evidence.jsonl")
        decision = _decision()
        evidence = _record(memory, decision)

    assert evidence is not None
    assert memory.degraded is False
    assert memory.health().durable is True
    assert _degraded_entry_logs(caplog) == []

    # The transactional write-through really happened: all three rows in
    # one committed transaction, plus the evidence mirror insert.
    executed = "\n".join(fake_postgres.executed)
    assert "tex_decisions" in executed
    assert "tex_decision_inputs" in executed
    assert "tex_policy_snapshots" in executed
    assert "tex_evidence_records" in executed
    assert any(conn.commits > 0 for conn in fake_postgres.connections)


# ── end to end: a dead database must not FORBID every verdict ─────────────


class _CollectingHandler(logging.Handler):
    """Captures records directly off the logger — importing ``tex.main``
    installs the service's JSON logging config, which stops ``tex.*``
    records from propagating to caplog's root-level handler."""

    def __init__(self) -> None:
        super().__init__(level=logging.ERROR)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def test_dead_db_decide_returns_real_verdicts_by_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tex.main import build_runtime

    monkeypatch.setenv("DATABASE_URL", _dead_db_url())
    monkeypatch.delenv("TEX_REQUIRE_DURABLE", raising=False)

    collector = _CollectingHandler()
    memory_logger = logging.getLogger(MEMORY_LOGGER)
    memory_logger.addHandler(collector)
    try:
        runtime = build_runtime()

        benign = runtime.evaluate_action_command.execute(
            EvaluationRequest(
                request_id=uuid4(),
                action_type="send_email",
                content=(
                    "Hi team, the Q3 review is on Tuesday at 2pm. Agenda attached."
                ),
                recipient="team@example.com",
                channel="email",
                environment="production",
                policy_id=None,
            )
        )
        leaking = runtime.evaluate_action_command.execute(
            EvaluationRequest(
                request_id=uuid4(),
                action_type="send_email",
                content="api_key = abc123",
                recipient="team@example.com",
                channel="email",
                environment="production",
                policy_id=None,
            )
        )
    finally:
        memory_logger.removeHandler(collector)

    # Real adjudication by content — NOT a blanket fail-closed FORBID.
    assert benign.response.verdict is Verdict.PERMIT
    assert leaking.response.verdict is Verdict.FORBID
    # Both carry real evidence from the (in-memory) chain.
    assert benign.response.evidence_hash
    # The memory system announced the degradation loudly, exactly once.
    assert runtime.memory.degraded is True
    entry_logs = [
        r for r in collector.records if "event=memory_degraded " in r.getMessage()
    ]
    assert len(entry_logs) == 1


# ── standing: deep-adjudication failure must leave a trace ────────────────


class _RaisingEvaluate:
    def execute(self, request: EvaluationRequest):
        raise RuntimeError("synthetic engine failure")


def test_deep_adjudication_error_is_logged_before_forbid_floor(
    caplog: pytest.LogCaptureFixture,
) -> None:
    engine = StandingGovernance(
        agent_registry=object(),
        evaluate_command=_RaisingEvaluate(),
    )
    agent = SimpleNamespace(agent_id=uuid4(), name="test-agent")

    with caplog.at_level(logging.ERROR, logger=STANDING_LOGGER):
        outcome = engine._adjudicate_deep(
            agent=agent,
            tenant="default",
            action_type="wire.transfer",
            content="transfer $2,000,000 to acct 4471",
            channel="api",
            environment="production",
            recipient=None,
            session_id=None,
        )

    # Ruling is unchanged: fail closed to the FORBID floor.
    assert outcome.verdict is Verdict.FORBID
    assert outcome.released is False
    assert outcome.forbid_scope == "deep_error"

    # ...but no longer silently: one ERROR with the traceback and scope.
    records = [
        r for r in caplog.records if "Deep adjudication raised" in r.getMessage()
    ]
    assert len(records) == 1
    message = records[0].getMessage()
    assert "deep_error" in message
    assert "wire.transfer" in message
    assert records[0].exc_info is not None
    assert "synthetic engine failure" in str(records[0].exc_info[1])
