"""
V15 tests: BackgroundScanScheduler — drift detection, alert dispatch,
lifecycle.

The scheduler depends on DiscoveryService via duck typing — anything
with a .scan() returning a DiscoveryScanResult-shaped object works.
We use a hand-rolled stub so we can drive the diff between two runs
deterministically without setting up real connectors.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from tex.discovery.alerts import AlertEngine
from tex.discovery.scheduler import BackgroundScanScheduler
from tex.discovery.service import DiscoveryScanResult
from tex.domain.discovery import (
    CandidateAgent,
    DiscoveredCapabilityHints,
    DiscoveryFindingKind,
    DiscoveryLedgerEntry,
    DiscoveryRiskBand,
    DiscoveryScanRun,
    DiscoverySource,
    ReconciliationAction,
    ReconciliationOutcome,
)
from tex.stores.drift_events import DriftEventKind, DriftEventStore


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


def _candidate(
    *,
    name: str = "alpha",
    external_id: str = "ext-1",
    tools: tuple[str, ...] = ("send_email",),
    risk: DiscoveryRiskBand = DiscoveryRiskBand.MEDIUM,
) -> CandidateAgent:
    return CandidateAgent(
        source=DiscoverySource.OPENAI,
        external_id=external_id,
        tenant_id="default",
        name=name,
        owner_hint="founder@example.com",
        risk_band=risk,
        confidence=0.9,
        capability_hints=DiscoveredCapabilityHints(
            inferred_tools=tools,
            inferred_data_scopes=("crm.contacts.read",),
        ),
    )


def _outcome(
    *,
    candidate: CandidateAgent,
    action: ReconciliationAction = ReconciliationAction.REGISTERED,
) -> ReconciliationOutcome:
    return ReconciliationOutcome(
        candidate_id=candidate.candidate_id,
        reconciliation_key=f"openai:{candidate.external_id}",
        finding_kind=DiscoveryFindingKind.NEW_AGENT,
        action=action,
        confidence=0.9,
        resulting_agent_id=uuid4()
        if action is ReconciliationAction.REGISTERED
        else None,
    )


def _entry(
    candidate: CandidateAgent,
    outcome: ReconciliationOutcome,
    sequence: int = 0,
) -> DiscoveryLedgerEntry:
    return DiscoveryLedgerEntry(
        sequence=sequence,
        candidate=candidate,
        outcome=outcome,
        payload_sha256="x" * 64,
        previous_hash=None,
        record_hash="y" * 64,
    )


def _result(*entries: DiscoveryLedgerEntry, tenant_id: str = "default") -> DiscoveryScanResult:
    """Build a DiscoveryScanResult with the given entries."""
    summary = DiscoveryScanRun(
        run_id=uuid4(),
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        sources_scanned=(DiscoverySource.OPENAI,),
        candidates_seen=len(entries),
        registered_count=len(entries),
        updated_drift_count=0,
        quarantined_count=0,
        no_op_count=0,
        held_count=0,
        skipped_count=0,
        errors=(),
    )
    return DiscoveryScanResult(summary=summary, entries=tuple(entries))


class StubService:
    """
    Minimal DiscoveryService stand-in. Hand it a list of result
    sequences, and each call to scan() pops the next one. This lets
    tests drive scan-to-scan diffs deterministically.
    """

    def __init__(self, results: list[DiscoveryScanResult]) -> None:
        self._results = list(results)
        self.scan_calls: int = 0

    def scan(
        self,
        *,
        tenant_id: str,
        timeout_seconds: float = 30.0,
        trigger: str = "manual",
        policy_version: str | None = None,
        **_: object,
    ) -> DiscoveryScanResult:
        self.scan_calls += 1
        if not self._results:
            return _result(tenant_id=tenant_id)
        return self._results.pop(0)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSchedulerLifecycle:
    def test_no_tenants_means_no_thread(self):
        store = DriftEventStore()
        sched = BackgroundScanScheduler(
            service=StubService([]),
            drift_store=store,
            tenants=[],
            interval_seconds=60,
        )
        sched.start()
        assert sched.is_running is False

    def test_status_reports_config(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = DriftEventStore()
        engine = AlertEngine()
        sched = BackgroundScanScheduler(
            service=StubService([]),
            drift_store=store,
            alert_engine=engine,
            tenants=["tenant-a"],
            interval_seconds=60,
        )
        status = sched.status
        assert status["interval_seconds"] >= 30
        assert status["tenants"] == ["tenant-a"]
        assert status["alerts_enabled"] is True
        assert "log" in status["alert_sinks"]

    def test_minimum_interval_guard(self):
        """Operator-supplied interval below MIN gets clamped."""
        sched = BackgroundScanScheduler(
            service=StubService([]),
            interval_seconds=1,  # well below 30
        )
        assert sched.status["interval_seconds"] >= 30


class TestDriftDetection:
    def test_first_scan_emits_new_agent_for_each_candidate(self):
        cand = _candidate(name="alpha", external_id="ext-1")
        out = _outcome(candidate=cand)
        result = _result(_entry(cand, out))

        store = DriftEventStore()
        sched = BackgroundScanScheduler(
            service=StubService([result]),
            drift_store=store,
            tenants=["default"],
            interval_seconds=60,
        )
        cycle = sched.trigger_now()

        # Drift summary in the cycle output.
        per_tenant = cycle["tenants"][0]
        assert per_tenant["drift"]["new"] == 1
        assert per_tenant["drift"]["changed"] == 0
        assert per_tenant["drift"]["disappeared"] == 0
        # And one drift event was emitted.
        events = store.list_recent(limit=10)
        assert len(events) == 1
        assert events[0].kind is DriftEventKind.NEW_AGENT

    def test_unchanged_candidate_in_second_scan_does_not_emit(self):
        cand = _candidate(name="alpha", external_id="ext-1")
        out = _outcome(candidate=cand)
        first = _result(_entry(cand, out, sequence=0))
        second = _result(_entry(cand, out, sequence=1))

        store = DriftEventStore()
        sched = BackgroundScanScheduler(
            service=StubService([first, second]),
            drift_store=store,
            tenants=["default"],
            interval_seconds=60,
        )
        sched.trigger_now()  # run 1: 1 new
        cycle2 = sched.trigger_now()  # run 2: 0 changes
        assert cycle2["tenants"][0]["drift"]["new"] == 0
        assert cycle2["tenants"][0]["drift"]["changed"] == 0
        assert cycle2["tenants"][0]["drift"]["disappeared"] == 0

    def test_capability_widening_emits_agent_changed(self):
        # Run 1: only send_email tool. Run 2: adds a second tool.
        cand_v1 = _candidate(
            name="alpha", external_id="ext-1", tools=("send_email",)
        )
        cand_v2 = _candidate(
            name="alpha",
            external_id="ext-1",
            tools=("send_email", "delete_record"),
        )
        first = _result(_entry(cand_v1, _outcome(candidate=cand_v1)))
        second = _result(_entry(cand_v2, _outcome(candidate=cand_v2)))

        store = DriftEventStore()
        sched = BackgroundScanScheduler(
            service=StubService([first, second]),
            drift_store=store,
            tenants=["default"],
            interval_seconds=60,
        )
        sched.trigger_now()
        cycle2 = sched.trigger_now()
        assert cycle2["tenants"][0]["drift"]["changed"] == 1
        # The most recent event should be AGENT_CHANGED with
        # change_kind=capability_widened.
        events = store.list_recent(limit=10)
        latest = events[0]
        assert latest.kind is DriftEventKind.AGENT_CHANGED
        assert latest.details["change_kind"] == "capability_widened"
        assert "delete_record" in latest.details.get("added", [])

    def test_disappearance_emits_agent_disappeared(self):
        cand = _candidate(name="alpha", external_id="ext-1")
        out = _outcome(candidate=cand)
        first = _result(_entry(cand, out))
        # Second scan returns no entries — the agent vanished.
        second = _result()

        store = DriftEventStore()
        sched = BackgroundScanScheduler(
            service=StubService([first, second]),
            drift_store=store,
            tenants=["default"],
            interval_seconds=60,
        )
        sched.trigger_now()
        cycle2 = sched.trigger_now()
        assert cycle2["tenants"][0]["drift"]["disappeared"] == 1
        events = store.list_by_kind(DriftEventKind.AGENT_DISAPPEARED, limit=10)
        assert len(events) == 1


class TestSchedulerAlertingIntegration:
    def test_alert_dispatched_for_high_risk_new_agent(self):
        # End-to-end: scheduler observes a new HIGH-risk agent, the
        # alert engine matches the rule, the sink receives the
        # payload. Uses a custom sink so we don't depend on logging.
        from tex.discovery.alerts import AlertSink

        class CapturingSink(AlertSink):
            name = "capture"

            def __init__(self):
                self.captured = []

            def deliver(self, payload):
                self.captured.append(payload)

        capture = CapturingSink()
        engine = AlertEngine(sinks=[capture])

        cand = _candidate(
            name="risky", external_id="risky-1", risk=DiscoveryRiskBand.HIGH
        )
        # Mark as NOT auto-registered so the rule fires.
        out = ReconciliationOutcome(
            candidate_id=cand.candidate_id,
            reconciliation_key=f"openai:{cand.external_id}",
            finding_kind=DiscoveryFindingKind.NEW_AGENT,
            action=ReconciliationAction.HELD_AMBIGUOUS,  # not REGISTERED
            confidence=0.9,
        )
        result = _result(_entry(cand, out))
        store = DriftEventStore()
        sched = BackgroundScanScheduler(
            service=StubService([result]),
            drift_store=store,
            alert_engine=engine,
            tenants=["default"],
            interval_seconds=60,
        )
        sched.trigger_now()

        # Worker thread has to settle.
        import time
        for _ in range(50):
            if capture.captured:
                break
            time.sleep(0.02)
        assert len(capture.captured) >= 1
        payload = capture.captured[0]
        assert payload["rule"] == "ungoverned_high_risk_appeared"
        assert payload["severity"] == "CRITICAL"
