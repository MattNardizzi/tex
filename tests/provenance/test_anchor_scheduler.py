"""T3 — the background AnchorScheduler drives the EXISTING RFC-3161 anchorer on
a live enforcement SealedFactLedger, off the hot path, and what it produces is
accepted by the EXISTING offline verifier (``verify_anchor_receipt``).

Uses a throwaway LOCAL TSA (``mint_local_tsa``): it exercises the real anchor +
verification logic with no network, but proves nothing about real wall-clock
time (only the freetsa path does that). The point under test is the binding +
verification + the fail-soft / off-hot-path contract, not the clock.
"""

from __future__ import annotations

import time

from tex.domain.evidence import EvidenceMaturity
from tex.interchange._local_tsa import issue_timestamp_response, mint_local_tsa
from tex.interchange.external_anchor import (
    CheckpointAnchorRecord,
    anchor_subject_digest,
    verify_anchor_receipt,
)
from tex.provenance.anchor_scheduler import AnchorScheduler
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind


def _append(ledger: SealedFactLedger, i: int) -> None:
    ledger.append(
        SealedFact(
            kind=SealedFactKind.ENFORCEMENT,
            subject_id=f"req-{i}",
            claim="gate decision (test)",
            maturity=EvidenceMaturity.RESEARCH_SOLID,
            detail={"allowed": bool(i % 2), "outcome": "executed" if i % 2 else "blocked"},
        )
    )


def _local_anchor_fn(tsa, *, nonce: int = 4242):
    """Mirror discovery.conduit.seal.make_rfc3161_anchor's shape, but issue the
    token from an in-process LocalTSA so the test needs no network."""

    def anchor(snapshot):
        cp = snapshot.checkpoint
        digest = anchor_subject_digest(cp.origin, cp.tree_size, cp.root_hash)
        resp = issue_timestamp_response(digest, tsa, nonce=nonce)
        return CheckpointAnchorRecord.from_response(
            checkpoint=cp,
            signed_note=snapshot.signed_note,
            authority="local-demo-tsa",
            response_der=resp,
            request_nonce=nonce,
        )

    return anchor


def _exploding_anchor_fn(snapshot):
    raise RuntimeError("TSA unreachable (simulated)")


def _wait_until(pred, timeout: float = 3.0, tick: float = 0.01) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(tick)
    return pred()


# --------------------------------------------------------------------------- count trigger
def test_count_trigger_produces_externally_verifiable_anchor():
    """After N appends an anchor is produced AND the existing offline verifier
    accepts it against the pinned TSA cert — the core deliverable."""
    ledger = SealedFactLedger()
    tsa = mint_local_tsa()
    sched = AnchorScheduler(
        ledger, anchor_fn=_local_anchor_fn(tsa), every_n_appends=3, interval_seconds=None
    )

    _append(ledger, 0)
    _append(ledger, 1)
    assert sched.maybe_anchor() is None  # below threshold (2 < 3)
    assert sched.anchor_count == 0

    _append(ledger, 2)
    record = sched.maybe_anchor()  # 3 new >= 3 -> fires
    assert record is not None
    assert record.tree_size == 3
    assert sched.anchor_count == 1

    # The EXISTING verifier (no new verifier written) accepts it offline.
    av = verify_anchor_receipt(record, pinned_tsa_cert_der=tsa.ca_pin_der)
    assert av.ok is True
    assert av.gen_time is not None
    assert av.failure_code is None


def test_no_new_facts_means_no_redundant_anchor():
    """A second pass with nothing appended does not re-anchor the same tree-head."""
    ledger = SealedFactLedger()
    tsa = mint_local_tsa()
    sched = AnchorScheduler(
        ledger, anchor_fn=_local_anchor_fn(tsa), every_n_appends=1, interval_seconds=None
    )
    _append(ledger, 0)
    assert sched.maybe_anchor() is not None
    assert sched.anchor_count == 1
    # No new appends -> new == 0 -> skip (root would be identical).
    assert sched.maybe_anchor() is None
    assert sched.anchor_count == 1


# --------------------------------------------------------------------------- interval trigger
def test_interval_trigger_fires_on_elapsed_time():
    """With the count trigger disabled and interval_seconds=0, any new content
    anchors on the next pass (deterministic, no sleeping)."""
    ledger = SealedFactLedger()
    tsa = mint_local_tsa()
    sched = AnchorScheduler(
        ledger, anchor_fn=_local_anchor_fn(tsa), every_n_appends=None, interval_seconds=0.0
    )
    _append(ledger, 0)
    record = sched.maybe_anchor()
    assert record is not None
    assert verify_anchor_receipt(record, pinned_tsa_cert_der=tsa.ca_pin_der).ok is True


# --------------------------------------------------------------------------- fail-soft
def test_anchor_failure_never_breaks_or_blocks_the_decision_path():
    """A failing anchor_fn is logged and dropped — never raised — and leaves the
    ledger (the decision path's record of truth) fully intact and still writable."""
    ledger = SealedFactLedger()
    _append(ledger, 0)
    _append(ledger, 1)
    sched = AnchorScheduler(
        ledger, anchor_fn=_exploding_anchor_fn, every_n_appends=1, interval_seconds=None
    )

    # Does not raise; returns None; records the dropped error.
    assert sched.maybe_anchor() is None
    assert sched.anchor_count == 0
    assert sched.last_anchor is None
    assert sched.last_error is not None and "RuntimeError" in sched.last_error

    # The decision path is untouched: the ledger still appends, and the chain +
    # signatures (verify_chain / verify_signatures — NOT this scheduler's job)
    # remain valid after the failed anchor.
    _append(ledger, 2)
    assert len(ledger) == 3
    assert ledger.verify_chain()["intact"] is True
    assert ledger.verify_signatures()["valid"] is True


# --------------------------------------------------------------------------- background daemon
def test_start_stop_daemon_anchors_in_background():
    """start()/stop() runs a daemon that anchors off the request thread; what it
    produces verifies against the pinned cert; stop() joins cleanly."""
    ledger = SealedFactLedger()
    tsa = mint_local_tsa()
    sched = AnchorScheduler(
        ledger,
        anchor_fn=_local_anchor_fn(tsa),
        every_n_appends=1,
        interval_seconds=0.0,
        poll_seconds=0.01,
    )
    for i in range(3):
        _append(ledger, i)

    sched.start()
    try:
        assert _wait_until(lambda: sched.anchor_count >= 1, timeout=3.0)
    finally:
        sched.stop()

    assert sched.is_running is False
    record = sched.last_anchor
    assert record is not None
    assert verify_anchor_receipt(record, pinned_tsa_cert_der=tsa.ca_pin_der).ok is True


def test_daemon_survives_failures_and_leaves_ledger_intact():
    """A daemon whose anchor_fn keeps failing never dies, never corrupts the
    ledger, and surfaces the error — proving anchoring is fully decoupled."""
    ledger = SealedFactLedger()
    _append(ledger, 0)
    sched = AnchorScheduler(
        ledger,
        anchor_fn=_exploding_anchor_fn,
        every_n_appends=1,
        interval_seconds=None,
        poll_seconds=0.01,
    )
    sched.start()
    try:
        assert _wait_until(lambda: sched.last_error is not None, timeout=3.0)
        # Keep writing the ledger while the failing daemon runs.
        for i in range(1, 6):
            _append(ledger, i)
        assert _wait_until(lambda: sched.is_running, timeout=0.5)  # still alive
    finally:
        sched.stop()

    assert sched.anchor_count == 0
    assert len(ledger) == 6
    assert ledger.verify_chain()["intact"] is True
    assert ledger.verify_signatures()["valid"] is True


# --------------------------------------------------------------------------- thread-safety
def test_concurrent_appends_during_anchoring_stay_chain_intact():
    """Appends from several threads while the daemon anchors must not break the
    chain — the scheduler only READS the (thread-safe) ledger."""
    import threading

    ledger = SealedFactLedger()
    tsa = mint_local_tsa()
    sched = AnchorScheduler(
        ledger,
        anchor_fn=_local_anchor_fn(tsa),
        every_n_appends=2,
        interval_seconds=0.0,
        poll_seconds=0.005,
    )

    def writer(base: int) -> None:
        for i in range(10):
            _append(ledger, base * 100 + i)

    sched.start()
    try:
        threads = [threading.Thread(target=writer, args=(t,)) for t in range(4)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        assert _wait_until(lambda: sched.anchor_count >= 1, timeout=3.0)
    finally:
        sched.stop()

    assert len(ledger) == 40
    assert ledger.verify_chain()["intact"] is True
    assert ledger.verify_signatures()["valid"] is True
    if sched.last_anchor is not None:
        av = verify_anchor_receipt(sched.last_anchor, pinned_tsa_cert_der=tsa.ca_pin_der)
        assert av.ok is True


# --------------------------------------------------------------------------- guardrails
def test_requires_at_least_one_trigger():
    import pytest

    with pytest.raises(ValueError):
        AnchorScheduler(
            SealedFactLedger(),
            anchor_fn=_exploding_anchor_fn,
            every_n_appends=None,
            interval_seconds=None,
        )
