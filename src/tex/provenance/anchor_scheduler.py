"""
Background anchor scheduler — drive the EXISTING RFC-3161 anchorer on the live
enforcement ``SealedFactLedger``, off the hot path (closes G11).

What gap this closes
--------------------
A ``SealedFactLedger`` record_hash = ``SHA-256(payload_sha256, previous_hash)``:
it binds **order, never time**. The real external-time anchorer
(``provenance.bundle.anchor_ledger_checkpoint`` → an RFC-3161 TSA, verified
offline by ``interchange.external_anchor.verify_anchor_receipt`` against a
**pinned** TSA cert) was only ever an on-demand bundle export — nothing drove it
on the *live* enforcement ledger. This scheduler does: periodically (after N new
appends, or once T seconds have elapsed with new content) it checkpoints the
ledger's current tree-head and hands it to the injected ``anchor_fn``, entirely
on a background thread.

It REUSES, never reimplements:
  * ``provenance.bundle.anchor_ledger_checkpoint``   (tree-head → anchor_fn)
  * the injected ``anchor_fn`` — build it in production with
    ``discovery.conduit.seal.make_rfc3161_anchor`` (network injected via a
    timeout-bounded ``poster``); tests inject a local-TSA fn (``mint_local_tsa``)
  * ``interchange.external_anchor.verify_anchor_receipt`` verifies what it
    produces — there is no second verifier here.

Off the hot path, fail-soft
---------------------------
The request/decision path NEVER calls into this scheduler — it *observes* the
ledger (``len`` + ``list_all`` under the ledger's own lock); it does not
instrument the append site. So a slow or failing anchor cannot block or break a
decision: an anchor failure is logged and dropped (captured in ``last_error``),
**never raised**. Thread-safe: at most one anchor runs at a time, and concurrent
appends are safe because the ledger is itself thread-safe and we only read it.

Honesty — what an anchor proves, and what it does NOT
-----------------------------------------------------
* It proves **WHEN, not whether-or-correctly.** A successful anchor lets a
  relying party conclude only "an authority that is NOT Tex saw this exact set
  of facts no later than ``genTime``" — *when* verified against a **pinned**
  external TSA cert. It says nothing about whether any decision in the chain was
  correct; chain integrity and authorship remain ``ledger.verify_chain`` /
  ``verify_signatures``' job. This scheduler only attaches a clock, not a verdict.
* **TAIL WINDOW (never zero).** Anchoring is periodic, so there is ALWAYS a
  trailing set of facts appended since the last checkpoint whose age is not yet
  proven. The window is bounded by ``every_n_appends`` / ``interval_seconds``,
  PLUS the poll latency and the TSA round-trip. The very last facts before a
  crash may never be anchored at all.
* A **local TSA** (``mint_local_tsa``, used by the tests) proves nothing about
  real wall-clock time — only pinning a real external authority's cert does. The
  scheduler is agnostic: it drives whatever ``anchor_fn`` you inject.

Maturity: ``research-early`` — it composes ``external_anchor`` (itself
``research-early``: real live CMS crypto, newly wired, not yet CI-benchmarked).
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from tex.interchange.external_anchor import CheckpointAnchorRecord
from tex.interchange.gix import SignedCheckpoint
from tex.provenance.bundle import anchor_ledger_checkpoint
from tex.provenance.ledger import SealedFactLedger

__all__ = ["AnchorScheduler", "AnchorFn"]

logger = logging.getLogger(__name__)

# A tree-head snapshot → external timestamp receipt (or ``None`` to skip). Built
# in production by ``discovery.conduit.seal.make_rfc3161_anchor``; injected so
# this module imports NO network library and tests inject a local-TSA fn.
AnchorFn = Callable[[SignedCheckpoint], "CheckpointAnchorRecord | None"]

_DEFAULT_EVERY_N = 64
_DEFAULT_INTERVAL = 300.0
_DEFAULT_ORIGIN = "tex.enforcement/sealed-fact-ledger"
# Hard floor on the poll cadence so an idle daemon never spins at 100% CPU.
_MIN_POLL = 0.001


class AnchorScheduler:
    """Periodically anchor a live ``SealedFactLedger``'s tree-head, off the hot path.

    Triggers (either fires; both may be active):
      * **count**    — at least ``every_n_appends`` new facts since the last
        anchor;
      * **interval** — at least ``interval_seconds`` since the last anchor
        *attempt*, with ≥1 new fact (an unchanged tree-head is never re-anchored:
        the root is identical, so it would only cost a redundant TSA call).

    Pass ``None`` to disable a trigger; at least one must remain active. Use it
    detached — call :meth:`maybe_anchor` yourself (a test, or an optional
    per-append hook) — or call :meth:`start` for a daemon thread that polls every
    ``poll_seconds`` (default: ``interval_seconds``, floored at 1s). Either way
    the anchoring work runs in the CALLING thread of :meth:`maybe_anchor`, so do
    not call it from the request/decision path; ``start()`` keeps it on the
    daemon thread.

    Accepts any object with the ``SealedFactLedger`` read contract
    (``__len__`` + ``list_all`` returning records with ``record_hash``) — the
    behavioural ledger duck-types too.
    """

    def __init__(
        self,
        ledger: SealedFactLedger,
        *,
        anchor_fn: AnchorFn,
        every_n_appends: int | None = _DEFAULT_EVERY_N,
        interval_seconds: float | None = _DEFAULT_INTERVAL,
        poll_seconds: float | None = None,
        origin: str = _DEFAULT_ORIGIN,
    ) -> None:
        if every_n_appends is not None and every_n_appends < 1:
            raise ValueError("every_n_appends must be >= 1 or None")
        if interval_seconds is not None and interval_seconds < 0:
            raise ValueError("interval_seconds must be >= 0 or None")
        if every_n_appends is None and interval_seconds is None:
            raise ValueError(
                "at least one of every_n_appends / interval_seconds must be set"
            )

        self._ledger = ledger
        self._anchor_fn = anchor_fn
        self._every_n = every_n_appends
        self._interval = interval_seconds
        # Poll cadence: how often the daemon evaluates the triggers. Default to
        # interval_seconds (floored at 1s) so an idle daemon does not spin; set
        # lower to honour the count trigger more promptly under high append load.
        if poll_seconds is not None:
            self._poll = max(_MIN_POLL, float(poll_seconds))
        elif interval_seconds is not None:
            self._poll = max(1.0, float(interval_seconds))
        else:
            self._poll = 1.0
        self._origin = origin

        # State lock — guards the counters/last_* fields + the single-flight flag,
        # NOT held across the (possibly slow) anchor network call.
        self._lock = threading.Lock()
        self._anchoring = False
        self._last_size = 0
        self._last_anchor_monotonic = time.monotonic()
        self._anchor_count = 0
        self._last_anchor: CheckpointAnchorRecord | None = None
        self._last_error: str | None = None

        # Thread lifecycle — separate lock so stop() never waits on the state lock.
        self._thread_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # ------------------------------------------------------------------ read
    @property
    def anchor_count(self) -> int:
        """Number of successful anchors produced so far."""
        with self._lock:
            return self._anchor_count

    @property
    def last_anchor(self) -> CheckpointAnchorRecord | None:
        """The most recent successful anchor record (``None`` until the first)."""
        with self._lock:
            return self._last_anchor

    @property
    def last_error(self) -> str | None:
        """The most recent dropped anchor failure (``None`` if none / cleared on
        the next success). Surfaced for observability; never raised."""
        with self._lock:
            return self._last_error

    @property
    def is_running(self) -> bool:
        with self._thread_lock:
            return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------ core
    def _should_anchor(self, size: int, now: float) -> bool:
        new = size - self._last_size
        if new <= 0:
            return False
        if self._every_n is not None and new >= self._every_n:
            return True
        if (
            self._interval is not None
            and (now - self._last_anchor_monotonic) >= self._interval
        ):
            return True
        return False

    def maybe_anchor(self, *, force: bool = False) -> CheckpointAnchorRecord | None:
        """Evaluate the triggers once and, if due, checkpoint + anchor the ledger.

        Runs in the CALLING thread (the daemon, or a test) — never call it from
        the request/decision path. Fail-soft: any error is logged and stored in
        :attr:`last_error`, **never raised**. Returns the anchor record on
        success, else ``None`` (not due, empty ledger, ``anchor_fn`` returned
        ``None``, or a dropped failure). ``force=True`` skips the trigger check
        but still requires ≥1 record. Single-flight: a concurrent call while an
        anchor is in progress returns ``None`` rather than piling up TSA calls.
        """
        with self._lock:
            if self._anchoring:
                return None
            size = len(self._ledger)
            if size == 0:
                return None
            if not force and not self._should_anchor(size, time.monotonic()):
                return None
            self._anchoring = True

        # Anchor OUTSIDE the lock so property reads / concurrent appends never
        # block on the (possibly slow) TSA round-trip.
        record: CheckpointAnchorRecord | None = None
        error: str | None = None
        try:
            record = anchor_ledger_checkpoint(
                self._ledger, anchor_fn=self._anchor_fn, origin=self._origin
            )
        except Exception as exc:  # noqa: BLE001 — anchoring must never break the decision path
            error = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "anchor attempt failed (dropped, decision path untouched): %s", error
            )

        with self._lock:
            self._anchoring = False
            # Advance the interval clock on every ATTEMPT so a failing TSA is not
            # hammered every poll; the count trigger still retries promptly while
            # un-anchored facts pile up. Persistent failure is visible via
            # last_error.
            self._last_anchor_monotonic = time.monotonic()
            if record is not None:
                # Pin progress to what was actually anchored (the checkpoint's
                # committed size), NOT a fresh len() — facts appended during the
                # round-trip stay pending for the next anchor (the tail window).
                self._last_size = record.tree_size
                self._anchor_count += 1
                self._last_anchor = record
                self._last_error = None
            elif error is not None:
                self._last_error = error
        return record

    # ------------------------------------------------------------------ daemon
    def start(self) -> "AnchorScheduler":
        """Start the daemon poll loop (idempotent). Returns ``self`` so the merge
        step is a single line: ``AnchorScheduler(ledger, anchor_fn=...).start()``."""
        with self._thread_lock:
            if self._thread is not None and self._thread.is_alive():
                return self
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run, name="tex-anchor-scheduler", daemon=True
            )
            self._thread.start()
        return self

    def stop(self, *, timeout: float | None = 5.0) -> None:
        """Signal the daemon to stop and join it (bounded). May wait for an
        in-flight anchor — the injected ``poster`` should itself be
        timeout-bounded so the join cannot hang indefinitely."""
        with self._thread_lock:
            thread = self._thread
            self._thread = None
        self._stop.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=timeout)

    def _run(self) -> None:
        # Poll loop: wait poll seconds (or until stop), then evaluate the
        # triggers. ``maybe_anchor`` is already fail-soft; the extra guard keeps
        # the daemon alive even on an unexpected bug in the trigger logic.
        while not self._stop.wait(self._poll):
            try:
                self.maybe_anchor()
            except Exception:  # noqa: BLE001 — the daemon must never die on a bug
                logger.exception("anchor scheduler poll iteration failed")

    # ------------------------------------------------------------------ ctx mgr
    def __enter__(self) -> "AnchorScheduler":
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.stop()
