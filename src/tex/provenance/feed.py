"""
Continuous provenance feed — the primitive made alive.

The behavioural provenance engine can resolve and seal an identity from a
window of an agent's actions. On its own, though, it only runs when
something calls ``/v1/provenance/observe``. That makes it a tool you point
at an agent — not a witness. This module closes that gap: it fires
``observe()`` automatically off the gate's decision stream, so identity
seals continuously, on its own, the instant an agent acts.

Three constraints shape the whole design, and they come straight from the
doctrine:

  1. **It never touches the hot path's latency.** The evaluate path calls
     exactly one cheap, non-blocking method (``note_action``): a counter
     bump under a short-held lock and, at most, an ``O(1)`` enqueue. All
     signature derivation and sealing happen on a background worker. The
     verdict the caller is waiting on never waits on provenance.

  2. **It seals in silence.** The feed resolves and seals BIRTH / SIGHTING
     / REIDENTIFIED / DRIFT events into the transparency log and says
     nothing. "A new thing was discovered" is the one trigger §1 forbids
     from breaking the voice. The feed has no channel to the surface for
     ordinary findings — by construction, not by convention.

  3. **The only thing that ever leaves the feed is a held decision.** When
     a resolution comes back ``requires_human`` — a possible merge, a
     drift past threshold — that, and only that, is routed onward, into a
     held-decision sink. The feed records it; whether and how Tex breaks
     silence to speak it is the surface's concern, not the feed's. A held
     decision is one of the two things (with the faltering confession)
     that earns the voice.

The feed also threads agent-to-agent delegations it can see in the action
stream into the sealed delegation graph, so the dormancy controller has a
defensible "is this load-bearing?" signal.
"""

from __future__ import annotations

import logging
import queue
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from tex.domain.signal_trust import SignalTrustTier
from tex.provenance.delegation import SealedDelegationGraph
from tex.provenance.engine import BehavioralProvenanceEngine
from tex.provenance.models import ProvenanceResolution

_logger = logging.getLogger(__name__)

# How many of an agent's actions accumulate before the feed schedules a
# re-observation. Small enough that identity stays fresh; large enough
# that a busy agent doesn't enqueue on every single action. The window
# the engine actually reads is independent (and larger), so a batch of 4
# still resolves against the agent's recent history, not just 4 events.
DEFAULT_BATCH_SIZE: int = 4

# How many of an agent's most-recent action-ledger entries to fold into
# each behavioural window.
DEFAULT_WINDOW: int = 200


@dataclass(frozen=True, slots=True)
class HeldDecision:
    """
    A consequential, ambiguous resolution the engine refused to settle on
    its own. This is held-decision material — surfaced for a human, the
    only discovery event that earns the voice.
    """

    agent_id: UUID
    kind: str  # the ProvenanceEventKind that triggered the hold
    confidence: float
    note: str
    detail: dict[str, Any] = field(default_factory=dict)
    raised_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    # Owning tenant, so the /held surface can filter to the caller's tenant
    # (a scoped key must not see — or seal — another tenant's held decisions).
    # Defaults to "default" for back-compat and the single-partition/operator view.
    tenant_id: str = "default"
    # Optional Layer-4 hold object (engine/hold.py, as a dict) when this held
    # decision originates from a PDP ABSTAIN rather than the provenance path.
    # Carries the two-sided certificate band, the epistemic/aleatoric type,
    # and the pivotal resolving question. Left None for provenance-origin holds.
    hold: dict[str, Any] | None = None
    # Optional durable decision id + sealed anchor, when known.
    decision_id: str | None = None
    anchor_sha256: str | None = None

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "agent_id": str(self.agent_id),
            "kind": self.kind,
            "confidence": round(self.confidence, 6),
            "note": self.note,
            "detail": self.detail,
            "raised_at": self.raised_at.isoformat(),
            "hold": self.hold,
            "decision_id": self.decision_id,
            "anchor_sha256": self.anchor_sha256,
            "tenant_id": self.tenant_id,
        }


class HeldDecisionSink:
    """
    Thread-safe holding area for resolutions that require a human. The
    feed appends; the surface pulls. Nothing here is a notification — it
    is a queue Tex *may* choose to speak from when it breaks silence.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._items: list[HeldDecision] = []

    def append(self, item: HeldDecision) -> None:
        with self._lock:
            self._items.append(item)

    def peek(self) -> tuple[HeldDecision, ...]:
        with self._lock:
            return tuple(self._items)

    def peek_for_tenant(self, tenant: str | None) -> tuple[HeldDecision, ...]:
        """
        Held items visible to ``tenant``.

        A ``None`` / ``"default"`` caller is the operator/fleet view and sees
        every held item (mirrors the discovery/agent-list omniscient-default
        convention). A specific tenant sees only its own held decisions, so a
        scoped key can neither read nor (via the returned decision_id) seal
        another tenant's holds. Comparison is casefold/trim on both sides.
        """
        with self._lock:
            if tenant is None:
                return tuple(self._items)
            wanted = tenant.strip().casefold()
            if wanted in ("", "default"):
                return tuple(self._items)
            return tuple(
                item
                for item in self._items
                if (item.tenant_id or "default").strip().casefold() == wanted
            )

    def pull(self) -> tuple[HeldDecision, ...]:
        """Return and clear the held items (the surface has spoken them)."""
        with self._lock:
            items = tuple(self._items)
            self._items.clear()
            return items

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


class ContinuousProvenanceFeed:
    """
    Wires the gate's decision stream into the provenance engine so identity
    seals continuously and silently. Safe to leave unstarted (tests drive
    it synchronously via :meth:`drain`); safe to start as a daemon worker
    in production.
    """

    def __init__(
        self,
        *,
        engine: BehavioralProvenanceEngine,
        action_ledger: Any,
        held_sink: HeldDecisionSink | None = None,
        delegation_graph: SealedDelegationGraph | None = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
        window: int = DEFAULT_WINDOW,
        signal_tier: SignalTrustTier = SignalTrustTier.NETWORK_OBSERVED,
    ) -> None:
        self._engine = engine
        self._ledger = action_ledger
        self._held = held_sink if held_sink is not None else HeldDecisionSink()
        self._delegation = delegation_graph
        self._batch_size = max(1, int(batch_size))
        self._window = max(1, int(window))
        self._signal_tier = signal_tier

        self._lock = threading.RLock()
        self._pending: dict[str, int] = {}
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._worker: threading.Thread | None = None
        self._stop = threading.Event()
        # Bookkeeping the dormancy controller and metrics can read.
        self._sealed_total = 0
        self._last_sealed_at: datetime | None = None

    # ------------------------------------------------------------------ held
    @property
    def held(self) -> HeldDecisionSink:
        return self._held

    @property
    def sealed_total(self) -> int:
        with self._lock:
            return self._sealed_total

    # ------------------------------------------------------------------ hot path
    def note_action(
        self,
        agent_id: UUID,
        *,
        delegate_agent_id: UUID | None = None,
        channel: str = "unknown",
    ) -> None:
        """
        Called by the evaluate path after an action is written to the
        ledger. Cheap and non-blocking by contract: a counter bump and at
        most one enqueue. Never derives a signature, never seals, never
        blocks the verdict. Any failure here is swallowed — provenance
        must not be able to break the gate.
        """
        try:
            if delegate_agent_id is not None and self._delegation is not None:
                # Seal the agent-to-agent edge off the hot path is ideal,
                # but the graph append is itself O(1) + one signature; keep
                # it here only because it is rare relative to plain actions.
                try:
                    self._delegation.observe_delegation(
                        delegator_id=agent_id,
                        delegate_id=delegate_agent_id,
                        channel=channel,
                    )
                except Exception:  # noqa: BLE001
                    pass

            key = str(agent_id)
            schedule = False
            with self._lock:
                count = self._pending.get(key, 0) + 1
                if count >= self._batch_size:
                    self._pending[key] = 0
                    schedule = True
                else:
                    self._pending[key] = count
            if schedule:
                self._queue.put_nowait(key)
        except Exception:  # noqa: BLE001
            # The feed is best-effort and must never raise into the gate.
            _logger.debug("continuous feed note_action swallowed an error", exc_info=True)

    # ------------------------------------------------------------------ worker
    def start(self) -> None:
        """Start the background sealing worker (idempotent)."""
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                return
            self._stop.clear()
            self._worker = threading.Thread(
                target=self._run,
                name="tex-provenance-feed",
                daemon=True,
            )
            self._worker.start()

    def stop(self, *, timeout: float = 2.0) -> None:
        self._stop.set()
        # Nudge the worker out of its blocking get().
        try:
            self._queue.put_nowait("__stop__")
        except Exception:  # noqa: BLE001
            pass
        worker = self._worker
        if worker is not None:
            worker.join(timeout=timeout)
        self._worker = None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                key = self._queue.get(timeout=0.25)
            except queue.Empty:
                continue
            if key == "__stop__":
                self._queue.task_done()
                continue
            try:
                self._seal_for(key)
            except Exception:  # noqa: BLE001
                _logger.warning("continuous feed sealing error", exc_info=True)
            finally:
                self._queue.task_done()

    # ------------------------------------------------------------------ sealing
    def _action_window(self, agent_id: UUID):
        ledger = self._ledger
        if ledger is None:
            return ()
        try:
            return ledger.list_for_agent(agent_id, limit=self._window)
        except TypeError:
            return tuple(ledger.list_for_agent(agent_id))[: self._window]
        except Exception:  # noqa: BLE001
            return ()

    def _seal_for(self, key: str) -> None:
        agent_id = UUID(key)
        entries = self._action_window(agent_id)
        if not entries:
            return
        resolution = self._engine.observe(
            agent_id=agent_id,
            entries=entries,
            signal_tier=self._signal_tier,
        )
        with self._lock:
            self._sealed_total += 1
            self._last_sealed_at = datetime.now(UTC)
        self._route(agent_id, resolution)

    def _route(self, agent_id: UUID, resolution: ProvenanceResolution) -> None:
        """
        The whole surface the feed has to the outside world. A held
        resolution is recorded for the voice; everything else is sealed
        and silent — there is deliberately no branch that emits an
        ordinary finding.
        """
        if not resolution.requires_human:
            return
        self._held.append(
            HeldDecision(
                agent_id=agent_id,
                kind=str(resolution.event_kind),
                confidence=resolution.confidence,
                note=resolution.note or "",
                detail={
                    "best_match": (
                        str(resolution.best_match.agent_id)
                        if resolution.best_match
                        else None
                    ),
                },
            )
        )

    # ------------------------------------------------------------------ test/forcing
    def flush(self) -> None:
        """Enqueue every agent that has pending actions below the batch."""
        with self._lock:
            pending = [k for k, c in self._pending.items() if c > 0]
            for k in pending:
                self._pending[k] = 0
        for k in pending:
            self._queue.put_nowait(k)

    def drain(self, *, timeout: float = 5.0) -> None:
        """
        Force every queued (and pending) agent to be processed
        synchronously and wait until done. Used by tests and by an
        explicit operator-triggered reconcile; production relies on the
        worker instead. Processes inline so it is deterministic even when
        the worker thread was never started.
        """
        self.flush()
        # Drain whatever is queued, inline.
        while True:
            try:
                key = self._queue.get_nowait()
            except queue.Empty:
                break
            if key == "__stop__":
                self._queue.task_done()
                continue
            try:
                self._seal_for(key)
            except Exception:  # noqa: BLE001
                _logger.warning("continuous feed drain error", exc_info=True)
            finally:
                self._queue.task_done()
