"""
PlaneSignalRegistry — the LIVE, OBSERVED signal store behind the per-agent
enforcement-plane badge (``GET /v1/govern/agents/plane``).

The honest premise
------------------
A governed agent's enforcement plane is NEVER asserted from capability,
configuration, or availability. It is derived from a *recorded, fresh,
observed* signal — and in the ABSENCE of one it degrades to the floor. This
module is that store: an in-memory, TTL/freshness-windowed, default-EMPTY
ledger of the two upgrade signals, plus the pure read that derives a plane.

Three planes, strictly ordered by strength:

  * ``DECIDE-ONLY``         — the floor. PDP decides only; no in-path Body, no
    observed downstream demand. This is what a plane DEGRADES TO. It needs no
    signal: it is the resting state of an empty registry (the Render reality
    and any fresh boot).
  * ``CREDENTIAL-ENFORCED`` — a downstream resource actually ran the B3
    demand-verifier and ACCEPTED a Tex-minted cred for this agent. Recorded
    via :meth:`record_handshake`. Broker/mint *availability* is NOT this; only
    an observed handshake upgrades. Fresh for ``cred_ttl_s`` (default 120s,
    mirroring the PoP freshness window).
  * ``IN-PATH-BLOCKING``    — a live kernel/proxy PEP is ACTUALLY polling the
    tenant's forbid-set (loader heartbeat). Recorded via :meth:`record_poll`.
    Tenant-scoped: an in-path Body blocks the tenant's whole egress, so it
    applies to every governed agent in that tenant — but ONLY while a fresh
    poll exists. Fresh for ``poll_ttl_s`` (default 90s = 3x the 30s loader
    poll interval).

Monotone-down on absence/staleness: any signal whose recorded ts is older than
its TTL is treated as if absent, and the plane drops. There is NO code path
that upgrades a plane from broker availability, mint capability, route
existence, or config alone — only a recorded, fresh signal upgrades.

WHAT IS REAL TODAY: only the floor. No producer is wired yet — ``verify_tgpcc``
(the B3 demand-verifier) is a pure offline function that returns a
``ResourceCheck`` to the resource and never reports back to Tex, and the
forbid-set routes record no poll recency. So both ingestion methods exist and
work, but with nothing fed (the state on Render and at boot) the registry
yields all-``DECIDE-ONLY``. A later, separate change can light up a real
producer without changing the derivation rule here.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Final

__all__ = [
    "PLANE_DECIDE_ONLY",
    "PLANE_CREDENTIAL_ENFORCED",
    "PLANE_IN_PATH_BLOCKING",
    "PlaneSignalRegistry",
    "AgentPlane",
]

# The three planes, weakest -> strongest. The floor is the resting state.
PLANE_DECIDE_ONLY: Final[str] = "DECIDE-ONLY"
PLANE_CREDENTIAL_ENFORCED: Final[str] = "CREDENTIAL-ENFORCED"
PLANE_IN_PATH_BLOCKING: Final[str] = "IN-PATH-BLOCKING"

# Default freshness windows. The credential window mirrors verify._POP_MAX_AGE
# (120s). The poll window is 3x the 30s loader poll interval (forbid_source).
_DEFAULT_CRED_TTL_S: Final[float] = 120.0
_DEFAULT_POLL_TTL_S: Final[float] = 90.0

# Bound the in-memory store so a hostile/noisy producer can't grow it without
# limit. LRU per dimension; the read is unaffected by the cap (oldest evicted).
_MAX_AGENTS: Final[int] = 50_000
_MAX_TENANT_POLLS: Final[int] = 10_000


@dataclass(frozen=True)
class AgentPlane:
    """The derived plane for one agent — exactly the DoD response shape."""

    agent_id: str
    plane: str
    last_handshake_ts: float | None

    def to_jsonable(self) -> dict[str, object]:
        return {
            "agent_id": self.agent_id,
            "plane": self.plane,
            "last_handshake_ts": self.last_handshake_ts,
        }


class PlaneSignalRegistry:
    """In-memory, TTL-windowed, default-EMPTY store of observed plane signals.

    Empty by construction: a freshly built registry records nothing, so every
    agent it is asked about reads ``DECIDE-ONLY`` with ``last_handshake_ts``
    ``None``. Reads are PURE (never mutate, never upgrade); only the explicit
    ``record_*`` ingestion points add a signal.
    """

    def __init__(
        self,
        *,
        cred_ttl_s: float = _DEFAULT_CRED_TTL_S,
        poll_ttl_s: float = _DEFAULT_POLL_TTL_S,
        clock=time.time,
    ) -> None:
        self._cred_ttl_s = float(cred_ttl_s)
        self._poll_ttl_s = float(poll_ttl_s)
        self._clock = clock
        self._lock = threading.Lock()
        # agent_id (str) -> last credential-handshake ts (float, monotone-max).
        self._handshakes: OrderedDict[str, float] = OrderedDict()
        # tenant (str) -> last forbid-set poll ts (float, monotone-max).
        # Tenant-scoped: we keep the freshest poll across all loaders for the
        # tenant (any one live loader means the tenant has a live in-path PEP).
        self._polls: OrderedDict[str, float] = OrderedDict()

    # ------------------------------------------------------------ ingestion

    def record_handshake(
        self,
        agent_id: str,
        tenant: str,  # noqa: ARG002 — accepted for the producer's call shape; agent_id keys
        resource: str,  # noqa: ARG002 — which downstream verified; not needed for the badge
        ts: float | None = None,
    ) -> None:
        """An OBSERVED B3 demand-verifier handshake: a downstream resource ran
        the verifier and ACCEPTED a Tex-minted cred whose subject is this agent.

        This is the ONLY honest producer of CREDENTIAL-ENFORCED. Broker/mint
        availability must NEVER call this — only a real accepted handshake does.
        """
        key = str(agent_id).strip()
        if not key:
            return
        when = self._clock() if ts is None else float(ts)
        with self._lock:
            # Monotone-max: never let a stale replay regress a fresher ts.
            prev = self._handshakes.get(key)
            if prev is not None and prev >= when:
                self._handshakes.move_to_end(key)
                return
            self._handshakes[key] = when
            self._handshakes.move_to_end(key)
            while len(self._handshakes) > _MAX_AGENTS:
                self._handshakes.popitem(last=False)

    def record_poll(
        self,
        tenant: str,
        loader_id: str,  # noqa: ARG002 — identifies the loader; tenant freshness is what matters
        ts: float | None = None,
    ) -> None:
        """A live kernel/proxy PEP polled the tenant's forbid-set (loader
        heartbeat) — the only honest producer of IN-PATH-BLOCKING. Tenant-scoped.
        """
        tid = (tenant or "").strip().casefold()
        if not tid:
            return
        when = self._clock() if ts is None else float(ts)
        with self._lock:
            prev = self._polls.get(tid)
            if prev is not None and prev >= when:
                self._polls.move_to_end(tid)
                return
            self._polls[tid] = when
            self._polls.move_to_end(tid)
            while len(self._polls) > _MAX_TENANT_POLLS:
                self._polls.popitem(last=False)

    # ----------------------------------------------------------------- read

    def _fresh_handshake_ts(self, agent_id: str, now: float) -> float | None:
        ts = self._handshakes.get(str(agent_id).strip())
        if ts is None:
            return None
        return ts if (now - ts) <= self._cred_ttl_s else None

    def _has_fresh_poll(self, tenant: str, now: float) -> bool:
        ts = self._polls.get((tenant or "").strip().casefold())
        if ts is None:
            return False
        return (now - ts) <= self._poll_ttl_s

    def derive(self, agent_id: str, tenant: str) -> AgentPlane:
        """Derive the plane for ONE agent from fresh, recorded signals only.

        Strictly monotone-down on absence/staleness:

          1. Start at the floor: ``DECIDE-ONLY``, ``last_handshake_ts=None``.
          2. A FRESH credential handshake for this agent => ``CREDENTIAL-ENFORCED``
             and ``last_handshake_ts`` = that ts.
          3. A FRESH in-path poll for this agent's tenant => ``IN-PATH-BLOCKING``
             (the stronger plane; the tenant has a live in-path Body blocking
             this agent's egress). ``last_handshake_ts`` is the credential
             handshake ts when present, else ``None`` (an in-path-only agent has
             no per-agent handshake — the DoD field stays null, the plane still
             reads IN-PATH-BLOCKING).

        Anything past its TTL is treated as absent => the plane drops. An empty
        registry => ``DECIDE-ONLY`` with ``last_handshake_ts=None``.
        """
        now = self._clock()
        with self._lock:
            handshake_ts = self._fresh_handshake_ts(agent_id, now)
            has_poll = self._has_fresh_poll(tenant, now)

        plane = PLANE_DECIDE_ONLY
        if handshake_ts is not None:
            plane = PLANE_CREDENTIAL_ENFORCED
        if has_poll:
            plane = PLANE_IN_PATH_BLOCKING
        return AgentPlane(
            agent_id=str(agent_id),
            plane=plane,
            last_handshake_ts=handshake_ts,
        )
