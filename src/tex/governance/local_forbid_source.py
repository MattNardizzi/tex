"""
Local-action forbid-set source — the hot, high-confidence FORBID *resources* the
in-kernel LOCAL-action PEP (``pep/kernel/localpep``) blocks with ``-EPERM``.

This is the LOCAL-plane twin of :mod:`tex.governance.forbid_source` (which warms
the NETWORK egress floor's ``verdict_cache``). It exists so the SAME live PDP
verdict that the egress proxy obeys can also drive the local-action Body — "one
verdict, many PEPs" — without forking the policy. The full decision still lives
in :class:`~tex.governance.standing.StandingGovernance`; this is only the small
hot set of ``(agent, resource)`` pairs a high-confidence FORBID has already been
established for.

Contract with the loader (``pep/kernel/localpep``)
--------------------------------------------------
:meth:`LocalForbidSource.signed_response` emits, for a tenant::

    {
      "set": {"forbid": [{"agent_id": "atlas-pay", "path": "/data/payroll.db"},
                          ...],
              "epoch": 7, "tenant": "acme"},
      "sig": "<hex HMAC-SHA256 over canonical(set)>"
    }

The loader VERIFIES ``sig`` with the shared ``TEX_LOCAL_PEP_SECRET`` BEFORE
warming any deny entry (a compromised agent cannot forge a signed set, nor strip
an entry — the signature is the cryptographic binding between the PDP verdict and
the kernel enforcement point). The loader then resolves ``agent_id`` -> the
agent's enrolled cgroup and ``path`` -> inode, and writes ``(cgroup_id, inode)``
into the in-kernel deny map. Path->inode and agent->cgroup resolution happen on
the fleet host (where the files and cgroups are), never in the PDP.

Safety properties (mirror the egress source, do not weaken)
-----------------------------------------------------------
* **Absence is never permit.** Membership means "block this local action inline";
  a resource not in the set is simply not in the fast-deny set (the full decision
  still governs whether the agent should have routed the action through Tex).
* **Revoke-wins / monotone within a TTL window.** An entry leaves only by explicit
  :meth:`revoke` or TTL expiry — never because a later feed merely omitted it. A
  withholding/empty feed can never un-block (the loader also never deletes on a
  fetch error).
* **Per-tenant, TTL'd, bounded+LRU, monotonic epoch** for loader anti-rollback.
* **Default OFF.** Nothing here runs unless ``TEX_LOCAL_PEP`` (composition) and,
  for the live-decision feed, the sink is wired in ``main.py``. Byte-for-byte
  inert otherwise.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from threading import RLock
from typing import Any
from typing import Callable

# Action types whose FORBID is attributable to a LOCAL resource (a file/binary),
# i.e. the loader can warm a (agent, resource) deny. Network action types are the
# egress source's job; agent-scoped/identity denials warm neither.
_LOCAL_ACTION_TYPES: frozenset[str] = frozenset(
    {
        "delete", "unlink", "remove", "rm", "destroy", "destructive",
        "truncate", "overwrite", "modify", "write", "rename", "move",
        "exec", "execute", "run",
        "file_delete", "file_write", "file_modify", "local_action",
    }
)

_DEFAULT_TTL_SECONDS = float(os.getenv("TEX_LOCAL_FORBID_TTL", "3600") or "3600")
_MAX_ENTRIES = int(os.getenv("TEX_LOCAL_FORBID_MAX", "65536") or "65536")
_USE_DEFAULT_TTL = object()

Clock = Callable[[], float]


def _norm_tenant(tenant: str | None) -> str | None:
    if tenant is None:
        return None
    t = tenant.strip()
    return t or None


def is_local_action_type(action_type: str | None) -> bool:
    return bool(action_type) and action_type.strip().casefold() in _LOCAL_ACTION_TYPES


@dataclass(frozen=True, slots=True)
class LocalForbidEntry:
    agent_id: str
    path: str
    tenant: str | None
    added_at: float
    ttl_seconds: float | None  # None == permanent (operator-seeded)

    def expired(self, now: float) -> bool:
        return self.ttl_seconds is not None and (now - self.added_at) >= self.ttl_seconds


class LocalForbidSource:
    """Per-tenant hot set of ``(agent_id, path)`` local-action FORBIDs."""

    __slots__ = ("_clock", "_default_ttl_seconds", "_max_entries", "_lock", "_epoch", "_entries")

    def __init__(
        self,
        *,
        clock: Clock | None = None,
        default_ttl_seconds: float | None = None,
        max_entries: int | None = None,
    ) -> None:
        self._clock: Clock = clock or time.time
        self._default_ttl_seconds = (
            default_ttl_seconds if default_ttl_seconds is not None else _DEFAULT_TTL_SECONDS
        )
        self._max_entries = max_entries if max_entries is not None else _MAX_ENTRIES
        self._lock = RLock()
        self._epoch = 0
        self._entries: dict[tuple[str, str, str | None], LocalForbidEntry] = {}

    @staticmethod
    def _key(agent_id: str, path: str, tenant: str | None) -> tuple[str, str, str | None]:
        return (agent_id.strip(), path.strip(), _norm_tenant(tenant))

    @property
    def epoch(self) -> int:
        with self._lock:
            return self._epoch

    def _upsert(self, entry: LocalForbidEntry) -> None:
        key = self._key(entry.agent_id, entry.path, entry.tenant)
        self._entries.pop(key, None)  # re-insert so LRU order tracks recency
        self._entries[key] = entry
        self._epoch += 1

    def _enforce_cap(self) -> None:
        # Evict oldest TTL'd entries first (permanent/operator entries never evict).
        while len(self._entries) > self._max_entries:
            for key, entry in self._entries.items():
                if entry.ttl_seconds is not None:
                    self._entries.pop(key, None)
                    break
            else:
                break  # only permanent entries remain

    def add(
        self,
        agent_id: str,
        path: str,
        *,
        tenant: str | None = None,
        ttl_seconds: float | None = _USE_DEFAULT_TTL,  # type: ignore[assignment]
    ) -> bool:
        """Add/refresh a forbid. Fail-closed: a blank agent/path is dropped, never
        widened to permit. Returns True if it took effect."""
        if not agent_id or not agent_id.strip() or not path or not path.strip():
            return False
        ttl = self._default_ttl_seconds if ttl_seconds is _USE_DEFAULT_TTL else ttl_seconds
        with self._lock:
            self._upsert(
                LocalForbidEntry(
                    agent_id=agent_id.strip(),
                    path=path.strip(),
                    tenant=_norm_tenant(tenant),
                    added_at=self._clock(),
                    ttl_seconds=ttl,
                )
            )
            self._enforce_cap()
        return True

    def feed_from_decision(
        self,
        *,
        action_type: str,
        recipient: str | None,
        agent_id: str | None,
        tenant: str | None,
    ) -> int:
        """FORBID sink wired into ``StandingGovernance.decide`` (gated). No-op
        (returns 0) unless the action is a LOCAL-resource action with a resolvable
        ``recipient`` (the resource path) and an ``agent_id``. The caller invokes
        this ONLY on a real FORBID outcome."""
        if not is_local_action_type(action_type):
            return 0
        if not recipient or not agent_id:
            return 0
        return 1 if self.add(agent_id, recipient, tenant=tenant) else 0

    def revoke(self, agent_id: str, path: str, *, tenant: str | None = None) -> int:
        with self._lock:
            if self._entries.pop(self._key(agent_id, path, tenant), None) is not None:
                self._epoch += 1
                return 1
        return 0

    def from_env(self, *, tenant: str | None = None) -> int:
        """Seed permanent forbids from ``TEX_LOCAL_FORBID_SET`` —
        whitespace/comma-separated ``agent_id=/path`` tokens. Operator-owned, no TTL."""
        raw = os.getenv("TEX_LOCAL_FORBID_SET", "")
        n = 0
        for tok in raw.replace(",", " ").split():
            if "=" not in tok:
                continue
            agent_id, _, path = tok.partition("=")
            if self.add(agent_id, path, tenant=tenant, ttl_seconds=None):
                n += 1
        return n

    def _live(self, tenant: str | None) -> list[LocalForbidEntry]:
        now = self._clock()
        norm = _norm_tenant(tenant)
        out: list[LocalForbidEntry] = []
        with self._lock:
            dead = [k for k, e in self._entries.items() if e.expired(now)]
            for k in dead:
                self._entries.pop(k, None)
            if dead:
                self._epoch += 1
            for e in self._entries.values():
                if e.tenant is None or e.tenant == norm:
                    out.append(e)
        return out

    def response_set(self, tenant: str | None) -> dict:
        """The unsigned loader payload for a tenant."""
        entries = self._live(tenant)
        return {
            "forbid": [{"agent_id": e.agent_id, "path": e.path} for e in entries],
            "epoch": self.epoch,
            "tenant": _norm_tenant(tenant) or "",
        }

    @staticmethod
    def _canonical(payload: dict) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def signed_response(self, tenant: str | None, *, secret: str | bytes) -> dict:
        """The loader payload as a CANONICAL STRING + an HMAC-SHA256 over exactly
        those bytes. Signing the literal string (not a re-serialized object) means
        the loader verifies the exact bytes it received — no cross-language
        canonicalization mismatch. The signature is the cryptographic binding
        between the live PDP verdict and the in-kernel enforcement point: a
        compromised agent can neither forge a set nor strip an entry without the
        shared ``TEX_LOCAL_PEP_SECRET``."""
        s = secret.encode("utf-8") if isinstance(secret, str) else secret
        canonical = self._canonical(self.response_set(tenant))
        sig = hmac.new(s, canonical, hashlib.sha256).hexdigest()
        return {"set_canonical": canonical.decode("utf-8"), "sig": sig}

    @staticmethod
    def verify_signed(envelope: dict, *, secret: str | bytes) -> dict | None:
        """Loader-side check (mirrored byte-for-byte in the Go loader): HMAC over
        the literal ``set_canonical`` string; return the parsed set iff it
        verifies, else None (fail-closed)."""
        s = secret.encode("utf-8") if isinstance(secret, str) else secret
        canonical = envelope.get("set_canonical")
        sig = envelope.get("sig")
        if not isinstance(canonical, str) or not isinstance(sig, str):
            return None
        expected = hmac.new(s, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None
        return json.loads(canonical)


def resolve_local_forbid_source(state: Any) -> "LocalForbidSource | None":
    """Resolve the active :class:`LocalForbidSource` from app state, or None.

    Mirrors ``resolve_forbid_source`` for the network floor. The source is only
    present when the local PEP is explicitly wired (``TEX_LOCAL_PEP`` /
    composition root attaches ``state.local_forbid_source`` AND passes its
    ``feed_from_decision`` as ``StandingGovernance(local_forbid_sink=...)``).
    Unwired -> None -> the route serves nothing (fail-closed, default-OFF).
    """
    src = getattr(state, "local_forbid_source", None)
    return src if isinstance(src, LocalForbidSource) else None
