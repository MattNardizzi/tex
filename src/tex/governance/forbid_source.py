"""
Forbid-set source — the hot, high-confidence FORBID destinations the kernel
floor blocks inline.

What this is (and is not)
-------------------------
The kernel-floor PEP (``pep/kernel``) keeps an in-kernel ``verdict_cache`` warm
by polling ``GET /v1/govern/forbid-set`` every 30s, so the highest-confidence
denials are refused in microseconds — before a packet leaves — without a
userspace round trip. This module is the *source* of that set.

It is deliberately the **hot set only**, never the policy:

  * Membership means "block this ``(ip, port)`` inline, no questions."
  * **Absence is never permit.** Every destination not in the set flows through
    the transparent redirect to the enforcement proxy for the full two-tier
    decision at ``/v1/govern/decide``. The hot set is a latency optimization
    layered on top of the real decision, not a replacement for it.

So this is NOT a parallel policy store. The full policy / decision stays in
``StandingGovernance`` and the six-layer PDP. This holds only the small set of
destinations a high-confidence FORBID has already been established for — the
``connect()``-time fast path.

The contract (do not break)
----------------------------
``pep/kernel/agent/main.go`` ``fetchForbidSet`` decodes exactly::

    { "forbid": [ { "ip": "1.2.3.4", "port": 443 }, ... ] }

and the loader keeps only addresses where ``ip.To4() != nil`` (IPv4) with a
``uint16`` port. So :meth:`ForbidSource.for_tenant` emits **only resolved IPv4
addresses** with a port in ``1..65535``. IPv6 destinations are not covered by
this fast path (the loader skips them); they fall through to the proxy for the
full decision — which is safe, never a permit.

The ``/forbid-set`` response also carries a monotonic ``epoch`` (bumped on every
mutation) so the loader can reject a stale/replayed set (``epoch < last``) —
cheap anti-rollback with no signing infrastructure. See
``governance_standing_routes.forbid_set``.

Where entries come from
-----------------------
Three real feeds, all fail-closed (a missing/blank/malformed feed yields an
empty set, which means "decide everything at the proxy"):

  1. **Operator config** — :meth:`ForbidSource.from_env` reads ``TEX_FORBID_SET``
     (comma/whitespace-separated ``host:port`` tokens, e.g.
     ``"evil.example.com:443, 1.2.3.4:8080"``), so a deploy can populate the
     hot set with zero code change. Env-seeded entries are **permanent**
     (no TTL) — the operator owns them.
  2. **Programmatic** — composition or any upstream that establishes a
     high-confidence destination-level FORBID calls :meth:`ForbidSource.add`.
  3. **Live decisions (opt-in)** — when ``TEX_FORBID_AUTOFEED`` is enabled,
     :meth:`ForbidSource.feed_from_decision` is wired as the FORBID sink of
     ``StandingGovernance.decide`` (see ``main.py``), so a live, *destination-
     attributable* FORBID on a network egress automatically warms the hot set.
     Auto-fed entries are **TTL'd** (default ``TEX_FORBID_TTL`` = 3600s) and
     **per-tenant**, so an over-broad or now-stale deny self-prunes and can
     never cross tenants. Default OFF — the feed is byte-for-byte inert until
     the flag is set.

Monotonicity / revoke-wins (do not weaken)
------------------------------------------
The set is monotone within a TTL window: an entry leaves **only** by explicit
:meth:`revoke` or TTL expiry — never because a later decision merely *didn't*
mention it. A withholding or empty feed therefore can never un-block (the same
property the kernel loader enforces by not deleting on a fetch error). This
mirrors Tex's ``tighten()`` discipline: denials only relax under an explicit,
auditable act.

Bound (do not remove)
---------------------
The kernel map is finite. Two bounds protect it: ``_MAX_EMITTED`` caps the
*emitted* set per read, and ``max_entries`` caps *stored* entries with LRU
eviction of the oldest TTL'd (auto-fed) entries only — permanent env-seed
entries are never evicted. Insert-past-cap is bounded, never a fail-open.

Honest freshness caveat
-----------------------
Host-based entries are resolved to IPs **at read time** (each kernel poll, so
~every 30s). A resolved IP is a point-in-time snapshot:

  * DNS can rotate between resolution and connect; a destination behind a CDN
    or large round-robin may expose addresses this snapshot did not capture.
    Those simply miss the fast path and are decided at the proxy — never a
    permit. The fast path is best-effort *blocking*; correctness lives at
    ``/decide``. (The robust end-state — feeding the forbidden *hostname* to
    the proxy's G7 vhost-binding so a rotated IP is still caught at L7 — is the
    deferred follow-up; see ``execution.md`` / the design notes.)
  * Coverage is only as good as what the operator/policy/live-feed marks
    high-confidence FORBID. An empty source is the safe default, not a failure.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import time
from dataclasses import dataclass
from threading import RLock
from typing import Any, Callable, Iterable, Mapping

__all__ = [
    "ForbidEntry",
    "ForbidSource",
    "autofeed_enabled",
    "network_destination_for_forbid",
    "resolve_forbid_source",
]

# Type of a DNS resolver: host -> list of address strings (mixed v4/v6, as
# socket.getaddrinfo yields). Injectable so tests need no network.
Resolver = Callable[[str], list[str]]

# A clock returning seconds (wall time by default). Injectable so TTL/expiry
# tests need no real sleeping.
Clock = Callable[[], float]

_ENV_FORBID_SET = "TEX_FORBID_SET"
_ENV_FORBID_TTL = "TEX_FORBID_TTL"
_ENV_FORBID_MAX = "TEX_FORBID_MAX_ENTRIES"
_ENV_FORBID_AUTOFEED = "TEX_FORBID_AUTOFEED"
_ENV_FORBID_AUTOFEED_ACTIONS = "TEX_FORBID_AUTOFEED_ACTIONS"

# Default TTL for an auto-fed (live-decision) entry, in seconds. Long enough to
# matter as a hot-set hint, short enough that an over-broad deny self-heals.
_DEFAULT_TTL_SECONDS = 3600.0

# Bound the STORED set. The kernel map is finite and this is the *hot* subset by
# definition; oldest TTL'd entries are evicted past the bound (permanent
# env-seed entries are never evicted). Far above any real high-confidence list.
_DEFAULT_MAX_ENTRIES = 8192

# Bound the EMITTED set per read (kept for back-compat; a second guard on top of
# max_entries). Anything beyond is decided at the proxy, never dropped to permit.
_MAX_EMITTED = 4096

# Ports to expand a bare ``host`` (no port) against. Agent egress — model
# endpoints and the common exfil channels — is overwhelmingly HTTPS, so a host
# named without a port defaults to 443. This is a convenience for operator
# config and the live feed; the precise form is always ``host:port``.
_DEFAULT_PORTS: tuple[int, ...] = (443,)

# Action-type prefixes/exact values a live FORBID must carry for its recipient
# to be eligible for the network hot set. The proxy labels real egress
# ``http_<method>`` (proxy.py:1185); ``https_opaque`` / ``http_opaque_body`` are
# ABSTAIN (held), never FORBID, but are excluded defensively. Non-network
# actions (e.g. ``wire_transfer``) never match, so their recipients (account
# numbers, addresses) can never pollute the destination hot set.
_NETWORK_ACTION_PREFIXES: tuple[str, ...] = ("http_",)
_EXCLUDED_ACTION_TYPES: frozenset[str] = frozenset(
    {"https_opaque", "http_opaque_body"}
)

# A sentinel so ``add(ttl_seconds=...)`` can distinguish "caller did not pass a
# TTL (use the instance default)" from "caller explicitly passed None (permanent)".
_USE_DEFAULT_TTL: float = -1.0


def _default_resolver(host: str) -> list[str]:
    """Resolve ``host`` to all A/AAAA addresses.

    Same strategy as the SSRF guard in ``kernel_mcp/syscall_gate`` (resolve
    both families, return every address) so the two paths agree on what a host
    resolves to. Kept local rather than importing that module's private helper
    to avoid a cross-module private dependency and its import cost. Returns
    ``[]`` on any resolution failure — fail-closed: an unresolvable forbid host
    contributes nothing to the hot set and is decided at the proxy instead.
    """
    addrs: set[str] = set()
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            results = socket.getaddrinfo(
                host, None, family=family, type=socket.SOCK_STREAM
            )
        except OSError:
            continue
        for entry in results:
            addrs.add(entry[4][0])
    return sorted(addrs)


def _valid_port(value: Any) -> int | None:
    """Coerce to a usable TCP port (1..65535), else None.

    Port 0 is rejected: the loader stores it as a cache key, but a real
    ``connect()`` never targets port 0, so it would be dead weight.
    """
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return port
    return None


def _norm_tenant(tenant: str | None) -> str | None:
    """Case-fold a tenant id, mapping blank to ``None`` (applies to all)."""
    if tenant is None:
        return None
    folded = tenant.strip().casefold()
    return folded or None


def _env_float(env: Mapping[str, str], key: str, default: float) -> float:
    try:
        return float(env.get(key, "") or default)
    except (TypeError, ValueError):
        return default


def _env_int(env: Mapping[str, str], key: str, default: int) -> int:
    try:
        return int(env.get(key, "") or default)
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True, slots=True)
class ForbidEntry:
    """One high-confidence FORBID destination.

    ``host`` is a hostname or an IP literal as configured; it is resolved to
    IPv4 at read time. ``tenant`` of ``None`` applies to every tenant; a set
    value scopes the entry to that tenant only (case-folded match).

    Provenance / lifetime:
      * ``decision_id`` — the decision that established this deny, when it came
        from the live feed (``None`` for env/programmatic seed). Lets a hot-set
        entry be traced back to its ruling and the sealed receipt chain.
      * ``added_at`` — clock seconds when the entry was (last) added/refreshed.
      * ``ttl_seconds`` — lifetime; ``None`` means **permanent** (env-seed /
        operator-owned). A finite TTL self-prunes at ``added_at + ttl_seconds``.
    """

    host: str
    port: int
    tenant: str | None = None
    reason: str = "high-confidence FORBID destination"
    decision_id: str | None = None
    added_at: float = 0.0
    ttl_seconds: float | None = None

    def expires_at(self) -> float | None:
        """Absolute expiry in clock seconds, or ``None`` for permanent."""
        if self.ttl_seconds is None:
            return None
        return self.added_at + self.ttl_seconds

    def is_expired(self, now: float) -> bool:
        exp = self.expires_at()
        return exp is not None and now >= exp


def network_destination_for_forbid(
    action_type: str | None,
    recipient: str | None,
    *,
    extra_actions: frozenset[str] = frozenset(),
) -> str | None:
    """The blockable network host a FORBID is about, or ``None``.

    Returns a bare host string (suitable for :meth:`ForbidSource.add_host`)
    ONLY when the action is network-egress-shaped (``http_*`` or an
    operator-configured extra action) and the recipient parses to a host. Any
    non-network action — a ``wire_transfer`` to an account, an internal
    ``message`` — yields ``None`` so it can never pollute the destination hot
    set. The opaque/undecodable egress labels are excluded defensively (they
    are ABSTAIN, never FORBID).
    """
    if not recipient:
        return None
    act = (action_type or "").strip().casefold()
    if not act or act in _EXCLUDED_ACTION_TYPES:
        return None
    is_network = act in extra_actions or any(
        act.startswith(p) for p in _NETWORK_ACTION_PREFIXES
    )
    if not is_network:
        return None
    host, _port = _parse_recipient_host(recipient)
    return host


def _parse_recipient_host(recipient: str) -> tuple[str | None, int | None]:
    """Extract a host (and optional port) from a recipient handle.

    The proxy passes a bare host (``_host_of`` / the vhost), but be defensive
    about a ``scheme://host[:port][/path]`` or ``host:port`` form too.
    """
    r = recipient.strip()
    if not r:
        return None, None
    if "://" in r:
        r = r.split("://", 1)[1]
    r = r.split("/", 1)[0]  # drop any path
    if not r:
        return None, None
    return _parse_token(r)


class ForbidSource:
    """The source of the kernel's hot FORBID ``(ip, port)`` set.

    Thread-safe. Holds :class:`ForbidEntry` records keyed by
    ``(host, port, tenant)`` (so a re-add *refreshes* rather than duplicates)
    and, on read, resolves host-based entries to IPv4 and emits the loader's
    exact JSON shape. Empty by construction — the safe default.

    Monotone within a TTL window: entries leave only via :meth:`revoke` or TTL
    expiry, never via mere absence from a later decision.
    """

    __slots__ = (
        "_entries",
        "_resolver",
        "_clock",
        "_lock",
        "_epoch",
        "_default_ttl_seconds",
        "_max_entries",
    )

    def __init__(
        self,
        entries: Iterable[ForbidEntry] = (),
        *,
        resolver: Resolver | None = None,
        clock: Clock | None = None,
        default_ttl_seconds: float | None = None,
        max_entries: int | None = None,
    ) -> None:
        self._resolver: Resolver = resolver or _default_resolver
        self._clock: Clock = clock or time.time
        self._default_ttl_seconds = (
            default_ttl_seconds
            if default_ttl_seconds is not None
            else _DEFAULT_TTL_SECONDS
        )
        self._max_entries = (
            max_entries if max_entries is not None else _DEFAULT_MAX_ENTRIES
        )
        self._lock = RLock()
        self._epoch = 0
        # Keyed by (host_casefold, port, tenant_casefold|None) so a re-add of the
        # same destination refreshes (not duplicates). Insertion-ordered so LRU
        # eviction can walk oldest-first.
        self._entries: dict[tuple[str, int, str | None], ForbidEntry] = {}
        for entry in entries:
            # Seed entries keep their own TTL (None => permanent).
            self._upsert(entry)

    # ------------------------------------------------------------------ keys

    @staticmethod
    def _key(host: str, port: int, tenant: str | None) -> tuple[str, int, str | None]:
        return (host.strip().casefold(), port, _norm_tenant(tenant))

    def _upsert(self, entry: ForbidEntry) -> None:
        """Insert/refresh one entry and bump the epoch. Re-insert so insertion
        order reflects recency (refresh => newest, for LRU). Callers that mutate
        post-construction hold ``self._lock``."""
        key = self._key(entry.host, entry.port, entry.tenant)
        self._entries.pop(key, None)
        self._entries[key] = entry
        self._epoch += 1

    # ------------------------------------------------------------------ feeds

    def add(
        self,
        host: str,
        port: int,
        *,
        tenant: str | None = None,
        reason: str = "high-confidence FORBID destination",
        decision_id: str | None = None,
        ttl_seconds: float | None = _USE_DEFAULT_TTL,
    ) -> bool:
        """Add (or refresh) one ``host:port`` FORBID destination.

        Returns False (no-op) if the port is invalid — fail-closed: a bad entry
        is dropped, never widened to permit. ``ttl_seconds`` defaults to the
        instance default (a finite TTL); pass ``None`` for a permanent entry.
        A re-add of the same ``(host, port, tenant)`` refreshes the TTL.
        """
        host = (host or "").strip()
        valid = _valid_port(port)
        if not host or valid is None:
            return False
        ttl = (
            self._default_ttl_seconds
            if ttl_seconds == _USE_DEFAULT_TTL
            else ttl_seconds
        )
        with self._lock:
            entry = ForbidEntry(
                host=host,
                port=valid,
                tenant=tenant,
                reason=reason,
                decision_id=decision_id,
                added_at=self._clock(),
                ttl_seconds=ttl,
            )
            self._upsert(entry)
            self._enforce_cap()
        return True

    def add_host(
        self,
        host: str,
        ports: Iterable[int] = _DEFAULT_PORTS,
        *,
        tenant: str | None = None,
        reason: str = "high-confidence FORBID destination",
        decision_id: str | None = None,
        ttl_seconds: float | None = _USE_DEFAULT_TTL,
    ) -> int:
        """Add a host across several ports (defaults to HTTPS). Returns the
        count actually added."""
        added = 0
        for port in ports:
            if self.add(
                host,
                port,
                tenant=tenant,
                reason=reason,
                decision_id=decision_id,
                ttl_seconds=ttl_seconds,
            ):
                added += 1
        return added

    def feed_from_decision(
        self,
        *,
        action_type: str | None,
        recipient: str | None,
        tenant: str | None = None,
        decision_id: str | None = None,
        reason: str = "live FORBID destination",
    ) -> int:
        """The live-decision sink: warm the hot set from a destination-
        attributable FORBID. No-op (returns 0) unless the action is network
        egress-shaped and the recipient is a host. Scoped to the deciding
        tenant and TTL'd, so it never crosses tenants and self-prunes.

        This is the seam ``StandingGovernance.decide`` calls (only when
        ``TEX_FORBID_AUTOFEED`` is on) after a destination-attributable FORBID.
        """
        host = network_destination_for_forbid(
            action_type, recipient, extra_actions=_autofeed_extra_actions()
        )
        if host is None:
            return 0
        return self.add_host(
            host,
            tenant=_norm_tenant(tenant),
            reason=reason,
            decision_id=decision_id,
        )

    def revoke(
        self,
        host: str,
        *,
        port: int | None = None,
        tenant: str | None = None,
    ) -> int:
        """Explicitly remove matching entries (revoke-wins). Matches by host,
        optionally narrowed to a port and/or tenant. Returns the count removed.

        This is the ONLY non-TTL way an entry leaves — absence from a later
        decision never removes anything.
        """
        host_cf = (host or "").strip().casefold()
        if not host_cf:
            return 0
        tenant_cf = _norm_tenant(tenant)
        removed = 0
        with self._lock:
            for key in list(self._entries.keys()):
                k_host, k_port, k_tenant = key
                if k_host != host_cf:
                    continue
                if port is not None and k_port != port:
                    continue
                if tenant is not None and k_tenant != tenant_cf:
                    continue
                del self._entries[key]
                removed += 1
            if removed:
                self._epoch += 1
        return removed

    def _enforce_cap(self) -> None:
        """Evict oldest TTL'd (auto-fed) entries until within ``max_entries``.
        Permanent (env-seed) entries are never evicted. Caller holds the lock."""
        if len(self._entries) <= self._max_entries:
            return
        # Walk insertion order (oldest first); drop the first finite-TTL entries.
        for key, entry in list(self._entries.items()):
            if len(self._entries) <= self._max_entries:
                break
            if entry.ttl_seconds is None:
                continue  # never evict a permanent seed entry
            del self._entries[key]
            self._epoch += 1

    def _prune_expired(self, now: float) -> None:
        """Drop entries past their TTL. Caller holds the lock."""
        expired = [k for k, e in self._entries.items() if e.is_expired(now)]
        for key in expired:
            del self._entries[key]
        if expired:
            self._epoch += 1

    # ------------------------------------------------------------------ read

    @property
    def epoch(self) -> int:
        """Monotonic version of the set, bumped on every mutation. The
        ``/forbid-set`` response carries this so the loader can reject a stale
        or replayed set (``epoch < last_applied``)."""
        with self._lock:
            return self._epoch

    def for_tenant(self, tenant: str | None) -> list[dict[str, Any]]:
        """Resolve and return the hot FORBID set for ``tenant`` in the loader's
        exact shape: ``[{"ip": "1.2.3.4", "port": 443}, ...]``.

        Only IPv4 addresses are emitted (the kernel loader is IPv4-only).
        Expired entries are pruned first; entries are de-duplicated by
        ``(ip, port)`` and sorted for a stable response. Per-entry resolution
        failures are swallowed (fail-closed: the destination is decided at the
        proxy, not permitted).
        """
        tid = (tenant or "").strip().casefold()
        with self._lock:
            self._prune_expired(self._clock())
            entries = list(self._entries.values())

        seen: set[tuple[str, int]] = set()
        out: list[dict[str, Any]] = []
        for entry in entries:
            if entry.tenant is not None and entry.tenant.strip().casefold() != tid:
                continue
            for ip in self._resolve_ipv4(entry.host):
                key = (ip, entry.port)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"ip": ip, "port": entry.port})
                if len(out) >= _MAX_EMITTED:
                    out.sort(key=lambda d: (d["ip"], d["port"]))
                    return out
        out.sort(key=lambda d: (d["ip"], d["port"]))
        return out

    def _resolve_ipv4(self, host: str) -> list[str]:
        """Resolve ``host`` to IPv4 literal(s). A literal IPv4 passes straight
        through; a literal IPv6 is dropped (loader is IPv4-only); a hostname is
        resolved and filtered to its A records. Fail-closed on any error."""
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            return [host] if literal.version == 4 else []

        try:
            addresses = self._resolver(host)
        except Exception:  # noqa: BLE001 — resolution failure is fail-closed
            return []
        ipv4: list[str] = []
        for addr in addresses:
            try:
                if ipaddress.ip_address(addr).version == 4:
                    ipv4.append(addr)
            except ValueError:
                continue
        return ipv4

    def __len__(self) -> int:
        with self._lock:
            self._prune_expired(self._clock())
            return len(self._entries)

    # ------------------------------------------------------------------ env

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        resolver: Resolver | None = None,
        clock: Clock | None = None,
    ) -> "ForbidSource":
        """Build from ``TEX_FORBID_SET``. Empty (safe) when unset or blank.

        Token grammar (comma- or whitespace-separated): ``host:port``,
        ``[ipv6]:port``, or a bare ``host`` (expanded across the default
        ports). Malformed tokens are skipped — fail-closed. Env-seeded entries
        are **permanent** (no TTL); only the live feed adds TTL'd entries.
        TTL/cap defaults are read from ``TEX_FORBID_TTL`` / ``TEX_FORBID_MAX_ENTRIES``.
        """
        environ = env if env is not None else os.environ
        source = cls(
            resolver=resolver,
            clock=clock,
            default_ttl_seconds=_env_float(
                environ, _ENV_FORBID_TTL, _DEFAULT_TTL_SECONDS
            ),
            max_entries=_env_int(environ, _ENV_FORBID_MAX, _DEFAULT_MAX_ENTRIES),
        )
        raw = (environ.get(_ENV_FORBID_SET) or "").strip()
        if not raw:
            return source
        for token in raw.replace(",", " ").split():
            host, port = _parse_token(token)
            if host is None:
                continue
            # Permanent (ttl_seconds=None): the operator owns env-seed entries.
            if port is None:
                source.add_host(host, ttl_seconds=None)
            else:
                source.add(host, port, ttl_seconds=None)
        return source


def _autofeed_extra_actions() -> frozenset[str]:
    """Operator-configured extra network action types eligible for the live
    feed (``TEX_FORBID_AUTOFEED_ACTIONS``, comma/space-separated). Empty by
    default — ``http_*`` is the built-in network shape."""
    raw = (os.environ.get(_ENV_FORBID_AUTOFEED_ACTIONS) or "").strip()
    if not raw:
        return frozenset()
    return frozenset(t.strip().casefold() for t in raw.replace(",", " ").split() if t)


def autofeed_enabled(env: Mapping[str, str] | None = None) -> bool:
    """Whether the live FORBID -> hot-set feed is switched on. Default OFF:
    behavior is byte-for-byte today's until ``TEX_FORBID_AUTOFEED`` is set to a
    truthy value (anything other than ``""``/``0``/``false``/``no``/``off``)."""
    environ = env if env is not None else os.environ
    val = (environ.get(_ENV_FORBID_AUTOFEED) or "").strip().casefold()
    return val not in ("", "0", "false", "no", "off")


def _parse_token(token: str) -> tuple[str | None, int | None]:
    """Parse one ``host:port`` token.

    Returns ``(host, port)`` where ``port`` is an int for a valid explicit
    port, or ``None`` for a *bare* host (expand against the default ports).
    Returns ``(None, None)`` for an unusable token — including a host with an
    explicit but invalid port: fail-closed, never silently re-home it onto a
    default port the operator did not type.
    """
    token = token.strip()
    if not token:
        return None, None
    # Bracketed IPv6 literal: [::1]:443
    if token.startswith("["):
        close = token.find("]")
        if close == -1:
            return None, None
        host = token[1:close]
        rest = token[close + 1 :]
        if rest.startswith(":"):
            valid = _valid_port(rest[1:])
            return (None, None) if valid is None else (host or None, valid)
        return (host or None), None
    colons = token.count(":")
    if colons == 0:
        return token, None
    if colons == 1:
        host, _, port = token.rpartition(":")
        valid = _valid_port(port)
        return (None, None) if valid is None else (host or None, valid)
    # Multiple colons, unbracketed -> bare IPv6 literal, no port. It will be
    # dropped at emit (loader is IPv4-only), but parse it honestly.
    return token, None


def resolve_forbid_source(state: Any) -> ForbidSource | None:
    """Resolve the active :class:`ForbidSource` from app state.

    Priority:
      1. An explicitly attached ``state.forbid_source`` that is a
         ``ForbidSource`` (composition or tests inject it).
      2. Otherwise build one from ``TEX_FORBID_SET`` once and cache it on
         ``state.forbid_source`` (empty, hence safe, when the env is unset).

    Returns ``None`` only if something non-``ForbidSource`` is attached — in
    which case the caller emits the safe empty set rather than trusting it.
    """
    attached = getattr(state, "forbid_source", None)
    if isinstance(attached, ForbidSource):
        return attached
    if attached is not None:
        return None
    built = ForbidSource.from_env()
    try:
        state.forbid_source = built
    except Exception:  # noqa: BLE001 — caching is best-effort
        pass
    return built
