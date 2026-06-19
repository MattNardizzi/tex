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

Where entries come from
-----------------------
Two real feeds, both fail-closed (a missing/blank/malformed feed yields an
empty set, which means "decide everything at the proxy"):

  1. **Programmatic** — composition or any upstream that establishes a
     high-confidence destination-level FORBID calls :meth:`ForbidSource.add`.
     This is the seam a future destination-indexed FORBID store would feed.
  2. **Operator config** — :meth:`ForbidSource.from_env` reads ``TEX_FORBID_SET``
     (comma/whitespace-separated ``host:port`` tokens, e.g.
     ``"evil.example.com:443, 1.2.3.4:8080"``), so a deploy can populate the
     hot set with zero code change.

Honest freshness caveat
-----------------------
Host-based entries are resolved to IPs **at read time** (each kernel poll, so
~every 30s). A resolved IP is a point-in-time snapshot:

  * DNS can rotate between resolution and connect; a destination behind a CDN
    or large round-robin may expose addresses this snapshot did not capture.
    Those simply miss the fast path and are decided at the proxy — never a
    permit. The fast path is best-effort *blocking*; correctness lives at
    ``/decide``.
  * Coverage is only as good as what the operator/policy marks high-confidence
    FORBID. An empty source is the safe default, not a failure.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from threading import RLock
from typing import Any, Callable, Iterable, Mapping

__all__ = ["ForbidEntry", "ForbidSource", "resolve_forbid_source"]

# Type of a DNS resolver: host -> list of address strings (mixed v4/v6, as
# socket.getaddrinfo yields). Injectable so tests need no network.
Resolver = Callable[[str], list[str]]

_ENV_FORBID_SET = "TEX_FORBID_SET"

# Bound the hot set. The kernel map is finite and this is the *hot* subset by
# definition; anything beyond the bound is decided at the proxy, not dropped
# to permit. Far above any real high-confidence destination list.
_MAX_EMITTED = 4096

# Ports to expand a bare ``host`` (no port) against. Agent egress — model
# endpoints and the common exfil channels — is overwhelmingly HTTPS, so a host
# named without a port defaults to 443. This is a convenience for operator
# config; the precise form is always ``host:port``.
_DEFAULT_PORTS: tuple[int, ...] = (443,)


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


@dataclass(frozen=True, slots=True)
class ForbidEntry:
    """One high-confidence FORBID destination.

    ``host`` is a hostname or an IP literal as configured; it is resolved to
    IPv4 at read time. ``tenant`` of ``None`` applies to every tenant; a set
    value scopes the entry to that tenant only (case-folded match).
    """

    host: str
    port: int
    tenant: str | None = None
    reason: str = "high-confidence FORBID destination"


class ForbidSource:
    """The source of the kernel's hot FORBID ``(ip, port)`` set.

    Thread-safe. Holds :class:`ForbidEntry` records and, on read, resolves
    host-based entries to IPv4 and emits the loader's exact JSON shape.
    Empty by construction — the safe default.
    """

    __slots__ = ("_entries", "_resolver", "_lock")

    def __init__(
        self,
        entries: Iterable[ForbidEntry] = (),
        *,
        resolver: Resolver | None = None,
    ) -> None:
        self._entries: list[ForbidEntry] = list(entries)
        self._resolver: Resolver = resolver or _default_resolver
        self._lock = RLock()

    # ------------------------------------------------------------------ feeds

    def add(
        self,
        host: str,
        port: int,
        *,
        tenant: str | None = None,
        reason: str = "high-confidence FORBID destination",
    ) -> bool:
        """Add one ``host:port`` FORBID destination. Returns False (no-op) if
        the port is invalid — fail-closed: a bad entry is dropped, never
        widened to permit."""
        host = (host or "").strip()
        valid = _valid_port(port)
        if not host or valid is None:
            return False
        with self._lock:
            self._entries.append(
                ForbidEntry(host=host, port=valid, tenant=tenant, reason=reason)
            )
        return True

    def add_host(
        self,
        host: str,
        ports: Iterable[int] = _DEFAULT_PORTS,
        *,
        tenant: str | None = None,
        reason: str = "high-confidence FORBID destination",
    ) -> int:
        """Add a host across several ports (defaults to HTTPS). Returns the
        count actually added."""
        added = 0
        for port in ports:
            if self.add(host, port, tenant=tenant, reason=reason):
                added += 1
        return added

    # ------------------------------------------------------------------ read

    def for_tenant(self, tenant: str | None) -> list[dict[str, Any]]:
        """Resolve and return the hot FORBID set for ``tenant`` in the loader's
        exact shape: ``[{"ip": "1.2.3.4", "port": 443}, ...]``.

        Only IPv4 addresses are emitted (the kernel loader is IPv4-only).
        Entries are de-duplicated by ``(ip, port)`` and sorted for a stable
        response. Per-entry resolution failures are swallowed (fail-closed:
        the destination is decided at the proxy, not permitted).
        """
        tid = (tenant or "").strip().casefold()
        with self._lock:
            entries = list(self._entries)

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
            return len(self._entries)

    # ------------------------------------------------------------------ env

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        resolver: Resolver | None = None,
    ) -> "ForbidSource":
        """Build from ``TEX_FORBID_SET``. Empty (safe) when unset or blank.

        Token grammar (comma- or whitespace-separated): ``host:port``,
        ``[ipv6]:port``, or a bare ``host`` (expanded across the default
        ports). Malformed tokens are skipped — fail-closed.
        """
        environ = env if env is not None else os.environ
        raw = (environ.get(_ENV_FORBID_SET) or "").strip()
        source = cls(resolver=resolver)
        if not raw:
            return source
        for token in raw.replace(",", " ").split():
            host, port = _parse_token(token)
            if host is None:
                continue
            if port is None:
                source.add_host(host)
            else:
                source.add(host, port)
        return source


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
