"""
Ignition registry — "Run discovery" said once, and only once.

Ignition is not a scan command and not a per-source connect ceremony. It
is the single moment a witness starts watching, and it surfaces exactly
one line: the count, and that Tex is beginning. After that the glass goes
clean and the inventory is pull-only — Tex does the work in the dark.

This registry is the server-side flag that makes "exactly one line" true.
It mirrors the manifesto door: ignition fires once per tenant and never
re-declares. A second ignition call after the first does not re-speak; the
door has already opened. The flag is what stops the surface from drifting
into a feed that re-announces itself.

In-memory by default — like the manifesto flag, it is intentionally
per-process state, not a durable record. The sealed inventory lives in the
ledgers; this is only the "have we said hello yet" bit.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

_logger = logging.getLogger(__name__)

DATABASE_URL_ENV = "DATABASE_URL"


_ONES = (
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
    "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen",
    "sixteen", "seventeen", "eighteen", "nineteen",
)
_TENS = (
    "", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy",
    "eighty", "ninety",
)


def humanize_count(n: int) -> str:
    """
    Spell a count the way Tex speaks it: "forty-one", not "41". Tex speaks
    meaning; bare digits are objects, not speech. Handles 0–9999, which
    covers any plausible estate; beyond that it falls back to digits.
    """
    if n < 0 or n > 9999:
        return str(n)
    if n < 20:
        return _ONES[n]
    if n < 100:
        tens, ones = divmod(n, 10)
        return _TENS[tens] + (f"-{_ONES[ones]}" if ones else "")
    if n < 1000:
        hundreds, rest = divmod(n, 100)
        head = f"{_ONES[hundreds]} hundred"
        return head if rest == 0 else f"{head} {humanize_count(rest)}"
    thousands, rest = divmod(n, 1000)
    head = f"{humanize_count(thousands)} thousand"
    return head if rest == 0 else f"{head} {humanize_count(rest)}"


@runtime_checkable
class IgnitionStore(Protocol):
    """The durable backing an :class:`IgnitionRegistry` may write through to.

    Duck-typed so a test can inject an in-memory fake and prod can inject a
    :class:`PostgresIgnitionStore` without either importing the other. The
    contract is deliberately tiny: read the whole fired-map once at boot,
    write one row on the rare first-Begin, delete one row on a sandbox reset.
    """

    def load(self) -> dict[str, datetime]:
        """The full ``{tenant: fired_at}`` map, read once at construction."""
        ...

    def mark(self, tenant: str, fired_at: datetime) -> None:
        """Persist that ``tenant`` fired at ``fired_at`` (idempotent)."""
        ...

    def clear(self, tenant: str) -> None:
        """Drop the durable fired row for ``tenant`` (sandbox reset)."""
        ...


class IgnitionRegistry:
    """Thread-safe per-tenant 'has ignition fired?' flag.

    In-memory by default. When an :class:`IgnitionStore` is supplied it becomes
    durable: the fired-map is loaded from the store at construction (so a fresh
    process after a deploy already knows the estate said hello), the first
    ``fire`` writes through, and ``reset`` clears the durable row too. Reads
    always serve the in-memory map — no I/O on the hot path.
    """

    def __init__(self, store: IgnitionStore | None = None) -> None:
        self._lock = threading.RLock()
        self._fired_at: dict[str, datetime] = {}
        self._store = store
        if store is not None:
            try:
                loaded = store.load()
            except Exception as exc:  # noqa: BLE001 — durability is an upgrade, never a dependency
                _logger.error("IgnitionRegistry: durable load failed: %s", exc)
                loaded = {}
            for tenant, fired in (loaded or {}).items():
                if isinstance(fired, datetime):
                    self._fired_at[str(tenant)] = fired

    def has_fired(self, tenant: str) -> bool:
        with self._lock:
            return tenant in self._fired_at

    def fire(self, tenant: str) -> datetime:
        """Mark ignition fired for a tenant; idempotent (keeps first time).

        The in-memory flag is always set; the durable write-through is
        best-effort — a store fault leaves the flag true for THIS process
        (the ceremony still won't replay in-session) and simply retries the
        honest posture on the next boot (re-show the once-only door), which
        over-ceremonies rather than losing the estate.
        """
        with self._lock:
            if tenant not in self._fired_at:
                fired = datetime.now(UTC)
                self._fired_at[tenant] = fired
                if self._store is not None:
                    try:
                        self._store.mark(tenant, fired)
                    except Exception as exc:  # noqa: BLE001
                        _logger.error(
                            "IgnitionRegistry: durable mark for %s failed: %s",
                            tenant, exc,
                        )
            return self._fired_at[tenant]

    def fired_at(self, tenant: str) -> datetime | None:
        with self._lock:
            return self._fired_at.get(tenant)

    def reset(self, tenant: str) -> None:
        """Clear the flag (operator re-ignition, tests). Clears durably too so a
        sandbox reset re-stages the day-one door even across a restart."""
        with self._lock:
            self._fired_at.pop(tenant, None)
            if self._store is not None:
                try:
                    self._store.clear(tenant)
                except Exception as exc:  # noqa: BLE001
                    _logger.error(
                        "IgnitionRegistry: durable clear for %s failed: %s",
                        tenant, exc,
                    )


# ─────────────────────────────────────────────────── durable Postgres backing
_IGNITION_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_ignition (
    tenant_id  TEXT PRIMARY KEY,
    fired_at   TIMESTAMPTZ NOT NULL
);
"""


class PostgresIgnitionStore:
    """Postgres-backed :class:`IgnitionStore` — the durable 'has Begin ever been
    pressed' record, so the opening ceremony is skipped on every visit after the
    first-ever Begin, even across a deploy that wipes per-process memory.

    Follows the Postgres-store idioms in this package
    (:mod:`tex.stores.agent_registry_postgres`): DATABASE_URL from the env,
    DDL-at-init (idempotent ``CREATE TABLE IF NOT EXISTS``), graceful disable to
    a no-op when the URL is unset or the schema bootstrap fails, so the runtime
    stays up and simply loses durability. ``psycopg`` is imported lazily so this
    module (imported widely for :func:`humanize_count`) stays light in pure
    in-memory deployments.
    """

    def __init__(self, *, dsn: str | None = None) -> None:
        self._dsn = dsn or os.environ.get(DATABASE_URL_ENV, "").strip()
        self._disabled = not bool(self._dsn)
        if self._disabled:
            _logger.warning(
                "PostgresIgnitionStore: %s not set; ignition flag will not "
                "survive restarts.",
                DATABASE_URL_ENV,
            )
            return
        try:
            self._ensure_schema()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "PostgresIgnitionStore: schema bootstrap failed: %s. "
                "Falling back to non-durable mode.",
                exc,
            )
            self._disabled = True

    @property
    def is_durable(self) -> bool:
        return not self._disabled

    def _ensure_schema(self) -> None:
        import psycopg

        with psycopg.connect(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(_IGNITION_SCHEMA_SQL)

    def load(self) -> dict[str, datetime]:
        if self._disabled:
            return {}
        import psycopg

        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT tenant_id, fired_at FROM tex_ignition")
                rows = cur.fetchall()
        out: dict[str, datetime] = {}
        for tenant, fired in rows:
            if isinstance(fired, datetime) and fired.tzinfo is None:
                fired = fired.replace(tzinfo=UTC)
            out[str(tenant)] = fired
        return out

    def mark(self, tenant: str, fired_at: datetime) -> None:
        if self._disabled:
            return
        import psycopg

        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                # First-Begin wins: an ON CONFLICT DO NOTHING keeps the original
                # fired_at (mirrors the in-memory 'keeps first time' contract).
                cur.execute(
                    "INSERT INTO tex_ignition (tenant_id, fired_at) VALUES (%s, %s) "
                    "ON CONFLICT (tenant_id) DO NOTHING",
                    (tenant, fired_at),
                )
            conn.commit()

    def clear(self, tenant: str) -> None:
        if self._disabled:
            return
        import psycopg

        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM tex_ignition WHERE tenant_id = %s", (tenant,))
            conn.commit()


def build_ignition_registry(*, durable: bool) -> IgnitionRegistry:
    """The registry the runtime attaches: durable (Postgres-backed) in prod
    where ``DATABASE_URL`` is set, pure in-memory otherwise."""
    store: IgnitionStore | None = PostgresIgnitionStore() if durable else None
    return IgnitionRegistry(store=store)
