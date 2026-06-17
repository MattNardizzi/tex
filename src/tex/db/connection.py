"""
Shared Postgres connection helper for Tex's write-through-cache stores.

Every durable store in `tex.stores.*_postgres` follows the same pattern:

  1. Read DSN from DATABASE_URL on construction.
  2. If unset → log warning and run pure in-memory.
  3. If set → ensure schema (idempotent), then bootstrap cache from disk.
  4. Writes flush to Postgres synchronously after the in-memory write.

This module centralizes:

- DSN resolution (so we have ONE place to change auth/SSL/pooling)
- Connection-string parsing for safe logging (no password leakage)
- A small `with_connection` context helper that the stores use so they
  do not each write their own try/except around `psycopg.connect`.

Why a connection pool isn't here yet: the existing stores open a fresh
short-lived connection per write. Under Tex's current load profile
(decisions on the slow path of an evaluation), this is fine and keeps
the code simple. When/if the per-write round trip becomes a bottleneck,
the right answer is `psycopg_pool.ConnectionPool` injected here — which
is a one-file change because every caller already routes through
`with_connection`.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Iterator

import psycopg

_logger = logging.getLogger(__name__)

DATABASE_URL_ENV = "DATABASE_URL"

# libpq connect timeout (seconds). Bounds every psycopg.connect so an
# unreachable/slow/connection-capped Postgres fails fast to the in-memory
# fallback instead of blocking this single-worker service's event loop. Tunable
# via TEX_DB_CONNECT_TIMEOUT.
_CONNECT_TIMEOUT_S = int(os.environ.get("TEX_DB_CONNECT_TIMEOUT", "5"))

# connect_timeout bounds only the CONNECT. A query that hangs or waits on a lock
# (e.g. contention on the single-writer evidence chain under sustained write load)
# otherwise pins its worker thread indefinitely — threads accumulate until the
# pool is exhausted and EVERY route, /health and /v1/speak/timed included, wedges
# (the multi-minute "0 bytes on everything" outage). statement_timeout caps total
# execution; lock_timeout caps how long a statement waits for a lock — so a
# contended write fails fast instead of hanging the worker. Milliseconds, tunable
# via env; passed as libpq options on every connect below.
_STATEMENT_TIMEOUT_MS = int(os.environ.get("TEX_DB_STATEMENT_TIMEOUT_MS", "15000"))
_LOCK_TIMEOUT_MS = int(os.environ.get("TEX_DB_LOCK_TIMEOUT_MS", "5000"))
_PG_OPTIONS = f"-c statement_timeout={_STATEMENT_TIMEOUT_MS} -c lock_timeout={_LOCK_TIMEOUT_MS}"


def resolve_dsn(dsn: str | None = None) -> str:
    """
    Resolve a DSN from the explicit argument or DATABASE_URL.

    Returns "" when neither is set. Callers treat empty DSN as
    "run in pure in-memory mode and log a warning".
    """
    if dsn is not None:
        return dsn.strip()
    return os.environ.get(DATABASE_URL_ENV, "").strip()


def safe_dsn_for_log(dsn: str) -> str:
    """
    Mask the password in a DSN for safe logging.

    Input:  postgres://user:secret@host:5432/db
    Output: postgres://user:***@host:5432/db
    """
    if "://" not in dsn:
        return dsn
    scheme, rest = dsn.split("://", 1)
    if "@" not in rest:
        return dsn
    creds, host_part = rest.rsplit("@", 1)
    if ":" in creds:
        user, _ = creds.split(":", 1)
        return f"{scheme}://{user}:***@{host_part}"
    return dsn


@contextmanager
def with_connection(
    dsn: str,
    *,
    autocommit: bool = False,
) -> Iterator[psycopg.Connection]:
    """
    Open a short-lived connection to Postgres.

    This is the only place stores should call `psycopg.connect`. Any
    future change (pooling, SSL pinning, statement timeout) lands here.

    ``connect_timeout`` is mandatory: without it libpq blocks forever on a
    slow/unreachable/connection-capped Postgres, and on this single-worker
    service that one hung connect freezes the whole event loop — every request,
    including /health and /v1/speak/timed, queues behind it. With a bounded
    timeout an unreachable DB fails fast and callers fall back to in-memory.
    """
    with psycopg.connect(
        dsn,
        autocommit=autocommit,
        connect_timeout=_CONNECT_TIMEOUT_S,
        options=_PG_OPTIONS,
    ) as conn:
        yield conn


def is_database_configured() -> bool:
    """True iff DATABASE_URL is set to a non-empty value."""
    return bool(resolve_dsn())


__all__ = [
    "DATABASE_URL_ENV",
    "resolve_dsn",
    "safe_dsn_for_log",
    "with_connection",
    "is_database_configured",
]
