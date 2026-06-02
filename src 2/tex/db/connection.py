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
    """
    with psycopg.connect(dsn, autocommit=autocommit) as conn:
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
