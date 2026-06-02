"""
Shared Postgres connection helpers for the memory layer.

All memory stores follow the same write-through pattern as
``agent_registry_postgres``: synchronous psycopg, idempotent schema
bootstrap, fallback to in-memory mode if ``DATABASE_URL`` is unset.
This module centralises the boilerplate so individual stores stay
focused on their schema and serialisation logic.

Why sync (psycopg, not asyncpg)
-------------------------------
The runtime that calls into memory — the PDP, the orchestrator, the
specialists, the evaluate-action command — is synchronous end-to-end.
The leaderboard is async because it sits behind a FastAPI route and
nothing else; the memory layer sits behind every evaluation and would
require an async refactor of the entire pipeline to use asyncpg. We
keep one sync helper here and let the async leaderboard keep its own
asyncpg pool.

Connection budget
-----------------
Render Starter caps Postgres at 100 client connections. The async
leaderboard uses a pool capped at 20×2 = 40. The memory layer opens a
short-lived psycopg connection per write (autocommit, no pool) which
returns to the OS within milliseconds. Under realistic load (tens of
evaluations per second per worker) this stays well below the cap.
"""

from __future__ import annotations

import logging
import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import psycopg

_logger = logging.getLogger(__name__)

DATABASE_URL_ENV = "DATABASE_URL"

_MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "db" / "migrations"

# Guard so the memory-system migration only runs once per process.
_migration_lock = threading.Lock()
_migrations_applied: set[str] = set()


def database_url() -> str | None:
    """Returns the configured DSN, or None if memory must run in-memory only."""
    url = os.environ.get(DATABASE_URL_ENV)
    if not url:
        return None
    return url.strip() or None


@contextmanager
def connect() -> Iterator[psycopg.Connection]:
    """
    Yields a short-lived autocommit psycopg connection.

    Raises ``RuntimeError`` if ``DATABASE_URL`` is not configured. Callers
    that need a graceful fallback should check ``database_url()`` first
    and route to their in-memory implementation.
    """
    url = database_url()
    if url is None:
        raise RuntimeError(
            f"{DATABASE_URL_ENV} is not configured; cannot open a Postgres "
            "connection. Memory stores fall back to in-memory mode when this "
            "happens."
        )

    conn = psycopg.connect(url, autocommit=True)
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:  # pragma: no cover — best effort
            _logger.exception("error closing psycopg connection")


@contextmanager
def connect_tx() -> Iterator[psycopg.Connection]:
    """
    Yields a non-autocommit psycopg connection wrapped in a single
    transaction. Commits on clean exit; rolls back on exception.

    This is the primitive for spec § "transactional guarantee" — the
    orchestrator's atomic write paths (decision + input + policy
    snapshot) use this so partial writes are impossible.

    Raises ``RuntimeError`` if ``DATABASE_URL`` is not configured. Callers
    that need a graceful fallback should check ``database_url()`` first.
    """
    url = database_url()
    if url is None:
        raise RuntimeError(
            f"{DATABASE_URL_ENV} is not configured; cannot open a transactional "
            "Postgres connection. Memory stores fall back to in-memory mode "
            "when this happens."
        )

    conn = psycopg.connect(url, autocommit=False)
    try:
        try:
            yield conn
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:  # pragma: no cover — best effort
                _logger.exception("error rolling back psycopg transaction")
            raise
    finally:
        try:
            conn.close()
        except Exception:  # pragma: no cover — best effort
            _logger.exception("error closing psycopg connection")


def apply_migration(name: str) -> None:
    """
    Runs a SQL migration file from ``src/tex/db/migrations``. Idempotent
    at the SQL level (every statement uses ``IF NOT EXISTS``) and at the
    process level (each migration runs at most once per process).
    """
    if database_url() is None:
        _logger.warning(
            "skipping migration %s: %s not set", name, DATABASE_URL_ENV
        )
        return

    with _migration_lock:
        if name in _migrations_applied:
            return

        path = _MIGRATIONS_DIR / name
        if not path.exists():
            raise FileNotFoundError(f"migration file not found: {path}")

        sql = path.read_text(encoding="utf-8")

        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql)
            _migrations_applied.add(name)
            _logger.info("applied memory-system migration: %s", name)
        except Exception:
            _logger.exception("failed to apply memory-system migration: %s", name)
            raise


def ensure_memory_schema() -> None:
    """
    Convenience entry point: applies the master memory-system migration.

    Stores call this in their constructors so callers don't need to
    remember to run migrations manually. Safe to call repeatedly.
    """
    apply_migration("001_memory_system.sql")
