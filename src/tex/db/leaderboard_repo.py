"""
Tex leaderboard — Postgres-backed repository.

Stays small and explicit. One table, four operations:
- ensure_schema(): idempotent CREATE TABLE IF NOT EXISTS
- top(limit): top-N players ordered by RP DESC
- get(handle): single-row fetch
- upsert(handle, rp_delta, decision_id): atomic upsert with RP increment

Connection management uses a single global asyncpg pool, lazily created.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

import asyncpg

DATABASE_URL_ENV = "DATABASE_URL"

# Single shared pool, lazily initialized.
_pool: Optional[asyncpg.Pool] = None


@dataclass(frozen=True, slots=True)
class LeaderboardEntry:
    handle: str
    rp: int
    streak: int
    rounds_played: int
    last_played_at: str  # ISO-formatted


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS leaderboard (
    handle           TEXT PRIMARY KEY,
    rp               INTEGER NOT NULL DEFAULT 0,
    streak           INTEGER NOT NULL DEFAULT 0,
    rounds_played    INTEGER NOT NULL DEFAULT 0,
    last_decision_id TEXT,
    last_played_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_leaderboard_rp_desc ON leaderboard (rp DESC);

CREATE TABLE IF NOT EXISTS leaderboard_used_decisions (
    decision_id  TEXT PRIMARY KEY,
    handle       TEXT NOT NULL,
    rp_delta     INTEGER NOT NULL,
    used_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


async def get_pool() -> asyncpg.Pool:
    """Return (and lazily create) the shared connection pool.

    Pool sizing matches the arcade leaderboard pool (see
    arcade_leaderboard_repo.py for the rationale). Two pools at
    max_size=20 each = 40 client conns out of Render Starter's
    100-conn ceiling, with comfortable headroom.

    Bounds are env-var overridable so we can tune without a deploy.
    """
    global _pool
    if _pool is None:
        url = os.environ.get(DATABASE_URL_ENV)
        if not url:
            raise RuntimeError(
                f"Environment variable {DATABASE_URL_ENV} is not set. "
                "Leaderboard endpoints cannot run without it."
            )
        # Render's internal URL uses 'postgresql://' which asyncpg accepts.
        min_size = int(os.environ.get("TEX_DB_POOL_MIN", "2"))
        max_size = int(os.environ.get("TEX_DB_POOL_MAX", "20"))
        _pool = await asyncpg.create_pool(
            dsn=url,
            min_size=min_size,
            max_size=max_size,
            command_timeout=10,
        )
    return _pool


async def ensure_schema() -> None:
    """Create the leaderboard tables if they don't exist. Idempotent."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(SCHEMA_SQL)


async def top(limit: int = 50) -> list[LeaderboardEntry]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT handle, rp, streak, rounds_played, last_played_at
            FROM leaderboard
            ORDER BY rp DESC, last_played_at ASC
            LIMIT $1
            """,
            limit,
        )
    return [
        LeaderboardEntry(
            handle=r["handle"],
            rp=r["rp"],
            streak=r["streak"],
            rounds_played=r["rounds_played"],
            last_played_at=r["last_played_at"].isoformat(),
        )
        for r in rows
    ]


async def get(handle: str) -> Optional[LeaderboardEntry]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT handle, rp, streak, rounds_played, last_played_at
            FROM leaderboard
            WHERE handle = $1
            """,
            handle,
        )
    if row is None:
        return None
    return LeaderboardEntry(
        handle=row["handle"],
        rp=row["rp"],
        streak=row["streak"],
        rounds_played=row["rounds_played"],
        last_played_at=row["last_played_at"].isoformat(),
    )


async def is_decision_used(decision_id: str) -> bool:
    """Check whether a decision_id has already been redeemed for RP."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT 1 FROM leaderboard_used_decisions WHERE decision_id = $1",
            decision_id,
        )
    return row is not None


async def submit(
    *,
    handle: str,
    rp_delta: int,
    decision_id: str,
) -> LeaderboardEntry:
    """
    Atomically:
      1. Mark this decision_id as used (insert into leaderboard_used_decisions)
      2. Upsert the player row with rp_delta applied (clamped to >= 0)

    Raises:
      ValueError if decision_id has already been used.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            # Insert into used-decisions guard. If conflict, this decision was
            # already redeemed — refuse to double-count.
            inserted = await conn.fetchrow(
                """
                INSERT INTO leaderboard_used_decisions (decision_id, handle, rp_delta)
                VALUES ($1, $2, $3)
                ON CONFLICT (decision_id) DO NOTHING
                RETURNING decision_id
                """,
                decision_id,
                handle,
                rp_delta,
            )
            if inserted is None:
                raise ValueError(f"decision_id already used: {decision_id}")

            # Upsert the player row.
            row = await conn.fetchrow(
                """
                INSERT INTO leaderboard (handle, rp, rounds_played, last_decision_id, last_played_at)
                VALUES ($1, GREATEST(0, $2), 1, $3, NOW())
                ON CONFLICT (handle) DO UPDATE SET
                    rp = GREATEST(0, leaderboard.rp + $2),
                    rounds_played = leaderboard.rounds_played + 1,
                    last_decision_id = $3,
                    last_played_at = NOW()
                RETURNING handle, rp, streak, rounds_played, last_played_at
                """,
                handle,
                rp_delta,
                decision_id,
            )

    assert row is not None
    return LeaderboardEntry(
        handle=row["handle"],
        rp=row["rp"],
        streak=row["streak"],
        rounds_played=row["rounds_played"],
        last_played_at=row["last_played_at"].isoformat(),
    )
