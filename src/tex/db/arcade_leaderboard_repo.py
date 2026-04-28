"""
Tex Arcade leaderboard — Postgres-backed repository.

Separate from the conveyor leaderboard (which is verdict-decision-based).
The arcade is a survival shooter: each run produces (score, survived_ms,
breaches, peak_speed). Players post one score per (handle, date_key),
last-write-wins inside a day, all-time top reflects the player's best.

Schema:
  arcade_leaderboard
    handle           TEXT
    date_key         TEXT    (UTC YYYY-MM-DD)
    score            INTEGER
    survived_ms      INTEGER
    breaches         INTEGER
    peak_speed_x10   INTEGER (peak speed * 10, integer storage)
    rating           TEXT
    submit_token     TEXT    (anti-replay nonce, unique per submission)
    submitted_at     TIMESTAMPTZ
    PRIMARY KEY (handle, date_key)

  arcade_leaderboard_used_tokens
    submit_token     TEXT PRIMARY KEY
    used_at          TIMESTAMPTZ

Rationale:
- (handle, date_key) PK gives one daily slot per handle, last-write-wins.
- A separate used-tokens table prevents the same client-generated token
  from being replayed.
- We keep score as the leaderboard-sort key; ties broken by submitted_at
  (earlier submitter wins ties).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

import asyncpg

DATABASE_URL_ENV = "DATABASE_URL"

_pool: Optional[asyncpg.Pool] = None


@dataclass(frozen=True, slots=True)
class ArcadeEntry:
    handle: str
    date_key: str
    score: int
    survived_ms: int
    breaches: int
    peak_speed: float       # de-normalized from peak_speed_x10
    rating: str
    submitted_at: str       # ISO


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS arcade_leaderboard (
    handle           TEXT NOT NULL,
    date_key         TEXT NOT NULL,
    score            INTEGER NOT NULL,
    survived_ms      INTEGER NOT NULL,
    breaches         INTEGER NOT NULL,
    peak_speed_x10   INTEGER NOT NULL,
    rating           TEXT NOT NULL,
    submit_token     TEXT NOT NULL,
    submitted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (handle, date_key)
);

CREATE INDEX IF NOT EXISTS idx_arcade_leaderboard_score_desc
    ON arcade_leaderboard (date_key, score DESC, submitted_at ASC);

CREATE INDEX IF NOT EXISTS idx_arcade_leaderboard_alltime_score
    ON arcade_leaderboard (score DESC, submitted_at ASC);

CREATE TABLE IF NOT EXISTS arcade_leaderboard_used_tokens (
    submit_token TEXT PRIMARY KEY,
    used_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


async def get_pool() -> asyncpg.Pool:
    """Return (and lazily create) the shared connection pool."""
    global _pool
    if _pool is None:
        url = os.environ.get(DATABASE_URL_ENV)
        if not url:
            raise RuntimeError(
                f"Environment variable {DATABASE_URL_ENV} is not set. "
                "Arcade leaderboard endpoints cannot run without it."
            )
        _pool = await asyncpg.create_pool(
            dsn=url,
            min_size=1,
            max_size=5,
            command_timeout=10,
        )
    return _pool


async def ensure_schema() -> None:
    """Create the arcade leaderboard tables if they don't exist. Idempotent."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(SCHEMA_SQL)


def _row_to_entry(row) -> ArcadeEntry:
    return ArcadeEntry(
        handle=row["handle"],
        date_key=row["date_key"],
        score=row["score"],
        survived_ms=row["survived_ms"],
        breaches=row["breaches"],
        peak_speed=row["peak_speed_x10"] / 10.0,
        rating=row["rating"],
        submitted_at=row["submitted_at"].isoformat(),
    )


async def top_for_day(date_key: str, limit: int = 50) -> list[ArcadeEntry]:
    """Top-N rows for a given UTC date, ordered by score desc, then earliest submission."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT handle, date_key, score, survived_ms, breaches,
                   peak_speed_x10, rating, submitted_at
            FROM arcade_leaderboard
            WHERE date_key = $1
            ORDER BY score DESC, submitted_at ASC
            LIMIT $2
            """,
            date_key,
            limit,
        )
    return [_row_to_entry(r) for r in rows]


async def top_alltime(limit: int = 50) -> list[ArcadeEntry]:
    """Top-N rows across all days. One per (handle, date_key) — same player can have
    multiple historical entries from different days."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT handle, date_key, score, survived_ms, breaches,
                   peak_speed_x10, rating, submitted_at
            FROM arcade_leaderboard
            ORDER BY score DESC, submitted_at ASC
            LIMIT $1
            """,
            limit,
        )
    return [_row_to_entry(r) for r in rows]


async def get(handle: str, date_key: str) -> Optional[ArcadeEntry]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT handle, date_key, score, survived_ms, breaches,
                   peak_speed_x10, rating, submitted_at
            FROM arcade_leaderboard
            WHERE handle = $1 AND date_key = $2
            """,
            handle,
            date_key,
        )
    return _row_to_entry(row) if row else None


async def rank_for_day(handle: str, date_key: str) -> Optional[int]:
    """Return 1-indexed rank within the day, or None if no entry."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT COUNT(*) + 1 AS rk
            FROM arcade_leaderboard a
            WHERE a.date_key = $2
              AND (
                a.score > (
                    SELECT score FROM arcade_leaderboard
                    WHERE handle = $1 AND date_key = $2
                )
              )
            """,
            handle,
            date_key,
        )
    if row is None:
        return None
    # If this handle has no row for the day, the inner SELECT is NULL and
    # the comparison fails — return None instead of a meaningless rank.
    own = await get(handle, date_key)
    if own is None:
        return None
    return int(row["rk"])


async def submit(
    *,
    handle: str,
    date_key: str,
    score: int,
    survived_ms: int,
    breaches: int,
    peak_speed: float,
    rating: str,
    submit_token: str,
) -> ArcadeEntry:
    """
    Atomically:
      1. Mark this submit_token as used (rejects replays).
      2. Upsert the (handle, date_key) row IF the new score is >= the existing
         score for that day (last-write-wins for ties; better-write-wins
         otherwise). For first submission, insert.

    Raises:
      ValueError("token-replay") if submit_token has already been used.
    """
    peak_speed_x10 = int(round(peak_speed * 10))
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            # Anti-replay token guard.
            inserted = await conn.fetchrow(
                """
                INSERT INTO arcade_leaderboard_used_tokens (submit_token)
                VALUES ($1)
                ON CONFLICT (submit_token) DO NOTHING
                RETURNING submit_token
                """,
                submit_token,
            )
            if inserted is None:
                raise ValueError("token-replay")

            # Upsert with score-improvement check baked into the WHERE clause
            # of the DO UPDATE.
            row = await conn.fetchrow(
                """
                INSERT INTO arcade_leaderboard
                    (handle, date_key, score, survived_ms, breaches,
                     peak_speed_x10, rating, submit_token, submitted_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
                ON CONFLICT (handle, date_key) DO UPDATE SET
                    score          = GREATEST(arcade_leaderboard.score, EXCLUDED.score),
                    survived_ms    = CASE WHEN EXCLUDED.score >= arcade_leaderboard.score
                                          THEN EXCLUDED.survived_ms
                                          ELSE arcade_leaderboard.survived_ms END,
                    breaches       = CASE WHEN EXCLUDED.score >= arcade_leaderboard.score
                                          THEN EXCLUDED.breaches
                                          ELSE arcade_leaderboard.breaches END,
                    peak_speed_x10 = CASE WHEN EXCLUDED.score >= arcade_leaderboard.score
                                          THEN EXCLUDED.peak_speed_x10
                                          ELSE arcade_leaderboard.peak_speed_x10 END,
                    rating         = CASE WHEN EXCLUDED.score >= arcade_leaderboard.score
                                          THEN EXCLUDED.rating
                                          ELSE arcade_leaderboard.rating END,
                    submit_token   = EXCLUDED.submit_token,
                    submitted_at   = NOW()
                RETURNING handle, date_key, score, survived_ms, breaches,
                          peak_speed_x10, rating, submitted_at
                """,
                handle,
                date_key,
                score,
                survived_ms,
                breaches,
                peak_speed_x10,
                rating,
                submit_token,
            )

    assert row is not None
    return _row_to_entry(row)


async def total_for_day(date_key: str) -> int:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS c FROM arcade_leaderboard WHERE date_key = $1",
            date_key,
        )
    return int(row["c"]) if row else 0
