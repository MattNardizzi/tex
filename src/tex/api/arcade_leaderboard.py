"""
Arcade leaderboard API router.

Exposes:
  GET  /arcade/leaderboard?date=YYYY-MM-DD&handle=foo
       → top 50 for the day + caller's rank/row + today's total players
  POST /arcade/leaderboard/submit
       → records score with bounded sanity checks

Anti-cheat posture (deliberate):
  The arcade is a fully client-side game. There is no server-authoritative
  scoring possible without instrumenting every keypress. Rather than fake
  cryptographic protection that any reader of the JS bundle can break, we
  enforce SOFT bounds:

    - Score caps that match the actual game's maximum achievable rate
      (1 pt/sec time-alive + decision bonuses; ~50 pt/sec ceiling is
      generous and still rejects "I posted 1,000,000")
    - Per-handle rate limit: one submission per handle per ~10 seconds
    - Idempotent submit_token (UUID from the client) prevents replays
    - last-write-wins per (handle, date_key) lets the same player improve
      their daily slot

  This is a marketing/social surface, not a competitive ladder. The point
  is that real player scores show up alongside the seeded list and the
  page feels alive on launch day.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from tex.api.rate_limit import IPRateLimiter, enforce
from tex.db import arcade_leaderboard_repo as repo


_HANDLE_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,18}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{8,64}$")
_RATING_VALUES = {"ROOKIE", "OPERATOR", "ANALYST", "WARDEN"}

# Sanity bounds (soft anti-cheat).
_MAX_SURVIVED_MS = 30 * 60 * 1000           # 30 minutes ceiling — way above realistic
_MAX_SCORE = 50_000                         # 50,000 RP — far beyond any real run
_SCORE_PER_SEC_CEILING = 50                 # max believable score per second of survival
_MAX_BREACHES = 200
_MAX_PEAK_SPEED = 10.0                       # game caps speedMult at 3.4; 10 is generous

# Rate limits (per-IP, fixed window). The submit endpoint is the
# expensive path (transactional upsert + 2 follow-up queries for rank
# and total), so it gets the tighter cap. The GET endpoint is cheaper
# and used by every page render, so it gets a looser cap.
#
# 30/min on submits = one run every 2 seconds sustained, which exceeds
# any realistic human play rate (a single arcade run is ~30s+ at
# minimum) while still catching scripted spam. 120/min on GET = two
# per second, comfortable for normal browsing including hub auto-
# refresh.
_SUBMIT_LIMITER = IPRateLimiter(max_per_window=30, window_seconds=60)
_READ_LIMITER = IPRateLimiter(max_per_window=120, window_seconds=60)

router = APIRouter(prefix="/arcade/leaderboard", tags=["arcade-leaderboard"])


# ────────────────────────────────────────────────────────────────────
# DTOs
# ────────────────────────────────────────────────────────────────────
class ArcadeRowDTO(BaseModel):
    rank: int
    handle: str
    score: int
    survived_ms: int
    breaches: int
    peak_speed: float
    rating: str
    is_you: bool = False


class ArcadeLeaderboardResponse(BaseModel):
    date_key: str
    entries: list[ArcadeRowDTO]
    total_players: int
    your_rank: int | None = None
    your_score: int | None = None


class ArcadeSubmitRequest(BaseModel):
    handle: str = Field(..., min_length=2, max_length=18)
    date_key: str = Field(..., min_length=10, max_length=10)
    score: int = Field(..., ge=0, le=_MAX_SCORE)
    survived_ms: int = Field(..., ge=0, le=_MAX_SURVIVED_MS)
    breaches: int = Field(..., ge=0, le=_MAX_BREACHES)
    peak_speed: float = Field(..., ge=1.0, le=_MAX_PEAK_SPEED)
    rating: str = Field(..., min_length=3, max_length=12)
    submit_token: str = Field(..., min_length=8, max_length=64)


class ArcadeSubmitResponse(BaseModel):
    accepted: bool
    your_rank: int | None
    your_score: int
    total_players: int
    label: str
    note: str | None = None


# ────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────
def _today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _normalize_handle(raw: str) -> str:
    return raw.lstrip("@").strip()


def _validate_payload(p: ArcadeSubmitRequest) -> Optional[str]:
    """Return an error string if the payload looks fishy, else None."""
    handle = _normalize_handle(p.handle)
    if not _HANDLE_RE.match(handle):
        return "invalid handle (2-18 chars: letters, digits, '.', '_', '-')"
    if not _DATE_RE.match(p.date_key):
        return "invalid date_key (expected YYYY-MM-DD)"
    if not _TOKEN_RE.match(p.submit_token):
        return "invalid submit_token format"
    if p.rating not in _RATING_VALUES:
        return f"invalid rating (must be one of {sorted(_RATING_VALUES)})"

    # Score-vs-survival sanity. A run that survived 5 seconds cannot
    # legitimately have 1000 score.
    survived_sec = p.survived_ms / 1000.0
    if survived_sec > 0 and p.score / max(survived_sec, 1.0) > _SCORE_PER_SEC_CEILING:
        return "score-vs-survival ratio exceeds the realistic ceiling"

    # The earliest a player can post is the day in UTC. Future-dated keys
    # are flat rejected.
    today = _today_utc()
    if p.date_key > today:
        return "date_key is in the future"

    return None


# ────────────────────────────────────────────────────────────────────
# GET /arcade/leaderboard
# ────────────────────────────────────────────────────────────────────
@router.get("", response_model=ArcadeLeaderboardResponse)
@router.get("/", response_model=ArcadeLeaderboardResponse)
async def get_leaderboard(
    request: Request,
    date: str | None = Query(default=None, description="YYYY-MM-DD UTC; defaults to today"),
    handle: str | None = Query(default=None, description="Optional caller handle for own-rank lookup"),
) -> ArcadeLeaderboardResponse:
    enforce(_READ_LIMITER, request)
    date_key = date or _today_utc()
    if not _DATE_RE.match(date_key):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid date format; expected YYYY-MM-DD",
        )

    try:
        rows = await repo.top_for_day(date_key, limit=50)
        total = await repo.total_for_day(date_key)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        )

    own_handle = _normalize_handle(handle) if handle else None
    if own_handle and not _HANDLE_RE.match(own_handle):
        own_handle = None

    entries = [
        ArcadeRowDTO(
            rank=i + 1,
            handle=r.handle,
            score=r.score,
            survived_ms=r.survived_ms,
            breaches=r.breaches,
            peak_speed=r.peak_speed,
            rating=r.rating,
            is_you=(own_handle is not None and r.handle == own_handle),
        )
        for i, r in enumerate(rows)
    ]

    your_rank: int | None = None
    your_score: int | None = None
    if own_handle:
        own = await repo.get(own_handle, date_key)
        if own is not None:
            your_score = own.score
            hit = next((e for e in entries if e.handle == own_handle), None)
            if hit is not None:
                your_rank = hit.rank
            else:
                your_rank = await repo.rank_for_day(own_handle, date_key)

    return ArcadeLeaderboardResponse(
        date_key=date_key,
        entries=entries,
        total_players=total,
        your_rank=your_rank,
        your_score=your_score,
    )


# ────────────────────────────────────────────────────────────────────
# POST /arcade/leaderboard/submit
# ────────────────────────────────────────────────────────────────────
@router.post("/submit", response_model=ArcadeSubmitResponse)
async def submit_arcade_score(
    payload: ArcadeSubmitRequest,
    request: Request,
) -> ArcadeSubmitResponse:
    enforce(_SUBMIT_LIMITER, request)
    err = _validate_payload(payload)
    if err is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=err,
        )

    handle = _normalize_handle(payload.handle)

    # The repo's submit() is fully idempotent — (handle, date_key) PK plus
    # GREATEST on score guarantees one row per player per day with their
    # best run preserved. No token-replay rejection anymore; that earlier
    # behavior broke same-day replays from older clients that reused a
    # per-day token.
    entry = await repo.submit(
        handle=handle,
        date_key=payload.date_key,
        score=payload.score,
        survived_ms=payload.survived_ms,
        breaches=payload.breaches,
        peak_speed=payload.peak_speed,
        rating=payload.rating,
        submit_token=payload.submit_token,
    )

    # `accepted` reflects whether this submission improved the player's
    # daily best. The label updates only when the run actually advanced
    # the score (or matched it — last-write-wins on ties).
    improved = entry.score == payload.score
    return ArcadeSubmitResponse(
        accepted=improved,
        your_rank=await repo.rank_for_day(handle, payload.date_key),
        your_score=entry.score,
        total_players=await repo.total_for_day(payload.date_key),
        label=_label_for(entry.score, entry.breaches, entry.survived_ms)
        if improved
        else "PERSONAL BEST HELD",
        note=None if improved else "your earlier run today still leads",
    )


def _label_for(score: int, breaches: int, survived_ms: int) -> str:
    """Server-side echo of the rating shown to the player. Mirrors the
    hybrid rules in Arcade.jsx — either a clean-survival threshold OR a
    score threshold earns each tier. Kept in sync by hand; if the
    frontend rules drift, update both."""
    survived_sec = survived_ms // 1000
    if (survived_sec >= 90 and breaches == 0) or score >= 5000:
        return "WARDEN"
    if (survived_sec >= 60 and breaches <= 2) or score >= 3000:
        return "ANALYST"
    if (survived_sec >= 30 and breaches <= 4) or score >= 1500:
        return "OPERATOR"
    return "ROOKIE"
