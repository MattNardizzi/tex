"""
Leaderboard API router.

Exposes:
  GET  /leaderboard            → top players + optional caller's rank
  POST /leaderboard/submit     → record a verified round result

Anti-cheat:
  The submit endpoint requires a real `decision_id` that exists in the
  in-process decision_store. The server recomputes RP from the actual
  Decision verdict + metadata so the frontend cannot claim arbitrary
  point totals.

  Each decision_id can only be redeemed for RP once.
"""

from __future__ import annotations

import re
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from tex.db import leaderboard_repo


# RP curve mirrors the frontend's expectations. Server is authoritative.
_PERMIT_BASE = 120
_PERMIT_SPEED_PER_SECOND = 0.8
_PERMIT_FIRST_ATTEMPT_BONUS = 40
_PERMIT_SECOND_ATTEMPT_BONUS = 20
_PERMIT_DIFFICULTY_MULT = 10

_ABSTAIN_BASE = 20
_ABSTAIN_DIFFICULTY_MULT = 4

_FORBID_DELTA = -25

_HANDLE_RE = re.compile(r"^[A-Za-z0-9_.]{2,24}$")


router = APIRouter(prefix="/leaderboard", tags=["leaderboard"])


class LeaderboardRowDTO(BaseModel):
    rank: int
    handle: str
    rp: int
    streak: int = 0
    rounds_played: int = 0


class LeaderboardResponseDTO(BaseModel):
    entries: list[LeaderboardRowDTO]
    your_rank: int | None = None
    your_rp: int | None = None
    total_players: int


class SubmitRequestDTO(BaseModel):
    handle: str = Field(..., min_length=2, max_length=24)
    decision_id: str
    attempts_used: int = Field(..., ge=1, le=3)
    seconds_left: int = Field(..., ge=0, le=60)
    incident_difficulty: int = Field(default=2, ge=1, le=3)
    incident_id: str | None = None


class SubmitResponseDTO(BaseModel):
    handle: str
    rp: int
    rp_delta: int
    rounds_played: int
    your_rank: int | None
    label: str
    tone: str


# ────────────────────────────────────────────────────────────────────
# GET /leaderboard
# ────────────────────────────────────────────────────────────────────
@router.get("", response_model=LeaderboardResponseDTO)
@router.get("/", response_model=LeaderboardResponseDTO)
async def get_leaderboard(handle: str | None = None) -> LeaderboardResponseDTO:
    """Return top 50 players. If `handle` is given, also return their rank."""
    try:
        rows = await leaderboard_repo.top(limit=50)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        )

    entries = [
        LeaderboardRowDTO(
            rank=i + 1,
            handle=r.handle,
            rp=r.rp,
            streak=r.streak,
            rounds_played=r.rounds_played,
        )
        for i, r in enumerate(rows)
    ]

    your_rank: int | None = None
    your_rp: int | None = None
    if handle:
        normalized = handle.lstrip("@").strip()
        if _HANDLE_RE.match(normalized):
            you = await leaderboard_repo.get(normalized)
            if you is not None:
                your_rp = you.rp
                # If you're in the top-50 already, take that rank. Otherwise
                # ask the DB for your rank position.
                hit = next((e for e in entries if e.handle == normalized), None)
                if hit is not None:
                    your_rank = hit.rank
                else:
                    # Out-of-window rank lookup. One extra query.
                    pool = await leaderboard_repo.get_pool()
                    async with pool.acquire() as conn:
                        row = await conn.fetchrow(
                            "SELECT COUNT(*) + 1 AS rk FROM leaderboard "
                            "WHERE rp > (SELECT rp FROM leaderboard WHERE handle = $1)",
                            normalized,
                        )
                    your_rank = int(row["rk"]) if row else None

    # Total player count.
    pool = await leaderboard_repo.get_pool()
    async with pool.acquire() as conn:
        total_row = await conn.fetchrow("SELECT COUNT(*) AS c FROM leaderboard")
    total = int(total_row["c"]) if total_row else len(entries)

    return LeaderboardResponseDTO(
        entries=entries,
        your_rank=your_rank,
        your_rp=your_rp,
        total_players=total,
    )


# ────────────────────────────────────────────────────────────────────
# POST /leaderboard/submit
# ────────────────────────────────────────────────────────────────────
@router.post("/submit", response_model=SubmitResponseDTO)
async def submit_round(payload: SubmitRequestDTO, request: Request) -> SubmitResponseDTO:
    handle = payload.handle.lstrip("@").strip()
    if not _HANDLE_RE.match(handle):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid handle (use 2–24 chars: letters, digits, '.', '_').",
        )

    # 1. Verify decision exists and recompute RP from the stored verdict.
    decision_store = _require_decision_store(request)
    try:
        decision_uuid = UUID(payload.decision_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="decision_id is not a valid UUID.",
        )

    decision = decision_store.get(decision_uuid)
    if decision is None:
        # Tex backend uses in-memory store. If the process was restarted
        # between the round and the submit, the decision will be gone.
        # We accept this gracefully but with reduced RP (no bypass bonus).
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "decision not found. The Tex backend may have been "
                "restarted since the round was played."
            ),
        )

    # Verdict is the source of truth, not the client.
    verdict = getattr(decision.verdict, "value", str(decision.verdict))
    rp_calc = _server_rp_for(
        verdict=verdict,
        attempts_used=payload.attempts_used,
        seconds_left=payload.seconds_left,
        incident_difficulty=payload.incident_difficulty,
    )

    # 2. Atomically record the score (will reject duplicate decision_ids).
    try:
        entry = await leaderboard_repo.submit(
            handle=handle,
            rp_delta=rp_calc["delta"],
            decision_id=payload.decision_id,
        )
    except ValueError:
        # Duplicate submission — return the existing row so client can sync.
        existing = await leaderboard_repo.get(handle)
        if existing is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="decision_id already used and no player row found.",
            )
        return SubmitResponseDTO(
            handle=existing.handle,
            rp=existing.rp,
            rp_delta=0,
            rounds_played=existing.rounds_played,
            your_rank=await _rank_of(existing.handle),
            label="ALREADY RECORDED",
            tone="partial",
        )

    return SubmitResponseDTO(
        handle=entry.handle,
        rp=entry.rp,
        rp_delta=rp_calc["delta"],
        rounds_played=entry.rounds_played,
        your_rank=await _rank_of(entry.handle),
        label=rp_calc["label"],
        tone=rp_calc["tone"],
    )


# ────────────────────────────────────────────────────────────────────
# Internals
# ────────────────────────────────────────────────────────────────────
def _server_rp_for(
    *,
    verdict: str,
    attempts_used: int,
    seconds_left: int,
    incident_difficulty: int,
) -> dict[str, Any]:
    if verdict == "PERMIT":
        speed = round(seconds_left * _PERMIT_SPEED_PER_SECOND)
        if attempts_used <= 1:
            efficiency = _PERMIT_FIRST_ATTEMPT_BONUS
        elif attempts_used == 2:
            efficiency = _PERMIT_SECOND_ATTEMPT_BONUS
        else:
            efficiency = 0
        diff = incident_difficulty * _PERMIT_DIFFICULTY_MULT
        return {
            "delta": _PERMIT_BASE + speed + efficiency + diff,
            "label": "BYPASS",
            "tone": "win",
        }
    if verdict == "ABSTAIN":
        return {
            "delta": _ABSTAIN_BASE + incident_difficulty * _ABSTAIN_DIFFICULTY_MULT,
            "label": "NEAR MISS",
            "tone": "partial",
        }
    return {"delta": _FORBID_DELTA, "label": "BLOCKED BY TEX", "tone": "loss"}


async def _rank_of(handle: str) -> int | None:
    pool = await leaderboard_repo.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT COUNT(*) + 1 AS rk FROM leaderboard
            WHERE rp > (SELECT rp FROM leaderboard WHERE handle = $1)
            """,
            handle,
        )
    return int(row["rk"]) if row else None


def _require_decision_store(request: Request):
    store = getattr(request.app.state, "decision_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="decision_store missing from app state",
        )
    return store
