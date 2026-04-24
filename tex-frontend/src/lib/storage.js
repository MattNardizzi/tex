// ────────────────────────────────────────────────────────────────────────
//  TEX ARENA — Storage (v6 "Interrogation")
// ────────────────────────────────────────────────────────────────────────
//  localStorage-backed. Simple model:
//    • handle
//    • clearedCaseIds
//    • perCase: { [id]: { bestScore, bestCatchMs, attempts } }
//    • totalPoints
//    • streakDays, lastPlayedDate  (ISO date string, YYYY-MM-DD)
//    • bountyClaimed
//    • history
// ────────────────────────────────────────────────────────────────────────

import { rankForPoints, RANKS } from "./scoring.js";
export { rankForPoints, RANKS };

const KEY_PLAYER = "tex-arena/player/v6";

function safeParse(raw) {
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

function todayISO() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

function daysBetween(a, b) {
  if (!a || !b) return Infinity;
  const ms = new Date(b).getTime() - new Date(a).getTime();
  return Math.round(ms / (1000 * 60 * 60 * 24));
}

function defaultPlayer() {
  return {
    handle: "",
    clearedCaseIds: [],
    perCase: {},
    totalPoints: 0,
    streakDays: 0,
    lastPlayedDate: null,
    bountyClaimed: false,
    history: [],
    createdAt: Date.now(),
  };
}

export function getPlayer() {
  if (typeof localStorage === "undefined") return defaultPlayer();
  const parsed = safeParse(localStorage.getItem(KEY_PLAYER));
  if (!parsed || typeof parsed !== "object") return defaultPlayer();
  return { ...defaultPlayer(), ...parsed };
}

export function savePlayer(player) {
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(KEY_PLAYER, JSON.stringify(player));
  } catch { /* quota or disabled — silent failure is fine */ }
}

export function setHandle(player, handle) {
  return { ...player, handle: String(handle || "").slice(0, 32) };
}

export function touchStreak(player) {
  const today = todayISO();
  if (player.lastPlayedDate === today) {
    return { ...player, lastPlayedDate: today };
  }
  const delta = daysBetween(player.lastPlayedDate, today);
  const nextStreak = delta === 1 ? player.streakDays + 1 : 1;
  return { ...player, streakDays: nextStreak, lastPlayedDate: today };
}

export function recordCaseResult(player, {
  caseId,
  verdict,
  score,
  catchMs,
  questionsUsed,
  decision,
}) {
  const streakApplied = touchStreak(player);
  const prior = streakApplied.perCase[caseId] || {
    bestScore: 0, bestCatchMs: null, attempts: 0, cleared: false,
  };

  const isCatch = verdict === "FORBID" || verdict === "ABSTAIN";
  const cleared = prior.cleared || isCatch;
  const bestScore = Math.max(prior.bestScore, score);
  const bestCatchMs =
    verdict === "FORBID"
      ? (prior.bestCatchMs == null ? catchMs : Math.min(prior.bestCatchMs, catchMs))
      : prior.bestCatchMs;

  const perCase = {
    ...streakApplied.perCase,
    [caseId]: {
      ...prior,
      bestScore,
      bestCatchMs,
      attempts: prior.attempts + 1,
      cleared,
      lastVerdict: verdict,
      lastPlayedAt: Date.now(),
    },
  };

  const clearedCaseIds = cleared && !streakApplied.clearedCaseIds.includes(caseId)
    ? [...streakApplied.clearedCaseIds, caseId]
    : streakApplied.clearedCaseIds;

  const history = [
    {
      caseId,
      verdict,
      score,
      catchMs,
      questionsUsed,
      ts: Date.now(),
      request_id: decision?.request_id || null,
    },
    ...(streakApplied.history || []),
  ].slice(0, 50);

  return {
    ...streakApplied,
    perCase,
    clearedCaseIds,
    totalPoints: streakApplied.totalPoints + score,
    history,
  };
}

export function claimBounty(player) {
  return { ...player, bountyClaimed: true };
}
