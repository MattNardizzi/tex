// ────────────────────────────────────────────────────────────────────
//  Local player storage
//  Persists handle, RP, streak, recent rounds to localStorage.
//  When you add a backend leaderboard, swap getPlayer/savePlayer to
//  fetch from your API instead — nothing else changes.
// ────────────────────────────────────────────────────────────────────

const KEY = "tex.arena.player.v8";

function defaultPlayer() {
  return {
    handle: "",
    rp: 0,
    streak: 0,
    lastPlayedAt: null,
    rounds: [], // { at, incidentId, verdict, rpDelta, attempts, secondsLeft }
  };
}

export function getPlayer() {
  if (typeof window === "undefined") return defaultPlayer();
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return defaultPlayer();
    const parsed = JSON.parse(raw);
    return { ...defaultPlayer(), ...parsed };
  } catch {
    return defaultPlayer();
  }
}

export function savePlayer(p) {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(KEY, JSON.stringify(p));
  } catch {}
}

export function setHandle(p, handle) {
  const cleaned = (handle || "").replace(/^@/, "").slice(0, 24).trim();
  return { ...p, handle: cleaned };
}

export function recordRound(p, { incidentId, verdict, rpDelta, attempts, secondsLeft, decision }) {
  const now = Date.now();
  const lastDay = p.lastPlayedAt ? new Date(p.lastPlayedAt).toDateString() : null;
  const today = new Date(now).toDateString();
  const yesterday = new Date(now - 86400000).toDateString();
  let streak = p.streak || 0;
  if (lastDay !== today) {
    streak = lastDay === yesterday ? streak + 1 : 1;
  }
  const rp = Math.max(0, (p.rp || 0) + rpDelta);
  const round = {
    at: now,
    incidentId,
    verdict,
    rpDelta,
    attempts,
    secondsLeft,
    evidenceHash: decision?.evidence?.evidence_hash || null,
    decisionId: decision?.decision_id || null,
    totalMs: decision?.total_ms || null,
  };
  return {
    ...p,
    rp,
    streak,
    lastPlayedAt: now,
    rounds: [round, ...(p.rounds || [])].slice(0, 20),
  };
}

export function resetPlayer() {
  if (typeof window === "undefined") return defaultPlayer();
  const fresh = defaultPlayer();
  savePlayer(fresh);
  return fresh;
}
