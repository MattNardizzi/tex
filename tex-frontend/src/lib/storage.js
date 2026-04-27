// ────────────────────────────────────────────────────────────────────
//  Local player storage + global score submission (v10)
//  Migrates from v8 key. Adds best-stealth tracking and incident history.
// ────────────────────────────────────────────────────────────────────

import { submitRound } from "./leaderboardClient.js";

const KEY = "tex.arena.player.v10";
const LEGACY_KEY = "tex.arena.player.v8";

function defaultPlayer() {
  return {
    handle: "",
    rp: 0,
    bestStealth: 0,
    bestScore: 0,
    streak: 0,
    lastPlayedAt: null,
    rounds: [],
  };
}

export function getPlayer() {
  if (typeof window === "undefined") return defaultPlayer();
  try {
    let raw = localStorage.getItem(KEY);
    if (!raw) {
      // One-time migration from v8 if it exists
      const legacy = localStorage.getItem(LEGACY_KEY);
      if (legacy) {
        const parsed = JSON.parse(legacy);
        const migrated = { ...defaultPlayer(), ...parsed };
        localStorage.setItem(KEY, JSON.stringify(migrated));
        return migrated;
      }
      return defaultPlayer();
    }
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

/**
 * Record a finished round into the player profile.
 * Score object comes from stealthScore.computeRoundScore().
 */
export function recordRound(p, { incident, score, rpDelta }) {
  const now = Date.now();
  const lastDay = p.lastPlayedAt ? new Date(p.lastPlayedAt).toDateString() : null;
  const today = new Date(now).toDateString();
  const yesterday = new Date(now - 86400000).toDateString();
  let streak = p.streak || 0;
  if (lastDay !== today) {
    streak = lastDay === yesterday ? streak + 1 : 1;
  }
  const rp = Math.max(0, (p.rp || 0) + (rpDelta || 0));

  const round = {
    at: now,
    incidentId: incident.id,
    incidentName: incident.name,
    tier: incident.tier,
    verdict: score.verdict,
    score: score.total,
    stealth: score.stealth,
    forfeit: score.forfeit,
    rpDelta: rpDelta || 0,
  };

  return {
    ...p,
    rp,
    streak,
    bestStealth: Math.max(p.bestStealth || 0, score.stealth || 0),
    bestScore: Math.max(p.bestScore || 0, score.total || 0),
    lastPlayedAt: now,
    rounds: [round, ...(p.rounds || [])].slice(0, 30),
  };
}

/** Fire-and-forget global score submission */
export async function submitRoundToServer(player, { decision, score, incident, attempts }) {
  const handle = (player.handle || "").trim();
  if (!handle) return null;
  const decisionId = decision?.decision_id;
  if (!decisionId) return null;

  try {
    return await submitRound({
      handle,
      decisionId,
      attemptsUsed: attempts || 1,
      secondsLeft: 0, // no clock in v10
      incidentDifficulty: incident?.tier || 2,
      incidentId: incident?.id || null,
    });
  } catch {
    return null;
  }
}

export function resetPlayer() {
  if (typeof window === "undefined") return defaultPlayer();
  const fresh = defaultPlayer();
  savePlayer(fresh);
  return fresh;
}
