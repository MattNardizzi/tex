// ────────────────────────────────────────────────────────────────────
//  Daily leaderboard — local-first, optional backend pass-through
//  ────────────────────────────────────────────────────────────────────
//  How it works:
//    - Every player on the same UTC day plays the same stream.
//    - Each player's daily score is stored in localStorage under a
//      per-day key. They can play unlimited TRAINING shifts but only
//      ONE real shift counts per day.
//    - The leaderboard is seeded with believable bot entries that
//      vary by day (so it doesn't look empty on launch). The player's
//      real score is inserted into the seeded list and ranked.
//    - If a backend leaderboard endpoint is available later, the
//      submitDailyScore() function will POST and merge the response.
//
//  This is a marketing surface, not a competitive ladder. The seeded
//  entries make the page feel populated. When real users start
//  posting, you can swap pure-seeded for a real read of an API.
// ────────────────────────────────────────────────────────────────────

import { todayKey } from "./dailyShift.js";

const KEY = "tex.conveyor.daily.v1";
const HANDLE_KEY = "tex.conveyor.handle.v1";

// ─── Handle ──────────────────────────────────────────────────────────

export function getHandle() {
  if (typeof window === "undefined") return "";
  return localStorage.getItem(HANDLE_KEY) || "";
}
export function setHandle(handle) {
  if (typeof window === "undefined") return;
  const cleaned = (handle || "").replace(/^@/, "").slice(0, 18).trim();
  localStorage.setItem(HANDLE_KEY, cleaned);
  return cleaned;
}

// ─── Per-day local store ─────────────────────────────────────────────

function readStore() {
  if (typeof window === "undefined") return {};
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? JSON.parse(raw) : {};
  } catch { return {}; }
}
function writeStore(s) {
  if (typeof window === "undefined") return;
  try { localStorage.setItem(KEY, JSON.stringify(s)); } catch {}
}

/** Has the player already submitted today's shift? */
export function hasPlayedToday(dateKey = todayKey()) {
  const store = readStore();
  return Boolean(store[dateKey]);
}

/** The player's recorded result for today (or null). */
export function todayResult(dateKey = todayKey()) {
  const store = readStore();
  return store[dateKey] || null;
}

/** Persist the player's daily result. Idempotent — first submission wins. */
export function submitDailyScore({ score, handle, dateKey = todayKey() }) {
  const store = readStore();
  if (store[dateKey]) return store[dateKey]; // first-write-wins
  const entry = {
    handle: handle || "anonymous",
    total: score.total,
    accuracy: score.accuracy,
    breaches: score.counts.breaches,
    rating: score.rating,
    avgResponseMs: score.avgResponseMs,
    submittedAt: Date.now(),
  };
  store[dateKey] = entry;
  writeStore(store);
  return entry;
}

// ─── Seeded leaderboard ──────────────────────────────────────────────
//
// Believable handles + score distributions for the daily list.
// The seed is the date so the list is stable across one day and
// changes the next day. Top scores cluster near 850–1100, mid 500–800,
// long tail down to 100. ~28 entries by default.

const SEED_HANDLES = [
  "warden_one", "kira_ops", "byteguard", "redteam_42", "ops_anika",
  "0xfaye", "m_rivers", "j_park_sec", "rev_ops_47", "compl_iance",
  "atlas_06", "noctis", "n_shah", "owasp_dad", "sigma_dz",
  "ledger_pi", "halt_catch", "deep_v", "the_clerk", "polic_y",
  "lattice", "nine_nines", "soc2_amy", "sentinel_x", "g0vern",
  "pre_release", "audit_trail", "operator_03", "sigma_oz", "wraith_io",
  "telos_q", "vault_03", "k_rao", "hashbrown", "mona_red",
  "ciso_ish", "sla_44", "pii_negative",
];

function mulberry32(a) {
  return function () {
    a |= 0;
    a = (a + 0x6D2B79F5) | 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function hashString(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

export function getSeededLeaderboard(dateKey = todayKey()) {
  const rng = mulberry32(hashString("seed-" + dateKey));
  const handles = SEED_HANDLES.slice();
  // Shuffle handles for the day.
  for (let i = handles.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [handles[i], handles[j]] = [handles[j], handles[i]];
  }

  const entries = [];
  // Top 5 — high scores, low breaches
  for (let i = 0; i < 5; i++) {
    entries.push({
      handle: handles[i],
      total: Math.round(870 + rng() * 230),
      accuracy: 0.9 + rng() * 0.08,
      breaches: rng() < 0.4 ? 0 : 1,
      rating: rng() < 0.3 ? "WARDEN" : "ANALYST",
      bot: true,
    });
  }
  // Mid tier
  for (let i = 5; i < 18; i++) {
    entries.push({
      handle: handles[i],
      total: Math.round(450 + rng() * 380),
      accuracy: 0.7 + rng() * 0.18,
      breaches: Math.floor(rng() * 3),
      rating: rng() < 0.5 ? "ANALYST" : "OPERATOR",
      bot: true,
    });
  }
  // Long tail
  for (let i = 18; i < 28; i++) {
    entries.push({
      handle: handles[i],
      total: Math.round(120 + rng() * 320),
      accuracy: 0.4 + rng() * 0.3,
      breaches: 1 + Math.floor(rng() * 4),
      rating: rng() < 0.5 ? "OPERATOR" : "ROOKIE",
      bot: true,
    });
  }

  return entries.sort((a, b) => b.total - a.total);
}

/**
 * Returns the merged leaderboard for the day with the player's row
 * inserted at the right rank. If the player hasn't played, the player
 * row is not included.
 */
export function getDailyLeaderboard(dateKey = todayKey()) {
  const seeded = getSeededLeaderboard(dateKey);
  const me = todayResult(dateKey);
  if (!me) return { entries: seeded, myRank: null, total: seeded.length };

  const merged = [...seeded, { ...me, you: true }].sort((a, b) => b.total - a.total);
  const myRank = merged.findIndex((e) => e.you) + 1;
  return { entries: merged, myRank, total: merged.length };
}
