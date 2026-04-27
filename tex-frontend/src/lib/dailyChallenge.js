// ────────────────────────────────────────────────────────────────────
//  Daily Challenge
//
//  - One incident per day, same for everyone.
//  - Date-seeded so it's deterministic without a backend.
//  - Streak counter persists in localStorage.
//  - Streak resets if the player misses a day.
//  - Today's run is one-shot — once finished, locked until tomorrow.
// ────────────────────────────────────────────────────────────────────

import { INCIDENTS, incidentById } from "./incidents.js";

const KEY = "tex.v10.daily";

// 30-day curated rotation — lets us hand-pick the order so daily
// difficulty has a rhythm instead of randomly stacking three Tier 3s.
const ROTATION = [
  "leak", "wire", "guarantee", "poison", "broadcast",
  "handoff", "inject", "cleanup", "pitch", "hallucination",
  "phi", "handover", "toolstorm", "leak", "wire",
  "guarantee", "poison", "broadcast", "handoff", "inject",
  "cleanup", "pitch", "hallucination", "phi", "handover",
  "toolstorm", "leak", "wire", "guarantee", "poison",
];

/** Compute today's date key — YYYY-MM-DD in local time */
export function todayKey() {
  const d = new Date();
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}

/** Number of days since epoch (UTC) — used to index rotation deterministically */
function dayIndex() {
  const ms = Date.now();
  return Math.floor(ms / 86400000);
}

/** Today's incident */
export function todayIncident() {
  const idx = dayIndex() % ROTATION.length;
  const id = ROTATION[idx];
  return incidentById(id) || INCIDENTS[0];
}

function load() {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return defaultState();
    return { ...defaultState(), ...JSON.parse(raw) };
  } catch {
    return defaultState();
  }
}

function save(state) {
  try {
    localStorage.setItem(KEY, JSON.stringify(state));
  } catch {
    /* ignore */
  }
}

function defaultState() {
  return {
    streak: 0,
    longestStreak: 0,
    lastPlayedDate: null,
    todayResult: null,        // { date, score, stealth, verdict }
    history: [],              // [{ date, incidentId, score, verdict }]
  };
}

export function getDailyState() {
  const state = load();
  // Streak hygiene — if last played was 2+ days ago, reset streak
  if (state.lastPlayedDate) {
    const last = new Date(state.lastPlayedDate);
    const today = new Date(todayKey());
    const diffDays = Math.round((today - last) / 86400000);
    if (diffDays > 1) {
      state.streak = 0;
      save(state);
    }
  }
  // Reset todayResult if it's stale
  if (state.todayResult && state.todayResult.date !== todayKey()) {
    state.todayResult = null;
    save(state);
  }
  return state;
}

/** Has the player completed today's daily? */
export function dailyCompleted() {
  const s = getDailyState();
  return Boolean(s.todayResult);
}

/** Record today's daily result */
export function recordDaily(incident, score) {
  const state = load();
  const today = todayKey();

  // Don't double-count
  if (state.todayResult && state.todayResult.date === today) {
    return state;
  }

  // Streak math
  if (state.lastPlayedDate) {
    const last = new Date(state.lastPlayedDate);
    const t = new Date(today);
    const diffDays = Math.round((t - last) / 86400000);
    if (diffDays === 1) {
      state.streak += 1;
    } else if (diffDays > 1) {
      state.streak = 1;
    }
    // diffDays === 0 means already played today — handled above
  } else {
    state.streak = 1;
  }
  state.longestStreak = Math.max(state.longestStreak, state.streak);

  state.lastPlayedDate = today;
  state.todayResult = {
    date: today,
    score: score.total,
    stealth: score.stealth,
    verdict: score.verdict,
    forfeit: score.forfeit,
  };
  state.history.unshift({
    date: today,
    incidentId: incident.id,
    score: score.total,
    verdict: score.verdict,
  });
  state.history = state.history.slice(0, 30);

  save(state);
  return state;
}

/** Time until midnight local — used for the countdown UI */
export function msUntilMidnight() {
  const now = new Date();
  const tomorrow = new Date(now);
  tomorrow.setHours(24, 0, 0, 0);
  return tomorrow - now;
}

export function formatCountdown(ms) {
  if (ms < 0) ms = 0;
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}
