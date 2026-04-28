// ────────────────────────────────────────────────────────────────────
//  Tex Arcade leaderboard — backend-aware with seeded fallback
//  ────────────────────────────────────────────────────────────────────
//  How it works:
//    - Backend is the source of truth (Postgres on Render).
//      Endpoints:
//        GET  /api/arcade/leaderboard?date=YYYY-MM-DD&handle=foo
//        POST /api/arcade/leaderboard/submit
//      "/api" is rewritten to the Render backend by Vercel in prod and
//      proxied by Vite in dev — see vercel.json + vite.config.js.
//
//    - The seeded leaderboard remains, but ONLY as an instant fallback
//      so the page never paints empty if the backend is briefly
//      unreachable. Once the fetch resolves, the real list replaces it.
//
//    - Submission is fire-and-forget from the ShiftReport screen via
//      `submitArcadeScore`. It returns a promise that the UI can use to
//      show submission status.
//
//    - Local-storage cache: the most recent successful fetch is cached
//      under TEX_LB_CACHE_KEY so a repeat visit shows the live list
//      immediately, then re-fetches in the background.
// ────────────────────────────────────────────────────────────────────

import { todayKey } from "./dailyShift.js";
import { generateUUIDv4 } from "./uuid.js";

// ── Endpoint base ─────────────────────────────────────────────────────
// "/api" is the same in dev (Vite proxy) and prod (Vercel rewrites).
const API_BASE = "/api";
const LB_PATH = "/arcade/leaderboard";

// ── Local storage keys ────────────────────────────────────────────────
const HANDLE_KEY = "tex.arcade.handle.v1";
const SUBMIT_KEY = "tex.arcade.submitted.v1";   // { [dateKey]: ResultBundle }
const CACHE_KEY  = "tex.arcade.lb.cache.v1";    // { dateKey, payload, fetchedAt }
const TOKEN_KEY  = "tex.arcade.submit.token.v1"; // { [dateKey]: token } so retries are idempotent

// ─── Handle ──────────────────────────────────────────────────────────

export function getHandle() {
  if (typeof window === "undefined") return "";
  return localStorage.getItem(HANDLE_KEY) || "";
}
export function setHandle(handle) {
  if (typeof window === "undefined") return "";
  const cleaned = (handle || "").replace(/^@/, "").slice(0, 18).trim();
  localStorage.setItem(HANDLE_KEY, cleaned);
  return cleaned;
}

// ─── Per-day local submission record ─────────────────────────────────
// Tracks "I've already pushed today's score" so the UI knows not to
// re-prompt for handle and ShiftReport can render the posted state.

function readSubmissions() {
  if (typeof window === "undefined") return {};
  try {
    const raw = localStorage.getItem(SUBMIT_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch { return {}; }
}
function writeSubmissions(s) {
  if (typeof window === "undefined") return;
  try { localStorage.setItem(SUBMIT_KEY, JSON.stringify(s)); } catch {}
}

export function hasPlayedToday(dateKey = todayKey()) {
  return Boolean(readSubmissions()[dateKey]);
}

export function todayResult(dateKey = todayKey()) {
  return readSubmissions()[dateKey] || null;
}

// ─── Submit token (anti-replay nonce per submission) ─────────────────
// The token is generated fresh PER RUN. Its only job is to make a single
// submit RPC idempotent against network retries (same fetch fired twice
// on a flaky connection). It is NOT meant to dedupe across runs — a
// player who plays the game three times today should write three
// distinct submissions, not have submissions 2 and 3 silently rejected.
//
// The legacy per-day cached token under TOKEN_KEY is deliberately
// ignored on read; we keep TOKEN_KEY only so we can clear stale entries
// for users coming from older builds.

function freshSubmitToken() {
  return generateUUIDv4().replace(/-/g, "").slice(0, 32);
}

// ─── Cache layer ─────────────────────────────────────────────────────

function readCache() {
  if (typeof window === "undefined") return null;
  try {
    const raw = localStorage.getItem(CACHE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}
function writeCache(payload) {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify({
      ...payload,
      fetchedAt: Date.now(),
    }));
  } catch {}
}

// ─── Backend fetch ───────────────────────────────────────────────────

/**
 * Hit the backend leaderboard endpoint. Returns a normalized payload
 * shaped like { entries, myRank, total, source: "backend" }, where each
 * entry is { handle, total, breaches, rating, you, survivedMs, peakSpeed }.
 *
 * On any network/server failure, returns null. Callers should fall back
 * to the seeded list in that case.
 */
export async function fetchDailyLeaderboard(dateKey = todayKey(), handle = "") {
  const url = new URL(`${API_BASE}${LB_PATH}`, window.location.origin);
  url.searchParams.set("date", dateKey);
  if (handle) url.searchParams.set("handle", handle);

  let res;
  try {
    res = await fetch(url.toString(), {
      method: "GET",
      headers: { "Accept": "application/json" },
      // Avoid stale CDN caches; the leaderboard changes constantly.
      cache: "no-store",
    });
  } catch {
    return null;
  }
  if (!res.ok) return null;

  let body;
  try { body = await res.json(); }
  catch { return null; }

  // Normalize backend rows to the shape the Hub already renders.
  const entries = (body.entries || []).map((r) => ({
    handle: r.handle,
    total: r.score,
    breaches: r.breaches,
    rating: r.rating,
    survivedMs: r.survived_ms,
    peakSpeed: r.peak_speed,
    you: r.is_you === true,
  }));

  const payload = {
    dateKey: body.date_key,
    entries,
    myRank: body.your_rank ?? null,
    myScore: body.your_score ?? null,
    total: body.total_players ?? entries.length,
    source: "backend",
  };

  writeCache(payload);
  return payload;
}

/**
 * Push the player's arcade run to the backend. Idempotent on retries
 * thanks to the per-day submit_token. Returns:
 *   { ok: true,  accepted, your_rank, your_score, total_players, label }
 *   { ok: false, error: "..." }                   on validation failure
 *   { ok: false, error: "network" }               on network error
 *
 * `result` is the arcade ShiftReport-shaped object built by Arcade.jsx.
 */
export async function submitArcadeScore({ result, handle, dateKey = todayKey() }) {
  const cleanedHandle = setHandle(handle);
  if (!cleanedHandle || cleanedHandle.length < 2) {
    return { ok: false, error: "invalid handle" };
  }

  const submitToken = freshSubmitToken();

  const body = {
    handle: cleanedHandle,
    date_key: dateKey,
    score: Math.max(0, Math.round(result.total ?? 0)),
    survived_ms: Math.max(0, Math.round(result._arcadeSurvivedMs ?? 0)),
    breaches: Math.max(0, result.counts?.breaches ?? 0),
    peak_speed: Math.max(1.0, Number(result._arcadePeakSpeed ?? 1.0)),
    rating: result.rating || "ROOKIE",
    submit_token: submitToken,
  };

  let res;
  try {
    res = await fetch(`${API_BASE}${LB_PATH}/submit`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    return { ok: false, error: "network" };
  }

  if (!res.ok) {
    let detail = `http_${res.status}`;
    try { const j = await res.json(); if (j?.detail) detail = String(j.detail); } catch {}
    return { ok: false, error: detail };
  }

  let resp;
  try { resp = await res.json(); }
  catch { return { ok: false, error: "bad-response" }; }

  // Mirror the result locally so hasPlayedToday/todayResult work.
  const subs = readSubmissions();
  subs[dateKey] = {
    handle: cleanedHandle,
    total: resp.your_score,
    breaches: body.breaches,
    rating: body.rating,
    survivedMs: body.survived_ms,
    peakSpeed: body.peak_speed,
    submittedAt: Date.now(),
    rank: resp.your_rank,
  };
  writeSubmissions(subs);

  return {
    ok: true,
    accepted: resp.accepted,
    your_rank: resp.your_rank,
    your_score: resp.your_score,
    total_players: resp.total_players,
    label: resp.label,
    note: resp.note,
  };
}

// ─── Seeded leaderboard (fallback only) ──────────────────────────────
//
// The seeded list is now strictly a fallback. It still seeds-by-date so
// the page never paints empty, but it's overwritten as soon as the
// backend fetch returns. Handles preserved verbatim from prior version.

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
  for (let i = handles.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [handles[i], handles[j]] = [handles[j], handles[i]];
  }

  const entries = [];
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

// ─── Synchronous getter ──────────────────────────────────────────────
//
// Returns immediately with the cached backend payload (if fresh enough),
// otherwise falls back to seeded. This is what the Hub uses on first
// render — followed by a fetchDailyLeaderboard() that swaps in fresh
// data once it returns.

export function getDailyLeaderboard(dateKey = todayKey()) {
  // 1. Cached backend data, if same day.
  const cache = readCache();
  if (cache && cache.dateKey === dateKey && Array.isArray(cache.entries)) {
    return {
      entries: cache.entries,
      myRank: cache.myRank ?? null,
      myScore: cache.myScore ?? null,
      total: cache.total ?? cache.entries.length,
      source: "cache",
    };
  }

  // 2. Local submission (player just finished a run), merged into seeded
  //    so they see themselves immediately even if backend hasn't returned.
  const seeded = getSeededLeaderboard(dateKey);
  const me = todayResult(dateKey);
  if (!me) {
    return { entries: seeded, myRank: null, total: seeded.length, source: "seeded" };
  }

  const merged = [...seeded, { ...me, you: true }].sort((a, b) => b.total - a.total);
  const myRank = merged.findIndex((e) => e.you) + 1;
  return { entries: merged, myRank, total: merged.length, source: "seeded+local" };
}

/** Persist the player's daily result locally. Used by ShiftReport before
 *  the backend submit returns, so the leaderboard has an immediate
 *  optimistic entry. The backend submit later overwrites with the
 *  authoritative row.
 *
 *  Better-write-wins: matches backend semantics. If the player already
 *  played today and posts a higher score, the local mirror updates so
 *  the seeded+local fallback path doesn't display a stale lower score.
 */
export function submitDailyScore({ score, handle, dateKey = todayKey() }) {
  const subs = readSubmissions();
  const incoming = {
    handle: handle || "anonymous",
    total: score.total,
    accuracy: score.accuracy,
    breaches: score.counts?.breaches ?? 0,
    rating: score.rating,
    avgResponseMs: score.avgResponseMs,
    submittedAt: Date.now(),
  };
  const existing = subs[dateKey];
  if (existing && (existing.total ?? 0) >= (incoming.total ?? 0)) {
    return existing;
  }
  subs[dateKey] = incoming;
  writeSubmissions(subs);
  return incoming;
}
