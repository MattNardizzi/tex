// ────────────────────────────────────────────────────────────────────
//  Daily shift — deterministic stream selection
//  ────────────────────────────────────────────────────────────────────
//  Every player on the same UTC day gets the same stream. Resets at
//  00:00 UTC. The seed is the date string, which feeds a tiny PRNG
//  that picks and orders ~32 messages with difficulty ramping:
//
//    seconds 0–37    → mostly tier 1  (14 cards)
//    seconds 37–65   → tier 1 + tier 2 mix (10 cards)
//    seconds 65–90   → tier 2 + tier 3 mix (8 cards)
//
//  The conveyor speed also ramps; speed lives in the Game component,
//  but the message stream alone produces enough variety on its own.
// ────────────────────────────────────────────────────────────────────

import { TIER_1, TIER_2, TIER_3, MESSAGES } from "./messages.js";

export const SHIFT_SECONDS = 90;
export const STREAM_LENGTH = 32; // messages dispatched across the shift

/** UTC date string like "2026-04-27" — used as the daily seed. */
export function todayKey(d = new Date()) {
  const yyyy = d.getUTCFullYear();
  const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(d.getUTCDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}

/** Tiny string-seeded PRNG (mulberry32 over hashed seed). */
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

function pickN(rng, pool, n) {
  // Sample without replacement.
  const arr = pool.slice();
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.slice(0, n);
}

/**
 * Build the daily stream — array of message objects in dispatch order.
 * The first ~third skews tier 1, the middle mixes tier 1+2, the last
 * third mixes tier 2+3. Within each segment messages are shuffled.
 */
export function buildDailyStream(dateKey = todayKey()) {
  const rng = mulberry32(hashString(dateKey));

  const seg1 = pickN(rng, TIER_1, 14); // 14 obvious to start (was 12 — eases the 50-60s spike)
  const seg2Mix = [
    ...pickN(rng, TIER_1, 4),
    ...pickN(rng, TIER_2, 6),
  ];
  const seg3Mix = [
    ...pickN(rng, TIER_2, 4),
    ...pickN(rng, TIER_3, 4),
  ];

  // Shuffle each segment independently using the same rng so the
  // stream still varies by day but maintains difficulty progression.
  function shuffle(arr) {
    const a = arr.slice();
    for (let i = a.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  }

  const stream = [...shuffle(seg1), ...shuffle(seg2Mix), ...shuffle(seg3Mix)];
  return stream.slice(0, STREAM_LENGTH);
}

/**
 * Dispatch schedule — when each message enters the conveyor.
 * Speed ramps: dwellMs decreases as the shift progresses.
 *
 * Returns: [{ message, enterAtMs, dwellMs }]
 *  - enterAtMs: when the card appears at the left edge
 *  - dwellMs:   how long it takes to traverse to the gate
 *
 * Cards must be fully dispatched + cleared by SHIFT_SECONDS, so we
 * target the last card to ENTER no later than (totalMs - lastDwell - 500ms)
 * so the final card has time to traverse and resolve before time-up.
 */
export function buildSchedule(stream) {
  const out = [];
  const totalMs = SHIFT_SECONDS * 1000;
  const n = stream.length;

  // Reserve time at the end for the last card to traverse to the gate.
  // Last-tier dwell is 4500ms; we add a 500ms safety margin.
  const lastSpawnDeadline = totalMs - 4500 - 500; // = 85,000ms

  // Even spread of spawn windows across the dispatch budget.
  // First card spawns at ~600ms; last at lastSpawnDeadline.
  const firstSpawn = 600;
  const span = lastSpawnDeadline - firstSpawn;

  for (let i = 0; i < n; i++) {
    const progress = n === 1 ? 0 : i / (n - 1);

    // Linear spread + a small jitter that scales with progress
    // (later cards arrive a touch faster, but we don't compress them).
    const enterAtMs = Math.round(firstSpawn + span * progress);

    // Dwell ramps by progress. Tuned to 4 steps (was 3) so the 50-60s
    // window — which is right where players were complaining of a
    // sudden difficulty spike — sits at 6000ms instead of 5500ms.
    const dwellMs =
      progress < 0.30 ? 6500 :
      progress < 0.55 ? 6000 :
      progress < 0.80 ? 5000 :
                        4500;

    out.push({ message: stream[i], enterAtMs, dwellMs, index: i });
  }
  return out;
}

/** Convenience — used by Game on mount. */
export function dailySchedule(dateKey = todayKey()) {
  return buildSchedule(buildDailyStream(dateKey));
}

/** Practice mode — seeded by Date.now() so each session is fresh. */
export function practiceSchedule() {
  const seed = `practice-${Date.now()}-${Math.random()}`;
  return buildSchedule(buildDailyStream(seed));
}

/** ms until next UTC midnight — used for the countdown on the Hub. */
export function msUntilNextShift() {
  const now = new Date();
  const next = new Date(Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate() + 1,
    0, 0, 0, 0,
  ));
  return next.getTime() - now.getTime();
}

export function formatCountdown(ms) {
  const total = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}
