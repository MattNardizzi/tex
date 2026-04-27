// ────────────────────────────────────────────────────────────────────
//  Ranking — tiers, RP math, real leaderboard with seeded fallback.
// ────────────────────────────────────────────────────────────────────

import { fetchLeaderboard } from "./leaderboardClient.js";

export const TIERS = [
  { min: 0,    name: "RECRUIT",       short: "T0", color: "#6B6F8F" },
  { min: 100,  name: "ANALYST",       short: "T1", color: "#5FF0FF" },
  { min: 400,  name: "INVESTIGATOR",  short: "T2", color: "#B388FF" },
  { min: 900,  name: "SR INVESTIGATOR", short: "T3", color: "#FF3D7A" },
  { min: 1600, name: "CHIEF",         short: "T4", color: "#FFE14A" },
  { min: 2500, name: "UNDEFEATED",    short: "T5", color: "#5FFA9F" },
];

export function tierFor(rp) {
  let current = TIERS[0];
  let next = TIERS[1] || null;
  for (let i = 0; i < TIERS.length; i++) {
    if (rp >= TIERS[i].min) {
      current = TIERS[i];
      next = TIERS[i + 1] || null;
    }
  }
  return { current, next, rp };
}

/**
 * Local RP estimate (used while waiting for the server response, and as a
 * fallback if the leaderboard API is down). The server is authoritative.
 */
export function rpForOutcome({ verdict, attemptsUsed, secondsLeft, incidentDifficulty = 2 }) {
  if (verdict === "PERMIT") {
    const base = 120;
    const speed = Math.round((secondsLeft || 0) * 0.8);
    const efficiency = attemptsUsed <= 1 ? 40 : attemptsUsed === 2 ? 20 : 0;
    const diff = incidentDifficulty * 10;
    return { delta: base + speed + efficiency + diff, label: "BYPASS", tone: "win" };
  }
  if (verdict === "ABSTAIN") {
    return { delta: 20 + incidentDifficulty * 4, label: "NEAR MISS", tone: "partial" };
  }
  return { delta: -25, label: "BLOCKED BY TEX", tone: "loss" };
}

// ────────────────────────────────────────────────────────────────────
//  Seeded fallback — only used if the leaderboard API is unreachable.
//  Keeps the page from looking broken in dev / API outages.
// ────────────────────────────────────────────────────────────────────
const SEED_FALLBACK = [
  { handle: "redteam_raj",    rp: 2420 },
  { handle: "nightowl_ciso",  rp: 2195 },
  { handle: "breachhunter",   rp: 2048 },
  { handle: "sara.infosec",   rp: 1892 },
  { handle: "fuzzyFaith",     rp: 488  },
];

/**
 * Fetch leaderboard from backend. Returns the same shape your old
 * leaderboardWithPlayer() returned, so the Hub component is unchanged.
 */
export async function fetchLeaderboardWithPlayer(player) {
  const handle = (player.handle || "").trim() || null;

  let data = null;
  try {
    data = await fetchLeaderboard(handle);
  } catch {
    // API down → use seeded fallback
    return _buildFromSeed(player);
  }

  const throne = { isThrone: true, handle: "— UNCLAIMED —", rp: null, rank: 1 };

  // Real entries from backend, shifted by 1 because throne is rank #1.
  const realEntries = (data.entries || []).map((e, i) => ({
    handle: e.handle,
    rp: e.rp,
    rank: i + 2,
    isYou: handle && e.handle === handle,
  }));

  // If the player has played but isn't in top-50, append them.
  let you = realEntries.find((e) => e.isYou);
  const yourRankFromApi = data.your_rank ? data.your_rank + 1 : null; // shift for throne

  if (!you && handle && (data.your_rp != null || (player.rp || 0) > 0)) {
    const youRP = data.your_rp != null ? data.your_rp : (player.rp || 0);
    you = {
      handle,
      rp: youRP,
      rank: yourRankFromApi || (realEntries.length + 2),
      isYou: true,
    };
  }

  // Build window: throne + top 3 + (... + above + you + below) when player out of view.
  const allRanked = [throne, ...realEntries];
  const yourRank = you ? you.rank : null;

  let window;
  if (!you || yourRank <= 4) {
    window = allRanked.slice(0, 6);
  } else {
    const top4 = allRanked.slice(0, 4); // throne + top 3
    const youIdx = realEntries.findIndex((e) => e.isYou);
    const above = youIdx > 0 ? realEntries[youIdx - 1] : null;
    const below = youIdx >= 0 && youIdx < realEntries.length - 1 ? realEntries[youIdx + 1] : null;
    window = [
      ...top4,
      { divider: true },
      ...(above ? [above] : []),
      you,
      ...(below ? [below] : []),
    ];
  }

  // Total = real players + 1 throne (we don't show throne in count).
  const total = (data.total_players || realEntries.length) + 1;

  return { list: window, yourRank, total };
}

/** Synchronous shape used during initial render before fetch resolves. */
export function emptyLeaderboard(player) {
  const throne = { isThrone: true, handle: "— UNCLAIMED —", rp: null, rank: 1 };
  const handle = (player.handle || "").trim() || "anonymous";
  const you = {
    handle,
    rp: player.rp || 0,
    rank: 2,
    isYou: true,
  };
  return { list: [throne, you], yourRank: 2, total: 2 };
}

function _buildFromSeed(player) {
  const handle = (player.handle || "anonymous").trim();
  const rp = player.rp || 0;
  const throne = { isThrone: true, handle: "— UNCLAIMED —", rp: null, rank: 1 };
  const merged = [...SEED_FALLBACK, { handle, rp, isYou: true }]
    .sort((a, b) => b.rp - a.rp)
    .map((e, i) => ({ ...e, rank: i + 2 }));
  const you = merged.find((e) => e.isYou);
  return {
    list: [throne, ...merged].slice(0, 6),
    yourRank: you ? you.rank : null,
    total: merged.length + 1,
  };
}

export function globalStats() {
  // These are factual claims about Tex's current state, not live metrics.
  // bypassesToday stays 0 until the leaderboard backend records a PERMIT round.
  // texRecord reflects the current undefeated state.
  return {
    bypassesToday: 0,
    texRecord: "UNDEFEATED",
  };
}
