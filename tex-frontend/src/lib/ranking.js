// ────────────────────────────────────────────────────────────────────
//  Ranking — tiers, RP math, seeded leaderboard
//
//  In this mode the PLAYER is attacking Tex. Scoring rewards:
//    - PERMIT (player wins cleanly — Tex let it through): big RP
//    - ABSTAIN (close — Tex escalated but didn't block): small RP
//    - FORBID (Tex caught it): RP loss
//    - Timeout/3 forbids: full RP loss
//
//  Why does winning require beating Tex?
//  Because in a red-team game, success = bypass. The game proves Tex
//  is hard to beat. Every loss is content the backend blocked live —
//  which IS the product demo. The few who win = real signal for you.
// ────────────────────────────────────────────────────────────────────

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
 * RP awarded / lost for a round outcome.
 * Player is attacking Tex. Winning = getting past Tex.
 */
export function rpForOutcome({ verdict, attemptsUsed, secondsLeft, incidentDifficulty = 2 }) {
  if (verdict === "PERMIT") {
    // Player BEAT Tex — slip past the gate. Big reward.
    const base = 120;
    const speed = Math.round((secondsLeft || 0) * 0.8); // up to ~48
    const efficiency = attemptsUsed <= 1 ? 40 : attemptsUsed === 2 ? 20 : 0;
    const diff = incidentDifficulty * 10;
    return { delta: base + speed + efficiency + diff, label: "BYPASS", tone: "win" };
  }
  if (verdict === "ABSTAIN") {
    // Tex escalated — player got close. Small reward.
    return { delta: 20 + incidentDifficulty * 4, label: "NEAR MISS", tone: "partial" };
  }
  // FORBID or timeout — Tex won. Player loses RP.
  return { delta: -25, label: "BLOCKED BY TEX", tone: "loss" };
}

// ────────────────────────────────────────────────────────────────────
//  Seeded leaderboard — hardcoded for v1. Replace with backend call later.
// ────────────────────────────────────────────────────────────────────

const SEED_LEADERBOARD = [
  { handle: "redteam_raj",        rp: 3840, region: "US", streak: 14 },
  { handle: "nightowl_ciso",      rp: 3210, region: "EU", streak: 9 },
  { handle: "breachhunter",       rp: 2965, region: "US", streak: 7 },
  { handle: "sara.infosec",       rp: 2702, region: "IN", streak: 5 },
  { handle: "detectiveXplorer",   rp: 2540, region: "CA", streak: 4 },
  { handle: "bypass_betty",       rp: 2380, region: "UK", streak: 3 },
  { handle: "0xghostrider",       rp: 2201, region: "DE", streak: 8 },
  { handle: "blueteam_ben",       rp: 2048, region: "AU", streak: 2 },
  { handle: "pkts_in_flight",     rp: 1890, region: "US", streak: 6 },
  { handle: "caf3ineCorrupted",   rp: 1754, region: "BR", streak: 2 },
  { handle: "jane.a.ops",         rp: 1602, region: "US", streak: 4 },
  { handle: "h4x_on_call",        rp: 1488, region: "SG", streak: 3 },
  { handle: "promptwhisperer",    rp: 1370, region: "NL", streak: 2 },
  { handle: "aegis_anon",         rp: 1245, region: "US", streak: 1 },
  { handle: "fuzzyFaith",         rp: 1120, region: "JP", streak: 1 },
];

/**
 * Returns a leaderboard slice with the player inserted at the correct rank.
 * Top N above, player highlighted, and N below.
 */
export function leaderboardWithPlayer(player) {
  const playerEntry = {
    handle: player.handle || "anonymous",
    rp: player.rp || 0,
    region: "—",
    streak: player.streak || 0,
    isYou: true,
  };
  const all = [...SEED_LEADERBOARD, playerEntry]
    .sort((a, b) => b.rp - a.rp)
    .map((e, i) => ({ ...e, rank: i + 1 }));

  const you = all.find((e) => e.isYou);
  const top = all.slice(0, 3);
  const yourRank = you.rank;
  const youIndex = all.indexOf(you);

  // Show top 3, then "...", then player + 1 above / 1 below if applicable
  let window = [];
  if (yourRank <= 3) {
    window = all.slice(0, 5);
  } else {
    const above = all[youIndex - 1];
    const below = all[youIndex + 1];
    window = [...top, { divider: true }, ...(above ? [above] : []), you, ...(below ? [below] : [])];
  }
  return { list: window, yourRank, total: all.length };
}

export function globalStats() {
  // Static-ish flavor stats for the hero. In production these come from backend.
  return {
    attemptsToday: 4847 + Math.floor(Math.random() * 200),
    bypassesToday: 3,   // Very few. This is the point.
    texRecord: "∞–0–3",
  };
}
