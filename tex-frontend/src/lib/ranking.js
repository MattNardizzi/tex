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

// Seeded leaderboard. NOBODY is UNDEFEATED (2500+) — that's Tex's bounty slot.
// All seeds cap at 2499 (Chief/Sr Investigator). Top rank slot stays empty
// as the dangling carrot: "beat Tex, take the throne."
const SEED_LEADERBOARD = [
  { handle: "redteam_raj",        rp: 2420, region: "US", streak: 14 },
  { handle: "nightowl_ciso",      rp: 2195, region: "EU", streak: 9 },
  { handle: "breachhunter",       rp: 2048, region: "US", streak: 7 },
  { handle: "sara.infosec",       rp: 1892, region: "IN", streak: 5 },
  { handle: "detectiveXplorer",   rp: 1710, region: "CA", streak: 4 },
  { handle: "bypass_betty",       rp: 1588, region: "UK", streak: 3 },
  { handle: "0xghostrider",       rp: 1442, region: "DE", streak: 8 },
  { handle: "blueteam_ben",       rp: 1310, region: "AU", streak: 2 },
  { handle: "pkts_in_flight",     rp: 1180, region: "US", streak: 6 },
  { handle: "caf3ineCorrupted",   rp: 1047, region: "BR", streak: 2 },
  { handle: "jane.a.ops",         rp: 968,  region: "US", streak: 4 },
  { handle: "h4x_on_call",        rp: 842,  region: "SG", streak: 3 },
  { handle: "promptwhisperer",    rp: 730,  region: "NL", streak: 2 },
  { handle: "aegis_anon",         rp: 611,  region: "US", streak: 1 },
  { handle: "fuzzyFaith",         rp: 488,  region: "JP", streak: 1 },
];

/**
 * Returns a leaderboard slice with the player inserted at the correct rank.
 * The TOP of the board is always an empty "throne" row — because nobody
 * has beaten Tex yet. That empty slot is the dangling carrot.
 *
 * Ranks: #1 throne (empty) → #2+ everyone else.
 */
export function leaderboardWithPlayer(player) {
  const playerEntry = {
    handle: player.handle || "anonymous",
    rp: player.rp || 0,
    region: "—",
    streak: player.streak || 0,
    isYou: true,
  };
  const throne = { isThrone: true, handle: "— UNCLAIMED —", rp: null };

  const sorted = [...SEED_LEADERBOARD, playerEntry]
    .sort((a, b) => b.rp - a.rp);

  // Throne is always rank #1. Everyone else starts at #2.
  const ranked = [
    { ...throne, rank: 1 },
    ...sorted.map((e, i) => ({ ...e, rank: i + 2 })),
  ];

  const you = ranked.find((e) => e.isYou);
  const yourRank = you.rank;
  const youIndex = ranked.indexOf(you);

  let window = [];
  if (yourRank <= 4) {
    window = ranked.slice(0, 6);
  } else {
    const top3 = ranked.slice(0, 4); // throne + top 3
    const above = ranked[youIndex - 1];
    const below = ranked[youIndex + 1];
    window = [
      ...top3,
      { divider: true },
      ...(above ? [above] : []),
      you,
      ...(below ? [below] : []),
    ];
  }
  return { list: window, yourRank, total: ranked.length };
}

export function globalStats() {
  // Static-ish flavor stats. Deliberately small bypass count — it's the hook.
  // texRecord is ∞–0–0 (zero anyone has ever beaten him).
  return {
    attemptsToday: 4847 + Math.floor(Math.random() * 200),
    bypassesToday: 0,
    texRecord: "∞–0–0",
  };
}
