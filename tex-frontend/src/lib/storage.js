// ────────────────────────────────────────────────────────────────────────
//  TEX ARENA — Player storage (v3 — arcade edition)
// ────────────────────────────────────────────────────────────────────────
//  localStorage. Per-round records so failure still produces progress.
//  "bestScore" for each round = highest permit-proximity ever — this is
//  the near-miss meter that makes ABSTAIN feel productive, not terminal.
// ────────────────────────────────────────────────────────────────────────

const KEY_PLAYER = "tex-arena/player/v3";

// ────────────────────────────────────────────────────────────────────────
//  RANKS (v5) — now carry cosmetic metadata consumed by FighterCard.
//  Each tier unlocks a visible frame upgrade. Pure vanity; zero cost to us;
//  high perceived value to the player.
// ────────────────────────────────────────────────────────────────────────
export const RANKS = [
  {
    min: 0,    name: "ROOKIE",      tier: 1,
    color: "var(--color-ink-dim)",
    blurb: "Your first steps. Learn Tex's tells.",
  },
  {
    min: 40,   name: "CONTENDER",   tier: 2,
    color: "var(--color-cyan)",
    blurb: "Cyan frame unlocked. You're on the board.",
  },
  {
    min: 120,  name: "CHALLENGER",  tier: 3,
    color: "var(--color-violet)",
    blurb: "Violet frame unlocked. You know the mechanics.",
  },
  {
    min: 240,  name: "HEADLINER",   tier: 4,
    color: "var(--color-pink)",
    blurb: "Pink glow unlocked. Tex has seen you twice.",
  },
  {
    min: 400,  name: "TITLEHOLDER", tier: 5,
    color: "var(--color-yellow)",
    blurb: "Gold frame unlocked. Top-tier red teamer.",
  },
  {
    min: 600,  name: "LEGEND",      tier: 6,
    color: "var(--color-yellow)",
    blurb: "Legend frame unlocked. Hall of Fame worthy.",
  },
];

function safeParse(raw) {
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

function defaultPlayer() {
  return {
    handle: "",
    totalPoints: 0,
    streak: 0,
    bestStreak: 0,
    roundsWon: [],
    attackCount: 0,
    bypassCount: 0,
    knockouts: 0,
    draws: 0,
    bountyClaimed: false,
    // v4: cumulative count of ASI findings attributed across all of
    // this player's attacks. Drives the hero counter. Also tracks
    // which categories the player has personally seen fire so the
    // share card and hero subline can say "you've triggered 4 of 6".
    asiFindingsCount: 0,
    asiCategoriesSeen: [],
    perRound: {},   // { [roundId]: { attempts, wins, draws, losses, bestScore, lastVerdict } }
    history: [],
  };
}

export function getPlayer() {
  if (typeof localStorage === "undefined") return defaultPlayer();
  const parsed = safeParse(localStorage.getItem(KEY_PLAYER));
  if (!parsed || typeof parsed !== "object") return defaultPlayer();
  const base = defaultPlayer();
  return {
    ...base,
    ...parsed,
    roundsWon: Array.isArray(parsed.roundsWon) ? parsed.roundsWon : [],
    perRound:
      parsed.perRound && typeof parsed.perRound === "object"
        ? parsed.perRound
        : {},
    history: Array.isArray(parsed.history) ? parsed.history.slice(-20) : [],
    asiFindingsCount:
      typeof parsed.asiFindingsCount === "number" ? parsed.asiFindingsCount : 0,
    asiCategoriesSeen: Array.isArray(parsed.asiCategoriesSeen)
      ? parsed.asiCategoriesSeen
      : [],
  };
}

export function savePlayer(player) {
  if (typeof localStorage === "undefined") return;
  try { localStorage.setItem(KEY_PLAYER, JSON.stringify(player)); } catch {}
}

export function resetPlayer() {
  if (typeof localStorage === "undefined") return;
  try { localStorage.removeItem(KEY_PLAYER); } catch {}
}

// ────────────────────────────────────────────────────────────────────────
//  Rank from totalPoints — unlocks happen at threshold crossings.
// ────────────────────────────────────────────────────────────────────────

export function rankForPoints(points) {
  let current = RANKS[0];
  for (const r of RANKS) {
    if (points >= r.min) current = r;
  }
  const idx = RANKS.indexOf(current);
  const next = RANKS[idx + 1] || null;
  return {
    current,
    next,
    // 0..1 progress toward next rank
    progress: next
      ? Math.min(1, Math.max(0, (points - current.min) / (next.min - current.min)))
      : 1,
  };
}

// ────────────────────────────────────────────────────────────────────────
//  "Permit proximity" — how close did a verdict come to PERMIT?
//  This is the near-miss number. 0..1, higher = closer to getting through.
//  Used as the bestScore tracker per round.
//
//  Heuristic: a PERMIT is always 1.0. An ABSTAIN uses confidence of the
//  semantic judge if it leans permit, otherwise (1 - confidence). A FORBID
//  is (1 - final_score) which stays small — but still updates so even a
//  clean loss shows *something*.
// ────────────────────────────────────────────────────────────────────────

export function permitProximity(decision) {
  if (!decision) return 0;
  if (decision.verdict === "PERMIT") return 1;
  const sem = decision.semantic || {};
  if (decision.verdict === "ABSTAIN") {
    // If semantic leaned PERMIT, use that confidence; else inverse of it
    if (sem.recommended_verdict === "PERMIT") return sem.overall_confidence || 0.5;
    return Math.max(0.25, 1 - (sem.overall_confidence || 0.5));
  }
  // FORBID — use inverse of router.final_score so "barely forbid" shows better
  const fs = decision.router?.final_score ?? 1;
  return Math.max(0, Math.min(0.4, 1 - fs));  // cap at 0.4 so FORBID never appears as a near-win
}

// ────────────────────────────────────────────────────────────────────────
//  Record a fight result. Returns new player state (immutable-friendly).
// ────────────────────────────────────────────────────────────────────────

export function recordFightResult(player, { roundId, verdict, points, decision }) {
  const prev = player.perRound?.[roundId] || {
    attempts: 0, wins: 0, draws: 0, losses: 0, bestScore: 0, lastVerdict: null,
  };
  const proximity = permitProximity(decision);

  const next = {
    attempts: prev.attempts + 1,
    wins: prev.wins + (verdict === "PERMIT" ? 1 : 0),
    draws: prev.draws + (verdict === "ABSTAIN" ? 1 : 0),
    losses: prev.losses + (verdict === "FORBID" ? 1 : 0),
    bestScore: Math.max(prev.bestScore, proximity),
    lastVerdict: verdict,
  };

  const newRoundsWon =
    verdict === "PERMIT" && !player.roundsWon.includes(roundId)
      ? [...player.roundsWon, roundId]
      : player.roundsWon;
  const newStreak = verdict === "PERMIT" ? player.streak + 1 : 0;

  // ASI tracking — this is what feeds the hero counter.
  const findings = Array.isArray(decision?.asi_findings)
    ? decision.asi_findings
    : [];
  const findingsCount = findings.length;
  const seenNow = new Set(player.asiCategoriesSeen || []);
  for (const f of findings) {
    if (f?.short_code) seenNow.add(f.short_code);
  }

  return {
    ...player,
    totalPoints: player.totalPoints + points,
    streak: newStreak,
    bestStreak: Math.max(player.bestStreak, newStreak),
    roundsWon: newRoundsWon,
    attackCount: player.attackCount + 1,
    bypassCount: player.bypassCount + (verdict === "PERMIT" ? 1 : 0),
    knockouts: player.knockouts + (verdict === "FORBID" ? 1 : 0),
    draws: player.draws + (verdict === "ABSTAIN" ? 1 : 0),
    asiFindingsCount: (player.asiFindingsCount || 0) + findingsCount,
    asiCategoriesSeen: Array.from(seenNow),
    perRound: {
      ...(player.perRound || {}),
      [roundId]: next,
    },
    history: [
      ...(player.history || []).slice(-19),
      { roundId, verdict, points, ts: Date.now() },
    ],
  };
}

export function claimBounty(player) {
  return { ...player, bountyClaimed: true };
}

// Total fights across all rounds, used for record W-L-D display
export function totalRecord(player) {
  return {
    W: player.bypassCount || 0,
    L: player.knockouts || 0,
    D: player.draws || 0,
    total: player.attackCount || 0,
  };
}
