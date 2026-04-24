// ────────────────────────────────────────────────────────────────────────
//  TEX ARENA — Scoring (v6 "Interrogation")
// ────────────────────────────────────────────────────────────────────────
//  DESIGN PRINCIPLE
//  ────────────────
//  Every number on screen must be traceable to a simple rule. No opaque
//  multipliers. If the player can't predict their score from what they
//  just did, the scoring isn't teaching — it's confusing.
//
//  SCORING TABLE (player sees this BEFORE they play, above the fold)
//  ──────────────────────────────────────────────────────────────────
//  FORBID   → catch speed × difficulty × streak
//  ABSTAIN  → 40% of FORBID score (Tex escalated — partial credit)
//  PERMIT   → 0   (the agent got through — Tex didn't catch it, neither did you)
//
//  CATCH SPEED (ms-based, rewards fast catches)
//  ──────────────────────────────────────────────
//  Tex usually fires in <200ms. We cap the curve so the difference
//  between 10ms and 200ms is meaningful but not brutal. The real
//  variance is question count — catching in 1 question scores way
//  more than catching in 3.
//
//  QUESTION EFFICIENCY (the secondary dial)
//  ──────────────────────────────────────────
//  Used 1 question to catch → 3x efficiency bonus
//  Used 2 questions          → 1.5x
//  Used 3 questions          → 1x
//  Player sees this. It's the difference between a 2,400-point run
//  and an 800-point run on the same case, and it creates the
//  "can I catch it on Q1" adrenaline spike.
// ────────────────────────────────────────────────────────────────────────

export const PERMIT_SCORE = 0;
export const ABSTAIN_CREDIT = 0.4;

// Catch speed curve: 1000 at 0ms, 100 at 1000ms, floor at 50.
// Simple, predictable, caps the extremes so network jitter doesn't dominate.
export function catchSpeedPoints(ms) {
  if (!Number.isFinite(ms) || ms < 0) return 100;
  const raw = Math.round(1000 - ms * 0.9);
  return Math.max(50, Math.min(1000, raw));
}

export function questionEfficiencyMultiplier(questionsUsed) {
  if (questionsUsed <= 1) return 3;
  if (questionsUsed === 2) return 1.5;
  return 1;
}

export function streakMultiplier(streakDays) {
  if (streakDays >= 7) return 2;
  if (streakDays >= 3) return 1.5;
  if (streakDays >= 1) return 1.2;
  return 1;
}

// Main entry. Returns the full breakdown so the VerdictMoment can show
// the full math — that transparency is what makes the scoring feel fair.
export function computeCaseScore({
  verdict,
  catchMs,
  caseDifficulty = 1,
  questionsUsed = 1,
  streakDays = 0,
}) {
  if (verdict === "PERMIT") {
    return {
      verdict,
      total: 0,
      breakdown: {
        base: 0,
        difficulty: caseDifficulty,
        efficiency: 1,
        streak: 1,
        credit: 1,
      },
      message: "The agent got through. Tex didn't catch it.",
    };
  }

  const base = catchSpeedPoints(catchMs);
  const efficiency = questionEfficiencyMultiplier(questionsUsed);
  const streak = streakMultiplier(streakDays);
  const credit = verdict === "ABSTAIN" ? ABSTAIN_CREDIT : 1;

  const total = Math.round(base * caseDifficulty * efficiency * streak * credit);

  return {
    verdict,
    total,
    breakdown: {
      base,
      difficulty: caseDifficulty,
      efficiency,
      streak,
      credit,
    },
    message:
      verdict === "FORBID"
        ? `Tex blocked it in ${catchMs}ms. Case closed.`
        : `Tex escalated for review. You made it sweat.`,
  };
}

// ────────────────────────────────────────────────────────────────────────
//  Rank ladder — same names you already ship, tuned for new score range.
//  At 1x all multipliers, a clean Case 1 FORBID is ~900 pts, Case 7 is ~6,300.
//  A perfect 7-case run with streak is ~40,000. Ranks sit on that curve.
// ────────────────────────────────────────────────────────────────────────

export const RANKS = [
  { min: 0,      name: "ROOKIE",      tier: 1, color: "var(--color-ink-dim)",
    blurb: "First day on the job. Learn the board." },
  { min: 1000,   name: "CONTENDER",   tier: 2, color: "var(--color-cyan)",
    blurb: "Cyan frame unlocked. You're on the board." },
  { min: 4000,   name: "INVESTIGATOR",tier: 3, color: "var(--color-violet)",
    blurb: "Violet frame unlocked. You think like Tex." },
  { min: 10000,  name: "INSPECTOR",   tier: 4, color: "var(--color-pink)",
    blurb: "Pink glow unlocked. The agents are afraid of you." },
  { min: 20000,  name: "CHIEF",       tier: 5, color: "var(--color-yellow)",
    blurb: "Gold frame unlocked. You run the floor." },
  { min: 35000,  name: "LEGEND",      tier: 6, color: "var(--color-yellow)",
    blurb: "Legend. Hall of Fame worthy." },
];

export function rankForPoints(points) {
  let current = RANKS[0];
  let next = RANKS[1] || null;
  for (let i = 0; i < RANKS.length; i++) {
    if (points >= RANKS[i].min) {
      current = RANKS[i];
      next = RANKS[i + 1] || null;
    }
  }
  const progressToNext = next
    ? Math.min(1, (points - current.min) / (next.min - current.min))
    : 1;
  return { current, next, progressToNext };
}
