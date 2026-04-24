// ────────────────────────────────────────────────────────────────────────
//  TEX ARENA — Scoring + Clearance Tiers (v7)
// ────────────────────────────────────────────────────────────────────────
//  DESIGN PRINCIPLE
//  Every number on screen traceable to a rule. No hidden multipliers.
//
//  SCORING
//    FORBID  → base × difficulty × efficiency × streak
//    ABSTAIN → 40% of FORBID
//    PERMIT  → 0
//
//  Base = 1000 - (catchMs × 0.9), clamped 50..1000. Fast catches
//  are rewarded but network jitter can't dominate the score.
//
//  Efficiency = 3× (Q1 catch), 1.5× (Q2), 1× (Q3). This is the dial
//  that separates "got lucky" from "read the agent."
//
//  CLEARANCE TIERS — named to feel like real security clearance
//  levels, not video game ranks. The reward is *identity*.
//    TRAINEE       — just started
//    ANALYST       — cleared first case
//    INVESTIGATOR  — cleared 3 cases
//    SR INVESTIGATOR — cleared 5 cases
//    CHIEF         — cleared all 7 (Warden doesn't need to be beat)
//    WARDEN HUNTER — cleared 6 + attempted Warden
//    UNDEFEATED    — caught the Warden
// ────────────────────────────────────────────────────────────────────────

export const PERMIT_SCORE = 0;
export const ABSTAIN_CREDIT = 0.4;

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
      breakdown: { base: 0, difficulty: caseDifficulty, efficiency: 1, streak: 1, credit: 1 },
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
    breakdown: { base, difficulty: caseDifficulty, efficiency, streak, credit },
    message: verdict === "FORBID"
      ? `Tex blocked it in ${catchMs}ms. Case closed.`
      : "Tex escalated for review. You made it sweat.",
  };
}

// ────────────────────────────────────────────────────────────────────────
//  CLEARANCE TIERS
//  Driven by cases cleared, not by points. This is the "play for what"
//  answer — a named clearance level that reads as real on a resume.
// ────────────────────────────────────────────────────────────────────────

export const CLEARANCE_TIERS = [
  { min: 0, name: "TRAINEE",
    short: "T0",
    color: "var(--color-ink-dim)",
    glowColor: "rgba(184, 188, 224, 0.4)",
    blurb: "Just walked in. No cases on record.",
    unlockCopy: "Clear Case 001 to become an ANALYST." },
  { min: 1, name: "ANALYST",
    short: "T1",
    color: "var(--color-cyan)",
    glowColor: "rgba(95, 240, 255, 0.5)",
    blurb: "You've caught your first agent.",
    unlockCopy: "Clear 2 more cases to become an INVESTIGATOR." },
  { min: 3, name: "INVESTIGATOR",
    short: "T2",
    color: "var(--color-violet)",
    glowColor: "rgba(168, 85, 247, 0.5)",
    blurb: "Pattern recognition kicking in.",
    unlockCopy: "Clear 2 more cases to make SR. INVESTIGATOR." },
  { min: 5, name: "SR. INVESTIGATOR",
    short: "T3",
    color: "var(--color-pink)",
    glowColor: "rgba(255, 61, 122, 0.55)",
    blurb: "Agents know your name.",
    unlockCopy: "Clear all 7 to make CHIEF." },
  { min: 7, name: "CHIEF",
    short: "T4",
    color: "var(--color-yellow)",
    glowColor: "rgba(255, 225, 74, 0.6)",
    blurb: "Every case, closed. The Warden is still standing.",
    unlockCopy: "Beat The Warden to become UNDEFEATED." },
  { min: 99, name: "UNDEFEATED",
    short: "T5",
    color: "var(--color-yellow)",
    glowColor: "rgba(255, 225, 74, 0.75)",
    blurb: "You cracked The Warden. Hall of Fame.",
    unlockCopy: "" },
];

export function tierFor(clearedCount, bountyCaught) {
  // Bounty win promotes you past CHIEF regardless of count
  if (bountyCaught) return CLEARANCE_TIERS[5];
  let current = CLEARANCE_TIERS[0];
  let next = CLEARANCE_TIERS[1] || null;
  for (let i = 0; i < CLEARANCE_TIERS.length; i++) {
    if (clearedCount >= CLEARANCE_TIERS[i].min) {
      current = CLEARANCE_TIERS[i];
      next = CLEARANCE_TIERS[i + 1] || null;
    }
  }
  return { current, next, clearedCount };
}

// Legacy export for components still using the old name
export function rankForPoints(points) {
  // For backwards compat only — not used in the new flow
  return {
    current: CLEARANCE_TIERS[0],
    next: CLEARANCE_TIERS[1],
    progressToNext: 0,
  };
}

export const RANKS = CLEARANCE_TIERS; // back-compat alias
