// ────────────────────────────────────────────────────────────────────────
//  rounds.js — v6 compat shim
// ────────────────────────────────────────────────────────────────────────
//  The game itself has moved to the "Interrogation" model in cases.js.
//  This file stays as a thin re-export so BuyerSurface and BountyClaim
//  (which share ASI + policy constants with the arena) don't need to
//  know about the reshuffle.
// ────────────────────────────────────────────────────────────────────────

export { ASI_DISPLAY, ASI_INFLUENCE_STYLE, BOUNTY_CASE_ID } from "./cases.js";

// Policy versions — unchanged from v5
export const POLICY_VERSION = "default-v1";
export const STRICT_POLICY_VERSION = "strict-v1";

// ASI coverage counts — used by BuyerSurface's coverage chips
export const ASI_COVERED_COUNT = 6;
export const ASI_TOTAL_COUNT = 10;

// Symbolic bounty ladder — unchanged from v5 for BountyClaim
export const SYMBOLIC_BOUNTY_LADDER = [1, 2, 4, 8, 16, 32, 64];
export function symbolicBountyAmount(claimersSoFar = 0) {
  const idx = Math.min(claimersSoFar, SYMBOLIC_BOUNTY_LADDER.length - 1);
  return SYMBOLIC_BOUNTY_LADDER[idx];
}
