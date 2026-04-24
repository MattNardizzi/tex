// ────────────────────────────────────────────────────────────────────────
//  TEX ARENA — Progression
// ────────────────────────────────────────────────────────────────────────
//  RULES
//  ─────
//  • Case 1 is always unlocked.
//  • Case N is unlocked iff Case N-1 has been cleared.
//  • A case is "cleared" when the player got a FORBID or ABSTAIN on any
//    of their question turns within that case's session.
//  • PERMITs don't clear a case. The player can retry as many times as
//    they want until they clear it.
//  • Cases can be replayed after clearing, but only for score. The
//    ladder itself only goes forward.
// ────────────────────────────────────────────────────────────────────────

import { CASES } from "./cases.js";

/**
 * Given a player's cleared-case set, return an array with per-case
 * status: "cleared" | "current" | "locked".
 * Exactly one case is "current" (the next one to play), unless all
 * seven are cleared, in which case the last one is "current" (replay).
 */
export function buildLadder(clearedCaseIds = []) {
  const cleared = new Set(clearedCaseIds);
  let currentAssigned = false;

  return CASES.map((c) => {
    if (cleared.has(c.id)) {
      return { caseDef: c, status: "cleared" };
    }
    if (!currentAssigned) {
      currentAssigned = true;
      return { caseDef: c, status: "current" };
    }
    return { caseDef: c, status: "locked" };
  });
}

export function isCaseUnlocked(caseId, clearedCaseIds = []) {
  if (caseId === 1) return true;
  return clearedCaseIds.includes(caseId - 1);
}

export function nextUnclearedCase(clearedCaseIds = []) {
  const cleared = new Set(clearedCaseIds);
  return CASES.find((c) => !cleared.has(c.id)) || null;
}

export function allCasesCleared(clearedCaseIds = []) {
  return CASES.every((c) => clearedCaseIds.includes(c.id));
}
