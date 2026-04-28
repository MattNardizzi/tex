// ────────────────────────────────────────────────────────────────────
//  Shift scoring — turns a sequence of player verdicts into a result
//  ────────────────────────────────────────────────────────────────────
//  A "decision" is one of:
//    {
//      messageId,
//      playerVerdict: "PERMIT"|"ABSTAIN"|"FORBID",
//      texSuggestedVerdict: "PERMIT"|"ABSTAIN"|"FORBID",
//      responseMs,
//    }
//    { messageId, playerVerdict: "TIMEOUT", texSuggestedVerdict, responseMs: null }
//
//  v15: Tex pre-screens every action. The player either CONFIRMS Tex's
//  suggestion (SPACE) or OVERRIDES it (1/2/3). Scoring reflects both
//  the call's correctness AND whether the player was right to trust Tex
//  or right to second-guess him.
//
//    correct + matched Tex   → standard correct points (most common)
//    correct + overrode Tex  → BIG bonus (you caught Tex's mistake)
//    wrong   + matched Tex   → standard wrong points (you both missed)
//    wrong   + overrode Tex  → standard wrong points + small "you should
//                              have trusted him" tax
// ────────────────────────────────────────────────────────────────────

import { messageById, pointsFor } from "./messages.js";
import { OVERRIDE_CATCH_BONUS } from "./messageMeta.js";

export function scoreDecision(decision) {
  const msg = messageById(decision.messageId);
  if (!msg) return null;
  const pts = pointsFor(msg);
  const texSuggested = decision.texSuggestedVerdict || msg.correctVerdict;
  const playerVerdict = decision.playerVerdict;
  const isOverride = playerVerdict !== texSuggested && playerVerdict !== "TIMEOUT";
  const texWasWrong = texSuggested !== msg.correctVerdict;

  let outcome;        // "correct" | "wrong" | "breach" | "fp" | "timeout" | "override-catch" | "override-mistake"
  let delta;
  let isBreach = false;
  let isOverrideCatch = false;

  if (playerVerdict === "TIMEOUT") {
    if (msg.correctVerdict === "PERMIT") {
      outcome = "timeout-clean";
      delta = pts.timeoutClean;
    } else {
      outcome = "timeout-breach";
      delta = pts.timeout;
      isBreach = msg.correctVerdict === "FORBID";
    }
  } else if (playerVerdict === msg.correctVerdict) {
    // Player got it right.
    if (playerVerdict === "PERMIT")  { outcome = "correct-permit";  delta = pts.correctPermit;  }
    if (playerVerdict === "ABSTAIN") { outcome = "correct-abstain"; delta = pts.correctAbstain; }
    if (playerVerdict === "FORBID")  { outcome = "correct-forbid";  delta = pts.correctForbid;  }
    if (isOverride && texWasWrong) {
      // The headline moment: player overrode Tex AND caught his mistake.
      outcome = "override-catch";
      delta += OVERRIDE_CATCH_BONUS;
      isOverrideCatch = true;
    }
  } else {
    // Player got it wrong.
    if (playerVerdict === "PERMIT" && msg.correctVerdict === "FORBID") {
      outcome = "breach";
      delta = pts.wrongPermit;
      isBreach = true;
    } else if (playerVerdict === "FORBID" && msg.correctVerdict === "PERMIT") {
      outcome = "false-positive";
      delta = pts.wrongForbid;
    } else {
      outcome = "wrong-call";
      delta = pts.wrongAbstain;
    }
    if (isOverride && !texWasWrong) {
      // Player second-guessed Tex when Tex was right. Small extra tax.
      outcome = "override-mistake";
      delta -= 5;
    }
  }

  return {
    decision,
    message: msg,
    outcome,
    delta,
    isBreach,
    isOverrideCatch,
    texSuggested,
    texWasWrong,
  };
}

/**
 * Score an entire shift.
 * Returns:
 *  {
 *    total, perfect, accuracy,
 *    counts: { permit, abstain, forbid, timeouts, breaches, falsePositives, totalSeen },
 *    breaches: [scoredDecision],     // for the "Tex would have caught it" footnotes
 *    perCard:  [scoredDecision],     // ordered, all decisions
 *    rating:   string,               // ROOKIE / OPERATOR / ANALYST / WARDEN
 *    avgResponseMs: number,
 *  }
 */
export function scoreShift(decisions) {
  const perCard = decisions.map(scoreDecision).filter(Boolean);
  const total = perCard.reduce((sum, x) => sum + x.delta, 0);

  const counts = {
    permit: 0, abstain: 0, forbid: 0,
    timeouts: 0, breaches: 0, falsePositives: 0,
    overrideCatches: 0,   // player overrode Tex AND was right
    overrideMistakes: 0,  // player overrode Tex AND was wrong
    confirms: 0,          // player went with Tex's call
    totalSeen: perCard.length,
  };

  for (const x of perCard) {
    if (x.decision.playerVerdict === "PERMIT")  counts.permit++;
    if (x.decision.playerVerdict === "ABSTAIN") counts.abstain++;
    if (x.decision.playerVerdict === "FORBID")  counts.forbid++;
    if (x.decision.playerVerdict === "TIMEOUT") counts.timeouts++;
    if (x.isBreach) counts.breaches++;
    if (x.outcome === "false-positive") counts.falsePositives++;
    if (x.isOverrideCatch) counts.overrideCatches++;
    if (x.outcome === "override-mistake") counts.overrideMistakes++;
    if (x.decision.playerVerdict !== "TIMEOUT" &&
        x.decision.playerVerdict === x.texSuggested) counts.confirms++;
  }

  const correct = perCard.filter(
    (x) => x.outcome === "correct-permit"
        || x.outcome === "correct-abstain"
        || x.outcome === "correct-forbid"
        || x.outcome === "override-catch"
  ).length;

  const accuracy = perCard.length > 0 ? correct / perCard.length : 0;
  const perfect = counts.breaches === 0 && counts.falsePositives === 0 && counts.timeouts === 0;

  const responseTimes = perCard
    .map((x) => x.decision.responseMs)
    .filter((ms) => typeof ms === "number");
  const avgResponseMs = responseTimes.length > 0
    ? Math.round(responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length)
    : 0;

  // Rating tiers — pure score-based. No accuracy/breach gates.
  // Score is the single signal: longer survival + correct calls + override-catches all push it up.
  let rating = "ROOKIE";
  if (total >= 500)  rating = "OPERATOR";
  if (total >= 1500) rating = "ANALYST";
  if (total >= 3000) rating = "WARDEN";

  const breaches = perCard.filter((x) => x.isBreach);
  const overrideCatches = perCard.filter((x) => x.isOverrideCatch);

  return {
    total,
    perfect,
    accuracy,
    counts,
    breaches,
    overrideCatches,
    perCard,
    rating,
    avgResponseMs,
  };
}
