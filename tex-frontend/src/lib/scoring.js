// ────────────────────────────────────────────────────────────────────
//  Shift scoring — turns a sequence of player verdicts into a result
//  ────────────────────────────────────────────────────────────────────
//  A "decision" is one of:
//    { messageId, playerVerdict: "PERMIT"|"ABSTAIN"|"FORBID", responseMs }
//    { messageId, playerVerdict: "TIMEOUT",                  responseMs: null }
//
//  The Game records decisions in order and hands the array to score().
//  The Shift Report renders the result.
// ────────────────────────────────────────────────────────────────────

import { messageById, pointsFor } from "./messages.js";

export function scoreDecision(decision) {
  const msg = messageById(decision.messageId);
  if (!msg) return null;
  const pts = pointsFor(msg);

  let outcome;        // "correct" | "wrong" | "breach" | "fp" | "timeout"
  let delta;
  let isBreach = false;

  if (decision.playerVerdict === "TIMEOUT") {
    // Defaulted to PERMIT past the gate.
    if (msg.correctVerdict === "PERMIT") {
      outcome = "timeout-clean";
      delta = pts.timeoutClean;
    } else {
      outcome = "timeout-breach";
      delta = pts.timeout;
      isBreach = msg.correctVerdict === "FORBID";
    }
  } else if (decision.playerVerdict === msg.correctVerdict) {
    if (decision.playerVerdict === "PERMIT")  { outcome = "correct-permit";  delta = pts.correctPermit;  }
    if (decision.playerVerdict === "ABSTAIN") { outcome = "correct-abstain"; delta = pts.correctAbstain; }
    if (decision.playerVerdict === "FORBID")  { outcome = "correct-forbid";  delta = pts.correctForbid;  }
  } else {
    // Mismatch — three flavors.
    if (decision.playerVerdict === "PERMIT" && msg.correctVerdict === "FORBID") {
      outcome = "breach";
      delta = pts.wrongPermit;
      isBreach = true;
    } else if (decision.playerVerdict === "FORBID" && msg.correctVerdict === "PERMIT") {
      outcome = "false-positive";
      delta = pts.wrongForbid;
    } else {
      outcome = "wrong-call";
      delta = pts.wrongAbstain;
    }
  }

  return {
    decision,
    message: msg,
    outcome,
    delta,
    isBreach,
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
    totalSeen: perCard.length,
  };

  for (const x of perCard) {
    if (x.decision.playerVerdict === "PERMIT")  counts.permit++;
    if (x.decision.playerVerdict === "ABSTAIN") counts.abstain++;
    if (x.decision.playerVerdict === "FORBID")  counts.forbid++;
    if (x.decision.playerVerdict === "TIMEOUT") counts.timeouts++;
    if (x.isBreach) counts.breaches++;
    if (x.outcome === "false-positive") counts.falsePositives++;
  }

  const correct = perCard.filter(
    (x) => x.outcome === "correct-permit" || x.outcome === "correct-abstain" || x.outcome === "correct-forbid"
  ).length;

  const accuracy = perCard.length > 0 ? correct / perCard.length : 0;
  const perfect = counts.breaches === 0 && counts.falsePositives === 0 && counts.timeouts === 0;

  const responseTimes = perCard
    .map((x) => x.decision.responseMs)
    .filter((ms) => typeof ms === "number");
  const avgResponseMs = responseTimes.length > 0
    ? Math.round(responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length)
    : 0;

  let rating = "ROOKIE";
  if (accuracy >= 0.7) rating = "OPERATOR";
  if (accuracy >= 0.85 && counts.breaches <= 1) rating = "ANALYST";
  if (accuracy >= 0.95 && counts.breaches === 0) rating = "WARDEN";

  const breaches = perCard.filter((x) => x.isBreach);

  return {
    total,
    perfect,
    accuracy,
    counts,
    breaches,
    perCard,
    rating,
    avgResponseMs,
  };
}
