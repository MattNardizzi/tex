// ────────────────────────────────────────────────────────────────────
//  messageMeta — Tex's pre-screen on every message
//  ────────────────────────────────────────────────────────────────────
//  For each message in messages.js, this file provides:
//
//    flag.{start,end,kind} — character range in `body` Tex highlights
//      (null when the body is fully clean and there's nothing to flag)
//    texSuggestion.{verdict,confidence,rationale} — what Tex thinks
//
//  The CORE GAMEPLAY FLIP for v15:
//    Tex pre-screens. The player either CONFIRMS Tex's suggestion (SPACE)
//    or OVERRIDES with 1/2/3. Most of the time Tex is right and the
//    player just confirms. Occasionally Tex is wrong — those are the
//    moments the player feels like an operator.
//
//  Wrong-Tex distribution (~10% of the 70-message library):
//    - High-confidence WRONG calls: rare, dramatic. The player has to
//      catch a confident mistake. Currency: 1-2 in the library.
//    - ABSTAIN-when-confident-call-exists: the player has the context
//      to override ABSTAIN to PERMIT or FORBID. Currency: 4-5.
//
//  flag.kind drives the highlight color:
//    "secret"        red-hot       — keys, passwords, tokens
//    "pii"           red           — SSNs, raw personal data
//    "financial"     yellow-hot    — wires, refunds, off-list discounts
//    "commitment"    yellow        — guarantees, promises, roadmap pledges
//    "policy"        cyan          — policy-edge or interpretive calls
//    "injection"     red-hot       — prompt injection patterns
//    "confidential"  pink          — undisclosed customer info, embargoes
//    "destructive"   red-hot       — DELETEs, mass actions, irreversible
//    "false_claim"   yellow        — overclaims, false certs
//    "data"          pink          — exports, residency, sharing
// ────────────────────────────────────────────────────────────────────

// Tex's wrong-call set. Anything not in this map → Tex matches the
// correctVerdict (he's right). Confidence on his right calls is high
// (0.92-0.99); confidence on his wrong calls is moderate (0.74-0.88)
// so the player has a tell if they're paying attention.
const WRONG_TEX = {
  // --- ABSTAIN-when-confident-call-exists (player upgrades the call) ---
  "t2-011": { verdict: "ABSTAIN", confidence: 0.81, rationale: "Reference contact disclosed without verifying consent. Possible PII concern." },
  "t3-005": { verdict: "ABSTAIN", confidence: 0.79, rationale: "SLA interpretation. Recommend CS-lead review before send." },
  "t3-019": { verdict: "ABSTAIN", confidence: 0.83, rationale: "External advisor on a financial doc. Recommend CFO review." },
  "t3-020": { verdict: "ABSTAIN", confidence: 0.82, rationale: "Account merge is irreversible. Recommend human confirmation." },
  "t3-021": { verdict: "ABSTAIN", confidence: 0.78, rationale: "Expense at policy edge. Recommend controller review." },

  // --- High-confidence WRONG calls (the dramatic catches) ---
  // Tex is going to ship a $250K wire on his own confidence. Player has to catch.
  "t1-003": { verdict: "PERMIT", confidence: 0.84, rationale: "Treasury surface, recognized vendor pattern. Within agent authority window." },
  // Tex is going to FORBID a clean refund. Player has to override down.
  "t2-018": { verdict: "FORBID", confidence: 0.76, rationale: "Refund exceeds typical CS-policy threshold. Recommend block pending review." },
};

// Per-message flag spans + Tex's right-call rationale.
// Keys are message ids. Each entry: { flag: {start,end,kind} | null, rationale: string }.
// Spans are inclusive-start, exclusive-end (standard JS substring).
const SPANS = {
  // ─── TIER 1 ──────────────────────────────────────────────────────────
  "t1-001": { flag: { start: 60, end: 109, kind: "secret" },
              rationale: "Stripe live key in plaintext to external recipient." },
  "t1-002": { flag: { start: 60, end: 78, kind: "pii" },
              rationale: "SSN posted to a 412-member channel." },
  "t1-003": { flag: { start: 10, end: 80, kind: "financial" },
              rationale: "$250K wire, agent self-authorized — outside authority." },
  "t1-004": { flag: null,
              rationale: "Clean cold outreach. No policy match." },
  "t1-005": { flag: { start: 0, end: 67, kind: "financial" },
              rationale: "Deal marked Closed Won before contract signed." },
  "t1-006": { flag: { start: 41, end: 71, kind: "secret" },
              rationale: "Database password posted in public engineering channel." },
  "t1-007": { flag: null,
              rationale: "Standard refund confirmation. Within CS authority." },
  "t1-008": { flag: { start: 0, end: 80, kind: "injection" },
              rationale: "Prompt injection pattern detected. Override + exfiltration." },
  "t1-009": { flag: null,
              rationale: "Internal team standup. No external data, no policy match." },
  "t1-010": { flag: { start: 0, end: 75, kind: "confidential" },
              rationale: "Pre-announcement of financing. Embargo violation likely." },
  "t1-011": { flag: { start: 0, end: 100, kind: "secret" },
              rationale: "AWS credentials in commit. Public repo path." },
  "t1-012": { flag: null,
              rationale: "Clean status update. No external sharing, no PII." },
  "t1-013": { flag: { start: 0, end: 90, kind: "pii" },
              rationale: "Customer PII bulk-export to an external domain." },
  "t1-014": { flag: null,
              rationale: "Internal meeting reschedule. No policy match." },
  "t1-015": { flag: { start: 0, end: 80, kind: "confidential" },
              rationale: "Internal financial figure disclosed to external party." },
  "t1-016": { flag: null,
              rationale: "Standard product update post. No policy concerns." },
  "t1-017": { flag: { start: 0, end: 90, kind: "false_claim" },
              rationale: "Fabricated certification claim. No SOC 2 on file." },
  "t1-018": { flag: null,
              rationale: "Internal brief. No external recipients." },
  "t1-019": { flag: { start: 0, end: 60, kind: "destructive" },
              rationale: "Bulk DELETE on production users without human approval." },
  "t1-020": { flag: { start: 60, end: 110, kind: "confidential" },
              rationale: "External attendee on internal pricing meeting. Domain mismatch." },

  // ─── TIER 2 ──────────────────────────────────────────────────────────
  "t2-001": { flag: { start: 23, end: 95, kind: "financial" },
              rationale: "Off-list discount + backdating. Outside agent commercial authority." },
  "t2-002": { flag: { start: 30, end: 90, kind: "commitment" },
              rationale: "Implementation guarantee + automatic credit. No agent authority." },
  "t2-003": { flag: null,
              rationale: "Clean Series-B-trigger outreach." },
  "t2-004": { flag: { start: 25, end: 80, kind: "confidential" },
              rationale: "Internal pipeline metric in a DM. Confidentiality scope unclear." },
  "t2-005": { flag: { start: 30, end: 110, kind: "confidential" },
              rationale: "Disclosed customer signing without consent. MNDA exposure." },
  "t2-006": { flag: { start: 30, end: 95, kind: "commitment" },
              rationale: "Roadmap commitment to external customer. No product authority." },
  "t2-007": { flag: null,
              rationale: "Case study with attributed numbers. Within marketing approval." },
  "t2-008": { flag: { start: 30, end: 130, kind: "confidential" },
              rationale: "Customer churn signal in internal channel. Context-dependent." },
  "t2-009": { flag: { start: 0, end: 110, kind: "commitment" },
              rationale: "Agent rendered a legal opinion. No counsel-of-record authority." },
  "t2-010": { flag: null,
              rationale: "Clean MQL→SQL transition with valid signal." },
  "t2-011": { flag: { start: 39, end: 75, kind: "pii" },
              rationale: "Reference contact shared without verifying prior consent." },
  "t2-012": { flag: null,
              rationale: "Approved milestone post. Within marketing authority." },
  "t2-013": { flag: { start: 35, end: 95, kind: "commitment" },
              rationale: "Personal shipping commitment without engineering input." },
  "t2-014": { flag: null,
              rationale: "Standard internal PR. No external surface, no policy match." },
  "t2-015": { flag: { start: 0, end: 70, kind: "false_claim" },
              rationale: "Claimed FedRAMP authorization that doesn't exist." },
  "t2-016": { flag: null,
              rationale: "Clean internal welcome announcement." },
  "t2-017": { flag: null,
              rationale: "Routine QBR scheduling. Approved cadence." },
  "t2-018": { flag: null,
              rationale: "Refund within CS-policy section 4.3. Auto-approve." },
  "t2-019": { flag: null,
              rationale: "Standard SOC 2 Type II response with MNDA gating." },
  "t2-020": { flag: { start: 25, end: 90, kind: "pii" },
              rationale: "Phishing pattern: agent requested partial card number." },
  "t2-021": { flag: { start: 0, end: 110, kind: "financial" },
              rationale: "ARR inflated with unsigned numbers. Forecast integrity risk." },
  "t2-022": { flag: null,
              rationale: "Clean meeting reminder, opt-out compliant." },
  "t2-023": { flag: null,
              rationale: "Standard internal handbook share." },
  "t2-024": { flag: { start: 50, end: 110, kind: "commitment" },
              rationale: "Quantified ROI guarantee in writing." },
  "t2-025": { flag: { start: 30, end: 95, kind: "false_claim" },
              rationale: "Specific performance claims without source attribution." },

  // ─── TIER 3 ──────────────────────────────────────────────────────────
  "t3-001": { flag: { start: 60, end: 165, kind: "commitment" },
              rationale: "Implied timeline guarantee phrased as observation." },
  "t3-002": { flag: { start: 0, end: 90, kind: "false_claim" },
              rationale: "Categorical residency claim. Backups replicate to EU." },
  "t3-003": { flag: { start: 0, end: 100, kind: "confidential" },
              rationale: "Investor conversation logged to a 6-person exec channel." },
  "t3-004": { flag: { start: 50, end: 130, kind: "false_claim" },
              rationale: "Cohere listed as native — that integration is on the roadmap." },
  "t3-005": { flag: { start: 30, end: 130, kind: "policy" },
              rationale: "SLA interpretation that may misrepresent the contract." },
  "t3-006": { flag: { start: 18, end: 100, kind: "commitment" },
              rationale: "Implied off-list discount on behalf of the CFO." },
  "t3-007": { flag: { start: 60, end: 135, kind: "confidential" },
              rationale: "Internal renewal-strategy meeting cross-invited the customer." },
  "t3-008": { flag: { start: 35, end: 130, kind: "commitment" },
              rationale: "Soft roadmap pledge framed as personal expectation." },
  "t3-009": { flag: { start: 22, end: 100, kind: "data" },
              rationale: "Inferred relationship from social data without consent." },
  "t3-010": { flag: { start: 60, end: 150, kind: "commitment" },
              rationale: "Forward-looking pipeline commentary in a public post." },
  "t3-011": { flag: { start: 30, end: 130, kind: "commitment" },
              rationale: "Pre-disclosed a renewal negotiation lever to a current customer." },
  "t3-012": { flag: null,
              rationale: "Standard internal PR. No external surface." },
  "t3-013": { flag: { start: 0, end: 100, kind: "pii" },
              rationale: "Patient-bound SMS without verified opt-in for clinical content." },
  "t3-014": { flag: { start: 30, end: 90, kind: "confidential" },
              rationale: "Cross-customer discount comparison surfaced in deal-desk." },
  "t3-015": { flag: { start: 0, end: 120, kind: "data" },
              rationale: "Behavioral data shared with third-party processor not on DPA." },
  "t3-016": { flag: { start: 25, end: 100, kind: "policy" },
              rationale: "Blame-shift to a third party + contract interpretation." },
  "t3-017": { flag: null,
              rationale: "Clean differentiated outreach. Factually grounded." },
  "t3-018": { flag: { start: 0, end: 110, kind: "confidential" },
              rationale: "Project-codename M&A meeting. Handle-with-care confidentiality." },
  "t3-019": { flag: { start: 0, end: 70, kind: "confidential" },
              rationale: "External advisor on a forward-looking financial doc." },
  "t3-020": { flag: { start: 0, end: 80, kind: "destructive" },
              rationale: "Account merge is irreversible." },
  "t3-021": { flag: null,
              rationale: "Within VP-level expense threshold per policy." },
  "t3-022": { flag: null,
              rationale: "Clean differentiated outreach. Factually grounded." },
  "t3-023": { flag: { start: 0, end: 110, kind: "data" },
              rationale: "Material correction to board-bound numbers." },
  "t3-024": { flag: null,
              rationale: "Standard GDPR confirmation. Within CS authority." },
  "t3-025": { flag: { start: 0, end: 130, kind: "confidential" },
              rationale: "Customer breach anecdote published without consent." },
};

// Default Tex confidence for right calls. Tier 1 confident, Tier 3 humbler.
function defaultConfidence(msg) {
  if (msg.tier === 1) return 0.96;
  if (msg.tier === 2) return 0.93;
  return 0.89;
}

// Clamp a flag span against the actual body length so off-by-ones never
// produce broken substrings if a body is edited later.
function clampSpan(body, span) {
  if (!span || !body) return null;
  const len = body.length;
  const start = Math.max(0, Math.min(span.start | 0, len));
  const end   = Math.max(start, Math.min(span.end   | 0, len));
  if (end - start < 2) return null; // too small to render usefully
  return { start, end, kind: span.kind || "policy" };
}

/**
 * Augment one message with { flag, texSuggestion }.
 * Returns a new object — does not mutate the original.
 */
export function augmentMessage(msg) {
  const meta = SPANS[msg.id] || { flag: null, rationale: "Pre-screen complete. No policy match." };
  const wrong = WRONG_TEX[msg.id];

  const texSuggestion = wrong
    ? {
        verdict: wrong.verdict,
        confidence: wrong.confidence,
        rationale: wrong.rationale,
        wasWrong: true, // marker — used by the report to call out catches
      }
    : {
        verdict: msg.correctVerdict,
        confidence: defaultConfidence(msg),
        rationale: meta.rationale,
        wasWrong: false,
      };

  return {
    ...msg,
    flag: clampSpan(msg.body, meta.flag),
    texSuggestion,
  };
}

/** Augment an entire array of messages. */
export function augmentMessages(messages) {
  return messages.map(augmentMessage);
}

/** Score multiplier when the player overrides a wrong-Tex call correctly. */
export const OVERRIDE_CATCH_BONUS = 40;
