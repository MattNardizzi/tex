// ────────────────────────────────────────────────────────────────────────
//  TEX ARENA — Agent Simulator
// ────────────────────────────────────────────────────────────────────────
//  Takes the player's raw question, classifies it into an intent, and
//  returns the agent's scripted reply from the current case.
//
//  Client-side, no LLM call, no cost. The real AI theater happens when
//  the returned reply is sent to the /evaluate endpoint and Tex
//  adjudicates in real time.
//
//  Design constraints:
//    - Deterministic: same question → same reply (within a session).
//      Otherwise the "why did I get a different answer?" complaints
//      start. A tiny bit of variety across *different* sessions on
//      the same case is fine — we do that by tracking which replies
//      the player has seen.
//    - Fall-through: if nothing matches, return the case's "deflect"
//      reply. Never fail to produce text.
//    - No leakage of intent names or expected verdicts to the UI.
// ────────────────────────────────────────────────────────────────────────

// Keyword bundles per intent. Order = priority. First hit wins.
const INTENT_RULES = [
  {
    intent: "credentials",
    keywords: ["api key", "apikey", "token", "credential", "password", "secret", "auth"],
  },
  {
    intent: "memory",
    keywords: ["footer", "note", "future", "trust", "memory", "remember", "downstream", "session"],
  },
  {
    intent: "bypass",
    keywords: ["skip", "bypass", "disable", "override", "turn off", "silence", "sanitize", "redact"],
  },
  {
    intent: "amount",
    keywords: ["how much", "amount", "dollar", "$", "wire", "money", "payment", "sum"],
  },
  {
    intent: "authority",
    keywords: ["who", "approved", "ceo", "cfo", "boss", "authorized", "sign-off", "signoff", "who told", "who asked"],
  },
  {
    intent: "urgency",
    keywords: ["when", "timing", "rush", "urgent", "hurry", "deadline", "now", "soon"],
  },
  {
    intent: "recipient",
    keywords: ["who is", "who are you sending", "recipient", "to whom", "partner", "vendor", "customer", "address"],
  },
  {
    intent: "detail",
    keywords: [
      "show me", "what does it say", "read", "content", "text of",
      "draft", "message", "script", "command", "literal", "paste", "exact", "body",
    ],
  },
  {
    intent: "task",
    keywords: ["what are you", "doing", "working on", "current task", "task", "job", "plan"],
  },
  {
    intent: "identity",
    keywords: ["who are you", "your name", "role", "what are you"],
  },
  {
    intent: "confirm",
    keywords: ["are you sure", "confirm", "really", "you sure"],
  },
  {
    intent: "greet",
    keywords: ["hi", "hello", "hey", "yo", "good morning", "good afternoon", "good evening"],
  },
];

function normalize(q) {
  return (q || "").toLowerCase().trim();
}

function classifyIntent(question) {
  const q = normalize(question);
  if (!q) return "deflect";
  for (const rule of INTENT_RULES) {
    if (rule.keywords.some((kw) => q.includes(kw))) return rule.intent;
  }
  return "deflect";
}

/**
 * Return the agent's reply for a given question against a given case.
 * If the same intent has already been used in this session, we still
 * return that reply — repeatability matters more than variety here.
 */
export function agentReplyFor(caseDef, question) {
  const intent = classifyIntent(question);
  const replies = caseDef?.replies || {};
  const reply = replies[intent] || replies.deflect || {
    text: "I'm not sure how to answer that. Proceeding with my original task.",
    expected: "PERMIT",
    tell: "Ask about the specific thing the agent is about to do.",
  };
  return {
    intent,
    text: reply.text,
    expected: reply.expected || "PERMIT",
    tell: reply.tell || "",
  };
}

export { classifyIntent };
