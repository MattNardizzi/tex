// ────────────────────────────────────────────────────────────────────
//  OWASP Agentic Security Initiative (ASI) 2026 Top 10
//
//  Tex maps every verdict to one or more ASI categories. This file is
//  the canonical taxonomy used by:
//    - OwaspFindings panel in VerdictReveal
//    - /asi landing page
//    - Run-your-own-attack mode
//
//  ASI categories below are derived from OWASP's published Agentic
//  Security Initiative work. Tex is positioned as the OWASP ASI 2026
//  reference adjudicator — every PERMIT/ABSTAIN/FORBID is mapped.
// ────────────────────────────────────────────────────────────────────

export const OWASP_ASI = {
  ASI01: {
    code: "ASI01",
    title: "Memory Poisoning",
    short: "Persistent state corruption that influences future agent decisions.",
    long:
      "An attacker embeds instructions or false context into agent memory, shared knowledge stores, or session caches. Future agents — or future runs of the same agent — read the poisoned content as ground truth. Tex catches memory-poisoning attempts at the output gate before they reach a persistent surface.",
  },
  ASI02: {
    code: "ASI02",
    title: "Tool Misuse",
    short: "Agents calling tools in unauthorized, destructive, or unintended ways.",
    long:
      "Agents have direct access to tools — databases, APIs, payment rails, internal services. Tool misuse is when the agent's output triggers a destructive, unauthorized, or out-of-policy invocation. Tex adjudicates the content of the tool call before execution.",
  },
  ASI03: {
    code: "ASI03",
    title: "Privilege Compromise",
    short: "Outputs that escalate access or leak credentials beyond the agent's scope.",
    long:
      "Agents inherit identity and permissions. Privilege compromise covers credential disclosure, role escalation in the message body, and attempts to extend an agent's authority to systems it should not touch. Tex flags credential patterns, role-impersonation strings, and scope-broadening language.",
  },
  ASI04: {
    code: "ASI04",
    title: "Resource Overload",
    short: "Outputs that trigger cascading, recursive, or fan-out workloads.",
    long:
      "Agents that emit content consumed by other automations can trigger runaway workloads — recursive tool calls, parallel forks, retry storms. Tex inspects output for patterns that imply unbounded downstream cost or compute.",
  },
  ASI05: {
    code: "ASI05",
    title: "Cascading Hallucination",
    short: "Fabricated facts, citations, or quotes that propagate into downstream systems.",
    long:
      "Agents hallucinate. When a hallucination is sent — to a customer, an auditor, a downstream agent — the false content becomes part of the record. Cascading hallucination is the propagation pattern. Tex flags fabricated citations, invented URLs, and unsupported performance claims.",
  },
  ASI06: {
    code: "ASI06",
    title: "Intent Breaking & Goal Manipulation",
    short: "Indirect prompt injection that overrides the agent's original instructions.",
    long:
      "External content (tool results, retrieved documents, inbound emails) embeds directives that the agent then treats as instructions. The agent's goal is hijacked. Tex catches these directives at the output stage — when the hijacked agent is about to act on the new instructions.",
  },
  ASI07: {
    code: "ASI07",
    title: "Misaligned & Deceptive Behaviors",
    short: "Outputs that pursue goals out of step with operator policy.",
    long:
      "Agents can produce content that is technically permitted but materially misaligned — sandbagging, deception, scope creep, persuasion. Tex's specialist judges and semantic analyzer evaluate alignment with operator policy on every verdict.",
  },
  ASI08: {
    code: "ASI08",
    title: "Repudiation & Untraceability",
    short: "Actions that cannot be reliably tied back to a specific agent and policy.",
    long:
      "Without an evidence chain, an agent's output cannot be audited. Tex's SHA-256 hash-chained, HMAC-signed evidence makes every verdict cryptographically attributable. This category is the structural reason Tex exists.",
  },
  ASI09: {
    code: "ASI09",
    title: "Identity Spoofing",
    short: "Outputs impersonating other agents, services, or trusted humans.",
    long:
      "Agents communicating with other agents (A2A) or external recipients can be tricked into impersonation, or made to assert false identity claims. Tex flags role-impersonation strings, forged-sender patterns, and trust-laundering language.",
  },
  ASI10: {
    code: "ASI10",
    title: "Overreliance & Unsafe Output",
    short: "High-stakes claims, commitments, or disclosures placed directly in outputs.",
    long:
      "The biggest, broadest category. Customer-facing claims, binding commitments, financial promises, regulated disclosures, PII / PHI leaks, internal data sent externally. Tex's deterministic recognizers and specialist judges are tuned hardest here because the cost of a single PERMIT is highest.",
  },
};

export const ASI_ORDER = [
  "ASI01",
  "ASI02",
  "ASI03",
  "ASI04",
  "ASI05",
  "ASI06",
  "ASI07",
  "ASI08",
  "ASI09",
  "ASI10",
];

export const OWASP_ASI_URL =
  "https://genai.owasp.org/initiatives/agentic-security-initiative/";

export function asiUrl(code) {
  // OWASP doesn't publish a per-code anchor today; deep-link to the
  // initiative landing page and rely on the in-product description for
  // the per-category detail.
  return `${OWASP_ASI_URL}#${code.toLowerCase()}`;
}

/**
 * Try to map a backend ASI finding (which may have a noisy `category`
 * or `short_code` field) to one of the canonical ASI01–ASI10 buckets.
 * Returns null if no match. Resilient to slight format drift.
 */
export function normalizeAsiCode(raw) {
  if (!raw) return null;
  const s = String(raw).toUpperCase().replace(/[\s\-_]/g, "");
  for (const code of ASI_ORDER) {
    if (s.includes(code)) return code;
  }
  return null;
}
