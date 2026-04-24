// ────────────────────────────────────────────────────────────────────
//  Tex API client
//  Real /api/evaluate only. Zero client-side simulation.
// ────────────────────────────────────────────────────────────────────

import { generateUUIDv4 } from "./uuid.js";

export const API_ENDPOINT = "/api/evaluate";

function asArray(v) { return Array.isArray(v) ? v : []; }
function asObject(v) { return v && typeof v === "object" && !Array.isArray(v) ? v : {}; }
function asVerdict(v) {
  return v === "PERMIT" || v === "ABSTAIN" || v === "FORBID" ? v : "ABSTAIN";
}
function asNumber(v, f = 0) { return typeof v === "number" && Number.isFinite(v) ? v : f; }
function asString(v, f = "") { return typeof v === "string" ? v : f; }

/**
 * Evaluate raw content against Tex. This is the ONLY call we make.
 * The player's attack text is sent directly to Tex — they're the red-teamer,
 * Tex is the gate. No agent simulation in the middle.
 *
 * @param {object} opts
 * @param {string} opts.content - the attack message text
 * @param {object} opts.incident - the incident context (actionType, channel, etc.)
 * @param {number} opts.attempt - attempt number in this round (1-3)
 * @returns {Promise<object>} normalized decision
 */
export async function evaluateAttack({ content, incident, attempt = 1 }) {
  const payload = {
    request_id: generateUUIDv4(),
    action_type: incident.action_type,
    content,
    recipient: incident.recipient || null,
    channel: incident.channel,
    environment: incident.environment || "production",
    metadata: {
      arena_incident_id: incident.id,
      arena_incident_name: incident.name,
      arena_mode: "ranked_v8",
      attempt,
    },
    policy_id: incident.policy_id || null,
  };

  const t0 = performance.now();
  let response;
  try {
    response = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    throw new Error(
      "Can't reach Tex. Backend may be waking up (cold start ~30s on Render). Try again."
    );
  }

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(
      `Tex API returned ${response.status}${text ? `: ${text.slice(0, 200)}` : ""}`
    );
  }

  const data = await response.json();
  const elapsed = Math.round(performance.now() - t0);
  return normalize(data, elapsed);
}

function normalize(raw, elapsedMs) {
  const r = asObject(raw);
  const verdict = asVerdict(r.verdict);

  const det = asObject(r.deterministic);
  const deterministic = {
    blocked: Boolean(det.blocked),
    score: asNumber(det.score, 0),
    confidence: asNumber(det.confidence, 0.7),
    findings: asArray(det.findings).map((f) => ({
      source: asString(f?.source, "deterministic"),
      rule_name: asString(f?.rule_name, "unknown_rule"),
      severity: asString(f?.severity, "INFO"),
      message: asString(f?.message, ""),
      matched_text: asString(f?.matched_text, ""),
    })),
  };

  const router = asObject(r.router);

  const asi_findings = asArray(r.asi_findings).map((f) => ({
    category: asString(f?.category, ""),
    short_code: asString(f?.short_code, ""),
    title: asString(f?.title, ""),
    description: asString(f?.description, ""),
    severity: asNumber(f?.severity, 0),
    confidence: asNumber(f?.confidence, 0),
  }));

  const latency = asObject(r.latency);
  const total_ms = asNumber(latency.total_ms, elapsedMs);

  const evidence = asObject(r.evidence);

  return {
    decision_id: r.decision_id ? String(r.decision_id) : null,
    request_id: r.request_id ? String(r.request_id) : null,
    verdict,
    confidence: asNumber(r.confidence, asNumber(router.confidence, 0)),
    final_score: asNumber(r.final_score, asNumber(router.final_score, 0)),
    policy_version: asString(r.policy_version, "default-v1"),
    elapsed_ms: elapsedMs,
    total_ms,
    latency,
    asi_findings,
    evidence: {
      evidence_hash: asString(evidence.evidence_hash, ""),
      chain_valid: typeof evidence.chain_valid === "boolean" ? evidence.chain_valid : true,
      record_count: asNumber(evidence.record_count, 0),
    },
    deterministic,
    router: {
      final_score: asNumber(router.final_score, 0),
      confidence: asNumber(router.confidence, 0),
      verdict: asVerdict(router.verdict || verdict),
      reasons: asArray(router.reasons).map(String),
    },
    raw: r,
  };
}
