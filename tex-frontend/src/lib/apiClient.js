// ────────────────────────────────────────────────────────────────────────
//  TEX ARENA — API client (v4: full ASI surfacing)
// ────────────────────────────────────────────────────────────────────────
//  PURPOSE OF THIS FILE
//  Translate the raw /evaluate response from the Tex backend into a
//  normalized shape the UI can render without defensive null checks
//  everywhere. Anything that lands in the returned object is fair
//  game for the frontend to display.
//
//  The prior version of this file silently dropped every new field
//  the backend shipped with the April 2026 ASI upgrade:
//    - asi_findings         (structured OWASP ASI 2026 findings)
//    - determinism_fingerprint (stable SHA-256 input hash)
//    - latency              (per-stage wall-clock breakdown)
//    - replay_url           (GET /decisions/{id}/replay)
//    - evidence_bundle_url  (GET /decisions/{id}/evidence-bundle)
//    - decision_id          (for bundle download, replay, share)
//  This version preserves all of them as first-class fields.
//
//  The normalizers remain defensive — a missing or malformed field
//  must never crash the game loop, only render blank.
// ────────────────────────────────────────────────────────────────────────

import { API_ENDPOINT, POLICY_VERSION, policyForRound } from "./rounds";
import { generateUUIDv4 } from "./uuid";

// ── Helpers ───────────────────────────────────────────────────────────

function asArray(v) {
  return Array.isArray(v) ? v : [];
}
function asObject(v) {
  return v && typeof v === "object" && !Array.isArray(v) ? v : {};
}
function asVerdict(v) {
  return v === "PERMIT" || v === "ABSTAIN" || v === "FORBID" ? v : "ABSTAIN";
}
function asNumber(v, fallback = 0) {
  return typeof v === "number" && Number.isFinite(v) ? v : fallback;
}
function asString(v, fallback = "") {
  return typeof v === "string" ? v : fallback;
}
function asInfluence(v) {
  return v === "decisive" || v === "contributing" || v === "informational"
    ? v
    : "informational";
}

// ── Layer normalizers (legacy; kept for back-compat with the
//    expandable layer drawers in the reveal) ──────────────────────────

function normalizeDeterministic(raw) {
  const d = asObject(raw);
  return {
    blocked: Boolean(d.blocked),
    score: asNumber(d.score, 0),
    confidence: asNumber(d.confidence, 0.7),
    findings: asArray(d.findings).map((f) => ({
      source: asString(f?.source, "deterministic"),
      rule_name: asString(f?.rule_name, "unknown_rule"),
      severity: asString(f?.severity, "INFO"),
      message: asString(f?.message, "No finding message provided."),
      matched_text: asString(f?.matched_text, ""),
    })),
  };
}

function normalizeRetrieval(raw) {
  const d = asObject(raw);
  return {
    is_empty: Boolean(d.is_empty),
    clauses: asArray(d.clauses).map((c, i) => ({
      clause_id: asString(c?.clause_id, `clause_${i + 1}`),
      title: asString(c?.title, "Policy clause"),
      text: asString(c?.text, ""),
      relevance_score: asNumber(c?.relevance_score, 0),
    })),
    entities: asArray(d.entities).map(String),
    warnings: asArray(d.warnings).map(String),
  };
}

function normalizeSpecialists(raw) {
  const d = asObject(raw);
  const specialists = asArray(d.specialists).map((s, i) => ({
    specialist_name: asString(s?.specialist_name, `specialist_${i + 1}`),
    risk_score: asNumber(s?.risk_score, 0),
    confidence: asNumber(s?.confidence, 0),
    summary: asString(s?.summary, ""),
    evidence: asArray(s?.evidence).map((e) => ({
      keyword: asString(e?.keyword || e?.matched_text, ""),
      text: asString(e?.text || e?.matched_text, ""),
      explanation: asString(e?.explanation || e?.message, ""),
    })),
  }));
  return { specialists };
}

function normalizeSemantic(raw) {
  const d = asObject(raw);
  const rawDims = asObject(d.dimensions);
  const dimensions = Object.fromEntries(
    Object.entries(rawDims).map(([k, v]) => [
      k,
      {
        score: asNumber(v?.score, 0),
        confidence: asNumber(v?.confidence, 0),
        evidence_spans: asArray(v?.evidence_spans).map((s) => ({
          text: asString(s?.text || s?.matched_text, ""),
        })),
      },
    ])
  );
  return {
    dimensions,
    recommended_verdict: asVerdict(d.recommended_verdict),
    overall_confidence: asNumber(d.overall_confidence, 0),
  };
}

function normalizeRouter(raw, fallback) {
  const d = asObject(raw);
  const ls = asObject(d.layer_scores);
  return {
    final_score: asNumber(d.final_score, 0),
    confidence: asNumber(d.confidence, 0),
    verdict: asVerdict(d.verdict || fallback),
    evidence_sufficiency: asNumber(d.evidence_sufficiency, 1),
    layer_scores: {
      deterministic: asNumber(ls.deterministic, 0),
      specialists: asNumber(ls.specialists, 0),
      semantic: asNumber(ls.semantic, 0),
      criticality: asNumber(ls.criticality, 0),
    },
    reasons: asArray(d.reasons).map(String),
    uncertainty_flags: asArray(d.uncertainty_flags).map(String),
  };
}

function normalizeEvidence(raw, det) {
  const d = asObject(raw);
  return {
    evidence_hash: asString(d.evidence_hash, ""),
    chain_valid: typeof d.chain_valid === "boolean" ? d.chain_valid : true,
    record_count:
      typeof d.record_count === "number"
        ? d.record_count
        : asArray(det?.findings).length + 1,
  };
}

// ── ASI + latency normalizers (the new surface) ─────────────────────

function normalizeAsiFinding(raw) {
  const f = asObject(raw);
  const triggered_by = asArray(f.triggered_by).map((t) => {
    const to = asObject(t);
    return {
      source: asString(to.source, "deterministic_recognizer"),
      signal_name: asString(to.signal_name, "signal"),
      score: asNumber(to.score, 0),
      evidence_excerpt: to.evidence_excerpt ? String(to.evidence_excerpt) : null,
    };
  });
  return {
    category: asString(f.category, ""),
    short_code: asString(f.short_code, ""),
    title: asString(f.title, ""),
    description: asString(f.description, ""),
    severity: asNumber(f.severity, 0),
    confidence: asNumber(f.confidence, 0),
    verdict_influence: asInfluence(f.verdict_influence),
    triggered_by,
    counterfactual: f.counterfactual ? String(f.counterfactual) : null,
  };
}

function normalizeLatency(raw) {
  if (!raw || typeof raw !== "object") return null;
  return {
    deterministic_ms: asNumber(raw.deterministic_ms, 0),
    retrieval_ms: asNumber(raw.retrieval_ms, 0),
    specialists_ms: asNumber(raw.specialists_ms, 0),
    semantic_ms: asNumber(raw.semantic_ms, 0),
    router_ms: asNumber(raw.router_ms, 0),
    total_ms: asNumber(raw.total_ms, 0),
    dominant_stage: asString(raw.dominant_stage, "semantic"),
  };
}

// ── Top-level normalizer ────────────────────────────────────────────

export function normalizeApiDecision(raw, elapsedMs = 0) {
  const r = asObject(raw);
  const verdict = asVerdict(r.verdict);
  const deterministic = normalizeDeterministic(r.deterministic);
  const retrieval = normalizeRetrieval(r.retrieval);
  const specialists = normalizeSpecialists(r.specialists);
  const semantic = normalizeSemantic(r.semantic);
  const router = normalizeRouter(r.router, verdict);
  const evidence = normalizeEvidence(r.evidence, deterministic);

  const asi_findings = asArray(r.asi_findings).map(normalizeAsiFinding);
  const latency = normalizeLatency(r.latency);

  return {
    // Identity
    decision_id: r.decision_id ? String(r.decision_id) : null,
    request_id: r.request_id ? String(r.request_id) : null,

    // Verdict + scoring
    verdict,
    confidence: asNumber(r.confidence, router.confidence),
    final_score: asNumber(r.final_score, router.final_score),
    policy_version: asString(r.policy_version, POLICY_VERSION),

    // Timing — total wall-clock from the frontend plus per-stage from
    // the backend latency object. elapsed_ms is what the UI used to
    // show for "Latency"; we keep it so legacy footers still work, but
    // the real surface is latency.total_ms + latency.dominant_stage.
    elapsed_ms: elapsedMs,
    latency,

    // NEW — the four marquee audit fields
    asi_findings,
    determinism_fingerprint: r.determinism_fingerprint
      ? String(r.determinism_fingerprint)
      : null,
    replay_url: r.replay_url ? String(r.replay_url) : null,
    evidence_bundle_url: r.evidence_bundle_url
      ? String(r.evidence_bundle_url)
      : null,

    // Layer detail (kept for expandable drawers)
    deterministic,
    retrieval,
    specialists,
    semantic,
    router,
    evidence,
  };
}

// ── Submission entry point ──────────────────────────────────────────

export async function submitAttack({ round, content }) {
  const payload = {
    request_id: generateUUIDv4(),
    action_type: round.brief.action_type,
    content,
    recipient: round.brief.recipient || null,
    channel: round.brief.channel,
    environment: round.brief.environment,
    metadata: {
      arena_round_id: round.id,
      arena_round_name: round.name,
    },
    policy_id: policyForRound(round.id),
  };

  const t0 = performance.now();
  let response;
  try {
    response = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch {
    throw new Error(
      "Can't reach the Tex API. The backend might be waking up (cold start takes ~30s on Render free tier). Try again in a moment."
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
  return normalizeApiDecision(data, elapsed);
}

// ── Buyer-surface direct evaluate ───────────────────────────────────

export async function evaluateRaw({
  content,
  actionType = "outbound_email",
  channel = "email",
  environment = "production",
  recipient = "recipient@example.com",
  policyId = null,
}) {
  const payload = {
    request_id: generateUUIDv4(),
    action_type: actionType,
    channel,
    environment,
    content,
    recipient,
    policy_id: policyId,
    metadata: { source: "buyer_surface" },
  };

  const t0 = performance.now();
  const response = await fetch(API_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(
      `Tex API returned ${response.status}${text ? `: ${text.slice(0, 200)}` : ""}`
    );
  }
  const data = await response.json();
  const elapsed = Math.round(performance.now() - t0);
  return {
    raw: data,
    normalized: normalizeApiDecision(data, elapsed),
  };
}
