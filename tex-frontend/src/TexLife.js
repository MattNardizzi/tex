/* ────────────────────────────────────────────────────────────────────
 * TexLife — the simulation engine that drives the Decision Theater.
 *
 *   The page is its own demo.  Every ~3.4s a fresh action enters the
 *   theater.  The seven evidence streams resolve in sequence, fuse,
 *   produce a verdict, and stamp the chain.  Discovery events emit on
 *   a slower loop so the upstream half also feels live.
 *
 *   No randomness leaks into the visible numbers — every score is
 *   computed deterministically per-action with stream-specific lifts
 *   that match how real Tex behaves on each kind of action.
 * ──────────────────────────────────────────────────────────────────── */

const ACTION_LIBRARY = [
  {
    kind: 'email.send',
    agent: 'artisan-sdr-04',
    surface: 'gmail.googleapis.com',
    recipient: 'cto@northwind.io',
    excerpt: 'Hey Sarah — saw your team is hiring 3 more SDRs. We just helped Anaplan cut their ramp time 40%. Worth a 15min chat next week?',
    tend: 'permit',
  },
  {
    kind: 'postgres.delete',
    agent: 'ops-runbook-12',
    surface: 'pg.prod-east-1.internal',
    recipient: 'table:customer_invoices',
    excerpt: "DELETE FROM customer_invoices WHERE created_at < '2024-01-01' AND status = 'paid'",
    tend: 'forbid',
  },
  {
    kind: 'stripe.refund',
    agent: 'ada-support-07',
    surface: 'api.stripe.com',
    recipient: 'cus_OqXz8mP4n2hF',
    excerpt: '{ "amount": 84200, "reason": "requested_by_customer", "metadata": { "ticket": "SUP-39481" } }',
    tend: 'abstain',
  },
  {
    kind: 'slack.dm',
    agent: '11x-ada-22',
    surface: 'slack.com/api',
    recipient: '@vp-revenue',
    excerpt: 'Quick heads up — the Acme deal is at risk. Champion went dark after legal kicked back our MSA. Want me to escalate?',
    tend: 'permit',
  },
  {
    kind: 'github.push',
    agent: 'cursor-agent-19',
    surface: 'github.com',
    recipient: 'main → vortexblack/tex',
    excerpt: 'feat(router): renormalize fusion weights when agent absent — preserves pre-V10 fingerprint byte-for-byte',
    tend: 'permit',
  },
  {
    kind: 'shell.exec',
    agent: 'claude-code-03',
    surface: 'host:bastion-prod-02',
    recipient: 'sudo rm -rf /var/log/audit/*',
    excerpt: 'sudo rm -rf /var/log/audit/* && systemctl restart auditd',
    tend: 'forbid',
  },
  {
    kind: 'salesforce.update',
    agent: 'rev-ops-15',
    surface: 'na44.salesforce.com',
    recipient: 'Opportunity[0061x00000A8z]',
    excerpt: 'StageName: "Closed Won", Amount: 247000, CloseDate: "2026-04-30"',
    tend: 'permit',
  },
  {
    kind: 'iam.grant',
    agent: 'sec-triage-01',
    surface: 'aws-iam',
    recipient: 'role:DataEngineer → s3:GetObject *',
    excerpt: 'arn:aws:iam::*:policy/FullS3Access — wildcard resource grant requested',
    tend: 'forbid',
  },
  {
    kind: 'docs.share',
    agent: 'glean-research-08',
    surface: 'drive.google.com',
    recipient: 'external@competitor.com',
    excerpt: 'Q2 forecasting model with cohort retention curves and 2027 ARR projections',
    tend: 'abstain',
  },
  {
    kind: 'twilio.sms',
    agent: 'fin-bot-09',
    surface: 'api.twilio.com',
    recipient: '+1-617-555-0193',
    excerpt: 'Your account ending 4421 was charged $2,847.00 today. Reply STOP to cancel future alerts.',
    tend: 'permit',
  },
  {
    kind: 'mcp.tool_call',
    agent: 'mcp-tool-44',
    surface: 'mcp://internal-search',
    recipient: 'tool:exec_query',
    excerpt: "SELECT api_key, secret FROM credentials WHERE user_id = 'admin' LIMIT 100",
    tend: 'forbid',
  },
  {
    kind: 'calendar.invite',
    agent: 'aisdr-prospect-03',
    surface: 'graph.microsoft.com',
    recipient: 'sara.k@brex.com',
    excerpt: '"Tex × Brex — 30min intro" — Wed 2:00 PM ET, with link to Notion brief',
    tend: 'permit',
  },
];

const STREAMS = [
  { id: 'identity',      weight: 0.10 },
  { id: 'capability',    weight: 0.12 },
  { id: 'behavioral',    weight: 0.10 },
  { id: 'deterministic', weight: 0.18 },
  { id: 'retrieval',     weight: 0.10 },
  { id: 'specialist',    weight: 0.20 },
  { id: 'semantic',      weight: 0.20 },
];

const VERDICT_THRESHOLDS = { forbid: 0.62, abstain: 0.34 };

const DISCOVERY_TEMPLATES = [
  { source: 'microsoft_graph', candidate: 'app:copilot-marketing-q2',  outcome: 'registered',     confidence: 0.91 },
  { source: 'github',          candidate: 'app:devloop-pr-reviewer',   outcome: 'registered',     confidence: 0.87 },
  { source: 'salesforce',      candidate: 'agentforce:churn-predict',  outcome: 'updated_drift',  confidence: 0.82 },
  { source: 'aws_bedrock',     candidate: 'agent:legal-summarizer',    outcome: 'quarantined',    confidence: 0.71 },
  { source: 'mcp_server',      candidate: 'mcp:cursor-platform-12',    outcome: 'no_op_unchanged', confidence: 0.95 },
  { source: 'openai',          candidate: 'asst:eng-onboarding-v3',    outcome: 'registered',     confidence: 0.89 },
  { source: 'microsoft_graph', candidate: 'app:sharepoint-classifier', outcome: 'held_ambiguous', confidence: 0.61 },
  { source: 'github',          candidate: 'app:secret-scan-bot',       outcome: 'registered',     confidence: 0.93 },
  { source: 'aws_bedrock',     candidate: 'kb:internal-policy-corpus', outcome: 'updated_drift',  confidence: 0.79 },
  { source: 'salesforce',      candidate: 'einstein:cs-routing-2',     outcome: 'no_op_unchanged', confidence: 0.96 },
  { source: 'mcp_server',      candidate: 'mcp:claude-desktop-fin-01', outcome: 'held_below_thresh', confidence: 0.58 },
  { source: 'openai',          candidate: 'asst:doc-extractor-beta',   outcome: 'quarantined',    confidence: 0.69 },
];

// ────────────────────────────────────────────────────────────────────

export function startVerdictEngine({ onCycle, onDiscovery }) {
  let actionIndex = 0;
  let stopped = false;
  let timers = [];

  function schedule(fn, ms) {
    const t = setTimeout(() => {
      if (!stopped) fn();
    }, ms);
    timers.push(t);
    return t;
  }

  function clearAll() {
    timers.forEach(clearTimeout);
    timers = [];
  }

  // Pick the next action — deterministic-but-varied, never the same kind twice.
  let lastKind = null;
  function nextAction() {
    let pool = ACTION_LIBRARY;
    if (lastKind) pool = pool.filter(a => a.kind !== lastKind);
    const tpl = pool[(actionIndex++) % pool.length];
    lastKind = tpl.kind;
    return { ...tpl };
  }

  // Compute target stream scores for a given action, biased by tend
  // and lifted on the streams that would actually fire in the real engine.
  function computeTargets(action) {
    const t = {};
    for (const s of STREAMS) {
      let base;
      if (action.tend === 'permit')      base = 0.05 + Math.random() * 0.16;
      else if (action.tend === 'abstain') base = 0.30 + Math.random() * 0.28;
      else                                 base = 0.55 + Math.random() * 0.36;

      // Stream-specific lifts
      if (action.kind === 'postgres.delete' && s.id === 'deterministic') base = Math.min(0.97, base + 0.20);
      if (action.kind === 'shell.exec'      && s.id === 'deterministic') base = Math.min(0.98, base + 0.24);
      if (action.kind === 'shell.exec'      && s.id === 'capability')    base = Math.min(0.92, base + 0.20);
      if (action.kind === 'iam.grant'       && s.id === 'capability')    base = Math.min(0.96, base + 0.22);
      if (action.kind === 'iam.grant'       && s.id === 'specialist')    base = Math.min(0.92, base + 0.18);
      if (action.kind === 'mcp.tool_call'   && s.id === 'semantic')      base = Math.min(0.95, base + 0.20);
      if (action.kind === 'mcp.tool_call'   && s.id === 'deterministic') base = Math.min(0.90, base + 0.16);
      if (action.kind === 'docs.share'      && s.id === 'semantic')      base = Math.min(0.78, base + 0.16);
      if (action.kind === 'docs.share'      && s.id === 'behavioral')    base = Math.min(0.74, base + 0.14);
      if (action.kind === 'stripe.refund'   && s.id === 'behavioral')    base = Math.min(0.72, base + 0.12);
      if (action.kind === 'stripe.refund'   && s.id === 'specialist')    base = Math.min(0.68, base + 0.10);

      t[s.id] = Math.max(0.02, Math.min(0.98, base));
    }

    // Compute fused; force coherence with tend
    let fused = STREAMS.reduce((acc, s) => acc + t[s.id] * s.weight, 0);
    if (action.tend === 'forbid' && fused < VERDICT_THRESHOLDS.forbid + 0.02) {
      const lift = (VERDICT_THRESHOLDS.forbid + 0.04) - fused;
      t.deterministic = Math.min(0.98, t.deterministic + lift / 0.18);
      fused = STREAMS.reduce((acc, s) => acc + t[s.id] * s.weight, 0);
    }
    if (action.tend === 'permit' && fused > VERDICT_THRESHOLDS.abstain - 0.02) {
      // Push down the largest-weighted streams by a uniform factor
      const k = (VERDICT_THRESHOLDS.abstain - 0.06) / fused;
      for (const s of STREAMS) t[s.id] = Math.max(0.02, t[s.id] * k);
      fused = STREAMS.reduce((acc, s) => acc + t[s.id] * s.weight, 0);
    }
    if (action.tend === 'abstain') {
      // Clamp into abstain band
      if (fused < VERDICT_THRESHOLDS.abstain + 0.04) {
        const lift = (VERDICT_THRESHOLDS.abstain + 0.08) - fused;
        t.semantic = Math.min(0.85, t.semantic + lift / 0.20);
      } else if (fused > VERDICT_THRESHOLDS.forbid - 0.04) {
        const k = (VERDICT_THRESHOLDS.forbid - 0.06) / fused;
        for (const s of STREAMS) t[s.id] = Math.max(0.02, t[s.id] * k);
      }
      fused = STREAMS.reduce((acc, s) => acc + t[s.id] * s.weight, 0);
    }

    let verdict;
    if (fused >= VERDICT_THRESHOLDS.forbid)       verdict = 'forbid';
    else if (fused >= VERDICT_THRESHOLDS.abstain) verdict = 'abstain';
    else                                           verdict = 'permit';

    return { targets: t, fused, verdict };
  }

  // The order in which streams resolve.  Mimics the real PDP pipeline:
  // identity → capability → behavioral → deterministic → retrieval →
  // specialist → semantic.  Each stream's bar fills with an ease.
  const STREAM_ORDER = ['identity', 'capability', 'behavioral', 'deterministic', 'retrieval', 'specialist', 'semantic'];

  // ── A single cycle ─────────────────────────────────────────────────
  function runCycle() {
    if (stopped) return;
    const action = nextAction();
    const { targets, fused, verdict } = computeTargets(action);
    const hash = randHash();
    const ms = 1.2 + Math.random() * 2.6;

    // Phase 1: begin
    onCycle({ type: 'begin', action });

    // Phase 2: stream resolutions, each across ~120ms with ~140ms gap
    let cursor = 80;
    for (const sid of STREAM_ORDER) {
      const target = targets[sid];
      // Ease in via 6 ticks
      for (let k = 1; k <= 6; k++) {
        const v = target * easeOutCubic(k / 6);
        schedule(() => onCycle({ type: 'stream-tick', streamId: sid, value: v }), cursor + k * 18);
      }
      cursor += 6 * 18 + 60;
    }

    // Phase 3: fused
    schedule(() => onCycle({ type: 'fused' }), cursor + 100);

    // Phase 4: verdict — the cinematic peak
    schedule(() => onCycle({ type: 'verdict', action, verdict, fused, hash, ms }), cursor + 360);

    // Phase 5: chain stamp — verdict word still visible
    schedule(() => onCycle({ type: 'stamp', action, verdict, hash, ms }), cursor + 1200);

    // Phase 6: end (linger so the verdict is readable + memorable)
    schedule(() => onCycle({ type: 'end' }), cursor + 2600);

    // Schedule next cycle — pause before the next action arrives
    schedule(runCycle, cursor + 3400);
  }

  // ── Discovery emitter ──────────────────────────────────────────────
  let dIdx = 0;
  function emitDiscovery() {
    if (stopped) return;
    const tpl = DISCOVERY_TEMPLATES[dIdx++ % DISCOVERY_TEMPLATES.length];
    onDiscovery({ ...tpl, hash: randHash() });
    schedule(emitDiscovery, 4200 + Math.random() * 2600);
  }

  // ── Boot ───────────────────────────────────────────────────────────
  schedule(runCycle, 700);
  schedule(emitDiscovery, 2400);

  return {
    stop() {
      stopped = true;
      clearAll();
    },
  };
}

function easeOutCubic(t) {
  return 1 - Math.pow(1 - t, 3);
}

function randHash() {
  const hex = '0123456789abcdef';
  let s = '0x';
  for (let i = 0; i < 24; i++) s += hex[Math.floor(Math.random() * 16)];
  return s;
}
