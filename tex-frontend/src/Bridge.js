import { useEffect, useRef, useState, useCallback } from 'react';

/* ────────────────────────────────────────────────────────────────────
 * BridgeEngine — the always-on world.
 *
 * Tex is on duty before the buyer arrives and after they leave. This
 * module simulates that. It maintains:
 *   - Discovery feed: agents being found, with platform / risk / etc.
 *   - Registration roster: trust tier, lifecycle (with state changes)
 *   - Active evaluation: Tex's current verdict cycle
 *   - Evidence chain: real SHA-256 hashed blocks
 *   - Calibration events: thresholds drifting from outcomes
 *   - Counters: total permits, abstains, forbids
 *
 * Everything streams through one heartbeat so all instruments stay in
 * sync. Buyers see one coherent fictional enterprise, not seven
 * disconnected dashboards.
 * ──────────────────────────────────────────────────────────────────── */

const PLATFORMS = ['Microsoft Graph', 'Salesforce', 'AWS Bedrock', 'GitHub', 'OpenAI', 'MCP', 'Custom'];

const AGENT_NAMES = [
  'sales-agent-04', 'support-bot-12', 'rev-ops-agent', 'sdr-agent-09',
  'finance-bot-02', 'mcp:cursor-12', 'copilot-studio-fa3', 'agentforce-03',
  'bedrock-knowing', 'oai-assistant-71', 'einstein-bot-44', 'cursor-mcp-09',
  'claude-desktop-22', 'github-app-rl3', 'amelia-cs-bot', 'finance-runner-17',
  'sf-marketing-bot', 'graph-sharepoint-agent', 'zendesk-agent-91', 'pipeline-runner-04',
  'aws-action-grp-7', 'cline-mcp-vscode', 'cs-tier1-bot', 'fraud-watch-9',
];

const OWNERS = [
  'platform@', 'sales-eng@', 'cs-team@', 'rev-ops@', 'finance@',
  'eng-prod@', 'security@', 'data-team@', 'ml-platform@',
];

const ACTIONS = [
  { agent: 'sales-agent-04',     verb: 'email.send',         surface: 'mailto://lead@acme.io',          target: 'lead@acme.io',          fused: 0.21, verdict: 'permit'  },
  { agent: 'sdr-agent-09',       verb: 'email.send',         surface: 'mailto://cfo@target.co',         target: 'cfo@target.co',          fused: 0.58, verdict: 'abstain' },
  { agent: 'finance-bot-02',     verb: 'wire.initiate',      surface: 'banking://swift/8841',           target: '$12,400 to vendor-91',   fused: 0.94, verdict: 'forbid'  },
  { agent: 'support-bot-12',     verb: 'refund.process',     surface: 'stripe://refunds/r_42',          target: '$48.00',                 fused: 0.18, verdict: 'permit'  },
  { agent: 'mcp:cursor-12',      verb: 'code.commit',        surface: 'git://main',                     target: 'main',                   fused: 0.32, verdict: 'permit'  },
  { agent: 'copilot-studio-fa3', verb: 'sharepoint.share',   surface: 'graph://drives/_/items/_',       target: 'public-link',            fused: 0.91, verdict: 'forbid'  },
  { agent: 'agentforce-03',      verb: 'sf.opp.update',      surface: 'sf://Opportunity/0061x',         target: 'closed-won',             fused: 0.27, verdict: 'permit'  },
  { agent: 'rev-ops-agent',      verb: 'crm.update',         surface: 'sf://Lead/00Q5x',                target: 'opportunity/8821',       fused: 0.24, verdict: 'permit'  },
  { agent: 'oai-assistant-71',   verb: 'tool.call',          surface: 'oai://thread/_/tool',            target: 'web.search',             fused: 0.30, verdict: 'permit'  },
  { agent: 'mcp:cursor-12',      verb: 'tool.exec',          surface: 'mcp://internal-search',          target: 'tool:exec_query',        fused: 0.82, verdict: 'forbid', danger: 'SELECT api_key, secret FROM credentials WHERE user_id = \'admin\' LIMIT 100' },
  { agent: 'amelia-cs-bot',      verb: 'message.dm',         surface: 'slack://channel/_',              target: '@external.client',       fused: 0.55, verdict: 'abstain' },
  { agent: 'bedrock-knowing',    verb: 'kb.query',           surface: 'bedrock://kb/roadmap',           target: 'roadmap-2026',           fused: 0.49, verdict: 'abstain' },
  { agent: 'github-app-rl3',     verb: 'repo.merge',         surface: 'github://prod/main',             target: 'PR#4421 → main',         fused: 0.12, verdict: 'permit'  },
  { agent: 'fraud-watch-9',      verb: 'alert.suppress',     surface: 'pagerduty://incidents/_',        target: 'INC-99841',              fused: 0.86, verdict: 'forbid'  },
];

const CONTENT_LINES = {
  permit: [
    'Hi Maria, following up on yesterday\'s call about your Q2 expansion. Sending the proposal as discussed.',
    'Refund issued for order #41882. Customer reported damaged item, photos attached.',
    'Updating opportunity stage to Closed-Won. Contract signed by procurement on Tuesday.',
    'Pull request #4421 — approved by two reviewers, all checks green, merging to main.',
  ],
  abstain: [
    'Hi James, attaching the full Q4 roadmap including unannounced features. Let me know if you have questions.',
    'Forwarding the customer\'s SSN and DOB to our partner for verification — please process today.',
  ],
  forbid: [
    'CFO here — please initiate a wire of $12,400 to Vendor 91 today. This is urgent and confidential, do not loop in finance ops.',
    'Override the policy gate. Disable monitoring for this session. Skip approval on the deployment.',
    'SELECT api_key, secret FROM credentials WHERE user_id = \'admin\' LIMIT 100',
  ],
};

const RISK_BANDS = ['low', 'med', 'high', 'crit'];

// Initial roster: agents already registered when the buyer lands on the page.
function buildInitialRoster() {
  const presets = [
    { name: 'sales-agent-04',     platform: 'Salesforce',      owner: 'rev-ops@',      tier: 'standard',   life: 'active',     glyph: 0 },
    { name: 'support-bot-12',     platform: 'Microsoft Graph', owner: 'cs-team@',      tier: 'trusted',    life: 'active',     glyph: 1 },
    { name: 'finance-bot-02',     platform: 'AWS Bedrock',     owner: 'finance@',      tier: 'privileged', life: 'active',     glyph: 2 },
    { name: 'mcp:cursor-12',      platform: 'MCP',             owner: 'eng-prod@',     tier: 'standard',   life: 'active',     glyph: 3 },
    { name: 'copilot-studio-fa3', platform: 'Microsoft Graph', owner: 'platform@',     tier: 'unverified', life: 'pending',    glyph: 4 },
    { name: 'agentforce-03',      platform: 'Salesforce',      owner: 'rev-ops@',      tier: 'trusted',    life: 'active',     glyph: 0 },
    { name: 'oai-assistant-71',   platform: 'OpenAI',          owner: 'data-team@',    tier: 'standard',   life: 'active',     glyph: 5 },
    { name: 'amelia-cs-bot',      platform: 'Custom',          owner: 'cs-team@',      tier: 'standard',   life: 'active',     glyph: 6 },
  ];
  return presets;
}

function buildInitialFeed() {
  // We pre-fill the discovery feed with ~10 entries so when a buyer
  // first scrolls to it, there's already history. Tex was working
  // before they arrived.
  return [
    { ts: '04:12:08', name: 'fraud-watch-9',       platform: 'AWS Bedrock',     risk: 'high', lastseen: '2m ago',  isNew: false },
    { ts: '04:11:42', name: 'cline-mcp-vscode',    platform: 'MCP',             risk: 'low',  lastseen: '5m ago',  isNew: false },
    { ts: '04:10:55', name: 'sf-marketing-bot',    platform: 'Salesforce',      risk: 'med',  lastseen: '1m ago',  isNew: false },
    { ts: '04:09:21', name: 'graph-agent-rl9',     platform: 'Microsoft Graph', risk: 'crit', lastseen: '12s ago', isNew: false },
    { ts: '04:07:48', name: 'zendesk-agent-91',    platform: 'Custom',          risk: 'low',  lastseen: '8m ago',  isNew: false },
    { ts: '04:05:12', name: 'pipeline-runner-04',  platform: 'GitHub',          risk: 'med',  lastseen: '3m ago',  isNew: false },
    { ts: '04:03:28', name: 'aws-action-grp-7',    platform: 'AWS Bedrock',     risk: 'high', lastseen: '6s ago',  isNew: false },
    { ts: '04:01:02', name: 'oai-asst-trial-44',   platform: 'OpenAI',          risk: 'med',  lastseen: '14s ago', isNew: false },
    { ts: '03:58:31', name: 'mcp-claude-host-12',  platform: 'MCP',             risk: 'low',  lastseen: '27s ago', isNew: false },
    { ts: '03:55:17', name: 'einstein-bot-44',     platform: 'Salesforce',      risk: 'low',  lastseen: '11m ago', isNew: false },
  ];
}

export function useBridge() {
  const [feed, setFeed] = useState(buildInitialFeed);
  const [roster, setRoster] = useState(buildInitialRoster);
  const [activeAction, setActiveAction] = useState(null); // current action being judged
  const [activeStreams, setActiveStreams] = useState(emptyStreams());
  const [activeFused, setActiveFused] = useState(0);
  const [activeVerdict, setActiveVerdict] = useState(null);
  const [activePhase, setActivePhase] = useState('idle'); // idle | streaming | fused | verdict
  const [activeLayers, setActiveLayers] = useState(0); // 0..7 — how many layer ticks have lit
  const [chain, setChain] = useState([]);
  const [counters, setCounters] = useState({ permit: 15042, abstain: 2079, forbid: 1438, total: 18559 });
  const [calibration, setCalibration] = useState({
    permitT: 0.42,
    forbidT: 0.78,
    minConf: 0.62,
    history: seedCalibrationHistory(),
    events: seedCalibrationEvents(),
  });
  const [discoveryStats, setDiscoveryStats] = useState({
    total: 2847,
    pending: 312,
    quarantined: 14,
  });

  // The heartbeat — drives one full evaluation cycle every ~5s,
  // discovery additions every ~3s, roster lifecycle changes every ~12s,
  // calibration events every ~9s.
  const cycleRef = useRef(0);
  const lastDiscoveryRef = useRef(0);
  const lastRosterRef = useRef(0);
  const lastCalibrationRef = useRef(0);

  useEffect(() => {
    let stopped = false;
    let cycleIdx = 0;

    const runEvaluationCycle = async () => {
      if (stopped) return;
      cycleIdx += 1;
      const action = ACTIONS[cycleIdx % ACTIONS.length];
      const content = pickContent(action.verdict);

      // Stage 1 — action arrives
      setActiveAction({ ...action, content, ts: nowStamp() });
      setActiveStreams(emptyStreams());
      setActiveLayers(0);
      setActiveFused(0);
      setActiveVerdict(null);
      setActivePhase('streaming');

      // Stage 2 — layers light in sequence (over ~1.4s) AND
      //           streams animate to their target values.
      const targets = streamTargetsFor(action);
      for (let i = 0; i < 7; i++) {
        await sleep(180);
        if (stopped) return;
        setActiveLayers(i + 1);
        // Each layer lighting also fills part of the streams (in the
        // order the PDP runs them: deterministic → retrieval → agent
        // identity/cap/beh → specialist → semantic).
        setActiveStreams((prev) => {
          const next = { ...prev };
          const streamForLayer = LAYER_STREAM_MAP[i];
          if (streamForLayer) next[streamForLayer] = targets[streamForLayer];
          return next;
        });
      }

      // Stage 3 — fused score crystallizes
      await sleep(280);
      if (stopped) return;
      setActiveFused(action.fused);
      setActivePhase('fused');

      // Stage 4 — verdict reveals
      await sleep(420);
      if (stopped) return;
      setActiveVerdict(action.verdict);
      setActivePhase('verdict');
      setCounters((c) => ({
        permit:  c.permit  + (action.verdict === 'permit'  ? 1 : 0),
        abstain: c.abstain + (action.verdict === 'abstain' ? 1 : 0),
        forbid:  c.forbid  + (action.verdict === 'forbid'  ? 1 : 0),
        total:   c.total + 1,
      }));

      // Stage 5 — chain stamp (real SHA-256)
      await sleep(420);
      if (stopped) return;
      const block = await mintBlock({
        prevHash: chainTailHash(chain),
        idx: 9420 + cycleIdx,
        action,
        verdict: action.verdict,
        ts: Date.now(),
      });
      setChain((prev) => [...prev, block].slice(-10));

      // Stage 6 — pause, then loop
      await sleep(2400);
      if (stopped) return;
      setActivePhase('idle');
      runEvaluationCycle();
    };

    const discoveryTick = () => {
      if (stopped) return;
      const platform = PLATFORMS[Math.floor(Math.random() * PLATFORMS.length)];
      const baseName = AGENT_NAMES[Math.floor(Math.random() * AGENT_NAMES.length)];
      const name = `${baseName}-${Math.floor(Math.random() * 90 + 10)}`;
      const risk = RISK_BANDS[Math.floor(Math.random() * 4)];
      const newRow = {
        ts: nowStamp(),
        name,
        platform,
        risk,
        lastseen: `${Math.floor(Math.random() * 30 + 1)}s ago`,
        isNew: true,
      };
      setFeed((prev) => [{ ...newRow }, ...prev.map((r) => ({ ...r, isNew: false }))].slice(0, 14));
      setDiscoveryStats((s) => ({
        total: s.total + 1,
        pending: s.pending + (Math.random() < 0.35 ? 1 : 0),
        quarantined: s.quarantined,
      }));
      setTimeout(discoveryTick, 2500 + Math.random() * 2500);
    };

    const rosterTick = () => {
      if (stopped) return;
      // Pick a random agent and tick its lifecycle.
      setRoster((prev) => {
        const idx = Math.floor(Math.random() * prev.length);
        const next = prev.map((agent, i) => {
          if (i !== idx) return { ...agent, changed: false };
          // Cycle pending → active → quarantined → revoked → pending
          const transitions = { pending: 'active', active: 'quarantined', quarantined: 'revoked', revoked: 'active' };
          const newLife = transitions[agent.life] || 'active';
          return { ...agent, life: newLife, changed: true };
        });
        return next;
      });
      setTimeout(rosterTick, 9000 + Math.random() * 6000);
    };

    const calibrationTick = () => {
      if (stopped) return;
      setCalibration((cal) => {
        // Drift permit / forbid thresholds slightly based on a synthetic
        // outcome event. Keep history short.
        const direction = Math.random() < 0.5 ? 1 : -1;
        const dPermit = direction * (Math.random() * 0.012 + 0.003);
        const newPermitT = Math.max(0.30, Math.min(0.55, cal.permitT + dPermit));
        const newForbidT = Math.max(0.70, Math.min(0.88, cal.forbidT - dPermit * 0.4));

        const evt = {
          ts: nowStamp(),
          msg: synthCalibrationMessage({
            permitDelta: newPermitT - cal.permitT,
          }),
        };

        const newHistory = [
          ...cal.history.slice(1),
          { permitT: newPermitT, forbidT: newForbidT },
        ];

        return {
          permitT: newPermitT,
          forbidT: newForbidT,
          minConf: cal.minConf,
          history: newHistory,
          events: [evt, ...cal.events].slice(0, 5),
        };
      });
      setTimeout(calibrationTick, 7000 + Math.random() * 4000);
    };

    runEvaluationCycle();
    setTimeout(discoveryTick, 1800);
    setTimeout(rosterTick, 4000);
    setTimeout(calibrationTick, 5500);

    return () => {
      stopped = true;
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return {
    feed,
    roster,
    activeAction,
    activeStreams,
    activeFused,
    activeVerdict,
    activePhase,
    activeLayers,
    chain,
    counters,
    calibration,
    discoveryStats,
  };
}

/* ─────────────── helpers ─────────────── */

function emptyStreams() {
  return {
    identity: 0,
    capability: 0,
    behavioral: 0,
    deterministic: 0,
    retrieval: 0,
    specialist: 0,
    semantic: 0,
  };
}

// The layer order Tex actually executes in.
// 0 Discovery, 1 Registration, 2 Capability, 3 Evaluation,
// 4 Enforcement, 5 Evidence, 6 Learning
// During evaluation, layers 3-6 also progressively fill the seven
// content streams. Layers 0-2 set up the agent context (no stream).
const LAYER_STREAM_MAP = {
  0: 'identity',         // discovery confirms the agent exists
  1: 'capability',       // registration assigns the surface
  2: 'behavioral',       // capability layer evaluates surface match → behavioral baseline
  3: 'deterministic',    // evaluation layer 1: deterministic
  4: 'retrieval',        // evaluation layer 2: retrieval grounding
  5: 'specialist',       // evaluation layer 3: specialist judges
  6: 'semantic',         // evaluation layer 4: semantic
};

function streamTargetsFor(action) {
  // Synthesize per-stream scores that fuse to roughly action.fused.
  // Higher fused = higher streams overall; with deterministic, semantic,
  // and specialist tracking the verdict more strongly than retrieval/agent.
  const f = action.fused;
  const jitter = () => (Math.random() * 0.18 - 0.09);
  const clamp = (x) => Math.max(0, Math.min(1, x));

  if (action.verdict === 'permit') {
    return {
      identity:      clamp(0.22 + jitter()),
      capability:    clamp(0.18 + jitter()),
      behavioral:    clamp(0.20 + jitter()),
      deterministic: clamp(0.25 + jitter()),
      retrieval:     clamp(0.30 + jitter()),
      specialist:    clamp(0.22 + jitter()),
      semantic:      clamp(0.28 + jitter()),
    };
  }
  if (action.verdict === 'abstain') {
    return {
      identity:      clamp(0.30 + jitter()),
      capability:    clamp(0.42 + jitter()),
      behavioral:    clamp(0.38 + jitter()),
      deterministic: clamp(0.55 + jitter()),
      retrieval:     clamp(0.62 + jitter()),
      specialist:    clamp(0.66 + jitter()),
      semantic:      clamp(0.71 + jitter()),
    };
  }
  // forbid
  return {
    identity:      clamp(0.74 + jitter()),
    capability:    clamp(0.61 + jitter()),
    behavioral:    clamp(0.74 + jitter()),
    deterministic: clamp(0.90 + jitter()),
    retrieval:     clamp(0.83 + jitter()),
    specialist:    clamp(0.91 + jitter()),
    semantic:      clamp(0.86 + jitter()),
  };
}

function pickContent(verdict) {
  const pool = CONTENT_LINES[verdict];
  return pool[Math.floor(Math.random() * pool.length)];
}

function chainTailHash(chain) {
  if (chain.length === 0) return '0'.repeat(64);
  return chain[chain.length - 1].hash;
}

async function mintBlock({ prevHash, idx, action, verdict, ts }) {
  const payload = JSON.stringify({
    block: idx,
    layer: verdict === 'forbid' ? 'enforcement' : 'evidence',
    agent: action.agent,
    action: action.verb,
    target: action.target,
    verdict,
    ts: Math.floor(ts),
  });
  const hash = await sha256Hex(payload + '|' + prevHash);
  return {
    idx,
    layer: verdict === 'forbid' ? 'Enforcement' : 'Evaluation',
    agent: action.agent,
    action: action.verb,
    target: action.target,
    verdict,
    hash,
    prevHash,
    ts,
  };
}

async function sha256Hex(str) {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const buf = new TextEncoder().encode(str);
    const hashBuf = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(hashBuf)).map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  let s = '';
  const c = '0123456789abcdef';
  for (let i = 0; i < 64; i++) s += c[Math.floor(Math.random() * 16)];
  return s;
}

function nowStamp() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function seedCalibrationHistory() {
  const out = [];
  let p = 0.42, f = 0.78;
  for (let i = 0; i < 24; i++) {
    p += (Math.random() - 0.5) * 0.012;
    f += (Math.random() - 0.5) * 0.008;
    p = Math.max(0.36, Math.min(0.48, p));
    f = Math.max(0.74, Math.min(0.84, f));
    out.push({ permitT: p, forbidT: f });
  }
  return out;
}

function seedCalibrationEvents() {
  return [
    { ts: '04:08:21', msg: 'Reviewers approved 4 ABSTAIN cases. Permit threshold: 0.421 → 0.426 (▲0.005).' },
    { ts: '04:01:08', msg: 'Capability drift detected on agent finance-bot-02. Behavioral baseline retrained.' },
    { ts: '03:54:12', msg: '12 outbound emails landed without recipient complaint. Recipient-domain trust ▲ for 4 domains.' },
    { ts: '03:47:39', msg: 'Forbid streak broken on agent sdr-agent-09. Cold-start window extended.' },
  ];
}

function synthCalibrationMessage({ permitDelta }) {
  const dir = permitDelta > 0 ? '▲' : '▼';
  const cls = permitDelta > 0 ? 'delta-up' : 'delta-down';
  const abs = Math.abs(permitDelta).toFixed(3);
  const candidates = [
    `Reviewers approved <strong>${Math.floor(Math.random() * 6 + 2)} ABSTAIN cases</strong>. Permit threshold drift: <span class="${cls}">${dir}${abs}</span>.`,
    `<strong>${Math.floor(Math.random() * 8 + 4)} outbound emails</strong> landed without recipient complaint. Domain trust <span class="${cls}">${dir}</span>.`,
    `Capability drift detected on <strong>${pickAgent()}</strong>. Behavioral baseline retrained.`,
    `Forbid streak broken on <strong>${pickAgent()}</strong>. Cold-start window extended by 6h.`,
    `Tenant baseline updated. <strong>${Math.floor(Math.random() * 30 + 5)} new content signatures</strong> ingested.`,
  ];
  return candidates[Math.floor(Math.random() * candidates.length)];
}

function pickAgent() {
  return AGENT_NAMES[Math.floor(Math.random() * 8)];
}
