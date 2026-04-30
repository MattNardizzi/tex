import React, { useEffect, useRef, useState, useCallback } from 'react';
import { TexField } from './TexField.js';

const STAGES = [
  { num: '01', name: 'Discovery',    desc: 'Find every agent' },
  { num: '02', name: 'Registration', desc: 'Bind to identity' },
  { num: '03', name: 'Capability',   desc: 'Define allowed' },
  { num: '04', name: 'Evaluation',   desc: 'Judge each act' },
  { num: '05', name: 'Enforcement',  desc: 'Permit · Block' },
  { num: '06', name: 'Evidence',     desc: 'Hash · Replay' },
  { num: '07', name: 'Learning',     desc: 'Calibrate · Drift' },
];

const SEED_RECEIPTS = [
  { hash: '0x7f3a91c2', kind: 'slack.dm',          agent: 'artisan-sdr-04',  verdict: 'permit',  ms: '1.7' },
  { hash: '0x9c12ab08', kind: 'postgres.delete',   agent: 'ops-runbook-12',  verdict: 'forbid',  ms: '2.4' },
  { hash: '0x4b8d5e71', kind: 'stripe.refund',     agent: 'ada-support-07',  verdict: 'abstain', ms: '3.1' },
  { hash: '0xe2901b4f', kind: 'github.push',       agent: 'cursor-agent-19', verdict: 'permit',  ms: '0.9' },
  { hash: '0x1d3c8a6b', kind: 'shell.exec',        agent: 'claude-code-03',  verdict: 'forbid',  ms: '1.2' },
  { hash: '0x6a07f2e9', kind: 'salesforce.update', agent: '11x-ada-22',      verdict: 'permit',  ms: '2.0' },
  { hash: '0xb84e1c50', kind: 'iam.grant',         agent: 'sec-triage-01',   verdict: 'forbid',  ms: '1.5' },
  { hash: '0x3f9d72a4', kind: 'docs.share',        agent: 'glean-research-08', verdict: 'abstain', ms: '2.7' },
  { hash: '0xc5b21e7d', kind: 'calendar.invite',   agent: 'rev-ops-15',      verdict: 'permit',  ms: '1.1' },
  { hash: '0x8e4a6f31', kind: 'mcp.tool_call',     agent: 'mcp-tool-44',     verdict: 'permit',  ms: '0.8' },
  { hash: '0x21d8b9c4', kind: 'twilio.sms',        agent: 'fin-bot-09',      verdict: 'permit',  ms: '1.4' },
  { hash: '0xf60c2a18', kind: 'file.delete',       agent: 'data-eng-06',     verdict: 'forbid',  ms: '0.9' },
];

export default function App() {
  const stageRef = useRef(null);
  const fieldRef = useRef(null);

  const [counts, setCounts] = useState(() => {
    const seed = 14000 + Math.floor(Math.random() * 4000);
    const forbid = Math.floor(seed * 0.07);
    const abstain = Math.floor(seed * 0.11);
    const permit = seed - forbid - abstain;
    return { permit, abstain, forbid, total: seed };
  });
  const [receipts, setReceipts] = useState(SEED_RECEIPTS);

  // Hero overlay state — describes what is currently being narrated.
  // Rendered by <HeroOverlay /> as floating DOM labels positioned at the
  // hero action's projected screen coordinates.
  const [hero, setHero] = useState(null);

  const onReceipt = useCallback((r) => {
    setCounts((c) => ({
      permit:  c.permit  + (r.verdict === 'permit'  ? 1 : 0),
      abstain: c.abstain + (r.verdict === 'abstain' ? 1 : 0),
      forbid:  c.forbid  + (r.verdict === 'forbid'  ? 1 : 0),
      total:   c.total + 1,
    }));
    setReceipts((prev) => [r, ...prev].slice(0, 32));
  }, []);

  const onHeroEvent = useCallback((evt) => {
    if (evt.type === 'spawn') {
      setHero({
        kind: evt.kind,
        agent: evt.agent,
        verdict: null,           // hidden until 'verdict' phase
        verdictRevealed: false,
        hash: evt.hash,
        screen: evt.origin,
        phase: 'travel',
        evidenceScreen: null,
      });
    } else if (evt.type === 'travel' || evt.type === 'evaluate-tick' || evt.type === 'verdict-tick') {
      setHero((h) => h ? { ...h, screen: evt.screen } : h);
    } else if (evt.type === 'evaluate') {
      setHero((h) => h ? { ...h, screen: evt.screen, phase: 'evaluate' } : h);
    } else if (evt.type === 'verdict') {
      setHero((h) => h ? {
        ...h,
        screen: evt.screen,
        phase: 'verdict',
        verdict: evt.verdict,
        verdictRevealed: true,
      } : h);
    } else if (evt.type === 'evidence') {
      setHero((h) => h ? {
        ...h,
        phase: 'evidence',
        evidenceScreen: evt.screen,
      } : h);
    } else if (evt.type === 'end') {
      setHero(null);
    }
  }, []);

  useEffect(() => {
    if (!stageRef.current) return;
    const field = new TexField(stageRef.current, {
      texImageUrl: '/tex.webp',
      onReceipt,
      onHeroEvent,
    });
    fieldRef.current = field;
    return () => {
      field.destroy();
      fieldRef.current = null;
    };
  }, [onReceipt, onHeroEvent]);

  const ticker = receipts.concat(receipts);

  return (
    <div className="shell">
      <div ref={stageRef} className="stage">
        {/* Top brand bar */}
        <div className="brand">
          <div className="brand-mark" aria-label="Tex">
            <BrandHex />
            <span className="brand-name">TEX</span>
          </div>
          <div className="brand-tag">
            <span className="live-dot" />
            Authority Layer · Live
          </div>
        </div>

        {/* Hero overlay — labels for the focal action */}
        <HeroOverlay hero={hero} />

        {/* Headline overlay */}
        <div className="hero">
          <div className="hero-eyebrow">Before AI acts, Tex decides</div>
          <h1 className="hero-headline">
            The authority layer<br />
            between AI <em>and the real world</em>.
          </h1>
          <p className="hero-sub">
            Watch every AI agent action — emails, database writes, Slack messages, refunds, deploys — pass through one cryptographically-linked loop. Permit, abstain, or forbid. Auditor-verifiable proof.
          </p>
        </div>

        {/* Legend (top-right) */}
        <aside className="legend" aria-label="The seven stages">
          <div className="legend-title">
            <span>The Loop</span>
            <span className="legend-title-count">07 stages</span>
          </div>
          {STAGES.map((s) => (
            <div className="legend-row" key={s.num}>
              <span className="legend-num">{s.num}</span>
              <span className="legend-name">{s.name}</span>
              <span className="legend-desc">{s.desc}</span>
            </div>
          ))}
        </aside>

        {/* Live metrics (bottom-left) */}
        <div className="metrics" aria-live="polite">
          <Metric label="Permit"    value={counts.permit}  klass="permit" />
          <Metric label="Abstain"   value={counts.abstain} klass="abstain" />
          <Metric label="Forbid"    value={counts.forbid}  klass="forbid" />
          <Metric label="Evaluated" value={counts.total}   klass="" />
        </div>

        {/* CTA dock (bottom-right) */}
        <div className="cta-dock">
          <div className="cta-meta">
            <div className="cta-meta-line">Run a real action</div>
            <div className="cta-meta-line">Through the live engine</div>
          </div>
          <a className="cta" href="https://vortexblack.ai/contact" rel="noopener">
            Request a demo
            <span className="cta-arrow">→</span>
          </a>
        </div>

        {/* Receipts ticker */}
        <div className="receipts" aria-hidden="true">
          <div className="receipts-track">
            <div className="receipts-flow">
              {ticker.map((r, i) => (
                <Receipt key={i + r.hash} r={r} />
              ))}
            </div>
          </div>
        </div>

        <div className="scroll-cue" aria-hidden="true">
          <span>Continue</span>
          <span className="scroll-cue-line" />
        </div>
      </div>

      <Manifesto />
      <Pillars />
      <Foot />
    </div>
  );
}

/**
 * HeroOverlay — the labels the buyer actually reads.
 *
 * As the field's hero action progresses, this component renders:
 *  - a small action card (kind + agent) attached to the action head
 *  - a stage tag (04 EVALUATION / 05 ENFORCEMENT / 06 EVIDENCE) that
 *    pulses inline at the right moment
 *  - the VERDICT label (PERMIT / ABSTAIN / FORBID) in the verdict color,
 *    persisting through the verdict phase
 *  - an EVIDENCE chip with the hash that flies down to the chain band
 */
function HeroOverlay({ hero }) {
  if (!hero || !hero.screen) return null;

  const { x, y } = hero.screen;
  const cardStyle = { transform: `translate(-50%, -50%) translate(${x}px, ${y - 56}px)` };

  return (
    <div className="hero-overlay" aria-hidden="true">
      {/* Action card — visible during travel + evaluate phases */}
      {(hero.phase === 'travel' || hero.phase === 'evaluate') && (
        <div className="ho-card" style={cardStyle}>
          <span className="ho-card-kind">{hero.kind}</span>
          <span className="ho-card-sep">·</span>
          <span className="ho-card-agent">agent: {hero.agent}</span>
        </div>
      )}

      {/* Stage tag — 04 Evaluation while Tex evaluates */}
      {hero.phase === 'evaluate' && (
        <div
          className="ho-stage stage-04"
          style={{ transform: `translate(-50%, -50%) translate(${x}px, ${y + 64}px)` }}
        >
          <span className="ho-stage-num">04</span>
          <span className="ho-stage-name">Evaluation</span>
        </div>
      )}

      {/* Verdict label — appears in 05 Enforcement phase, with verdict text */}
      {hero.phase === 'verdict' && hero.verdictRevealed && (
        <div
          className={`ho-verdict v-${hero.verdict}`}
          style={{ transform: `translate(-50%, -50%) translate(${x}px, ${y - 56}px)` }}
        >
          <div className="ho-verdict-row">
            <span className="ho-verdict-stage">05 Enforcement</span>
          </div>
          <div className="ho-verdict-row">
            <span className="ho-verdict-label">{hero.verdict.toUpperCase()}</span>
          </div>
          <div className="ho-verdict-row ho-verdict-context">
            <span className="ho-verdict-kind">{hero.kind}</span>
            <span className="ho-card-sep">·</span>
            <span>agent: {hero.agent}</span>
          </div>
        </div>
      )}

      {/* Evidence chip — flies down to the hash chain */}
      {hero.phase === 'evidence' && hero.evidenceScreen && (
        <div
          className="ho-evidence"
          style={{
            transform: `translate(-50%, -50%) translate(${hero.evidenceScreen.x}px, ${hero.evidenceScreen.y - 28}px)`,
          }}
        >
          <span className="ho-evidence-stage">06 Evidence</span>
          <span className="ho-evidence-hash">{hero.hash}</span>
        </div>
      )}
    </div>
  );
}

function Metric({ label, value, klass }) {
  return (
    <div className="metric">
      <div className="metric-label">{label}</div>
      <div className={`metric-value ${klass}`}>{value.toLocaleString()}</div>
    </div>
  );
}

function Receipt({ r }) {
  const glyph = r.verdict === 'permit' ? '✓' : r.verdict === 'forbid' ? '✕' : '◇';
  const glyphClass = r.verdict === 'permit' ? 'ok' : r.verdict === 'forbid' ? 'no' : 'maybe';
  return (
    <span className="receipt">
      <span className={`glyph ${glyphClass}`}>{glyph}</span>
      <span className="hash">{r.hash}</span>
      <span className="receipt-sep">·</span>
      <span>{r.kind}</span>
      <span className="receipt-sep">·</span>
      <span>agent: {r.agent}</span>
      <span className="receipt-sep">·</span>
      <span className={`verdict ${r.verdict}`}>{r.verdict.toUpperCase()}</span>
      <span className="receipt-sep">·</span>
      <span>{r.ms}ms</span>
    </span>
  );
}

function BrandHex() {
  return (
    <svg className="brand-hex" viewBox="0 0 26 30" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M13 1.155L24.124 7.578v12.844L13 26.845L1.876 20.422V7.578L13 1.155Z"
            stroke="#00d9ff" strokeWidth="1.4" />
      <text x="13" y="19" fontFamily="Fraunces, serif" fontSize="13" fontWeight="500"
            fill="#00d9ff" textAnchor="middle">T</text>
    </svg>
  );
}

function Manifesto() {
  return (
    <section className="manifesto">
      <div className="manifesto-inner">
        <div className="manifesto-eyebrow">The position</div>
        <p className="manifesto-text">
          AI agents are taking real-world actions across your business right now.
          <br /><span className="ghost">Writing emails. Updating your database. Posting in Slack. Making promises to customers.</span>
          <br /><br />
          Most platforms control a moment — or a single layer.
          <br /><em>Tex controls the entire system.</em>
          <br /><br />
          One continuous loop of control, enforcement, and proof.
        </p>
      </div>
    </section>
  );
}

function Pillars() {
  const items = [
    { num: '01', name: 'Discovery',    desc: 'Tex finds every AI agent across Microsoft Graph, Salesforce, Bedrock, GitHub, OpenAI, and MCP — including the ones you didn\'t know existed.' },
    { num: '02', name: 'Registration', desc: 'Each agent is bound to a verified identity, lifecycle state, and owner. No agent acts without a record.' },
    { num: '03', name: 'Capability',   desc: 'Tex defines what each agent is allowed to do. Capability is policy — not vibes, not prompts.' },
    { num: '04', name: 'Evaluation',   desc: 'Every action passes a six-layer pipeline: deterministic, retrieval, specialists, semantic, fusion, ASI findings.' },
    { num: '05', name: 'Enforcement',  desc: 'PERMIT, ABSTAIN, or FORBID — returned in milliseconds, before the action executes. Across any channel, any system.' },
    { num: '06', name: 'Evidence',     desc: 'Every decision is SHA-256 hash-chained. Replay any action. Export auditor-verifiable bundles. Tamper-evident by design.' },
    { num: '07', name: 'Learning',     desc: 'Outcomes feed back. Thresholds calibrate. Drift detects. The system improves without you rewriting policy.' },
  ];
  return (
    <section className="pillars">
      <div className="pillars-inner">
        <div className="pillars-head">
          <div className="pillars-eyebrow">Seven stages · One loop</div>
          <h2 className="pillars-title">Not seven products. One system.</h2>
        </div>
        <div className="pillar-grid">
          {items.map((p) => (
            <div className="pillar" key={p.num}>
              <div className="pillar-num">{p.num}</div>
              <div className="pillar-name">{p.name}</div>
              <div className="pillar-desc">{p.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function Foot() {
  return (
    <footer className="foot">
      <span>VortexBlack · Tex · {new Date().getFullYear()}</span>
      <span><a href="https://vortexblack.ai">vortexblack.ai</a></span>
    </footer>
  );
}
