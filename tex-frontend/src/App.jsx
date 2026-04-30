import React from 'react';
import { useBridge } from './Bridge.js';
import texAvatar from './tex-avatar.jpg';
import Sevenfold from './Sevenfold.jsx';
import './sevenfold.css';

/* ────────────────────────────────────────────────────────────────────
 * Tex — texaegis.com
 * The Command Bridge.
 *
 * The homepage is one always-on operating environment. Tex is on duty
 * before the buyer arrives and after they leave. Every scene is a
 * different instrument on the same bridge:
 *
 *   00  Cold open      — three lines, the world before the bridge
 *   01  Discovery      — live agent manifest
 *   02  Registration   — roster with trust tiers and lifecycle
 *   03  Capability     — declared surface as a constraint grid
 *   04  Evaluation     — Tex front and center, seven streams firing
 *   05  Enforcement    — two lanes, permit flows, forbid blocked
 *   06  Evidence       — the cryptographic chain extending
 *   07  Learning       — calibrator drifting from real outcomes
 *   --  Wedge          — Tex vs every other vendor
 *   --  Trial          — the audit CTA
 *   --  Manifesto      — closing
 *   --  Foot
 * ──────────────────────────────────────────────────────────────────── */

export default function App() {
  const bridge = useBridge();

  return (
    <>
      <div className="bridge-bg" aria-hidden="true" />
      <div className="bridge-vignette" aria-hidden="true" />
      <div className="grain" aria-hidden="true" />

      <Hud counters={bridge.counters} />

      {/* TexPresence — the persistent sigil. Tex is watching every
          scene, eye-glow synced to the live verdict. Floats in the
          right gutter. Visible throughout. */}
      <TexPresence verdict={bridge.activeVerdict} phase={bridge.activePhase} />

      <Sevenfold
        verdict={bridge.activeVerdict}
        phase={bridge.activePhase}
        counters={bridge.counters}
        chain={bridge.chain}
        activeAction={bridge.activeAction}
        activeStreams={bridge.activeStreams}
        activeFused={bridge.activeFused}
        activeLayers={bridge.activeLayers}
      />

      <SceneDiscovery feed={bridge.feed} stats={bridge.discoveryStats} verdict={bridge.activeVerdict} />

      <SceneRegistration roster={bridge.roster} verdict={bridge.activeVerdict} />

      <SceneCapability verdict={bridge.activeVerdict} />

      <SceneEvaluation bridge={bridge} />

      <SceneEnforcement verdict={bridge.activeVerdict} />

      <SceneEvidence chain={bridge.chain} verdict={bridge.activeVerdict} />

      <SceneLearning calibration={bridge.calibration} verdict={bridge.activeVerdict} />

      <Wedge />

      <Monolith bridge={bridge} />

      <Trial />

      <Manifesto />

      <Foot />
    </>
  );
}

/* ─────────────────────── Tex Presence — the persistent watcher ─────────────────────── */

function TexPresence({ verdict, phase }) {
  // A small Tex sigil fixed to the viewport edge. Eye-glow color
  // tracks the live verdict. This is what makes Tex "visible
  // throughout" — every scene, the buyer feels watched.
  return (
    <div className={`tex-presence verdict-${verdict || 'idle'} phase-${phase || 'idle'}`} aria-hidden="true">
      <div className="tex-presence-frame">
        <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
          {/* outer hexagon */}
          <polygon points="50,6 88,28 88,72 50,94 12,72 12,28" fill="none" stroke="currentColor" strokeWidth="1.4" opacity="0.45" />
          {/* inner hexagon — the sigil */}
          <polygon points="50,22 76,36 76,64 50,78 24,64 24,36" fill="none" stroke="currentColor" strokeWidth="1.4" />
          {/* T mark */}
          <line x1="36" y1="40" x2="64" y2="40" stroke="currentColor" strokeWidth="2" />
          <line x1="50" y1="40" x2="50" y2="62" stroke="currentColor" strokeWidth="2" />
          {/* the eye — pulses */}
          <circle cx="50" cy="50" r="3.4" fill="currentColor" className="tex-presence-eye" />
        </svg>
      </div>
      <div className="tex-presence-meta">
        <span className="tex-presence-status">
          <span className="dot" /> tex
        </span>
        <span className="tex-presence-verdict">{verdict ? verdict : 'watching'}</span>
      </div>
    </div>
  );
}

/* ─────────────────────── Hero Reveal — Tex emerges from darkness ─────────────────────── */

function HeroReveal({ verdict, counters }) {
  return (
    <section className="hero-reveal" aria-label="tex">
      <div className="hero-reveal-aura" aria-hidden="true" />
      <div className="hero-reveal-grid" aria-hidden="true" />

      <div className="hero-reveal-figure">
        <img src={texAvatar} alt="Tex" />
        <div className={`hero-reveal-eye verdict-${verdict || 'idle'}`} aria-hidden="true" />
      </div>

      <div className="hero-reveal-flank hero-reveal-flank-l">
        <div className="hero-reveal-tag">// adjudicator</div>
        <div className="hero-reveal-stat">
          <span className="num">{(counters.permit + counters.abstain + counters.forbid).toLocaleString()}</span>
          <span className="lbl">actions evaluated · this tenant</span>
        </div>
        <div className="hero-reveal-stat">
          <span className="num">2,847</span>
          <span className="lbl">agents under watch</span>
        </div>
        <div className="hero-reveal-stat">
          <span className="num">7 / 7</span>
          <span className="lbl">layers active</span>
        </div>
      </div>

      <div className="hero-reveal-flank hero-reveal-flank-r">
        <div className="hero-reveal-tag" style={{ textAlign: 'right' }}>// chain</div>
        <div className="hero-reveal-stat right">
          <span className="num">9,423</span>
          <span className="lbl">blocks · sealed</span>
        </div>
        <div className="hero-reveal-stat right">
          <span className="num">0</span>
          <span className="lbl">gaps · last 30d</span>
        </div>
        <div className="hero-reveal-stat right">
          <span className="num">1.4ms</span>
          <span className="lbl">gate latency · p50</span>
        </div>
      </div>

      <div className="hero-reveal-name">
        <div className="hero-reveal-eyebrow">// the system</div>
        <h1 className="hero-reveal-title">
          <span>Tex</span>
        </h1>
        <p className="hero-reveal-sub">
          Identity. Posture. Behavior. Policy. Detection. Enforcement. Audit.<br/>
          <em>Seven layers. One adjudicator. One sealed cryptographic chain.</em>
        </p>
      </div>

      <div className="hero-reveal-floor" aria-hidden="true" />
    </section>
  );
}

/* ─────────────────────── Monolith — closing presence before manifesto ─────────────────────── */

function Monolith({ bridge }) {
  return (
    <section className="monolith" aria-label="monolith">
      <div className="monolith-aura" aria-hidden="true" />

      <div className="monolith-grid">
        <div className="monolith-col monolith-col-l">
          <div className="monolith-pair">
            <span className="k">// discovery</span>
            <span className="v">2,847 agents</span>
            <span className="n">found across 7 connectors</span>
          </div>
          <div className="monolith-pair">
            <span className="k">// registration</span>
            <span className="v">2,535 active</span>
            <span className="n">312 held · 14 quarantined · 1 revoked</span>
          </div>
          <div className="monolith-pair">
            <span className="k">// capability</span>
            <span className="v">surface bound</span>
            <span className="n">23 cells · agent · sales-agent-04</span>
          </div>
          <div className="monolith-pair">
            <span className="k">// evaluation</span>
            <span className="v">{bridge.counters.total.toLocaleString()} judgments</span>
            <span className="n">7 streams · fused · 2.4ms p50</span>
          </div>
        </div>

        <div className="monolith-figure">
          <img src={texAvatar} alt="" />
          <div className="monolith-rings" aria-hidden="true">
            <div className="monolith-ring r1" />
            <div className="monolith-ring r2" />
            <div className="monolith-ring r3" />
          </div>
          <div className="monolith-name">
            <span className="eyebrow">// the system</span>
            <span className="title">Tex</span>
          </div>
        </div>

        <div className="monolith-col monolith-col-r">
          <div className="monolith-pair right">
            <span className="k">// enforcement</span>
            <span className="v">{bridge.counters.forbid.toLocaleString()} blocks</span>
            <span className="n">action did not execute</span>
          </div>
          <div className="monolith-pair right">
            <span className="k">// evidence</span>
            <span className="v">9,423 blocks</span>
            <span className="n">SHA-256 · sealed · 0 gaps</span>
          </div>
          <div className="monolith-pair right">
            <span className="k">// learning</span>
            <span className="v">drift · live</span>
            <span className="n">permit {bridge.calibration.permitT.toFixed(3)} · forbid {bridge.calibration.forbidT.toFixed(3)}</span>
          </div>
          <div className="monolith-pair right">
            <span className="k">// status</span>
            <span className="v" style={{ color: 'var(--green)' }}>on duty</span>
            <span className="n">heartbeat · 1.0s · uptime 99.998%</span>
          </div>
        </div>
      </div>

      <div className="monolith-payoff">
        Nine vendors couldn't do this. <em>One Tex does.</em>
      </div>
    </section>
  );
}

/* ─────────────────────── Persistent HUD ─────────────────────── */

function Hud({ counters }) {
  return (
    <div className="hud" role="banner">
      <div className="hud-left">
        <div className="hud-brand">
          <span className="hud-mark" aria-hidden="true" />
          Tex
        </div>
        <span className="hud-status">on duty</span>
      </div>
      <nav className="hud-center" aria-label="primary">
        <a href="#discovery">Discovery</a>
        <a href="#registration">Registration</a>
        <a href="#capability">Capability</a>
        <a href="#evaluation">Evaluation</a>
        <a href="#enforcement">Enforcement</a>
        <a href="#evidence">Evidence</a>
        <a href="#learning">Learning</a>
      </nav>
      <div className="hud-right">
        <span className="hud-counter permit">PERMIT <strong>{counters.permit.toLocaleString()}</strong></span>
        <span className="hud-counter abstain">ABSTAIN <strong>{counters.abstain.toLocaleString()}</strong></span>
        <span className="hud-counter forbid">FORBID <strong>{counters.forbid.toLocaleString()}</strong></span>
      </div>
    </div>
  );
}

/* ─────────────────────── Cold open ─────────────────────── */

function ColdOpen() {
  return (
    <section className="coldopen" aria-label="cold open">
      <div className="coldopen-eyebrow">tex bridge · live</div>
      <div className="coldopen-stack">
        <p>
          <em>2,847</em> AI agents are running in your company right now.
        </p>
        <p>
          You've never seen <em className="amber">2,694</em> of them.
        </p>
        <p>
          Tex sees all of them. Governs all of them. <em>Proves all of them.</em>
        </p>
      </div>
      <div className="coldopen-cue">
        <div className="coldopen-cue-text">enter the bridge</div>
        <div className="coldopen-cue-line" />
      </div>
    </section>
  );
}

/* ─────────────────────── Scene 01 — Discovery ─────────────────────── */

function SceneDiscovery({ feed, stats }) {
  return (
    <section className="scene scene-discovery" id="discovery" aria-label="discovery layer">
      <div>
        <div className="scene-eyebrow">Layer 01 <span className="nm">/ DISCOVERY</span></div>
        <h2 className="scene-title">Tex finds the agents <em>nobody told IT about</em>.</h2>
        <p className="scene-lede">
          Microsoft tenants accumulate Copilot Studio agents the way they accumulate SharePoint sites.
          Salesforce orgs sprout Agentforce bots. Engineering installs Cursor, Cline, and a dozen MCP
          servers. <strong>Tex scans every connector and surfaces every agent</strong> — even
          the ones running on credentials nobody remembers issuing.
        </p>
        <p className="scene-lede" style={{ marginTop: 18 }}>
          Each candidate gets a risk band, a reconciliation key, and a held-for-review state.
          <em> Nothing escapes inventory.</em>
        </p>
      </div>

      <div className="discovery-instrument panel">
        <div className="panel-bar">
          <div className="panel-bar-l">
            <strong>discovery.feed</strong>
            <span>tex-bridge / live</span>
          </div>
          <span className="panel-bar-status">scanning</span>
        </div>

        <div className="disc-connectors" role="list">
          <div className="disc-conn scanning"><span className="disc-conn-name">MS Graph</span><span className="disc-conn-state">scan…</span></div>
          <div className="disc-conn done">    <span className="disc-conn-name">Salesforce</span><span className="disc-conn-state">412</span></div>
          <div className="disc-conn scanning"><span className="disc-conn-name">Bedrock</span> <span className="disc-conn-state">scan…</span></div>
          <div className="disc-conn done">    <span className="disc-conn-name">GitHub</span>   <span className="disc-conn-state">208</span></div>
          <div className="disc-conn done">    <span className="disc-conn-name">OpenAI</span>   <span className="disc-conn-state">147</span></div>
          <div className="disc-conn scanning"><span className="disc-conn-name">MCP</span>      <span className="disc-conn-state">scan…</span></div>
        </div>

        <div className="disc-feed" role="log" aria-live="polite">
          <div className="disc-feed-list">
            {feed.map((row, i) => (
              <div key={`${row.ts}-${row.name}-${i}`} className={`disc-row${row.isNew ? ' new' : ''}`}>
                <span className="platform">{row.platform.replace(' ', '\u00A0')}</span>
                <span className="name">{row.name}</span>
                <span className="lastseen">{row.lastseen}</span>
                <span className={`risk ${row.risk}`}>{row.risk}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="disc-summary">
          <div className="disc-sum-cell">
            <div className="disc-sum-num"><em>{stats.total.toLocaleString()}</em></div>
            <div className="disc-sum-lbl">Discovered</div>
          </div>
          <div className="disc-sum-cell">
            <div className="disc-sum-num">{stats.pending}</div>
            <div className="disc-sum-lbl">Held for review</div>
          </div>
          <div className="disc-sum-cell">
            <div className="disc-sum-num">{stats.quarantined}</div>
            <div className="disc-sum-lbl">Quarantined</div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ─────────────────────── Scene 02 — Registration ─────────────────────── */

function SceneRegistration({ roster }) {
  return (
    <section className="scene scene-registration" id="registration" aria-label="registration layer">
      <div className="reg-roster panel">
        <div className="panel-bar">
          <div className="panel-bar-l">
            <strong>roster.active</strong>
            <span>{roster.length} of 2,847 shown</span>
          </div>
          <span className="panel-bar-status">live</span>
        </div>

        {roster.map((agent, i) => (
          <div className={`reg-row${agent.changed ? ' changed' : ''}`} key={`${agent.name}-${i}`}>
            <div className="reg-glyph">
              <Glyph kind={agent.glyph} />
            </div>
            <div>
              <div className="reg-name">{agent.name}</div>
              <div className="reg-owner">{agent.owner}{agent.platform.toLowerCase().split(' ')[0]} · {agent.platform}</div>
            </div>
            <span className={`reg-tier ${agent.tier}`}>{agent.tier}</span>
            <div className="reg-lifecycle">
              <span className={`reg-life-state ${agent.life}`}>{agent.life}</span>
            </div>
          </div>
        ))}
      </div>

      <div className="reg-detail">
        <div className="scene-eyebrow">Layer 02 <span className="nm">/ REGISTRATION</span></div>
        <h2 className="scene-title">Every agent has <em>a name, an owner, and a clock</em>.</h2>
        <p className="scene-lede">
          Tex doesn't trust a discovered agent. It registers it — assigning a UUID, a trust tier
          (UNVERIFIED → STANDARD → TRUSTED → PRIVILEGED), an owner email, and a lifecycle state.
          <strong> When an agent drifts, Tex moves it to QUARANTINED automatically.</strong>
          When it's terminal, it goes REVOKED — and revoke is permanent.
        </p>
        <div className="reg-detail-card" style={{ marginTop: 28 }}>
          <div className="reg-detail-eyebrow">attestation chain</div>
          <div className="reg-detail-title">Issued by Tex.<br/>Signed by you.</div>
          <p className="reg-detail-body">
            Each registration is bound to an attestation chain — a series of signed claims from the
            registering operator, the originating platform, and Tex itself. Auditors verify every
            claim. Agents without a complete chain are blocked from sensitive actions.
          </p>
          <div className="reg-detail-attest">
            <div><span className="key">issued_by</span> tex / vortexblack</div>
            <div><span className="key">signed_by</span> matthew.s / eng-prod@</div>
            <div><span className="key">trust_tier</span> STANDARD</div>
            <div><span className="key">attests</span> 3 / 3 active</div>
          </div>
        </div>
      </div>
    </section>
  );
}

function Glyph({ kind = 0 }) {
  // 7 small SVG glyphs that visually distinguish agent platforms.
  // Hexagon, diamond, triangle, square, octagon, circle, asterisk.
  const variants = [
    // 0 — hexagon (Salesforce-ish)
    <polygon points="18,3 31,11 31,25 18,33 5,25 5,11" fill="none" stroke="#5ee0ff" strokeWidth="1.2" />,
    // 1 — diamond (Microsoft Graph)
    <polygon points="18,3 33,18 18,33 3,18" fill="none" stroke="#5ee0ff" strokeWidth="1.2" />,
    // 2 — triangle (Bedrock)
    <polygon points="18,5 33,30 3,30" fill="none" stroke="#5ee0ff" strokeWidth="1.2" />,
    // 3 — square rotated (MCP)
    <rect x="6" y="6" width="24" height="24" fill="none" stroke="#5ee0ff" strokeWidth="1.2" transform="rotate(45 18 18)" />,
    // 4 — octagon (Copilot Studio)
    <polygon points="11,3 25,3 33,11 33,25 25,33 11,33 3,25 3,11" fill="none" stroke="#5ee0ff" strokeWidth="1.2" />,
    // 5 — circle with bar (OpenAI)
    <g><circle cx="18" cy="18" r="13" fill="none" stroke="#5ee0ff" strokeWidth="1.2" /><line x1="6" y1="18" x2="30" y2="18" stroke="#5ee0ff" strokeWidth="1.2" /></g>,
    // 6 — asterisk (custom)
    <g stroke="#5ee0ff" strokeWidth="1.2"><line x1="18" y1="4" x2="18" y2="32" /><line x1="6" y1="11" x2="30" y2="25" /><line x1="6" y1="25" x2="30" y2="11" /></g>,
  ];
  return (
    <svg viewBox="0 0 36 36" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      {variants[kind % variants.length]}
      <circle cx="18" cy="18" r="2" fill="#5ee0ff" />
    </svg>
  );
}

/* ─────────────────────── Scene 03 — Capability ─────────────────────── */

function SceneCapability() {
  // Static-ish for layout; the constraint matrix shows ALLOWED cells.
  // Rows = action types. Columns = channels.
  const ROWS = ['email.send', 'crm.update', 'wire.initiate', 'sharepoint.share', 'tool.call', 'code.commit', 'refund.process'];
  const COLS = ['mailto', 'salesforce', 'banking', 'graph', 'mcp', 'github'];

  // Allowed cells for the example agent. We mark the wire/banking
  // attempt as a violation to dramatize an out-of-surface action.
  const allow = (row, col) => {
    if (row === 'email.send' && col === 'mailto') return 'bright';
    if (row === 'crm.update' && col === 'salesforce') return 'allowed';
    if (row === 'sharepoint.share' && col === 'graph') return 'allowed';
    if (row === 'tool.call' && col === 'mcp') return 'allowed';
    if (row === 'code.commit' && col === 'github') return 'allowed';
    if (row === 'refund.process' && col === 'banking') return 'allowed';
    if (row === 'wire.initiate' && col === 'banking') return 'violation';
    return null;
  };

  return (
    <section className="scene scene-capability" id="capability" aria-label="capability layer">
      <div>
        <div className="scene-eyebrow">Layer 03 <span className="nm">/ CAPABILITY</span></div>
        <h2 className="scene-title">You set what each agent <em>is allowed to touch</em>.</h2>
        <p className="scene-lede">
          Capability isn't a content policy — it's a structural one.
          Action types × channels × environments × recipient bounds.
          The matrix is the agent's entire surface.
          <strong> Anything outside is a CRITICAL finding</strong>, regardless of how innocent the content sounds.
        </p>
        <p className="scene-lede" style={{ marginTop: 18 }}>
          Below: agent <code style={{ color: 'var(--cyan)', fontFamily: 'var(--mono)', fontSize: '13px' }}>sales-agent-04</code> tries to call <code style={{ color: 'var(--red)', fontFamily: 'var(--mono)', fontSize: '13px' }}>wire.initiate</code> on a banking channel. The cell is dark red. <em>Out of surface.</em>
        </p>
      </div>

      <div className="cap-grid-wrap panel">
        <div className="panel-bar">
          <div className="panel-bar-l">
            <strong>surface.matrix</strong>
            <span>agent / sales-agent-04</span>
          </div>
          <span className="panel-bar-status">active</span>
        </div>

        <div style={{ padding: '24px' }}>
          <div className="cap-grid-meta">
            <span>action × channel</span>
            <span>declared surface · <strong>23 cells</strong> · 1 violation</span>
          </div>

          <div className="cap-axis-x">
            <span className="blank" />
            {COLS.map((c) => <span key={c}>{c}</span>)}
          </div>

          <div className="cap-grid-rows">
            {ROWS.map((row) => (
              <div className="cap-grid-row" key={row}>
                <span className="cap-row-label">{row}</span>
                {COLS.map((col) => {
                  const state = allow(row, col);
                  return <span key={col} className={`cap-cell${state ? ` ${state}` : ''}`} />;
                })}
              </div>
            ))}
          </div>

          <div className="cap-incident">
            <span><strong>OUT OF SURFACE</strong> · sales-agent-04 attempted <code>wire.initiate</code> on banking channel · CRITICAL finding · agent moved to QUARANTINED</span>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ─────────────────────── Scene 04 — Evaluation (the theater) ─────────────────────── */

function SceneEvaluation({ bridge }) {
  const { activeAction, activeStreams, activeFused, activeVerdict, activePhase, activeLayers, calibration } = bridge;

  const scoreClass = (v) => v >= 0.65 ? 'high' : v >= 0.4 ? 'med' : '';
  const fusedClass = scoreClass(activeFused);

  return (
    <section className="scene scene-eval" id="evaluation" aria-label="evaluation layer">
      <div className="scene-head" style={{ maxWidth: 1480, margin: '0 auto', padding: '0 40px 40px' }}>
        <div className="scene-head-l">
          <div className="scene-eyebrow">Layer 04 <span className="nm">/ EVALUATION</span></div>
          <h2 className="scene-title">Seven streams of evidence. <em>One verdict.</em></h2>
          <p className="scene-lede">
            Every action is judged on identity, capability, behavior, deterministic rules, retrieval
            precedent, specialist judges, and a structured semantic model.
            <strong> Tex fuses all seven into one bounded score</strong>, weighed by policy, in under three milliseconds.
            The verdict is <em>PERMIT, ABSTAIN, or FORBID</em>. There are no other answers.
          </p>
        </div>
        <div className="scene-head-r">
          <div>tex.pdp / v0.1.0</div>
          <div style={{ marginTop: 8 }}>permit ≤ {calibration.permitT.toFixed(3)} · forbid ≥ {calibration.forbidT.toFixed(3)}</div>
        </div>
      </div>

      <div className="eval-stage">
        <EvalActionCard action={activeAction} phase={activePhase} />
        <div className={`eval-tex verdict-${activeVerdict || 'idle'}`}>
          <img src={texAvatar} alt="" />
          <EvalLayers active={activeLayers} />
          {activeVerdict && (
            <div className={`eval-verdict show`}>
              <div className={`eval-verdict-word ${activeVerdict}`}>{activeVerdict}</div>
            </div>
          )}
          <div className="eval-tex-base">
            <strong>tex</strong> · adjudicator
            <div style={{ fontSize: 9, marginTop: 4, letterSpacing: '0.24em' }}>v0.1.0 · evidence-chain online</div>
          </div>
        </div>
        <EvalStreamsCard streams={activeStreams} fused={activeFused} fusedClass={fusedClass} />
      </div>
    </section>
  );
}

function EvalLayers({ active }) {
  const layers = ['Discov', 'Reg', 'Cap', 'Eval', 'Enf', 'Evid', 'Learn'];
  return (
    <div className="eval-layers" aria-hidden="true">
      {layers.map((l, i) => (
        <div key={l} className={`eval-layer${i < active ? ' lit' : ''}`}>
          <span className="eval-layer-dot" />
          <span className="eval-layer-name">{l}</span>
        </div>
      ))}
    </div>
  );
}

function EvalActionCard({ action, phase }) {
  if (!action) {
    return (
      <div className="eval-action-card">
        <div className="eval-action-eyebrow">
          <span>inbound action</span>
          <span className="ts">awaiting</span>
        </div>
        <div className="eval-action-line" style={{ color: 'var(--ink-faint)' }}>—</div>
      </div>
    );
  }
  const dangerContent = action.danger || (action.verdict === 'forbid' && action.content);
  return (
    <div className="eval-action-card">
      <div className="eval-action-eyebrow">
        <span>inbound action</span>
        <span className="ts">{action.ts}</span>
      </div>
      <div className="eval-action-line">
        <span className="verb">{action.verb}</span>
        <span className="agent">· {action.agent}</span>
      </div>
      <div className="eval-action-rows">
        <div className="row"><span className="key">surface</span><span className="val">{action.surface}</span></div>
        <div className="row"><span className="key">target</span><span className="val">{action.target}</span></div>
        <div className="row"><span className="key">phase</span><span className="val" style={{ textTransform: 'uppercase', letterSpacing: '0.18em', fontSize: 10, color: 'var(--cyan)' }}>{phase}</span></div>
      </div>
      {action.content && (
        <div className={`eval-action-content${action.verdict === 'forbid' ? ' danger' : ''}`}>
          "{action.content}"
        </div>
      )}
    </div>
  );
}

function EvalStreamsCard({ streams, fused, fusedClass }) {
  const STREAMS = [
    { id: 'identity',      name: 'Identity',      w: 0.06 },
    { id: 'capability',    name: 'Capability',    w: 0.09 },
    { id: 'behavioral',    name: 'Behavioral',    w: 0.07 },
    { id: 'deterministic', name: 'Deterministic', w: 0.23 },
    { id: 'retrieval',     name: 'Retrieval',     w: 0.10 },
    { id: 'specialist',    name: 'Specialist',    w: 0.20 },
    { id: 'semantic',      name: 'Semantic',      w: 0.27 },
  ];
  const cls = (v) => v >= 0.65 ? 'high' : v >= 0.4 ? 'med' : '';
  return (
    <div className="eval-streams-card">
      <div className="eval-streams-head">
        <span>evidence streams</span>
        <span className="meta">7 peers · fused</span>
      </div>
      {STREAMS.map((s) => {
        const v = streams[s.id] || 0;
        return (
          <div className="eval-stream" key={s.id}>
            <span className="eval-stream-name">{s.name}</span>
            <span className="eval-stream-bar">
              <span className={`eval-stream-bar-fill ${cls(v)}`} style={{ right: `${(1 - v) * 100}%` }} />
            </span>
            <span className="eval-stream-score">{v.toFixed(2)}</span>
            <span className="eval-stream-w">w {s.w.toFixed(2)}</span>
          </div>
        );
      })}
      <div className="eval-streams-fused">
        <span className="label">Σ fused</span>
        <span className="bar">
          <span className={`bar-fill ${fusedClass}`} style={{ right: `${(1 - fused) * 100}%` }} />
        </span>
        <span className="score">{fused.toFixed(3)}</span>
        <span className="eval-stream-w" />
      </div>
    </div>
  );
}

/* ─────────────────────── Scene 05 — Enforcement ─────────────────────── */

function SceneEnforcement() {
  return (
    <section className="scene-enforcement" id="enforcement" aria-label="enforcement layer">
      <div className="scene-head">
        <div className="scene-head-l">
          <div className="scene-eyebrow">Layer 05 <span className="nm">/ ENFORCEMENT</span></div>
          <h2 className="scene-title">A verdict is <em>not a recommendation</em>.</h2>
          <p className="scene-lede">
            Most vendors stop at "decision." Their dashboards show what should have been blocked,
            in the past tense. <strong>Tex physically stops the action</strong> before it leaves
            the machine — at the gate, decorator, proxy, or middleware.
            Fail-closed by default. The action <em>did not run</em>.
          </p>
        </div>
        <div className="scene-head-r">
          <div>fail_closed = true</div>
          <div style={{ marginTop: 8 }}>4 deployment shapes</div>
        </div>
      </div>

      <div className="enf-lanes">
        <div className="enf-lane enf-lane-permit">
          <div className="enf-source">
            <div className="lbl">Inbound</div>
            <div className="val">refund.process</div>
            <div className="note">support-bot-12 · $48.00</div>
          </div>
          <div className="enf-track">
            <div className="enf-particle" />
            <div className="enf-gate" />
            <div className="enf-tag">PERMIT · executed</div>
          </div>
          <div className="enf-dest">
            <div className="lbl">Destination</div>
            <div className="val">stripe / refund r_42</div>
            <div className="note">delivered · 1.4ms gate latency</div>
          </div>
        </div>

        <div className="enf-lane enf-lane-forbid">
          <div className="enf-source">
            <div className="lbl">Inbound</div>
            <div className="val">wire.initiate</div>
            <div className="note">finance-bot-02 · $12,400</div>
          </div>
          <div className="enf-track">
            <div className="enf-particle" />
            <div className="enf-gate" />
            <div className="enf-tag">FORBID · blocked</div>
          </div>
          <div className="enf-dest">
            <div className="lbl">Destination</div>
            <div className="val">— never reached</div>
            <div className="note">action did not execute</div>
          </div>
        </div>
      </div>

      <div className="enf-shapes">
        <div className="enf-shape">
          <div className="enf-shape-name">Decorator</div>
          <div className="enf-shape-title">Three lines, anywhere Python runs.</div>
          <div className="enf-shape-body">Wrap any function. LangChain, CrewAI, custom agent loops. The decorator owns the call.</div>
        </div>
        <div className="enf-shape">
          <div className="enf-shape-name">HTTP proxy</div>
          <div className="enf-shape-title">Drop in front of any endpoint.</div>
          <div className="enf-shape-body">No SDK required. Sit Tex between any agent and any action surface. Same engine, same chain.</div>
        </div>
        <div className="enf-shape">
          <div className="enf-shape-name">MCP middleware</div>
          <div className="enf-shape-title">Every tool call routes through Tex.</div>
          <div className="enf-shape-body">Cursor, Claude Desktop, Cline. One server URL covers every connected client.</div>
        </div>
        <div className="enf-shape">
          <div className="enf-shape-name">Gateway</div>
          <div className="enf-shape-title">Native guardrail in your stack.</div>
          <div className="enf-shape-body">Portkey, LiteLLM, Cloudflare AI Gateway, Solo, TrueFoundry, Bedrock — drop-in adapter.</div>
        </div>
      </div>
    </section>
  );
}

/* ─────────────────────── Scene 06 — Evidence ─────────────────────── */

function SceneEvidence({ chain }) {
  const display = chain.length > 0 ? chain.slice(-4).reverse() : seedChainBlocks();
  return (
    <section className="scene scene-evidence" id="evidence" aria-label="evidence layer">
      <div>
        <div className="scene-eyebrow">Layer 06 <span className="nm">/ EVIDENCE</span></div>
        <h2 className="scene-title">Every decision <em>linked</em> to the one before it.</h2>
        <p className="scene-lede">
          Every verdict is hashed with the SHA-256 of the previous one.
          The result is an append-only chain your auditors verify <em>without trusting Tex</em>,
          without trusting your security team, and without re-running the model.
          The math is the audit.
        </p>
        <p className="scene-lede" style={{ marginTop: 18 }}>
          <strong>Tamper with one block, every block after it stops verifying.</strong>
          The chain ships as a downloadable bundle for SOC 2, FINRA, ISO 42001, EU AI Act, NIST AI RMF.
        </p>
      </div>

      <div className="chain-list">
        <div className="panel-bar" style={{ marginBottom: 4 }}>
          <div className="panel-bar-l">
            <strong>evidence.chain</strong>
            <span>tail · last 4 blocks</span>
          </div>
          <span className="panel-bar-status">verified</span>
        </div>
        {display.map((b) => (
          <div className={`chain-block ${b.verdict || 'permit'}`} key={b.idx}>
            <div className="chain-block-head">
              <span className="num">block {String(b.idx).padStart(5, '0')}</span>
              <span>{b.ts ? new Date(b.ts).toISOString().slice(11, 19) : '04:34:12'}Z</span>
            </div>
            <div className="chain-block-row"><span className="key">layer</span><span className="val">{b.layer}</span></div>
            <div className="chain-block-row"><span className="key">agent</span><span className="val">{b.agent}</span></div>
            <div className="chain-block-row"><span className="key">action</span><span className="val">{b.action} → {b.target}</span></div>
            <div className="chain-block-row"><span className="key">verdict</span><span className={`val ${b.verdict || 'permit'}`}>{(b.verdict || 'permit').toUpperCase()}</span></div>
            <div className="chain-block-row"><span className="key">hash</span><span className="val hash">{b.hash}</span></div>
            <div className="chain-block-link">
              <span className="arrow">↳</span>
              <span>prev: {short(b.prevHash)}</span>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function seedChainBlocks() {
  const blocks = [
    { idx: 9423, layer: 'Enforcement', agent: 'finance-bot-02', action: 'wire.initiate',  target: '$12,400 to vendor-91',  verdict: 'forbid',  hash: fakeHash(), prevHash: fakeHash(), ts: Date.now() - 1700 },
    { idx: 9422, layer: 'Evaluation',  agent: 'support-bot-12', action: 'refund.process', target: '$48.00',                 verdict: 'permit',  hash: fakeHash(), prevHash: fakeHash(), ts: Date.now() - 3300 },
    { idx: 9421, layer: 'Evaluation',  agent: 'sdr-agent-09',   action: 'email.send',     target: 'cfo@target.co',          verdict: 'abstain', hash: fakeHash(), prevHash: fakeHash(), ts: Date.now() - 5100 },
    { idx: 9420, layer: 'Evaluation',  agent: 'sales-agent-04', action: 'email.send',     target: 'lead@acme.io',           verdict: 'permit',  hash: fakeHash(), prevHash: fakeHash(), ts: Date.now() - 7000 },
  ];
  return blocks;
}

function fakeHash() {
  const c = '0123456789abcdef';
  let s = '';
  for (let i = 0; i < 64; i++) s += c[Math.floor(Math.random() * 16)];
  return s;
}

function short(h) {
  if (!h) return '';
  return `${h.slice(0, 4)}…${h.slice(-4)}`;
}

/* ─────────────────────── Scene 07 — Learning ─────────────────────── */

function SceneLearning({ calibration }) {
  return (
    <section className="scene scene-learning" id="learning" aria-label="learning layer">
      <div>
        <div className="scene-eyebrow">Layer 07 <span className="nm">/ LEARNING</span></div>
        <h2 className="scene-title">Tex sharpens itself <em>from your reality</em>.</h2>
        <p className="scene-lede">
          Every reviewer decision, every approved ABSTAIN, every confirmed FORBID feeds back into
          calibration. Permit threshold drifts. Forbid threshold tightens.
          Per-tenant baselines update.
          <strong> Tex is the only system in the category that closes the feedback loop without retraining a model.</strong>
        </p>
        <p className="scene-lede" style={{ marginTop: 18 }}>
          Your reviewers approved <strong>47 ABSTAIN cases</strong> this week. Tex moved permit threshold from <em>0.42 to 0.44</em>. <em>The system got slightly more lenient — because you told it to.</em>
        </p>
      </div>

      <div>
        <div className="learn-chart panel">
          <div className="panel-bar">
            <div className="panel-bar-l">
              <strong>calibrator</strong>
              <span>thresholds · 24h</span>
            </div>
            <span className="panel-bar-status">drifting</span>
          </div>
          <div style={{ padding: 24 }}>
            <CalibratorChart history={calibration.history} permitT={calibration.permitT} forbidT={calibration.forbidT} />
          </div>
        </div>

        <div className="learn-events">
          {calibration.events.map((evt, i) => (
            <div className="learn-event" key={`${evt.ts}-${i}`}>
              <span className="ts">{evt.ts}</span>
              <span className="msg" dangerouslySetInnerHTML={{ __html: evt.msg }} />
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function CalibratorChart({ history, permitT, forbidT }) {
  // Plot two lines (permit threshold + forbid threshold) over the last 24
  // ticks. Y axis: 0.25 → 0.95.
  const W = 600, H = 220, PAD_L = 36, PAD_R = 16, PAD_T = 14, PAD_B = 24;
  const yMin = 0.30, yMax = 0.92;
  const yScale = (v) => PAD_T + ((yMax - v) / (yMax - yMin)) * (H - PAD_T - PAD_B);
  const xScale = (i) => PAD_L + (i / (history.length - 1)) * (W - PAD_L - PAD_R);

  const permitPath = history.map((p, i) => `${i === 0 ? 'M' : 'L'} ${xScale(i)} ${yScale(p.permitT)}`).join(' ');
  const forbidPath = history.map((p, i) => `${i === 0 ? 'M' : 'L'} ${xScale(i)} ${yScale(p.forbidT)}`).join(' ');

  return (
    <svg viewBox={`0 0 ${W} ${H}`} xmlns="http://www.w3.org/2000/svg" aria-label="calibrator chart">
      {/* gridlines */}
      {[0.4, 0.5, 0.6, 0.7, 0.8].map((g) => (
        <g key={g}>
          <line x1={PAD_L} x2={W - PAD_R} y1={yScale(g)} y2={yScale(g)} stroke="#5ee0ff" strokeOpacity="0.08" />
          <text x={PAD_L - 8} y={yScale(g) + 3} textAnchor="end" fontFamily="JetBrains Mono, monospace" fontSize="9" fill="#7e8699">{g.toFixed(1)}</text>
        </g>
      ))}
      {/* x axis */}
      <line x1={PAD_L} x2={W - PAD_R} y1={H - PAD_B} y2={H - PAD_B} stroke="#5ee0ff" strokeOpacity="0.18" />
      <text x={PAD_L} y={H - 8} fontFamily="JetBrains Mono, monospace" fontSize="9" fill="#7e8699">−24h</text>
      <text x={W - PAD_R} y={H - 8} textAnchor="end" fontFamily="JetBrains Mono, monospace" fontSize="9" fill="#7e8699">now</text>

      {/* forbid line */}
      <path d={forbidPath} fill="none" stroke="#ff5b5b" strokeWidth="1.5" />
      {/* permit line */}
      <path d={permitPath} fill="none" stroke="#5ee0ff" strokeWidth="1.5" />

      {/* current value markers */}
      <circle cx={xScale(history.length - 1)} cy={yScale(forbidT)} r="3.5" fill="#ff5b5b" />
      <circle cx={xScale(history.length - 1)} cy={yScale(permitT)} r="3.5" fill="#5ee0ff" />

      {/* labels */}
      <text x={xScale(history.length - 1) + 8} y={yScale(forbidT) + 3} fontFamily="JetBrains Mono, monospace" fontSize="9" fill="#ff5b5b">forbid {forbidT.toFixed(3)}</text>
      <text x={xScale(history.length - 1) + 8} y={yScale(permitT) + 3} fontFamily="JetBrains Mono, monospace" fontSize="9" fill="#5ee0ff">permit {permitT.toFixed(3)}</text>
    </svg>
  );
}

/* ─────────────────────── Wedge — competitive ─────────────────────── */

function Wedge() {
  // Each row = a vendor. For each layer (D, R, C, E_eval, E_enf, Ev, L)
  // mark whether the vendor genuinely covers it.
  const LAYERS = [
    { k: 'D',  short: 'Discov',  full: 'Discovery' },
    { k: 'R',  short: 'Reg',     full: 'Registration' },
    { k: 'C',  short: 'Cap',     full: 'Capability' },
    { k: 'E1', short: 'Eval',    full: 'Evaluation' },
    { k: 'E2', short: 'Enforce', full: 'Enforcement' },
    { k: 'Ev', short: 'Evid',    full: 'Evidence' },
    { k: 'L',  short: 'Learn',   full: 'Learning' },
  ];

  const VENDORS = [
    { name: 'Okta',           sub: 'identity provider',           lit: ['R'] },
    { name: 'Auth0 / Oasis',  sub: 'auth + agent identity',       lit: ['R'] },
    { name: 'Microsoft AGT',  sub: 'agent governance toolkit',    lit: ['D', 'R'] },
    { name: 'Zenity',         sub: 'AI agent security',           lit: ['D', 'E1'] },
    { name: 'Noma',           sub: 'AI runtime detection',        lit: ['D', 'E1'] },
    { name: 'Pillar',         sub: 'agent posture',               lit: ['D', 'C'] },
    { name: 'Rubrik SAGE',    sub: 'AI activity monitoring',      lit: ['E1', 'Ev'] },
    { name: 'Virtue AI',      sub: 'agent observability',         lit: ['E1'] },
    { name: 'OPA / Cedar',    sub: 'policy engine',               lit: ['C'] },
  ];

  return (
    <section className="wedge" id="wedge" aria-label="wedge">
      <div className="wedge-head">
        <div className="scene-eyebrow" style={{ display: 'inline-flex' }}>The category mistake</div>
        <h2 className="scene-title">Everyone else governs <em>a piece</em>. Tex closes <em>the loop</em>.</h2>
        <p className="scene-lede">
          The market broke this problem into nine products. Identity. Posture. Behavior. Policy.
          Detection. Observability. Each vendor lights one or two layers.
          <strong> None of them physically stop the action. None of them seal the chain.</strong>
        </p>
      </div>

      <div className="competitor-table">
        <div className="competitor-row head">
          <div className="competitor-vendor" style={{ paddingLeft: 18 }}>vendor</div>
          {LAYERS.map((l) => (
            <div key={l.k} className={`competitor-cell head-cell${l.k === 'E2' ? ' amber' : ''}`}>
              <span>{l.short}</span>
            </div>
          ))}
          <div className="competitor-tally" style={{ paddingRight: 18 }}>covered</div>
        </div>

        {VENDORS.map((v) => (
          <div className="competitor-row" key={v.name}>
            <div className="competitor-vendor">
              {v.name}
              <span className="competitor-vendor-sub">{v.sub}</span>
            </div>
            {LAYERS.map((l) => (
              <div key={l.k} className={`competitor-cell${v.lit.includes(l.k) ? ' lit' : ''}`}>
                <span className="dot" />
              </div>
            ))}
            <div className="competitor-tally">
              <span>{v.lit.length}</span><span className="of"> / 7</span>
            </div>
          </div>
        ))}

        <div className="competitor-row tex">
          <div className="competitor-vendor">
            Tex
            <span className="competitor-vendor-sub">all seven, sealed in one chain</span>
          </div>
          {LAYERS.map((l) => (
            <div key={l.k} className={`competitor-cell lit${l.k === 'E2' ? ' amber' : ''}`}>
              <span className="dot" />
            </div>
          ))}
          <div className="competitor-tally">
            <span>7</span><span className="of"> / 7</span>
          </div>
        </div>
      </div>

      <p className="wedge-payoff">
        Nine products. Nine dashboards. Nine teams reconciling alerts.<br/>
        Or <em>one Tex</em>.
      </p>
    </section>
  );
}

/* ─────────────────────── Trial · Manifesto · Foot ─────────────────────── */

function Trial() {
  return (
    <section className="trial" id="trial" aria-label="trial">
      <div className="trial-eyebrow">14-day free audit</div>
      <h1 className="trial-title">
        Find every agent. Stop the bad ones.<br/>
        <em>Prove what happened.</em>
      </h1>
      <p className="trial-sub">
        Connect Tex to one platform you already use — Microsoft Graph, Salesforce, GitHub, OpenAI,
        Bedrock, or MCP. We run discovery, evaluate live agent actions, enforce verdicts, and
        deliver a board-ready readout with the cryptographic chain in fourteen days.
        The chain is yours to keep.
      </p>
      <div className="trial-cta">
        <a className="btn" href="mailto:matthew@texaegis.com?subject=Tex%20audit">
          Book the audit <span aria-hidden="true">→</span>
        </a>
        <a className="btn btn-ghost" href="#wedge">See the comparison</a>
      </div>
      <div className="trial-foot">
        <span>OWASP ASI 2026</span>
        <span>NIST AI RMF</span>
        <span>ISO 42001</span>
        <span>EU AI Act</span>
        <span>SOC 2</span>
        <span>FINRA</span>
      </div>
    </section>
  );
}

function Manifesto() {
  return (
    <section className="manifesto" aria-label="manifesto">
      <p className="manifesto-line">
        Find every agent. Identify every agent.<br/>
        Authorize what they can do. Decide every action.
      </p>
      <p className="manifesto-line amber">
        <em>Stop the ones that shouldn't happen.</em>
      </p>
      <p className="manifesto-line">
        Prove the rest. Learn from <em>all of it</em>.
      </p>
    </section>
  );
}

function Foot() {
  return (
    <footer className="foot">
      <div className="foot-brand">
        <span className="hud-mark" aria-hidden="true" />
        <span>Tex · texaegis.com</span>
      </div>
      <div className="foot-meta">
        <span>VortexBlack, 2026</span>
        <span>Boston · USA</span>
        <span>matthew@texaegis.com</span>
      </div>
    </footer>
  );
}
