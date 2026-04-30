import React, { useEffect, useRef, useState, useCallback } from 'react';
import texAvatar from './tex-avatar.png';
import './styles.css';

/* -----------------------------------------------------------
   THE SEVEN LAYERS
   The user-specified canonical architecture.
   ----------------------------------------------------------- */
const LAYERS = [
  {
    id: '01',
    key: 'discovery',
    name: 'Discovery',
    verb: 'Find every agent.',
    one: 'Inventory every agent, copilot, workflow, and shadow automation across your stack.',
    detail:
      'Tex maps the full population of acting AI in your environment — first-party agents, vendor copilots, MCP-bound tools, and autonomous workflows that no one wrote down.',
    proof: ['agents.indexed', 'first-party + vendor + shadow', 'continuous re-scan'],
    metric: { label: 'agents observed', value: '4,217' },
  },
  {
    id: '02',
    key: 'registration',
    name: 'Registration',
    verb: 'Bind actor and owner.',
    one: 'Tie every action to its agent, human owner, tenant, environment, and trust level.',
    detail:
      'Identity is not a name — it is a chain. Tex registers each agent with cryptographic identity, ownership, environment, and the human accountable for it.',
    proof: ['actor.signed', 'owner.bound', 'env.scoped'],
    metric: { label: 'actors registered', value: '4,217 / 4,217' },
  },
  {
    id: '03',
    key: 'capability',
    name: 'Capability',
    verb: 'Define allowed power.',
    one: 'Convert written policy into live, machine-enforceable execution boundaries.',
    detail:
      'Capability is the contract: what this agent may do, to what data, in which environments, with what budget, under whose authority. Tex compiles policy into runtime constraints.',
    proof: ['policy.compiled', 'scope.bound', 'budget.set'],
    metric: { label: 'capabilities defined', value: '186' },
  },
  {
    id: '04',
    key: 'evaluation',
    name: 'Evaluation',
    verb: 'Read the real action.',
    one: 'Inspect the actual message, tool call, file write, API request, or promise — pre-execution.',
    detail:
      'Six judgment layers fire in parallel: deterministic patterns, retrieval, specialist models, semantic intent, router, and evidence. The verdict is reached before the action reaches the world.',
    proof: ['deterministic', 'retrieval', 'specialists', 'semantic', 'router', 'evidence'],
    metric: { label: 'p95 latency', value: '142 ms' },
  },
  {
    id: '05',
    key: 'enforcement',
    name: 'Enforcement',
    verb: 'Permit. Abstain. Forbid.',
    one: 'Stop, hold, or release the action before it reaches the real world.',
    detail:
      'A single verdict, three states, machine-binding. Permit releases the action under recorded authority. Abstain holds for human review. Forbid blocks and seals the attempt.',
    proof: ['PERMIT', 'ABSTAIN', 'FORBID'],
    metric: { label: 'verdicts / day', value: '2.41 M' },
  },
  {
    id: '06',
    key: 'evidence',
    name: 'Evidence',
    verb: 'Seal the proof.',
    one: 'Hash-chain the request, policy, verdict, permit, verification, and outcome.',
    detail:
      'Every decision becomes a SHA-256 hash-chained, HMAC-signed evidence bundle. Tamper-evident. Auditor-ready. The chain is the record — everyone logs it; Tex proves it.',
    proof: ['sha-256', 'hmac-signed', 'append-only'],
    metric: { label: 'bundles sealed', value: '14,392,118' },
  },
  {
    id: '07',
    key: 'learning',
    name: 'Learning',
    verb: 'Improve without chaos.',
    one: 'Tune thresholds from outcomes — without letting the system rewrite its own rules.',
    detail:
      'Calibration uses sealed evidence to refine thresholds and routing. Policy stays human-authored. The loop closes without surrendering authorship of the rules.',
    proof: ['signal.bound', 'human.authored', 'audit.preserved'],
    metric: { label: 'thresholds tuned', value: '23 this week' },
  },
];

/* -----------------------------------------------------------
   AMBIENT FIELD — slow-moving signal field behind everything
   ----------------------------------------------------------- */
function AmbientField() {
  const ref = useRef(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let raf,
      t = 0,
      mx = 0,
      my = 0;

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(window.innerWidth * dpr);
      canvas.height = Math.floor(window.innerHeight * dpr);
      canvas.style.width = window.innerWidth + 'px';
      canvas.style.height = window.innerHeight + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    const move = (e) => {
      mx = e.clientX / window.innerWidth - 0.5;
      my = e.clientY / window.innerHeight - 0.5;
    };
    resize();
    window.addEventListener('resize', resize);
    window.addEventListener('pointermove', move);

    const draw = () => {
      t += 0.0035;
      const w = window.innerWidth,
        h = window.innerHeight;
      ctx.clearRect(0, 0, w, h);

      // Deep void gradient
      const bg = ctx.createRadialGradient(
        w * 0.62 + mx * 60,
        h * 0.42 + my * 40,
        0,
        w * 0.62,
        h * 0.42,
        Math.max(w, h) * 0.9
      );
      bg.addColorStop(0, 'rgba(20, 38, 48, 0.35)');
      bg.addColorStop(0.45, 'rgba(4, 8, 12, 0.5)');
      bg.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, w, h);

      // Hairline grid
      ctx.strokeStyle = 'rgba(140, 220, 230, 0.04)';
      ctx.lineWidth = 1;
      const cell = 96;
      const ox = (t * 18) % cell;
      const oy = (t * 12) % cell;
      ctx.beginPath();
      for (let x = -cell + ox; x < w + cell; x += cell) {
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
      }
      for (let y = -cell + oy; y < h + cell; y += cell) {
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
      }
      ctx.stroke();

      // Drifting particles — sparse, slow
      for (let i = 0; i < 38; i++) {
        const phase = i * 1.31 + t * 0.6;
        const x = ((Math.sin(phase) * 0.5 + 0.5) * w + t * 30 * (i % 3 === 0 ? 1 : -1)) % w;
        const y = (Math.cos(phase * 0.73) * 0.5 + 0.5) * h;
        const sz = i % 11 === 0 ? 1.8 : 0.9;
        ctx.fillStyle = i % 11 === 0 ? 'rgba(86, 230, 220, 0.55)' : 'rgba(180, 220, 230, 0.18)';
        ctx.fillRect(x, y, sz, sz);
      }

      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
      window.removeEventListener('pointermove', move);
    };
  }, []);
  return <canvas className="ambient" ref={ref} aria-hidden="true" />;
}

/* -----------------------------------------------------------
   LAYER BAR — top-of-page navigation, 7 cells, always visible
   ----------------------------------------------------------- */
function LayerBar({ active, setActive }) {
  return (
    <nav className="layer-bar" aria-label="Seven layer navigation">
      <div className="bar-brand">
        <div className="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="22" height="22">
            <path
              d="M12 2 L21 7 L21 17 L12 22 L3 17 L3 7 Z"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.4"
            />
            <path d="M7 9 H17 M12 9 V16" stroke="currentColor" strokeWidth="1.4" />
          </svg>
        </div>
        <div className="brand-text">
          <span className="brand-name">TEX</span>
          <span className="brand-sub">by VortexBlack</span>
        </div>
      </div>
      <ol className="bar-cells" role="tablist">
        {LAYERS.map((layer, i) => (
          <li key={layer.id}>
            <button
              type="button"
              role="tab"
              aria-selected={i === active}
              className={`bar-cell ${i === active ? 'is-active' : ''}`}
              onClick={() => setActive(i)}
              onMouseEnter={() => setActive(i)}
            >
              <span className="cell-num">{layer.id}</span>
              <span className="cell-name">{layer.name}</span>
              <span className="cell-rule" aria-hidden="true" />
            </button>
          </li>
        ))}
      </ol>
      <a className="bar-cta" href="#trial">
        <span>Activate</span>
        <span className="cta-arrow">→</span>
      </a>
    </nav>
  );
}

/* -----------------------------------------------------------
   AEGIS RING — the heptagonal system geometry
   The avatar sits at the center; 7 vertices = 7 layers.
   ----------------------------------------------------------- */
function AegisRing({ active, setActive }) {
  const cx = 500,
    cy = 500;
  const radius = 320;
  // Heptagon vertices, starting at top
  const vertices = LAYERS.map((_, i) => {
    const angle = (-Math.PI / 2) + (i * 2 * Math.PI) / 7;
    return {
      x: cx + Math.cos(angle) * radius,
      y: cy + Math.sin(angle) * radius,
      angle,
    };
  });

  // Path connecting vertices
  const heptPath =
    vertices.map((v, i) => `${i === 0 ? 'M' : 'L'} ${v.x} ${v.y}`).join(' ') + ' Z';

  return (
    <div className="aegis-stage">
      <svg
        className="aegis-svg"
        viewBox="0 0 1000 1000"
        aria-hidden="true"
        preserveAspectRatio="xMidYMid meet"
      >
        <defs>
          <radialGradient id="centerGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="rgba(86, 230, 220, 0.18)" />
            <stop offset="50%" stopColor="rgba(86, 230, 220, 0.04)" />
            <stop offset="100%" stopColor="rgba(0,0,0,0)" />
          </radialGradient>
          <linearGradient id="ringStroke" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="rgba(86, 230, 220, 0.6)" />
            <stop offset="50%" stopColor="rgba(180, 220, 230, 0.3)" />
            <stop offset="100%" stopColor="rgba(86, 230, 220, 0.6)" />
          </linearGradient>
          <filter id="vertexGlow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="6" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Outer aura */}
        <circle cx={cx} cy={cy} r={radius + 80} fill="url(#centerGlow)" />

        {/* Concentric guide circles */}
        <circle cx={cx} cy={cy} r={radius + 30} className="ring-guide" />
        <circle cx={cx} cy={cy} r={radius - 60} className="ring-guide faint" />
        <circle cx={cx} cy={cy} r={radius - 140} className="ring-guide faint" />

        {/* Cardinal cross */}
        <line x1={cx - radius - 30} y1={cy} x2={cx + radius + 30} y2={cy} className="cardinal" />
        <line x1={cx} y1={cy - radius - 30} x2={cx} y2={cy + radius + 30} className="cardinal" />

        {/* Heptagonal frame */}
        <path d={heptPath} className="hept-frame" />

        {/* Spoke lines from center to each vertex */}
        {vertices.map((v, i) => (
          <line
            key={`spoke-${i}`}
            x1={cx}
            y1={cy}
            x2={v.x}
            y2={v.y}
            className={`spoke ${i === active ? 'spoke-active' : ''}`}
          />
        ))}

        {/* Tick marks around outer circle */}
        {Array.from({ length: 84 }).map((_, i) => {
          const a = (i / 84) * Math.PI * 2;
          const r1 = radius + 30;
          const r2 = i % 12 === 0 ? radius + 50 : radius + 38;
          return (
            <line
              key={`tick-${i}`}
              x1={cx + Math.cos(a) * r1}
              y1={cy + Math.sin(a) * r1}
              x2={cx + Math.cos(a) * r2}
              y2={cy + Math.sin(a) * r2}
              className={`tick ${i % 12 === 0 ? 'tick-major' : ''}`}
            />
          );
        })}

        {/* Active arc sweep */}
        <circle
          cx={cx}
          cy={cy}
          r={radius + 30}
          fill="none"
          stroke="url(#ringStroke)"
          strokeWidth="1.5"
          strokeDasharray="60 1440"
          className="ring-sweep"
          style={{
            transformOrigin: `${cx}px ${cy}px`,
            transform: `rotate(${(active * 360) / 7 - 90}deg)`,
          }}
        />

        {/* Vertex nodes (rendered as SVG overlay; clickable HTML on top) */}
        {vertices.map((v, i) => (
          <g key={`vtx-${i}`} filter={i === active ? 'url(#vertexGlow)' : undefined}>
            <circle
              cx={v.x}
              cy={v.y}
              r={i === active ? 14 : 8}
              className={`vertex-dot ${i === active ? 'is-active' : ''}`}
            />
            <circle cx={v.x} cy={v.y} r={i === active ? 22 : 14} className="vertex-ring" />
          </g>
        ))}
      </svg>

      {/* Avatar at center */}
      <div className="avatar-mount">
        <div className="avatar-aura" aria-hidden="true" />
        <img className="avatar-img" src={texAvatar} alt="Tex — AI control system" />
      </div>

      {/* HTML clickable layer chips, positioned outside heptagon vertices along radial axis */}
      {vertices.map((v, i) => {
        const layer = LAYERS[i];
        // Push chip outward from center along the same angle as the vertex
        const outRadius = radius + 80;
        const chipX = cx + Math.cos(v.angle) * outRadius;
        const chipY = cy + Math.sin(v.angle) * outRadius;
        const xPct = (chipX / 1000) * 100;
        const yPct = (chipY / 1000) * 100;
        return (
          <button
            key={`chip-${i}`}
            type="button"
            className={`vertex-chip ${i === active ? 'is-active' : ''}`}
            style={{ left: `${xPct}%`, top: `${yPct}%` }}
            onClick={() => setActive(i)}
            onMouseEnter={() => setActive(i)}
            aria-label={`${layer.name} — ${layer.verb}`}
          >
            <span className="chip-num">{layer.id}</span>
            <span className="chip-name">{layer.name}</span>
          </button>
        );
      })}
    </div>
  );
}

/* -----------------------------------------------------------
   LIVE VERDICT TICKER — stamps on a chain
   ----------------------------------------------------------- */
const SAMPLE_VERDICTS = [
  { v: 'PERMIT', actor: 'agent_revops_07', action: 'send_email::client_quarterly', risk: '0.12' },
  { v: 'ABSTAIN', actor: 'copilot_legal_03', action: 'file.write::contracts/draft.docx', risk: '0.61' },
  { v: 'FORBID', actor: 'agent_support_22', action: 'api.call::stripe.refund.full', risk: '0.94' },
  { v: 'PERMIT', actor: 'workflow_ops_11', action: 'tool.invoke::salesforce.update', risk: '0.18' },
  { v: 'PERMIT', actor: 'agent_marketing_04', action: 'send_message::slack#campaigns', risk: '0.22' },
  { v: 'FORBID', actor: 'agent_research_19', action: 'browse::external.unverified', risk: '0.88' },
  { v: 'ABSTAIN', actor: 'copilot_finance_02', action: 'export::ledger.q3', risk: '0.55' },
  { v: 'PERMIT', actor: 'agent_hr_05', action: 'create::onboarding.task', risk: '0.09' },
];

function VerdictTicker() {
  return (
    <div className="ticker" aria-label="Live verdict stream">
      <div className="ticker-mask">
        <div className="ticker-track">
          {[...SAMPLE_VERDICTS, ...SAMPLE_VERDICTS].map((row, i) => (
            <div key={i} className={`tick-row tick-${row.v.toLowerCase()}`}>
              <span className="tick-tag">{row.v}</span>
              <span className="tick-actor">{row.actor}</span>
              <span className="tick-action">{row.action}</span>
              <span className="tick-risk">r={row.risk}</span>
              <span className="tick-hash">
                0x{Math.random().toString(16).slice(2, 10)}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* -----------------------------------------------------------
   HERO — the 5-second answer
   ----------------------------------------------------------- */
function Hero({ active, setActive }) {
  return (
    <section className="hero" id="top">
      <div className="hero-grid">
        <div className="hero-left">
          <div className="kicker">
            <span className="kicker-dot" />
            <span>Tex by VortexBlack</span>
            <span className="kicker-sep">/</span>
            <span>OWASP ASI 2026 reference adjudicator</span>
          </div>

          <h1 className="hero-h1">
            <span className="h1-line">Every AI agent action</span>
            <span className="h1-line h1-italic">passes through Tex.</span>
          </h1>

          <p className="hero-lede">
            A seven-layer cryptographic control plane that decides — in real time —
            whether an AI agent is allowed to act, then seals the proof of every decision.
          </p>

          <div className="five-second">
            <div className="five-row">
              <span className="five-label">In five seconds</span>
              <span className="five-rule" />
            </div>
            <p className="five-body">
              Tex sits between your AI agents and the real world. It judges every action
              before it executes, and produces a tamper-evident evidence chain auditors and
              regulators can verify.
            </p>
          </div>

          <div className="hero-actions">
            <a href="#trial" className="btn-primary">
              <span>Activate 2-week trial</span>
              <span className="btn-arrow">→</span>
            </a>
            <a href="#layer-01" className="btn-ghost">
              <span>Trace the seven layers</span>
            </a>
          </div>

          <div className="hero-stats">
            <div className="stat">
              <span className="stat-num">142<span className="stat-unit">ms</span></span>
              <span className="stat-lbl">p95 verdict</span>
            </div>
            <div className="stat">
              <span className="stat-num">SHA-256</span>
              <span className="stat-lbl">hash-chained</span>
            </div>
            <div className="stat">
              <span className="stat-num">EU AI Act</span>
              <span className="stat-lbl">aug 2026 ready</span>
            </div>
          </div>
        </div>

        <div className="hero-right">
          <AegisRing active={active} setActive={setActive} />
        </div>
      </div>

      <VerdictTicker />
    </section>
  );
}

/* -----------------------------------------------------------
   LAYER SECTION — one per layer, anchored, navigable
   ----------------------------------------------------------- */
function LayerSection({ layer, index, active, setActive }) {
  const ref = useRef(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting && e.intersectionRatio > 0.55) {
            setActive(index);
          }
        });
      },
      { threshold: [0.55, 0.7] }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, [index, setActive]);

  return (
    <section
      ref={ref}
      id={`layer-${layer.id}`}
      className={`layer-section ${active === index ? 'is-active' : ''}`}
      data-layer={layer.key}
    >
      <div className="ls-grid">
        <div className="ls-left">
          <div className="ls-meta">
            <span className="ls-num">L{layer.id}</span>
            <span className="ls-rule" />
            <span className="ls-key">{layer.key}.layer</span>
          </div>

          <h2 className="ls-h2">
            <span className="ls-name">{layer.name}</span>
            <span className="ls-verb">— {layer.verb}</span>
          </h2>

          <p className="ls-one">{layer.one}</p>

          <p className="ls-detail">{layer.detail}</p>

          <div className="ls-proof">
            {layer.proof.map((p) => (
              <span key={p} className="proof-pill">
                {p}
              </span>
            ))}
          </div>
        </div>

        <div className="ls-right">
          <div className="ls-card">
            <div className="card-head">
              <span className="card-tag">EVIDENCE BUNDLE</span>
              <span className="card-id">tx_{layer.id}_{layer.key.slice(0, 4).toUpperCase()}</span>
            </div>
            <div className="card-body">
              <div className="card-row">
                <span className="row-k">layer</span>
                <span className="row-v">{layer.id} · {layer.name.toLowerCase()}</span>
              </div>
              <div className="card-row">
                <span className="row-k">verdict</span>
                <span className="row-v row-v-mono">
                  {layer.id === '05' ? 'PERMIT' : 'OBSERVED'}
                </span>
              </div>
              <div className="card-row">
                <span className="row-k">prev_hash</span>
                <span className="row-v row-v-mono">
                  0x{Math.abs(parseInt(layer.id, 10) * 9173).toString(16).padStart(8, '0')}…
                </span>
              </div>
              <div className="card-row">
                <span className="row-k">this_hash</span>
                <span className="row-v row-v-mono row-accent">
                  0x{Math.abs(parseInt(layer.id, 10) * 31337 + 7).toString(16).padStart(8, '0')}…
                </span>
              </div>
              <div className="card-row">
                <span className="row-k">signed</span>
                <span className="row-v row-v-mono">hmac-sha256 ✓</span>
              </div>
            </div>
            <div className="card-foot">
              <span className="metric-label">{layer.metric.label}</span>
              <span className="metric-value">{layer.metric.value}</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* -----------------------------------------------------------
   CHAIN BAND — the seven hashes linked
   ----------------------------------------------------------- */
function ChainBand() {
  return (
    <section className="chain-band" id="proof">
      <div className="cb-head">
        <span className="kicker">
          <span className="kicker-dot" />
          <span>The Chain</span>
        </span>
        <h2 className="cb-h2">
          Seven layers. <span className="ital">One sealed record.</span>
        </h2>
        <p className="cb-lede">
          Each layer's output is hashed into the next. Break any link and the entire
          chain reports tampering. Everyone logs it. Tex proves it.
        </p>
      </div>
      <div className="chain-track">
        {LAYERS.map((l, i) => (
          <React.Fragment key={l.id}>
            <div className="chain-node">
              <span className="chain-num">{l.id}</span>
              <span className="chain-name">{l.name}</span>
              <span className="chain-hash">
                0x{Math.abs(parseInt(l.id, 10) * 31337 + 7).toString(16).padStart(8, '0')}
              </span>
            </div>
            {i < LAYERS.length - 1 && <div className="chain-link" aria-hidden="true" />}
          </React.Fragment>
        ))}
      </div>
    </section>
  );
}

/* -----------------------------------------------------------
   CTA / CLOSING
   ----------------------------------------------------------- */
function ClosingPanel() {
  return (
    <section className="closing" id="trial">
      <div className="cl-grid">
        <div className="cl-left">
          <span className="kicker">
            <span className="kicker-dot" />
            <span>Begin with the audit</span>
          </span>
          <h2 className="cl-h2">
            Who controls<br />
            <span className="ital">your agents?</span>
          </h2>
          <p className="cl-lede">
            Two weeks. We inventory the agents you have, map their authority, run real
            actions through the seven layers, and hand you a sealed evidence bundle.
          </p>
          <div className="hero-actions">
            <a href="https://texaegis.com" className="btn-primary">
              <span>Activate 2-week trial</span>
              <span className="btn-arrow">→</span>
            </a>
            <a href="mailto:hello@texaegis.com" className="btn-ghost">
              <span>Talk to the founder</span>
            </a>
          </div>
        </div>
        <div className="cl-right">
          <div className="cl-card">
            <div className="cl-card-row">
              <span className="cl-rk">01</span>
              <span className="cl-rn">Inventory</span>
              <span className="cl-rd">Map every agent, copilot, and shadow workflow.</span>
            </div>
            <div className="cl-card-row">
              <span className="cl-rk">02</span>
              <span className="cl-rn">Control</span>
              <span className="cl-rd">Bind authority and run real actions through Tex.</span>
            </div>
            <div className="cl-card-row">
              <span className="cl-rk">03</span>
              <span className="cl-rn">Proof</span>
              <span className="cl-rd">Receive the sealed evidence chain.</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="site-foot">
      <div className="foot-left">
        <div className="brand-mark sm" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="18" height="18">
            <path d="M12 2 L21 7 L21 17 L12 22 L3 17 L3 7 Z" fill="none" stroke="currentColor" strokeWidth="1.4"/>
            <path d="M7 9 H17 M12 9 V16" stroke="currentColor" strokeWidth="1.4"/>
          </svg>
        </div>
        <span className="foot-name">Tex by VortexBlack</span>
      </div>
      <div className="foot-mid">
        Cryptographic control plane for AI agents. Boston · 2026.
      </div>
      <div className="foot-right">
        <a href="#top">↑ top</a>
      </div>
    </footer>
  );
}

/* -----------------------------------------------------------
   APP
   ----------------------------------------------------------- */
function App() {
  const [active, setActive] = useState(0);

  // Smooth scroll when bar is clicked
  const onSelect = useCallback((i) => {
    setActive(i);
    const target = document.getElementById(`layer-${LAYERS[i].id}`);
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, []);

  return (
    <div className="root-shell">
      <AmbientField />
      <LayerBar active={active} setActive={onSelect} />

      <main className="page">
        <Hero active={active} setActive={setActive} />

        <div className="layers-stack">
          {LAYERS.map((layer, i) => (
            <LayerSection
              key={layer.id}
              layer={layer}
              index={i}
              active={active}
              setActive={setActive}
            />
          ))}
        </div>

        <ChainBand />
        <ClosingPanel />
        <Footer />
      </main>
    </div>
  );
}

export default App;
