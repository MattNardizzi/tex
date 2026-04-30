import React, { useEffect, useRef, useState, useCallback } from 'react';
import texAvatar from './tex-avatar.png';
import './styles.css';

/* =============================================================
   THE SEVEN LAYERS
   Positioning: Tex is the unified control plane that does what
   Okta, Zenity, Noma, Pillar, Rubrik SAGE, Microsoft AGT, OPA,
   and Cedar each do separately — combined into one cryptographic loop.
   ============================================================= */
const LAYERS = [
  {
    id: '01',
    key: 'discovery',
    name: 'Discovery',
    verb: 'See every agent.',
    absorbs: 'AI Posture Management',
    rivals: 'Zenity · Noma · Prompt Security',
    one: 'Continuous, agent-aware inventory across every tenant, vendor, and shadow workflow.',
    detail:
      'Tex maps the full population of acting AI in your environment — first-party agents, vendor copilots, MCP-bound tools, and the autonomous workflows nobody wrote down. Every agent is a row, every row has a hash.',
    proof: ['agents.indexed', 'first-party + vendor + shadow', 'continuous re-scan'],
    metric: { label: 'agents observed', value: '4,217' },
    instrument: 'radar',
  },
  {
    id: '02',
    key: 'registration',
    name: 'Registration',
    verb: 'Bind actor and owner.',
    absorbs: 'Identity for Non-Humans',
    rivals: 'Okta · Astrix · Aembit',
    one: 'Every agent gets a cryptographic identity, a human owner, an environment, and a trust tier.',
    detail:
      'What Okta does for humans, Tex does for agents — but bound to the action chain. Each registration ties an agent to its owner, scope, environment, and accountability path. No orphans. No anonymous actors.',
    proof: ['actor.signed', 'owner.bound', 'env.scoped'],
    metric: { label: 'actors registered', value: '4,217 / 4,217' },
    instrument: 'binding',
  },
  {
    id: '03',
    key: 'capability',
    name: 'Capability',
    verb: 'Define allowed power.',
    absorbs: 'Policy as Code',
    rivals: 'OPA · Cedar · Microsoft AGT',
    one: 'Convert written policy into live, machine-enforceable execution boundaries.',
    detail:
      'Capability is the contract: what this agent may do, to what data, in which environments, with what budget, under whose authority. Tex compiles policy into runtime constraints — the same job OPA and Cedar do, fused with the rest of the loop.',
    proof: ['policy.compiled', 'scope.bound', 'budget.set'],
    metric: { label: 'capabilities defined', value: '186' },
    instrument: 'compiler',
  },
  {
    id: '04',
    key: 'evaluation',
    name: 'Evaluation',
    verb: 'Read the real action.',
    absorbs: 'Runtime Adjudication',
    rivals: 'Pillar · Lasso · Robust Intelligence',
    one: 'Six judgment layers fire in parallel against the actual action — not the prompt.',
    detail:
      'Deterministic patterns, retrieval, specialist models, semantic intent, router, and evidence run simultaneously against the real outbound message, tool call, file write, or API request. Verdict reached in 142ms p95.',
    proof: ['deterministic', 'retrieval', 'specialists', 'semantic', 'router', 'evidence'],
    metric: { label: 'p95 latency', value: '142 ms' },
    instrument: 'judges',
  },
  {
    id: '05',
    key: 'enforcement',
    name: 'Enforcement',
    verb: 'Permit. Abstain. Forbid.',
    absorbs: 'Action Gateway',
    rivals: 'CalypsoAI · Pangea · Protect AI',
    one: 'Stop, hold, or release the action before it reaches the real world.',
    detail:
      'A single verdict, three states, machine-binding. Permit releases the action under recorded authority. Abstain holds for human review. Forbid blocks and seals the attempt as evidence.',
    proof: ['PERMIT', 'ABSTAIN', 'FORBID'],
    metric: { label: 'verdicts / day', value: '2.41 M' },
    instrument: 'gates',
  },
  {
    id: '06',
    key: 'evidence',
    name: 'Evidence',
    verb: 'Seal the proof.',
    absorbs: 'Audit Chain',
    rivals: 'Rubrik SAGE · Datadog · Splunk',
    one: 'Hash-chain the request, policy, verdict, permit, verification, and outcome.',
    detail:
      'Every decision becomes a SHA-256 hash-chained, HMAC-signed evidence bundle. Tamper-evident. Auditor-ready. Regulator-ready. Everyone logs it. Tex proves it.',
    proof: ['sha-256', 'hmac-signed', 'append-only'],
    metric: { label: 'bundles sealed', value: '14,392,118' },
    instrument: 'chain',
  },
  {
    id: '07',
    key: 'learning',
    name: 'Learning',
    verb: 'Tune without drift.',
    absorbs: 'Closed-Loop Calibration',
    rivals: 'Arize · WhyLabs · Fiddler',
    one: 'Refine thresholds from sealed outcomes — without letting the system rewrite the rules.',
    detail:
      'Calibration uses the evidence chain to retune thresholds and routing. Policy stays human-authored. The loop closes without surrendering authorship. The system improves; the rules stay yours.',
    proof: ['signal.bound', 'human.authored', 'audit.preserved'],
    metric: { label: 'thresholds tuned', value: '23 this week' },
    instrument: 'dial',
  },
];

/* =============================================================
   3D PARALLAX GRID — perspective floor + ceiling, mouse-reactive
   Pure canvas, no Three.js dependency. Real depth via vanishing point.
   ============================================================= */
function PerspectiveGrid() {
  const ref = useRef(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let raf, t = 0, mx = 0, my = 0;

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(window.innerWidth * dpr);
      canvas.height = Math.floor(window.innerHeight * dpr);
      canvas.style.width = window.innerWidth + 'px';
      canvas.style.height = window.innerHeight + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    const move = (e) => {
      mx = (e.clientX / window.innerWidth - 0.5);
      my = (e.clientY / window.innerHeight - 0.5);
    };
    resize();
    window.addEventListener('resize', resize);
    window.addEventListener('pointermove', move);

    const draw = () => {
      t += 0.012;
      const w = window.innerWidth, h = window.innerHeight;
      ctx.clearRect(0, 0, w, h);

      // Deep void radial wash
      const wash = ctx.createRadialGradient(
        w * 0.5 + mx * 80, h * 0.42 + my * 60, 0,
        w * 0.5, h * 0.5, Math.max(w, h) * 0.85
      );
      wash.addColorStop(0, 'rgba(28, 60, 70, 0.32)');
      wash.addColorStop(0.5, 'rgba(6, 10, 16, 0.55)');
      wash.addColorStop(1, 'rgba(0, 0, 0, 0.95)');
      ctx.fillStyle = wash;
      ctx.fillRect(0, 0, w, h);

      // ===== FLOOR GRID =====
      // Vanishing point shifts slightly with mouse for parallax
      const vpX = w * 0.5 + mx * 60;
      const vpY = h * 0.46 + my * 28;

      const floorTop = vpY;
      const floorBot = h + 80;
      const floorH = floorBot - floorTop;

      const numH = 28;       // horizontal lines (depth)
      const numV = 50;       // vertical lines (across)
      const scrollT = (t * 0.18) % 1; // scrolling offset, 0..1

      // Horizontal lines, perspective (bottom = closer)
      for (let i = 0; i < numH; i++) {
        // Perspective curve: lines are dense near horizon, spread near viewer
        const p = (i + scrollT) / numH;
        const y = floorTop + Math.pow(p, 2.2) * floorH;
        const distFade = 1 - Math.pow(p, 0.6); // far = faint, near = bright
        const alpha = 0.05 + 0.13 * distFade;
        ctx.strokeStyle = `rgba(86, 230, 220, ${alpha})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }

      // Vertical lines, converging at vanishing point
      for (let i = 0; i <= numV; i++) {
        const xRatio = (i / numV - 0.5) * 2; // -1..1
        const xBottom = w * 0.5 + xRatio * w * 0.9;
        const distFromCenter = Math.abs(xRatio);
        const alpha = 0.04 + 0.10 * (1 - distFromCenter * 0.5);
        ctx.strokeStyle = `rgba(86, 230, 220, ${alpha})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(vpX + xRatio * 16, vpY);
        ctx.lineTo(xBottom, floorBot);
        ctx.stroke();
      }

      // ===== CEILING GRID (inverted) =====
      const ceilBot = vpY;
      const ceilTop = -80;
      const ceilH = ceilBot - ceilTop;

      for (let i = 0; i < numH; i++) {
        const p = (i + scrollT) / numH;
        const y = ceilBot - Math.pow(p, 2.2) * ceilH;
        const distFade = 1 - Math.pow(p, 0.6);
        const alpha = 0.03 + 0.08 * distFade;
        ctx.strokeStyle = `rgba(86, 230, 220, ${alpha})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }

      for (let i = 0; i <= numV; i++) {
        const xRatio = (i / numV - 0.5) * 2;
        const xTop = w * 0.5 + xRatio * w * 0.9;
        const distFromCenter = Math.abs(xRatio);
        const alpha = 0.025 + 0.07 * (1 - distFromCenter * 0.5);
        ctx.strokeStyle = `rgba(86, 230, 220, ${alpha})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(vpX + xRatio * 16, vpY);
        ctx.lineTo(xTop, ceilTop);
        ctx.stroke();
      }

      // ===== HORIZON GLOW =====
      const horizonGlow = ctx.createLinearGradient(0, vpY - 60, 0, vpY + 60);
      horizonGlow.addColorStop(0, 'rgba(86, 230, 220, 0)');
      horizonGlow.addColorStop(0.5, 'rgba(86, 230, 220, 0.18)');
      horizonGlow.addColorStop(1, 'rgba(86, 230, 220, 0)');
      ctx.fillStyle = horizonGlow;
      ctx.fillRect(0, vpY - 60, w, 120);

      // ===== DRIFTING DATA POINTS =====
      for (let i = 0; i < 22; i++) {
        const phase = i * 1.31 + t * 0.5;
        const x = ((Math.sin(phase) * 0.5 + 0.5) * w + t * 25 * (i % 3 === 0 ? 1 : -1)) % w;
        const y = (Math.cos(phase * 0.73) * 0.5 + 0.5) * h;
        const sz = i % 9 === 0 ? 1.8 : 0.9;
        ctx.fillStyle = i % 9 === 0 ? 'rgba(120, 240, 230, 0.55)' : 'rgba(180, 220, 230, 0.18)';
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

/* =============================================================
   LAYER BAR — top-of-page navigation
   ============================================================= */
function LayerBar({ active, setActive }) {
  return (
    <nav className="layer-bar" aria-label="Seven layer navigation">
      <div className="bar-brand">
        <div className="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="22" height="22">
            <path d="M12 2 L21 7 L21 17 L12 22 L3 17 L3 7 Z" fill="none" stroke="currentColor" strokeWidth="1.4" />
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

/* =============================================================
   AEGIS RING — animated heptagon + avatar
   - Pulsing energy traveling around vertices
   - Spoke-to-active-vertex beam
   - Counter-rotating coordinate ring
   ============================================================= */
function AegisRing({ active, setActive }) {
  const cx = 500, cy = 500;
  const radius = 320;
  const vertices = LAYERS.map((_, i) => {
    const angle = (-Math.PI / 2) + (i * 2 * Math.PI) / 7;
    return {
      x: cx + Math.cos(angle) * radius,
      y: cy + Math.sin(angle) * radius,
      angle,
    };
  });
  const heptPath = vertices.map((v, i) => `${i === 0 ? 'M' : 'L'} ${v.x} ${v.y}`).join(' ') + ' Z';

  // Coordinate ticks rendered around outer ring
  const ticks = Array.from({ length: 60 }, (_, i) => i);

  // Pulse animation: which vertex is currently "lit" by the energy traveler
  const [pulseIdx, setPulseIdx] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setPulseIdx((v) => (v + 1) % 7), 600);
    return () => clearInterval(id);
  }, []);

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
            <stop offset="0%" stopColor="rgba(86, 230, 220, 0.22)" />
            <stop offset="50%" stopColor="rgba(86, 230, 220, 0.06)" />
            <stop offset="100%" stopColor="rgba(0,0,0,0)" />
          </radialGradient>
          <linearGradient id="ringStroke" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="rgba(86, 230, 220, 0.7)" />
            <stop offset="50%" stopColor="rgba(180, 220, 230, 0.35)" />
            <stop offset="100%" stopColor="rgba(86, 230, 220, 0.7)" />
          </linearGradient>
          <filter id="vertexGlow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="6" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter id="strongGlow" x="-100%" y="-100%" width="300%" height="300%">
            <feGaussianBlur stdDeviation="14" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Center aura */}
        <circle cx={cx} cy={cy} r={radius + 100} fill="url(#centerGlow)" />

        {/* Outer rotating coordinate ring */}
        <g className="rotating-ring">
          <circle cx={cx} cy={cy} r={radius + 80} className="ring-guide-thin" />
          {ticks.map((i) => {
            const a = (i / 60) * Math.PI * 2;
            const r1 = radius + 70;
            const r2 = i % 5 === 0 ? radius + 92 : radius + 80;
            return (
              <line
                key={`tk-${i}`}
                x1={cx + Math.cos(a) * r1}
                y1={cy + Math.sin(a) * r1}
                x2={cx + Math.cos(a) * r2}
                y2={cy + Math.sin(a) * r2}
                className={`tick ${i % 5 === 0 ? 'tick-major' : ''}`}
              />
            );
          })}
          {/* Coordinate labels at quadrants */}
          {[0, 15, 30, 45].map((i) => {
            const a = (i / 60) * Math.PI * 2;
            const r = radius + 110;
            return (
              <text
                key={`lbl-${i}`}
                x={cx + Math.cos(a) * r}
                y={cy + Math.sin(a) * r}
                className="ring-coord"
                textAnchor="middle"
                dominantBaseline="middle"
              >
                {String(i * 6).padStart(3, '0')}°
              </text>
            );
          })}
        </g>

        {/* Concentric guide rings */}
        <circle cx={cx} cy={cy} r={radius + 30} className="ring-guide" />
        <circle cx={cx} cy={cy} r={radius - 60} className="ring-guide faint" />
        <circle cx={cx} cy={cy} r={radius - 140} className="ring-guide faint" />

        {/* Cardinal cross */}
        <line x1={cx - radius - 30} y1={cy} x2={cx + radius + 30} y2={cy} className="cardinal" />
        <line x1={cx} y1={cy - radius - 30} x2={cx} y2={cy + radius + 30} className="cardinal" />

        {/* Heptagonal frame */}
        <path d={heptPath} className="hept-frame" />

        {/* Spokes */}
        {vertices.map((v, i) => (
          <line
            key={`spoke-${i}`}
            x1={cx} y1={cy} x2={v.x} y2={v.y}
            className={`spoke ${i === active ? 'spoke-active' : ''}`}
          />
        ))}

        {/* Beam from center to active vertex (animated, layered) */}
        <line
          x1={cx} y1={cy}
          x2={vertices[active].x} y2={vertices[active].y}
          className="active-beam-glow"
          filter="url(#strongGlow)"
        />
        <line
          x1={cx} y1={cy}
          x2={vertices[active].x} y2={vertices[active].y}
          className="active-beam"
        />

        {/* Active arc sweep */}
        <circle
          cx={cx} cy={cy} r={radius + 30}
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

        {/* Vertex nodes */}
        {vertices.map((v, i) => (
          <g key={`vtx-${i}`}>
            <circle cx={v.x} cy={v.y} r={i === active ? 24 : 14} className="vertex-ring-outer" />
            <circle
              cx={v.x} cy={v.y} r={i === active ? 14 : 7}
              className={`vertex-dot ${i === active ? 'is-active' : ''} ${i === pulseIdx ? 'is-pulse' : ''}`}
              filter={i === active ? 'url(#vertexGlow)' : undefined}
            />
            {/* Pulse traveler */}
            {i === pulseIdx && i !== active && (
              <circle cx={v.x} cy={v.y} r="20" className="pulse-wave" />
            )}
          </g>
        ))}
      </svg>

      {/* Avatar with reactive aura */}
      <div className="avatar-mount">
        <div className="avatar-aura" aria-hidden="true" />
        <div className="avatar-ring-1" aria-hidden="true" />
        <div className="avatar-ring-2" aria-hidden="true" />
        <img className="avatar-img" src={texAvatar} alt="Tex — AI control system" />
      </div>

      {/* Vertex chips */}
      {vertices.map((v, i) => {
        const layer = LAYERS[i];
        const outRadius = radius + 130;
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

/* =============================================================
   VERDICT TICKER
   ============================================================= */
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
              <span className="tick-hash">0x{((i * 31337 + 7) % 0xffffffff).toString(16).padStart(8, '0')}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* =============================================================
   HERO
   ============================================================= */
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
            <span className="h1-line">One control plane</span>
            <span className="h1-line h1-italic">for every AI agent.</span>
          </h1>

          <p className="hero-lede">
            Identity. Posture. Runtime. Policy. Evidence. Calibration. What
            Okta, Zenity, Noma, Pillar, Microsoft AGT, OPA, and Cedar each do
            separately — Tex does as <span className="lede-strong">one cryptographic loop</span>.
          </p>

          <div className="five-second">
            <div className="five-row">
              <span className="five-label">In five seconds</span>
              <span className="five-rule" />
            </div>
            <p className="five-body">
              Seven layers, one chain. Tex inventories every agent in your
              company, binds it to a human owner, defines what it can do,
              judges what it actually does, blocks what it shouldn't, seals the
              proof, and learns from outcomes — without surrendering authorship
              of the rules.
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
              <span className="stat-num">8<span className="stat-unit"> tools</span></span>
              <span className="stat-lbl">replaced by one</span>
            </div>
            <div className="stat">
              <span className="stat-num">142<span className="stat-unit">ms</span></span>
              <span className="stat-lbl">p95 verdict</span>
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

/* =============================================================
   PER-LAYER VISUALIZATIONS
   Each is a unique, animated SVG/canvas instrument.
   ============================================================= */

/* L01 — Discovery: Radar sweep finding agents */
function VizDiscovery({ active }) {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setTick((v) => v + 1), 50);
    return () => clearInterval(id);
  }, [active]);
  // Generate stable agent dot positions
  const agents = React.useMemo(() => {
    const arr = [];
    for (let i = 0; i < 28; i++) {
      const a = (i * 137.5) * Math.PI / 180;
      const r = 30 + (i * 13) % 130;
      arr.push({
        x: 200 + Math.cos(a) * r,
        y: 200 + Math.sin(a) * r,
        angle: ((Math.atan2(Math.sin(a), Math.cos(a)) + Math.PI * 2) % (Math.PI * 2)),
        type: i % 3,
      });
    }
    return arr;
  }, []);
  const sweepAngle = (tick * 0.04) % (Math.PI * 2);
  return (
    <div className="viz viz-discovery">
      <svg viewBox="0 0 400 400" className="viz-svg">
        <defs>
          <radialGradient id="rdrGlow" cx="50%" cy="50%">
            <stop offset="0%" stopColor="rgba(86,230,220,0.4)" />
            <stop offset="100%" stopColor="rgba(86,230,220,0)" />
          </radialGradient>
          <linearGradient id="sweepGrad" gradientUnits="userSpaceOnUse" x1="200" y1="200" x2="370" y2="200">
            <stop offset="0%" stopColor="rgba(86,230,220,0.6)" />
            <stop offset="100%" stopColor="rgba(86,230,220,0)" />
          </linearGradient>
        </defs>
        {/* Concentric range rings */}
        {[40, 80, 120, 170].map((r) => (
          <circle key={r} cx="200" cy="200" r={r} className="rdr-ring" />
        ))}
        {/* Crosshairs */}
        <line x1="20" y1="200" x2="380" y2="200" className="rdr-crosshair" />
        <line x1="200" y1="20" x2="200" y2="380" className="rdr-crosshair" />
        {/* Sweep wedge */}
        <g style={{ transform: `rotate(${sweepAngle}rad)`, transformOrigin: '200px 200px' }}>
          <path
            d={`M 200 200 L 370 200 A 170 170 0 0 0 ${200 + Math.cos(-0.5) * 170} ${200 + Math.sin(-0.5) * 170} Z`}
            fill="url(#sweepGrad)"
          />
          <line x1="200" y1="200" x2="370" y2="200" className="rdr-sweep-line" />
        </g>
        {/* Center node */}
        <circle cx="200" cy="200" r="6" className="rdr-center" />
        <circle cx="200" cy="200" r="14" fill="url(#rdrGlow)" />
        {/* Agent dots — light up if sweep just passed */}
        {agents.map((ag, i) => {
          const swept = Math.abs(((sweepAngle - ag.angle + Math.PI * 2) % (Math.PI * 2)));
          const isHot = swept < 0.4 || swept > Math.PI * 2 - 0.4;
          const wasHot = swept < 1.2;
          const opacity = isHot ? 1 : wasHot ? 0.5 : 0.25;
          return (
            <g key={i}>
              <circle
                cx={ag.x} cy={ag.y}
                r={ag.type === 0 ? 3.5 : 2.5}
                className={`rdr-agent rdr-type-${ag.type}`}
                style={{ opacity }}
              />
              {isHot && (
                <circle cx={ag.x} cy={ag.y} r="10" className="rdr-agent-flash" />
              )}
            </g>
          );
        })}
        {/* Coordinate readout */}
        <text x="20" y="30" className="viz-readout">SCAN.RANGE 0.0–8.0km</text>
        <text x="20" y="380" className="viz-readout">AGENTS.OBSERVED 4,217</text>
      </svg>
    </div>
  );
}

/* L02 — Registration: Identity binding (particles -> fingerprint chain) */
function VizRegistration({ active }) {
  const [t, setT] = useState(0);
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setT((v) => v + 1), 50);
    return () => clearInterval(id);
  }, [active]);
  // Three identity rows building progressively
  const rows = [
    { id: 'agent_revops_07', owner: 'm.nardizzi@', env: 'prod-us', tier: 'T1' },
    { id: 'copilot_legal_03', owner: 'k.shah@', env: 'prod-eu', tier: 'T2' },
    { id: 'workflow_ops_11', owner: 'r.patel@', env: 'staging', tier: 'T3' },
  ];
  return (
    <div className="viz viz-registration">
      <svg viewBox="0 0 400 400" className="viz-svg">
        <defs>
          <linearGradient id="bindGrad" x1="0%" x2="100%">
            <stop offset="0%" stopColor="rgba(86,230,220,0)" />
            <stop offset="50%" stopColor="rgba(86,230,220,0.7)" />
            <stop offset="100%" stopColor="rgba(86,230,220,0)" />
          </linearGradient>
        </defs>
        {rows.map((r, i) => {
          const y = 80 + i * 110;
          const buildPhase = ((t + i * 30) % 80) / 80;
          return (
            <g key={r.id}>
              {/* Actor box */}
              <rect x="20" y={y - 26} width="120" height="52" className="bind-box bind-actor" />
              <text x="80" y={y - 10} className="bind-label" textAnchor="middle">ACTOR</text>
              <text x="80" y={y + 8} className="bind-id" textAnchor="middle">{r.id}</text>

              {/* Binding line */}
              <line x1="140" y1={y} x2="260" y2={y} className="bind-line" />
              <line
                x1="140" y1={y} x2={140 + 120 * buildPhase} y2={y}
                className="bind-line-active"
              />
              <circle cx={140 + 120 * buildPhase} cy={y} r="4" className="bind-pulse" />

              {/* Owner box */}
              <rect x="260" y={y - 26} width="120" height="52" className="bind-box bind-owner" />
              <text x="320" y={y - 10} className="bind-label" textAnchor="middle">OWNER</text>
              <text x="320" y={y + 8} className="bind-id" textAnchor="middle">{r.owner}</text>

              {/* Tier badge */}
              <rect x="350" y={y + 14} width="28" height="14" className="bind-tier" />
              <text x="364" y={y + 24} className="bind-tier-text" textAnchor="middle">{r.tier}</text>
            </g>
          );
        })}
        <text x="20" y="30" className="viz-readout">BIND.CHAIN.ACTIVE</text>
        <text x="20" y="380" className="viz-readout">4,217 / 4,217 BOUND</text>
      </svg>
    </div>
  );
}

/* L03 — Capability: Policy compiler (yaml -> compiled boundaries) */
function VizCapability({ active }) {
  const [t, setT] = useState(0);
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setT((v) => v + 1), 60);
    return () => clearInterval(id);
  }, [active]);
  const lines = [
    'agent: revops_*',
    'verb: send_email',
    'scope: tier_1_clients',
    'budget: 200 / day',
    'env: production',
  ];
  const visibleLines = Math.min(lines.length, Math.floor((t % 80) / 10));
  return (
    <div className="viz viz-capability">
      <svg viewBox="0 0 400 400" className="viz-svg">
        <defs>
          <linearGradient id="compileBeam" x1="0%" x2="100%">
            <stop offset="0%" stopColor="rgba(86,230,220,0)" />
            <stop offset="50%" stopColor="rgba(86,230,220,0.6)" />
            <stop offset="100%" stopColor="rgba(86,230,220,0)" />
          </linearGradient>
        </defs>
        {/* Source policy panel */}
        <rect x="20" y="60" width="160" height="280" className="compile-panel" />
        <text x="30" y="50" className="viz-readout">policy.yaml</text>
        {lines.map((line, i) => (
          <text
            key={i}
            x="30"
            y={90 + i * 28}
            className={`compile-line ${i < visibleLines ? 'visible' : ''}`}
          >
            {line}
          </text>
        ))}

        {/* Compile beam */}
        <line x1="180" y1="200" x2="220" y2="200" className="compile-beam" />
        <text x="200" y="190" className="viz-readout" textAnchor="middle">⇒</text>

        {/* Compiled output panel */}
        <rect x="220" y="60" width="160" height="280" className="compile-panel compile-out" />
        <text x="230" y="50" className="viz-readout" style={{ fill: 'var(--tex)' }}>capability.bin</text>
        {/* Compiled binary visualization */}
        {Array.from({ length: 28 }).map((_, i) => {
          const row = Math.floor(i / 4);
          const col = i % 4;
          const x = 230 + col * 36;
          const y = 80 + row * 36;
          const lit = ((i + Math.floor(t / 5)) % 7 < 3);
          return (
            <rect
              key={i}
              x={x} y={y} width="28" height="28"
              className={`compile-block ${lit ? 'lit' : ''}`}
            />
          );
        })}
        <text x="20" y="380" className="viz-readout">186 CAPABILITIES COMPILED</text>
      </svg>
    </div>
  );
}

/* L04 — Evaluation: Six judges firing in parallel */
function VizEvaluation({ active }) {
  const [t, setT] = useState(0);
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setT((v) => v + 1), 80);
    return () => clearInterval(id);
  }, [active]);
  const judges = [
    { name: 'DETERMINISTIC', latency: '02ms' },
    { name: 'RETRIEVAL', latency: '38ms' },
    { name: 'SPECIALISTS', latency: '94ms' },
    { name: 'SEMANTIC', latency: '112ms' },
    { name: 'ROUTER', latency: '128ms' },
    { name: 'EVIDENCE', latency: '142ms' },
  ];
  const cyclePos = (t % 50) / 50;
  return (
    <div className="viz viz-evaluation">
      <svg viewBox="0 0 400 400" className="viz-svg">
        {/* Input action top */}
        <rect x="120" y="20" width="160" height="40" className="judge-input" />
        <text x="200" y="44" className="judge-input-text" textAnchor="middle">ACTION INTAKE</text>

        {/* Six judge lanes */}
        {judges.map((j, i) => {
          const y = 90 + i * 42;
          const phase = (cyclePos * 6 + i * 0.4) % 1;
          const fillX = 130 + phase * 200;
          const isActive = phase > 0.05 && phase < 0.95;
          return (
            <g key={j.name}>
              {/* Lane track */}
              <line x1="130" y1={y} x2="330" y2={y} className="judge-track" />
              {/* Lane label */}
              <text x="120" y={y + 4} className="judge-label" textAnchor="end">{j.name}</text>
              {/* Latency tag */}
              <text x="340" y={y + 4} className="judge-latency">{j.latency}</text>
              {/* Pulse traveling */}
              {isActive && (
                <>
                  <line
                    x1="130" y1={y} x2={fillX} y2={y}
                    className="judge-fill"
                  />
                  <circle cx={fillX} cy={y} r="4" className="judge-pulse" />
                </>
              )}
            </g>
          );
        })}

        {/* Verdict output bottom */}
        <rect x="120" y="350" width="160" height="40" className="judge-verdict" />
        <text x="200" y="374" className="judge-verdict-text" textAnchor="middle">VERDICT SEALED</text>

        {/* Connecting lines */}
        <line x1="200" y1="60" x2="200" y2="80" className="judge-conn" />
        <line x1="200" y1="340" x2="200" y2="350" className="judge-conn" />
      </svg>
    </div>
  );
}

/* L05 — Enforcement: Permit/Abstain/Forbid gates */
function VizEnforcement({ active }) {
  const [t, setT] = useState(0);
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setT((v) => v + 1), 80);
    return () => clearInterval(id);
  }, [active]);
  // Cycle through 3 verdicts
  const stage = Math.floor((t / 16) % 3);
  const subPos = ((t % 16) / 16);
  const verdicts = [
    { label: 'PERMIT', color: 'var(--permit)', y: 100 },
    { label: 'ABSTAIN', color: 'var(--abstain)', y: 200 },
    { label: 'FORBID', color: 'var(--forbid)', y: 300 },
  ];
  return (
    <div className="viz viz-enforcement">
      <svg viewBox="0 0 400 400" className="viz-svg">
        {/* Source */}
        <rect x="20" y="180" width="80" height="40" className="enf-source" />
        <text x="60" y="204" className="enf-text" textAnchor="middle">ACTION</text>

        {/* Three gates */}
        {verdicts.map((v, i) => (
          <g key={v.label}>
            <rect
              x="280" y={v.y - 22} width="100" height="44"
              className={`enf-gate enf-gate-${v.label.toLowerCase()} ${stage === i ? 'active' : ''}`}
            />
            <text
              x="330" y={v.y + 4}
              className={`enf-gate-text enf-gate-text-${v.label.toLowerCase()} ${stage === i ? 'active' : ''}`}
              textAnchor="middle"
            >
              {v.label}
            </text>
          </g>
        ))}

        {/* Verdict path — line from source to active gate */}
        {(() => {
          const target = verdicts[stage];
          const startX = 100, startY = 200;
          const endX = 280, endY = target.y;
          const midX = startX + (endX - startX) * subPos;
          const midY = startY + (endY - startY) * subPos;
          return (
            <>
              <path
                d={`M ${startX} ${startY} Q ${(startX + endX) / 2} ${startY}, ${endX} ${endY}`}
                className={`enf-path enf-path-${target.label.toLowerCase()}`}
              />
              <circle cx={midX} cy={midY} r="6" className={`enf-token enf-token-${target.label.toLowerCase()}`} />
            </>
          );
        })()}

        <text x="20" y="30" className="viz-readout">RUNTIME ACTION GATE</text>
        <text x="20" y="380" className="viz-readout">2.41M VERDICTS / DAY</text>
      </svg>
    </div>
  );
}

/* L06 — Evidence: Hash chain with linking blocks */
function VizEvidence({ active }) {
  const [t, setT] = useState(0);
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setT((v) => v + 1), 90);
    return () => clearInterval(id);
  }, [active]);
  const blocks = [
    { id: 'B-7A0', verdict: 'PERMIT', hash: '0x4f17ee5e' },
    { id: 'B-7A1', verdict: 'ABSTAIN', hash: '0x3c91a7d2' },
    { id: 'B-7A2', verdict: 'PERMIT', hash: '0x9a6f0413' },
    { id: 'B-7A3', verdict: 'FORBID', hash: '0x729c86b2' },
  ];
  return (
    <div className="viz viz-evidence">
      <svg viewBox="0 0 400 400" className="viz-svg">
        <defs>
          <linearGradient id="chainFlow" x1="0%" x2="100%">
            <stop offset="0%" stopColor="rgba(86,230,220,0)" />
            <stop offset="50%" stopColor="rgba(86,230,220,0.9)" />
            <stop offset="100%" stopColor="rgba(86,230,220,0)" />
          </linearGradient>
        </defs>
        {blocks.map((b, i) => {
          const y = 50 + i * 80;
          return (
            <g key={b.id}>
              {/* Block */}
              <rect x="40" y={y} width="320" height="60" className="ev-block" />
              {/* Block ID */}
              <text x="56" y={y + 22} className="ev-block-id">{b.id}</text>
              {/* Verdict tag */}
              <text x="56" y={y + 44} className={`ev-verdict ev-${b.verdict.toLowerCase()}`}>{b.verdict}</text>
              {/* Hash */}
              <text x="200" y={y + 22} className="ev-hash">prev: 0x0000{((i * 7919) % 0xffff).toString(16).padStart(4, '0')}…</text>
              <text x="200" y={y + 44} className="ev-hash ev-hash-self">self: {b.hash}…</text>
              {/* Signed badge */}
              <rect x="320" y={y + 14} width="32" height="32" className="ev-sign" />
              <text x="336" y={y + 36} className="ev-sign-text" textAnchor="middle">✓</text>
              {/* Connecting hash flow line */}
              {i < blocks.length - 1 && (
                <>
                  <line x1="200" y1={y + 60} x2="200" y2={y + 80} className="ev-link" />
                  {/* Animated pulse */}
                  <circle
                    cx="200"
                    cy={y + 60 + ((t * 2 + i * 8) % 20)}
                    r="3"
                    className="ev-link-pulse"
                  />
                </>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* L07 — Learning: Threshold dial with feedback signal */
function VizLearning({ active }) {
  const [t, setT] = useState(0);
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setT((v) => v + 1), 80);
    return () => clearInterval(id);
  }, [active]);
  const cx = 200, cy = 170;
  const radius = 80;
  const startAngle = -Math.PI * 0.75;
  const sweepRange = Math.PI * 1.5;
  const tNorm = Math.sin(t * 0.04) * 0.5 + 0.5;
  const value = 0.3 + tNorm * 0.65;
  const dialAngle = startAngle + value * sweepRange;
  const dialX = cx + Math.cos(dialAngle) * radius;
  const dialY = cy + Math.sin(dialAngle) * radius;
  const startX = cx + Math.cos(startAngle) * radius;
  const startY = cy + Math.sin(startAngle) * radius;
  const endX = cx + Math.cos(startAngle + sweepRange) * radius;
  const endY = cy + Math.sin(startAngle + sweepRange) * radius;
  const fillLargeArc = (value * sweepRange) > Math.PI ? 1 : 0;

  return (
    <div className="viz viz-learning">
      <svg viewBox="0 0 400 400" className="viz-svg">
        {/* Dial track */}
        <path
          d={`M ${startX} ${startY} A ${radius} ${radius} 0 1 1 ${endX} ${endY}`}
          className="dial-track"
        />
        {/* Active arc */}
        <path
          d={`M ${startX} ${startY} A ${radius} ${radius} 0 ${fillLargeArc} 1 ${dialX} ${dialY}`}
          className="dial-fill"
        />
        {/* Tick marks */}
        {Array.from({ length: 13 }).map((_, i) => {
          const a = startAngle + (i / 12) * sweepRange;
          const r1 = radius - 6;
          const r2 = i % 4 === 0 ? radius + 12 : radius + 5;
          return (
            <line
              key={i}
              x1={cx + Math.cos(a) * r1}
              y1={cy + Math.sin(a) * r1}
              x2={cx + Math.cos(a) * r2}
              y2={cy + Math.sin(a) * r2}
              className={`dial-tick ${i % 4 === 0 ? 'major' : ''}`}
            />
          );
        })}
        {/* Needle */}
        <line x1={cx} y1={cy} x2={dialX} y2={dialY} className="dial-needle" />
        <circle cx={cx} cy={cy} r="6" className="dial-hub" />
        <circle cx={dialX} cy={dialY} r="4" className="dial-tip" />

        {/* Lock icon */}
        <g transform="translate(40 50)">
          <rect x="0" y="6" width="20" height="16" className="dial-lock-body" />
          <path d="M 4 6 L 4 2 Q 4 -2 10 -2 Q 16 -2 16 2 L 16 6" className="dial-lock-shackle" />
          <text x="32" y="18" className="viz-readout">RULES.LOCKED</text>
        </g>

        {/* Threshold readout block — below dial */}
        <text x={cx} y={285} className="dial-value" textAnchor="middle">
          τ = {value.toFixed(3)}
        </text>
        <text x={cx} y={305} className="dial-sublabel" textAnchor="middle">THRESHOLD · TUNED</text>

        {/* Animated feedback signal at bottom */}
        <g transform="translate(40 340)">
          {Array.from({ length: 32 }).map((_, i) => {
            const h = Math.abs(Math.sin((i + t * 0.4) * 0.4)) * 18 + 2;
            return (
              <rect
                key={i}
                x={i * 10}
                y={22 - h}
                width="6"
                height={h}
                className="dial-sig-bar"
              />
            );
          })}
        </g>

        <text x={cx} y={388} className="viz-readout" textAnchor="middle">23 THRESHOLDS TUNED · WEEK</text>
      </svg>
    </div>
  );
}

const VIZ_MAP = {
  discovery: VizDiscovery,
  registration: VizRegistration,
  capability: VizCapability,
  evaluation: VizEvaluation,
  enforcement: VizEnforcement,
  evidence: VizEvidence,
  learning: VizLearning,
};

/* =============================================================
   LAYER SECTION
   ============================================================= */
function LayerSection({ layer, index, active, setActive }) {
  const ref = useRef(null);
  const isActive = active === index;
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

  const Viz = VIZ_MAP[layer.key];

  return (
    <section
      ref={ref}
      id={`layer-${layer.id}`}
      className={`layer-section ${isActive ? 'is-active' : ''}`}
      data-layer={layer.key}
    >
      <div className="ls-grid">
        <div className="ls-left">
          <div className="ls-meta">
            <span className="ls-num">L{layer.id}</span>
            <span className="ls-rule" />
            <span className="ls-key">{layer.key}.layer</span>
          </div>

          <div className="ls-absorbs">
            <span className="absorbs-label">Absorbs</span>
            <span className="absorbs-cat">{layer.absorbs}</span>
            <span className="absorbs-rivals">{layer.rivals}</span>
          </div>

          <h2 className="ls-h2">
            <span className="ls-name">{layer.name}</span>
            <span className="ls-verb">— {layer.verb}</span>
          </h2>

          <p className="ls-one">{layer.one}</p>
          <p className="ls-detail">{layer.detail}</p>

          <div className="ls-proof">
            {layer.proof.map((p) => (
              <span key={p} className="proof-pill">{p}</span>
            ))}
          </div>
        </div>

        <div className="ls-right">
          <div className="ls-viz-wrap">
            <div className="ls-viz-head">
              <span className="viz-tag">LIVE INSTRUMENT</span>
              <span className="viz-id">tx_{layer.id}_{layer.key.slice(0, 4).toUpperCase()}</span>
            </div>
            <Viz active={isActive} />
            <div className="ls-viz-foot">
              <span className="metric-label">{layer.metric.label}</span>
              <span className="metric-value">{layer.metric.value}</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* =============================================================
   CHAIN BAND
   ============================================================= */
function ChainBand() {
  return (
    <section className="chain-band" id="proof">
      <div className="cb-head">
        <span className="kicker">
          <span className="kicker-dot" />
          <span>The Chain</span>
        </span>
        <h2 className="cb-h2">
          Eight tools.<br />
          <span className="ital">One sealed loop.</span>
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

/* =============================================================
   CLOSING
   ============================================================= */
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
            Two weeks. We inventory the agents you have, map their authority, run
            real actions through the seven layers, and hand you a sealed evidence
            bundle. One control plane in. Eight tools out.
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
      <div className="foot-mid">Cryptographic control plane for AI agents. Boston · 2026.</div>
      <div className="foot-right"><a href="#top">↑ top</a></div>
    </footer>
  );
}

/* =============================================================
   APP
   ============================================================= */
function App() {
  const [active, setActive] = useState(0);
  const onSelect = useCallback((i) => {
    setActive(i);
    const target = document.getElementById(`layer-${LAYERS[i].id}`);
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, []);

  return (
    <div className="root-shell">
      <PerspectiveGrid />
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
