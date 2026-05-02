import React, { useEffect, useRef, useState, useCallback, useContext, createContext } from 'react';
import texAvatar from './tex-avatar.png';
import './styles.css';

/* =============================================================
   CALENDLY — booking config
   ============================================================= */
const CALENDLY_URL = 'https://calendly.com/matt-vortexblack/tex-trial';
const FOUNDER_EMAIL = 'matt@vortexblack.ai';

const TrialContext = createContext({ openTrial: () => {} });
const useTrial = () => useContext(TrialContext);

/* =============================================================
   THE SEVEN LAYERS
   Positioning: Tex is one custom-deployed control plane for every
   AI agent in your company — discovery, identity, policy, runtime,
   evidence, learning. Configured to your stack. Wired to your tools.
   ============================================================= */
const LAYERS = [
  {
    id: '01',
    key: 'discovery',
    name: 'Discovery',
    verb: 'See every agent.',
    absorbs: 'Agent inventory',
    rivals: 'Continuous · agentless · cross-stack',
    one: 'We scan your specific stack — your Slack, your Drive, your AgentForce, whatever you\'re using — and build a live inventory of every AI agent in your company.',
    detail:
      'First-party agents, vendor copilots, MCP-bound tools, browser automations, the autonomous workflows nobody wrote down. We map them all, bind them to a hash, and keep the inventory live as your stack evolves.',
    proof: ['agents.indexed', 'first-party + vendor + shadow', 'continuous re-scan'],
    metric: { label: 'agents observed', value: '4,217' },
    instrument: 'radar',
  },
  {
    id: '02',
    key: 'registration',
    name: 'Registration',
    verb: 'Bind actor and owner.',
    absorbs: 'Agent identity',
    rivals: 'Owner · scope · environment · trust tier',
    one: 'Every agent we discover gets a cryptographic identity, a human owner, an environment, and a trust tier — wired into how your team already works.',
    detail:
      'No orphans. No anonymous actors. We bind each agent to its owner, its scope, and the accountability path back to a real person. When a partner, auditor, or regulator asks "who authorized this agent," the answer is one query away.',
    proof: ['actor.signed', 'owner.bound', 'env.scoped'],
    metric: { label: 'actors registered', value: '4,217 / 4,217' },
    instrument: 'binding',
  },
  {
    id: '03',
    key: 'capability',
    name: 'Capability',
    verb: 'Define allowed power.',
    absorbs: 'Policy as code',
    rivals: 'Compiled · scoped · budgeted',
    one: 'We configure policy rules to your specific compliance obligations and compile them into runtime constraints your agents cannot exceed.',
    detail:
      'Capability is the contract: what this agent may do, to what data, in which environments, with what budget, under whose authority. Your written rules become live, machine-enforceable boundaries — yours to author, yours to amend, never auto-rewritten.',
    proof: ['policy.compiled', 'scope.bound', 'budget.set'],
    metric: { label: 'capabilities defined', value: '186' },
    instrument: 'compiler',
  },
  {
    id: '04',
    key: 'evaluation',
    name: 'Evaluation',
    verb: 'Read the real action.',
    absorbs: 'Runtime adjudication',
    rivals: 'Six judges · parallel · deterministic',
    one: 'Six judgment layers fire in parallel against the actual action — not the prompt — and reach a verdict in 142ms p95.',
    detail:
      'Deterministic patterns, retrieval, specialist models, semantic intent, router, and evidence run simultaneously against the real outbound message, tool call, file write, or API request. Each layer\'s output is hashed into the next so the verdict is reproducible from inputs alone.',
    proof: ['deterministic', 'retrieval', 'specialists', 'semantic', 'router', 'evidence'],
    metric: { label: 'p95 latency', value: '142 ms' },
    instrument: 'judges',
  },
  {
    id: '05',
    key: 'enforcement',
    name: 'Enforcement',
    verb: 'Permit. Abstain. Forbid.',
    absorbs: 'Action gateway',
    rivals: 'Three states · machine-binding',
    one: 'We wire enforcement into your existing tools so the verdict actually stops, holds, or releases the action before it reaches the real world.',
    detail:
      'A single verdict, three states, machine-binding. Permit releases the action under recorded authority. Abstain holds for human review — your reviewer, your queue, your call. Forbid blocks the action and seals the attempt as evidence. No "after-the-fact alerts" — actual runtime control.',
    proof: ['PERMIT', 'ABSTAIN', 'FORBID'],
    metric: { label: 'verdicts / day', value: '2.41 M' },
    instrument: 'gates',
  },
  {
    id: '06',
    key: 'evidence',
    name: 'Evidence',
    verb: 'Seal the proof.',
    absorbs: 'Audit chain',
    rivals: 'SHA-256 · HMAC-signed · replayable',
    one: 'Every decision becomes a SHA-256 hash-chained, HMAC-signed evidence bundle — replayable on demand, six months or six years later.',
    detail:
      'One dashboard showing every AI agent in your company, what they\'re allowed to do, what they actually did, and an audit-grade evidence record for every decision. Tamper-evident. Auditor-ready. When the question comes — examiner, partner, lawsuit, internal investigation — the answer is one query and a deterministic replay.',
    proof: ['sha-256', 'hmac-signed', 'append-only'],
    metric: { label: 'bundles sealed', value: '14,392,118' },
    instrument: 'chain',
  },
  {
    id: '07',
    key: 'learning',
    name: 'Learning',
    verb: 'Tune without drift.',
    absorbs: 'Closed-loop calibration',
    rivals: 'Human-authored · audit-preserved',
    one: 'Refine thresholds from sealed outcomes — without letting the system rewrite the rules you wrote.',
    detail:
      'Calibration uses your own evidence chain to retune thresholds and routing as your business changes. Policy stays human-authored. Every proposed change is logged, reviewed, and approval-gated. The system improves; the rules stay yours.',
    proof: ['signal.bound', 'human.authored', 'audit.preserved'],
    metric: { label: 'thresholds tuned', value: '23 this week' },
    instrument: 'dial',
  },
];

/* =============================================================
   V11 — MAGAZINE COVER HERO
   Tex full-bleed. Headline breaks across shoulder. Seven anatomical
   layer anchors. Verdicts stream across his chest. Bootup sequence
   on first load. Stillness with intention.
   ============================================================= */

/* Per-layer anatomical anchor positions, expressed as percentages of
   the Tex avatar image dimensions (which we'll preserve exactly).
   Each anchor has:
   - body: where the hairline terminates ON Tex's anatomy (% of avatar)
   - label: where the label floats (% of avatar, outside the silhouette)
   - side: 'left' or 'right' — determines which way the hairline elbow goes
   - glow: optional — body-local point where the focused glow blooms when active
*/
/* Anatomical anchor mapping — two-column editorial layout.
   `body`  — point ON Tex (% of figure-wrap = avatar bounding box)
   `label` — where the label sits (% of STAGE = full viewport)
   `side`  — 'left' or 'right' column
   Layers are organized in two disciplined columns at fixed x-positions.
   Vertical positions are evenly spaced down each column.
*/
const ANATOMY = {
  // LEFT COLUMN (4 anchors) — labels at x=3%, body points on Tex's left side
  '07': { body: { x: 50, y: 6  }, label: { x: 3, y: 22 }, side: 'right' },  // Learning — above head
  '01': { body: { x: 50, y: 23 }, label: { x: 3, y: 36 }, side: 'right' },  // Discovery — forehead
  '05': { body: { x: 20, y: 65 }, label: { x: 3, y: 50 }, side: 'right' },  // Enforcement — left shoulder
  '06': { body: { x: 50, y: 78 }, label: { x: 3, y: 64 }, side: 'right' },  // Evidence — chest hex
  // RIGHT COLUMN (3 anchors) — labels at x=97%, body points on Tex's right side
  '04': { body: { x: 65, y: 28 }, label: { x: 97, y: 30 }, side: 'left' },  // Evaluation — temple
  '02': { body: { x: 50, y: 50 }, label: { x: 97, y: 44 }, side: 'left' },  // Registration — throat
  '03': { body: { x: 80, y: 65 }, label: { x: 97, y: 58 }, side: 'left' },  // Capability — right shoulder
};

/* =============================================================
   PERSPECTIVE GRID — radically simplified.
   No floor lattice, no ceiling, no mouse parallax. Just deep void
   with a single horizontal horizon line and a soft radial wash.
   The page becomes a portrait, not a dashboard.
   ============================================================= */
function PerspectiveGrid() {
  const ref = useRef(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const draw = () => {
      const w = window.innerWidth, h = window.innerHeight;
      ctx.clearRect(0, 0, w, h);

      // Deep void radial wash centered slightly above midpoint
      const wash = ctx.createRadialGradient(
        w * 0.5, h * 0.46, 0,
        w * 0.5, h * 0.5, Math.max(w, h) * 0.85
      );
      wash.addColorStop(0, 'rgba(18, 38, 48, 0.32)');
      wash.addColorStop(0.5, 'rgba(6, 9, 14, 0.65)');
      wash.addColorStop(1, 'rgba(0, 0, 0, 0.98)');
      ctx.fillStyle = wash;
      ctx.fillRect(0, 0, w, h);

      // Horizon hairline — a single bright cyan line at 70% height
      const horizonY = Math.floor(h * 0.70);
      const horizonGrad = ctx.createLinearGradient(0, horizonY, w, horizonY);
      horizonGrad.addColorStop(0, 'rgba(127, 241, 233, 0)');
      horizonGrad.addColorStop(0.18, 'rgba(127, 241, 233, 0.05)');
      horizonGrad.addColorStop(0.5, 'rgba(127, 241, 233, 0.55)');
      horizonGrad.addColorStop(0.82, 'rgba(127, 241, 233, 0.05)');
      horizonGrad.addColorStop(1, 'rgba(127, 241, 233, 0)');
      ctx.strokeStyle = horizonGrad;
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.moveTo(0, horizonY);
      ctx.lineTo(w, horizonY);
      ctx.stroke();

      // Soft horizon bloom
      const bloom = ctx.createLinearGradient(0, horizonY - 60, 0, horizonY + 60);
      bloom.addColorStop(0, 'rgba(86, 230, 220, 0)');
      bloom.addColorStop(0.5, 'rgba(86, 230, 220, 0.08)');
      bloom.addColorStop(1, 'rgba(86, 230, 220, 0)');
      ctx.fillStyle = bloom;
      ctx.fillRect(0, horizonY - 60, w, 120);

      // Floor reflection mist below horizon — very subtle
      const mist = ctx.createLinearGradient(0, horizonY, 0, h);
      mist.addColorStop(0, 'rgba(86, 230, 220, 0.04)');
      mist.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = mist;
      ctx.fillRect(0, horizonY, w, h - horizonY);

      // A few static specks for texture (was animated — major scroll hog)
      for (let i = 0; i < 14; i++) {
        const seed = i * 1.31;
        const x = ((Math.sin(seed) * 0.5 + 0.5) * w);
        const y = (Math.cos(seed * 0.73) * 0.5 + 0.5) * h;
        ctx.fillStyle = 'rgba(127, 241, 233, 0.32)';
        ctx.fillRect(x, y, 1, 1);
      }
    };

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(window.innerWidth * dpr);
      canvas.height = Math.floor(window.innerHeight * dpr);
      canvas.style.width = window.innerWidth + 'px';
      canvas.style.height = window.innerHeight + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      draw();
    };

    resize();

    // Debounced resize — no per-frame rAF anymore
    let resizeT;
    const onResize = () => {
      clearTimeout(resizeT);
      resizeT = setTimeout(resize, 120);
    };
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
      clearTimeout(resizeT);
    };
  }, []);
  return <canvas className="ambient" ref={ref} aria-hidden="true" />;
}

/* =============================================================
   LAYER BAR — kept structurally but tightened to one row of
   layers, no runtime clock cluttering. Small, top-pinned.
   ============================================================= */
function LayerBar({ active, setActive, currentPath }) {
  const { openTrial: onActivate } = useTrial();
  const isHIW = currentPath === '/how-it-works';

  return (
    <nav className="layer-bar" aria-label="Seven layer navigation">
      <div className="bar-brand" onClick={() => navigate('/')} style={{ cursor: 'pointer' }}>
        <div className="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="20" height="20">
            <path d="M12 2 L21 7 L21 17 L12 22 L3 17 L3 7 Z" fill="none" stroke="currentColor" strokeWidth="1.4" />
            <path d="M7 9 H17 M12 9 V16" stroke="currentColor" strokeWidth="1.4" />
          </svg>
        </div>
        <div className="brand-text">
          <span className="brand-name">TEX</span>
          <span className="brand-sub">VortexBlack</span>
        </div>
      </div>

      <ol className="bar-cells" role="tablist">
        {LAYERS.map((layer, i) => (
          <li key={layer.id}>
            <button
              type="button"
              role="tab"
              aria-selected={i === active}
              className={`bar-cell ${i === active && !isHIW ? 'is-active' : ''}`}
              onClick={() => setActive(i)}
            >
              <span className="cell-num">L{layer.id}</span>
              <span className="cell-name">{layer.name}</span>
              <span className="cell-rule" aria-hidden="true" />
              <span className="cell-tick" aria-hidden="true" />
            </button>
          </li>
        ))}
      </ol>

      <button
        type="button"
        className={`bar-howitworks ${isHIW ? 'is-active' : ''}`}
        onClick={() => navigate('/how-it-works')}
        aria-label="How it works"
      >
        <span className="bar-howitworks-dot" aria-hidden="true" />
        <span>How it works</span>
      </button>

      <button type="button" className="bar-cta" onClick={onActivate}>
        <span>Book a demo</span>
        <span className="cta-arrow">→</span>
      </button>
    </nav>
  );
}

/* =============================================================
   AEGIS RING — kept as named export but redirects to FullBleedTex
   so internal refs in App still resolve. Not used in v11 hero.
   ============================================================= */
function AegisRing() { return null; }

/* =============================================================
   VERDICT STREAM — refactored: a horizontal row of live verdicts
   that streams across Tex's chest, in front of the avatar but
   behind the headline, with screen blend so it reads as data
   flowing through his body.
   ============================================================= */
const SAMPLE_VERDICTS = [
  { v: 'PERMIT',  actor: 'agent_revops_07',     action: 'send_email::client.quarterly',      risk: '0.12' },
  { v: 'ABSTAIN', actor: 'copilot_legal_03',    action: 'file.write::contracts/draft.docx',  risk: '0.61' },
  { v: 'FORBID',  actor: 'agent_support_22',    action: 'api.call::stripe.refund.full',      risk: '0.94' },
  { v: 'PERMIT',  actor: 'workflow_ops_11',     action: 'tool.invoke::salesforce.update',    risk: '0.18' },
  { v: 'PERMIT',  actor: 'agent_marketing_04',  action: 'send_message::slack#campaigns',     risk: '0.22' },
  { v: 'FORBID',  actor: 'agent_research_19',   action: 'browse::external.unverified',       risk: '0.88' },
  { v: 'ABSTAIN', actor: 'copilot_finance_02',  action: 'export::ledger.q3',                 risk: '0.55' },
  { v: 'PERMIT',  actor: 'agent_hr_05',         action: 'create::onboarding.task',           risk: '0.09' },
];

function ChestDataStream({ onVerdict }) {
  // Notify parent on each verdict cycle so we can pulse the chest glow.
  useEffect(() => {
    if (!onVerdict) return;
    const id = setInterval(() => {
      const i = Math.floor(Math.random() * SAMPLE_VERDICTS.length);
      onVerdict(SAMPLE_VERDICTS[i].v);
    }, 1800);
    return () => clearInterval(id);
  }, [onVerdict]);

  return (
    <div className="chest-stream" aria-hidden="true">
      <div className="chest-stream-track">
        {[...SAMPLE_VERDICTS, ...SAMPLE_VERDICTS, ...SAMPLE_VERDICTS].map((row, i) => (
          <div key={i} className={`chest-row chest-${row.v.toLowerCase()}`}>
            <span className="chest-tag">{row.v}</span>
            <span className="chest-actor">{row.actor}</span>
            <span className="chest-arrow">→</span>
            <span className="chest-action">{row.action}</span>
            <span className="chest-risk">r={row.risk}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function VerdictTicker() { return null; /* superseded by ChestDataStream */ }

/* =============================================================
   FULL-BLEED TEX — the centerpiece component
   - Avatar held at viewport-height scale, centered
   - Anatomical anchor labels with hairlines into body points
   - Active layer triggers a focused body-point glow
   - Bootup sequence: eyes -> forehead -> chest -> halo -> anchors
   ============================================================= */
function FullBleedTex({ active, setActive }) {
  /* Bootup phases:
     0 = void (initial)
     1 = eyes ignite
     2 = forehead T
     3 = chest emblem
     4 = full halo
     5 = anchor labels reveal one by one
     6 = stream begins
  */
  const [phase, setPhase] = useState(0);
  useEffect(() => {
    const seq = [
      [0, 1],
      [380, 2],
      [720, 3],
      [1080, 4],
      [1500, 5],
      [2700, 6],
    ];
    const timers = seq.map(([ms, p]) => setTimeout(() => setPhase(p), ms));
    return () => timers.forEach(clearTimeout);
  }, []);

  /* Pulse the chest glow on every passing FORBID/ABSTAIN verdict */
  const [chestPulse, setChestPulse] = useState(0);
  const handleVerdict = useCallback((v) => {
    if (v === 'FORBID' || v === 'ABSTAIN') setChestPulse((n) => n + 1);
  }, []);

  /* Auto-cycle active layer after bootup. Pauses when hero is not in view
     (off-screen) to free the main thread during scroll on the rest of the page. */
  useEffect(() => {
    if (phase < 5) return;
    let id = null;
    let visible = true;

    const start = () => {
      if (id) return;
      id = setInterval(() => {
        if (!visible) return;
        setActive((prev) => (prev + 1) % 7);
        // Subtle chest pulse occasionally for residual life on the figure
        if (Math.random() < 0.34) setChestPulse((n) => n + 1);
      }, 3600);
    };
    const stop = () => {
      if (id) { clearInterval(id); id = null; }
    };

    start();

    const onVis = () => { visible = !document.hidden; };
    document.addEventListener('visibilitychange', onVis);

    const stage = stageRef.current;
    let obs = null;
    if (stage && 'IntersectionObserver' in window) {
      obs = new IntersectionObserver((entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting && e.intersectionRatio > 0.1) {
            visible = !document.hidden;
            start();
          } else {
            visible = false;
            stop();
          }
        });
      }, { threshold: [0, 0.1] });
      obs.observe(stage);
    }

    return () => {
      stop();
      document.removeEventListener('visibilitychange', onVis);
      if (obs) obs.disconnect();
    };
  }, [phase, setActive]);

  /* Measure stage + figure-wrap so we can compute body anchor positions in
     stage-space coordinates, which lets us draw hairlines that span from
     screen-edge labels to body-anchored dots. */
  const stageRef = useRef(null);
  const figureRef = useRef(null);
  const [bodyPositions, setBodyPositions] = useState({});

  useEffect(() => {
    const measure = () => {
      const stage = stageRef.current;
      const figure = figureRef.current;
      if (!stage || !figure) return;
      const sRect = stage.getBoundingClientRect();
      const fRect = figure.getBoundingClientRect();
      const next = {};
      for (const id in ANATOMY) {
        const body = ANATOMY[id].body;
        // Body point in stage-relative pixels:
        const bx = (fRect.left - sRect.left) + (body.x / 100) * fRect.width;
        const by = (fRect.top  - sRect.top)  + (body.y / 100) * fRect.height;
        // Convert to % of stage for resolution-independent positioning
        next[id] = {
          xPct: (bx / sRect.width) * 100,
          yPct: (by / sRect.height) * 100,
        };
      }
      setBodyPositions(next);
    };
    measure();
    window.addEventListener('resize', measure);
    // Re-measure once everything's painted (image loaded)
    const t = setTimeout(measure, 100);
    return () => {
      window.removeEventListener('resize', measure);
      clearTimeout(t);
    };
  }, []);

  const activeLayer = LAYERS[active];
  const activeBody = bodyPositions[activeLayer.id];

  return (
    <div ref={stageRef} className={`tex-stage phase-${phase}`} data-active={activeLayer.id}>
      {/* Floor reflection */}
      <div className="tex-reflection" aria-hidden="true">
        <img src={texAvatar} alt="" className="tex-reflection-img" />
      </div>

      {/* Tex figure wrap */}
      <div ref={figureRef} className="tex-figure-wrap" aria-hidden="false">
        <img src={texAvatar} alt="Tex — AI control system" className="tex-figure" />

        {/* Eye ignite — fires phase 1+ */}
        <div className="tex-eyes-ignite" aria-hidden="true" />

        {/* Per-layer focused glow on active body point */}
        {phase >= 4 && (
          <div
            className="tex-focus-glow"
            key={`focus-${active}`}
            style={{
              left: `${ANATOMY[activeLayer.id].body.x}%`,
              top: `${ANATOMY[activeLayer.id].body.y}%`,
            }}
          />
        )}

        {/* Chest pulse on FORBID/ABSTAIN — kept for layer transitions but
            chest data stream removed for a calmer hero composition */}
        <div
          className="tex-chest-pulse"
          key={`pulse-${chestPulse}`}
          aria-hidden="true"
        />
      </div>

      {/* Anchor LABELS — positioned in stage coords at viewport edges */}
      {phase >= 5 && (
        <div className="tex-anchors">
          {LAYERS.map((layer, i) => {
            const a = ANATOMY[layer.id];
            const isActive = i === active;
            return (
              <button
                key={layer.id}
                type="button"
                className={`tex-anchor ${isActive ? 'is-active' : ''} side-${a.side}`}
                style={{
                  left: `${a.label.x}%`,
                  top: `${a.label.y}%`,
                  animationDelay: `${i * 0.11}s`,
                }}
                onClick={() => setActive(i)}
                onMouseEnter={() => setActive(i)}
                aria-label={`${layer.name} — ${layer.verb}`}
              >
                <span className="anchor-num">L{layer.id}</span>
                <span className="anchor-name">{layer.name}</span>
                <span className="anchor-verb">{layer.verb}</span>
              </button>
            );
          })}
        </div>
      )}

      {/* Hairline lines drawn in a normalized 100x100 viewBox so polyline %-style coords work */}
      {phase >= 5 && Object.keys(bodyPositions).length > 0 && (
        <svg
          className="tex-hairlines tex-hairlines-lines"
          aria-hidden="true"
          viewBox="0 0 100 100"
          preserveAspectRatio="none"
        >
          {LAYERS.map((layer, i) => {
            const a = ANATOMY[layer.id];
            const body = bodyPositions[layer.id];
            if (!body) return null;
            const isActive = i === active;
            const lx = a.label.x;
            const ly = a.label.y + 1.6;
            const bx = body.xPct;
            const by = body.yPct;
            const ex = a.side === 'right'
              ? Math.max(bx - 4, lx + 4)   // ensure elbow is past label, before body
              : Math.min(bx + 4, lx - 4);
            return (
              <polyline
                key={layer.id}
                className={`hairline-path ${isActive ? 'is-lit' : ''}`}
                points={`${lx},${ly} ${ex},${ly} ${bx},${by}`}
                fill="none"
                vectorEffect="non-scaling-stroke"
                style={{ animationDelay: `${i * 0.11 + 0.2}s` }}
              />
            );
          })}
        </svg>
      )}

      {/* Body dots + active rings — separate SVG using natural aspect with % units */}
      {phase >= 5 && Object.keys(bodyPositions).length > 0 && (
        <svg
          className="tex-hairlines tex-hairlines-dots"
          aria-hidden="true"
          width="100%"
          height="100%"
        >
          {LAYERS.map((layer, i) => {
            const body = bodyPositions[layer.id];
            if (!body) return null;
            const isActive = i === active;
            return (
              <g key={layer.id} className={`hairline-dot-grp ${isActive ? 'is-lit' : ''}`}
                 style={{ animationDelay: `${i * 0.11 + 0.2}s` }}>
                <circle
                  className="hairline-body-dot"
                  cx={`${body.xPct}%`} cy={`${body.yPct}%`} r="3.5"
                />
                <circle
                  className="hairline-body-ring"
                  cx={`${body.xPct}%`} cy={`${body.yPct}%`} r="9"
                  fill="none"
                />
              </g>
            );
          })}
        </svg>
      )}
    </div>
  );
}

/* =============================================================
   HERO — the magazine cover composition
   ============================================================= */
function Hero({ active, setActive }) {
  const { openTrial } = useTrial();

  return (
    <section className="hero hero-v11" id="top">
      {/* The full-bleed Tex */}
      <FullBleedTex active={active} setActive={setActive} />

      {/* Headline locked to Tex's anatomy — kicker above, italic across upper chest */}
      <div className="hv11-headline-wrap">
        <div className="hv11-kicker">
          <span className="hv11-kicker-dot" />
          <span>Tex by VortexBlack</span>
          <span className="hv11-kicker-sep">/</span>
          <span>Custom-deployed in 4–6 weeks</span>
        </div>
        <h1 className="hv11-headline">
          <span className="hv11-h-line">One control plane</span>
          <span className="hv11-h-line hv11-h-italic">for every AI agent.</span>
        </h1>
      </div>

      {/* Bottom telemetry bar */}
      <div className="hv11-bottom">
        <div className="hv11-bottom-left">
          <button type="button" onClick={openTrial} className="btn-primary hv11-cta">
            <span>Book a demo</span>
            <span className="btn-arrow">→</span>
          </button>
          <a href="#layer-01" className="btn-ghost hv11-trace">
            <span>Trace the seven layers</span>
          </a>
        </div>

        <div className="hv11-readout" aria-hidden="false">
          <span className="hv11-readout-dot" />
          <span className="hv11-readout-label">RUNTIME</span>
          <span className="hv11-readout-sep" />
          <span className="hv11-readout-value">142<span className="hv11-readout-unit">ms p95</span></span>
          <span className="hv11-readout-sep" />
          <span className="hv11-readout-value hv11-readout-strong">14.4<span className="hv11-readout-unit">M sealed</span></span>
          <span className="hv11-readout-sep" />
          <span className="hv11-readout-value hv11-readout-strong">2.41<span className="hv11-readout-unit">M / day</span></span>
        </div>
      </div>
    </section>
  );
}



/* =============================================================
   CONTROL PLANE INTRO — the section that follows the hero.
   Image-1 composition: kicker + headline + body + framed
   "In five seconds" callout + CTAs + 3 stats on the left;
   orbital ring of seven layers around a smaller Tex avatar
   on the right.
   ============================================================= */
function ControlPlaneIntro() {
  const { openTrial } = useTrial();

  // Layer order around the orbit, starting at top and going clockwise.
  // Angle in degrees, 0 = top, going clockwise.
  const ORBIT = [
    { id: '01', name: 'Discovery',    angle: 0   },
    { id: '02', name: 'Registration', angle: 52  },
    { id: '03', name: 'Capability',   angle: 104 },
    { id: '04', name: 'Evaluation',   angle: 156 },
    { id: '05', name: 'Enforcement',  angle: 204 },
    { id: '06', name: 'Evidence',     angle: 256 },
    { id: '07', name: 'Learning',     angle: 308 },
  ];

  return (
    <section className="cpi" id="control-plane">
      <div className="cpi-grid">

        {/* LEFT: copy block */}
        <div className="cpi-left">
          <div className="cpi-kicker">
            <span className="cpi-kicker-dot" />
            <span>Tex by VortexBlack</span>
            <span className="cpi-kicker-sep">/</span>
            <span>Custom-deployed in 4–6 weeks</span>
          </div>

          <h2 className="cpi-h2">
            <span className="cpi-h-line">One control plane</span>
            <span className="cpi-h-line cpi-h-italic">for every AI agent.</span>
          </h2>

          <p className="cpi-lede">
            We deploy a unified AI control plane in your environment in 4–6 weeks.
            Discovery scans your stack — your Slack, your Drive, your AgentForce,
            whatever you're using. We configure policy rules to your specific
            compliance obligations. We wire enforcement into your existing tools.
          </p>

          {/* Framed callout — corner brackets, hairline rule, FS-001 tag */}
          <figure className="cpi-callout">
            <span className="cpi-callout-corner cpi-corner-tl" aria-hidden="true" />
            <span className="cpi-callout-corner cpi-corner-tr" aria-hidden="true" />
            <span className="cpi-callout-corner cpi-corner-bl" aria-hidden="true" />
            <span className="cpi-callout-corner cpi-corner-br" aria-hidden="true" />
            <header className="cpi-callout-head">
              <span className="cpi-callout-label">In five seconds</span>
              <span className="cpi-callout-rule" aria-hidden="true" />
              <span className="cpi-callout-tag">FS-001</span>
            </header>
            <blockquote className="cpi-callout-body">
              One platform, one dashboard, one relationship. Every AI agent in
              your company, what they're allowed to do, what they actually did,
              and audit-grade evidence for every decision they made.
            </blockquote>
          </figure>

          <div className="cpi-actions">
            <button type="button" onClick={openTrial} className="cpi-cta">
              <span>Book a 20-min founder call</span>
              <span className="btn-arrow">→</span>
            </button>
            <a href="#layer-01" className="cpi-trace">
              <span>Trace the seven layers</span>
            </a>
          </div>

          <div className="cpi-stats">
            <div className="cpi-stat">
              <span className="cpi-stat-value">4–6<span className="cpi-stat-unit">weeks</span></span>
              <span className="cpi-stat-label">to deployed control plane</span>
            </div>
            <div className="cpi-stat">
              <span className="cpi-stat-value">142<span className="cpi-stat-unit">ms</span></span>
              <span className="cpi-stat-label">p95 verdict</span>
            </div>
            <div className="cpi-stat">
              <span className="cpi-stat-value">1<span className="cpi-stat-unit">dashboard</span></span>
              <span className="cpi-stat-label">every AI agent, every decision</span>
            </div>
          </div>
        </div>

        {/* RIGHT: orbital ring composition */}
        <div className="cpi-right" aria-hidden="false">
          <div className="cpi-orbit">
            {/* Concentric guide rings */}
            <div className="cpi-ring cpi-ring-outer" aria-hidden="true" />
            <div className="cpi-ring cpi-ring-mid"   aria-hidden="true" />
            <div className="cpi-ring cpi-ring-inner" aria-hidden="true" />

            {/* Connector spokes — one per chip */}
            <svg className="cpi-spokes" viewBox="0 0 100 100" aria-hidden="true" preserveAspectRatio="none">
              {ORBIT.map((o) => {
                const rad = (o.angle - 90) * Math.PI / 180;
                const r = 47;
                const x = 50 + Math.cos(rad) * r;
                const y = 50 + Math.sin(rad) * r;
                return (
                  <line
                    key={o.id}
                    x1="50" y1="50"
                    x2={x} y2={y}
                    className="cpi-spoke"
                    vectorEffect="non-scaling-stroke"
                  />
                );
              })}
            </svg>

            {/* Tex figure at center, smaller */}
            <div className="cpi-figure">
              <img src={texAvatar} alt="Tex" className="cpi-figure-img" />
              <div className="cpi-figure-glow" aria-hidden="true" />
            </div>

            {/* Layer chips placed around the orbit */}
            {ORBIT.map((o, i) => {
              const rad = (o.angle - 90) * Math.PI / 180;
              const r = 47;
              const x = 50 + Math.cos(rad) * r;
              const y = 50 + Math.sin(rad) * r;
              return (
                <a
                  key={o.id}
                  href={`#layer-${o.id}`}
                  className="cpi-chip"
                  style={{
                    left: `${x}%`,
                    top: `${y}%`,
                    animationDelay: `${0.4 + i * 0.07}s`,
                  }}
                >
                  <span className="cpi-chip-num">{o.id}</span>
                  <span className="cpi-chip-name">{o.name}</span>
                </a>
              );
            })}

            {/* Active node — orbits the outer ring */}
            <div className="cpi-node-active" aria-hidden="true" />
          </div>
        </div>
      </div>
    </section>
  );
}


/* =============================================================
   HOME HOW-IT-WORKS INTRO — small banner that introduces the
   inlined HIW carousel on the homepage. Mirrors the route page's
   hero copy but condensed so the home flow stays focused.
   ============================================================= */
function HomeHowItWorksIntro() {
  return (
    <section className="hh-hiw-intro" id="how-it-works">
      <div className="hh-hiw-inner">
        <span className="hh-hiw-kicker">
          <span className="cpi-kicker-dot" />
          <span>How it works</span>
          <span className="cpi-kicker-sep">/</span>
          <span>Concierge deployment · 4–6 weeks</span>
        </span>
        <h2 className="hh-hiw-h2">
          <span className="hh-hiw-h-line">Six weeks from signed</span>
          <span className="hh-hiw-h-line hh-hiw-h-italic">to a sealed control plane.</span>
        </h2>
        <p className="hh-hiw-lede">
          Tex is configured to your stack, your rules, your compliance reality —
          by the people who built the engine. No off-the-shelf dashboard. No
          junior consultants. No rip-and-replace. Six phases. One outcome.
        </p>
        <div className="hh-hiw-scroll" aria-hidden="true">
          <span>Scroll to begin deployment</span>
          <span className="hh-hiw-arrow">↓</span>
        </div>
      </div>
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

  // Local "in-view" state — independent of which layer is the global active one.
  // Fires earlier than the active threshold so panels light up as soon as they
  // begin entering the viewport, not after they're 55% on screen.
  const [inView, setInView] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          // In-view: fires at 15% — used for content fade-in
          if (e.intersectionRatio > 0.15) {
            setInView(true);
          }
          // Active: fires at 45% — used for the global "current layer"
          if (e.isIntersecting && e.intersectionRatio > 0.45) {
            setActive(index);
          }
        });
      },
      { threshold: [0.15, 0.45, 0.7] }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, [index, setActive]);

  const Viz = VIZ_MAP[layer.key];

  return (
    <section
      ref={ref}
      id={`layer-${layer.id}`}
      className={`layer-section ${isActive ? 'is-active' : ''} ${inView ? 'is-inview' : ''}`}
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
          Seven layers.<br />
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
  const { openTrial } = useTrial();
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
            Four to six weeks. We deploy a unified AI control plane in your
            environment, configured to your specific stack and your specific
            compliance obligations. One implementation, one platform, one
            ongoing relationship — instead of buying eight tools and stitching
            them together yourself.
          </p>
          <div className="hero-actions">
            <button type="button" onClick={openTrial} className="btn-primary">
              <span>Book a demo</span>
              <span className="btn-arrow">→</span>
            </button>
            <a href={`mailto:${FOUNDER_EMAIL}?subject=Tex%20%E2%80%94%20founder%20conversation`} className="btn-ghost">
              <span>Talk to the founder</span>
            </a>
            <a
              href="/how-it-works"
              className="btn-ghost"
              onClick={(e) => { e.preventDefault(); navigate('/how-it-works'); }}
            >
              <span>Not ready to talk? See the deployment timeline</span>
              <span className="btn-arrow">→</span>
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
      <div className="foot-mid">One control plane for every AI agent. Boston · 2026.</div>
      <div className="foot-right"><a href="#top">↑ top</a></div>
    </footer>
  );
}

/* =============================================================
   APP
   ============================================================= */
/* =============================================================
   TRIAL MODAL — Calendly inline embed in a fullscreen overlay
   Loads Calendly's widget script on demand. Falls back to opening
   the booking link in a new tab if the script fails.
   ============================================================= */
function TrialModal({ open, onClose }) {
  const containerRef = useRef(null);
  const [scriptStatus, setScriptStatus] = useState('idle'); // idle | loading | ready | error

  // Load Calendly script lazily on first open
  useEffect(() => {
    if (!open) return;
    if (window.Calendly) {
      setScriptStatus('ready');
      return;
    }
    if (scriptStatus === 'loading' || scriptStatus === 'ready') return;
    setScriptStatus('loading');

    const existing = document.querySelector('script[data-tex-calendly]');
    if (existing) {
      existing.addEventListener('load', () => setScriptStatus('ready'));
      existing.addEventListener('error', () => setScriptStatus('error'));
      return;
    }
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = 'https://assets.calendly.com/assets/external/widget.css';
    document.head.appendChild(link);
    const script = document.createElement('script');
    script.src = 'https://assets.calendly.com/assets/external/widget.js';
    script.async = true;
    script.dataset.texCalendly = 'true';
    script.onload = () => setScriptStatus('ready');
    script.onerror = () => setScriptStatus('error');
    document.body.appendChild(script);
  }, [open, scriptStatus]);

  // Independent safety timeout — surfaces fallback if script never loads
  useEffect(() => {
    if (scriptStatus !== 'loading') return;
    const t = setTimeout(() => {
      if (!window.Calendly) setScriptStatus('error');
    }, 9000);
    return () => clearTimeout(t);
  }, [scriptStatus]);

  // Initialize the inline widget once script + container are ready
  useEffect(() => {
    if (!open || scriptStatus !== 'ready') return;
    if (!containerRef.current) return;
    // Clear any prior render (in case modal was reopened)
    containerRef.current.innerHTML = '';
    if (window.Calendly && window.Calendly.initInlineWidget) {
      window.Calendly.initInlineWidget({
        url: `${CALENDLY_URL}?hide_landing_page_details=1&hide_gdpr_banner=1&background_color=04060a&text_color=f6f4ee&primary_color=56e6dc`,
        parentElement: containerRef.current,
        prefill: {},
        utm: { utmSource: 'texaegis.com', utmMedium: 'website', utmCampaign: 'trial-cta' },
      });
      // Sanity check — if the iframe never lands, surface fallback
      const sanityTimeout = setTimeout(() => {
        if (containerRef.current && containerRef.current.querySelector('iframe') == null) {
          setScriptStatus('error');
        }
      }, 6000);
      return () => clearTimeout(sanityTimeout);
    } else {
      setScriptStatus('error');
    }
  }, [open, scriptStatus]);

  // Lock body scroll while modal is open
  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = prev; };
  }, [open]);

  // Close on Escape
  useEffect(() => {
    if (!open) return;
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="trial-modal" role="dialog" aria-modal="true" aria-label="Book a demo">
      <div className="trial-backdrop" onClick={onClose} />
      <div className="trial-panel">
        <header className="trial-head">
          <div className="trial-head-left">
            <span className="trial-tag">DEMO · INTAKE</span>
            <h3 className="trial-title">Book a demo</h3>
            <p className="trial-sub">
              See Tex run on your stack. Pick a slot below.
            </p>
          </div>
          <button type="button" className="trial-close" onClick={onClose} aria-label="Close">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M5 5 L19 19 M19 5 L5 19" strokeLinecap="round" />
            </svg>
          </button>
        </header>
        <div className="trial-body">
          {scriptStatus === 'error' ? (
            <div className="trial-fallback">
              <p>Couldn't load the inline scheduler.</p>
              <a className="btn-primary" href={CALENDLY_URL} target="_blank" rel="noopener noreferrer">
                <span>Open scheduler</span>
                <span className="btn-arrow">→</span>
              </a>
            </div>
          ) : (
            <>
              {scriptStatus !== 'ready' && (
                <div className="trial-loading">
                  <div className="trial-spinner" aria-hidden="true" />
                  <span>Loading scheduler…</span>
                </div>
              )}
              <div ref={containerRef} className="trial-embed" />
            </>
          )}
        </div>
      </div>
    </div>
  );
}


/* =============================================================
   ROUTING — minimal client-side router (no deps)
   - useRoute() returns the current pathname
   - navigate(path) pushes history + emits popstate-equivalent event
   - vercel.json already rewrites /* -> / so refreshes work
   ============================================================= */
function useRoute() {
  const [path, setPath] = useState(typeof window !== 'undefined' ? window.location.pathname : '/');
  useEffect(() => {
    const onPop = () => setPath(window.location.pathname);
    window.addEventListener('popstate', onPop);
    window.addEventListener('tex:navigate', onPop);
    return () => {
      window.removeEventListener('popstate', onPop);
      window.removeEventListener('tex:navigate', onPop);
    };
  }, []);
  return path;
}

function navigate(path) {
  if (typeof window === 'undefined') return;
  if (window.location.pathname === path) return;
  window.history.pushState({}, '', path);
  window.dispatchEvent(new Event('tex:navigate'));
  window.scrollTo({ top: 0, behavior: 'auto' });
}

/* =============================================================
   PHASES — Six-week deployment journey
   Phase 0 (Discovery Call) -> Phase 5 (Ongoing Calibration)
   ============================================================= */
const PHASES = [
  {
    id: '00',
    name: 'Discovery Call',
    duration: 'Week 0',
    durationSub: 'Before contract',
    one: '30-minute call with the founder. We map your AI agent surface area, your compliance obligations, and your existing security stack.',
    deliverables: [
      'Surface area assessment',
      'Compliance obligation mapping',
      'Existing security stack review',
      'Written scope-of-work and pricing',
    ],
    outcome: 'You leave with a written scope-of-work and pricing. No commitment.',
    instrument: 'discovery',
  },
  {
    id: '01',
    name: 'Inventory',
    duration: 'Week 1',
    durationSub: 'Read-only scan',
    one: 'We connect Tex to your environment via read-only credentials. Discovery scans your Slack, Drive, GitHub, AgentForce, vendor copilots, and MCP-bound tools.',
    deliverables: [
      'Read-only credential connection',
      'Cross-stack agent discovery',
      'First-party + vendor + shadow workflow detection',
      'Owner and trust tier proposal',
    ],
    outcome: 'Signed inventory dashboard with every agent, owner, and trust tier proposed.',
    instrument: 'inventory',
  },
  {
    id: '02',
    name: 'Policy Configuration',
    duration: 'Week 2–3',
    durationSub: 'Workshop + compile',
    one: 'We sit with your compliance and security teams in a structured policy workshop. Your written rules become live, machine-enforceable policy as code. You author. We compile.',
    deliverables: [
      'Structured policy workshop',
      'Regulatory + AUP + data handling translation',
      'Policy-as-code compilation per agent class',
      'Capability layer scoped to your obligations',
    ],
    outcome: 'Your specific policy rules running in the capability layer, scoped per agent class.',
    instrument: 'policy',
  },
  {
    id: '03',
    name: 'Enforcement Wiring',
    duration: 'Week 3–5',
    durationSub: 'Runtime integration',
    one: "We integrate Tex's adjudication engine into your existing agent stack. Your agents call Tex before executing. PERMIT releases. ABSTAIN routes to human review. FORBID blocks and seals as evidence.",
    deliverables: [
      'Adjudication engine integration',
      'PERMIT / ABSTAIN / FORBID wiring',
      'Human-review routing for ABSTAIN',
      'No rip-and-replace of existing tools',
    ],
    outcome: 'Live runtime enforcement with verdict latency under 200ms.',
    instrument: 'enforcement',
  },
  {
    id: '04',
    name: 'Evidence + Handoff',
    duration: 'Week 5–6',
    durationSub: 'Production handoff',
    one: 'Every decision is sealed in a hash-chained, HMAC-signed evidence bundle, replayable on demand. Security gets a dashboard. Compliance gets audit-ready reports. We hand you the keys.',
    deliverables: [
      'SHA-256 hash-chained evidence bundles',
      'HMAC-signed, replayable on demand',
      'Security dashboard + compliance reports',
      '90-day runbook + named point of contact',
    ],
    outcome: 'Production-grade adjudication, full audit trail, named ongoing point of contact.',
    instrument: 'evidence',
  },
  {
    id: '05',
    name: 'Ongoing Calibration',
    duration: 'Month 2+',
    durationSub: 'Closed-loop tuning',
    one: 'Tex tunes thresholds against your actual outcomes. Policy stays human-authored — you author the rules, we measure their performance. Your stack evolves; the inventory keeps up.',
    deliverables: [
      'Threshold tuning against sealed outcomes',
      'Quarterly business reviews',
      'On-demand integration support',
      'Continuous discovery as your stack evolves',
    ],
    outcome: 'A living control plane that improves with use — without rewriting your rules.',
    instrument: 'calibration',
  },
];

/* =============================================================
   PHASE INSTRUMENT VISUALS
   One unique schematic per phase, matching the AegisRing language.
   ============================================================= */
function PhaseInstrument({ phase, active }) {
  const t = phase.instrument;
  if (t === 'discovery') return <InstDiscovery active={active} />;
  if (t === 'inventory') return <InstInventory active={active} />;
  if (t === 'policy') return <InstPolicy active={active} />;
  if (t === 'enforcement') return <InstEnforcement active={active} />;
  if (t === 'evidence') return <InstEvidence active={active} />;
  if (t === 'calibration') return <InstCalibration active={active} />;
  return null;
}

/* Phase 0 — Discovery: orbiting handshake */
function InstDiscovery({ active }) {
  const [t, setT] = useState(0);
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setT((v) => v + 1), 50);
    return () => clearInterval(id);
  }, [active]);
  const angle = (t * 0.04) % (Math.PI * 2);
  return (
    <svg viewBox="0 0 400 400" className="phase-svg">
      <defs>
        <radialGradient id="discGlow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="rgba(86, 230, 220, 0.35)" />
          <stop offset="100%" stopColor="rgba(86, 230, 220, 0)" />
        </radialGradient>
      </defs>
      <circle cx="200" cy="200" r="160" fill="url(#discGlow)" />
      <circle cx="200" cy="200" r="120" className="phase-ring" />
      <circle cx="200" cy="200" r="80" className="phase-ring faint" />
      {/* Two nodes facing each other (you + founder) */}
      <g>
        <circle cx={200 + Math.cos(angle) * 120} cy={200 + Math.sin(angle) * 120} r="10" className="phase-node-bright" />
        <circle cx={200 - Math.cos(angle) * 120} cy={200 - Math.sin(angle) * 120} r="10" className="phase-node" />
      </g>
      {/* Connecting line */}
      <line
        x1={200 + Math.cos(angle) * 120} y1={200 + Math.sin(angle) * 120}
        x2={200 - Math.cos(angle) * 120} y2={200 - Math.sin(angle) * 120}
        className="phase-link"
      />
      <circle cx="200" cy="200" r="4" className="phase-center" />
      <text x="200" y="350" className="phase-readout" textAnchor="middle">DISCOVERY · 30 MIN</text>
    </svg>
  );
}

/* Phase 1 — Inventory: agents found, building list */
function InstInventory({ active }) {
  const [t, setT] = useState(0);
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setT((v) => v + 1), 80);
    return () => clearInterval(id);
  }, [active]);
  const found = Math.min(7, Math.floor(t / 4));
  const agents = [
    { x: 60, y: 80, name: 'agent_revops_07' },
    { x: 320, y: 110, name: 'copilot_legal_03' },
    { x: 90, y: 200, name: 'agent_marketing_04' },
    { x: 280, y: 240, name: 'workflow_ops_11' },
    { x: 140, y: 320, name: 'agent_hr_05' },
    { x: 250, y: 60, name: 'agent_support_22' },
    { x: 350, y: 320, name: 'agent_research_19' },
  ];
  return (
    <svg viewBox="0 0 400 400" className="phase-svg">
      <defs>
        <linearGradient id="invSweep" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="rgba(86, 230, 220, 0)" />
          <stop offset="50%" stopColor="rgba(86, 230, 220, 0.5)" />
          <stop offset="100%" stopColor="rgba(86, 230, 220, 0)" />
        </linearGradient>
      </defs>
      {/* Sweep band */}
      <rect x="0" y={(t * 4) % 400 - 60} width="400" height="60" fill="url(#invSweep)" className="phase-sweep-band" />
      {/* Agents */}
      {agents.map((a, i) => (
        <g key={i} className={i < found ? 'phase-agent-found' : 'phase-agent'}>
          <rect x={a.x - 16} y={a.y - 8} width="100" height="16" className="phase-agent-bg" />
          <circle cx={a.x} cy={a.y} r="3" className={i < found ? 'phase-dot-bright' : 'phase-dot'} />
          <text x={a.x + 10} y={a.y + 3} className="phase-readout-sm">{a.name}</text>
        </g>
      ))}
      <text x="20" y="380" className="phase-readout">AGENTS · {found}/7 INDEXED</text>
    </svg>
  );
}

/* Phase 2 — Policy: source rules compile to gates */
function InstPolicy({ active }) {
  const [t, setT] = useState(0);
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setT((v) => v + 1), 60);
    return () => clearInterval(id);
  }, [active]);
  const phase = Math.floor((t / 12) % 3);
  const rules = ['data_class != PII', 'env == prod', 'budget < $100', 'tier >= REVIEWED'];
  return (
    <svg viewBox="0 0 400 400" className="phase-svg">
      {/* Source code */}
      <g transform="translate(20,40)">
        <rect width="160" height="220" className="phase-panel" />
        <text x="10" y="20" className="phase-panel-label">policy.tex</text>
        {rules.map((r, i) => (
          <text key={i} x="10" y={50 + i * 28}
            className={`phase-code ${phase >= 1 ? 'is-compiled' : ''}`}
            style={{ animationDelay: `${i * 0.15}s` }}>
            {r}
          </text>
        ))}
      </g>
      {/* Arrow */}
      <g transform="translate(190,140)">
        <line x1="0" y1="10" x2="20" y2="10" className="phase-arrow" />
        <path d="M 18 6 L 24 10 L 18 14 Z" className="phase-arrow-head" />
      </g>
      {/* Compiled output */}
      <g transform="translate(220,40)">
        <rect width="160" height="220" className={`phase-panel ${phase >= 2 ? 'is-active' : ''}`} />
        <text x="10" y="20" className="phase-panel-label">compiled</text>
        {rules.map((_, i) => (
          <g key={i} transform={`translate(10,${40 + i * 28})`}>
            <rect width="140" height="20" className={`phase-gate ${phase >= 2 ? 'is-set' : ''}`}
              style={{ animationDelay: `${0.4 + i * 0.1}s` }} />
            <text x="10" y="14" className="phase-gate-text">GATE_{i + 1}</text>
          </g>
        ))}
      </g>
      <text x="200" y="380" className="phase-readout" textAnchor="middle">POLICY · COMPILED</text>
    </svg>
  );
}

/* Phase 3 — Enforcement: PERMIT/ABSTAIN/FORBID gate */
function InstEnforcement({ active }) {
  const [t, setT] = useState(0);
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setT((v) => v + 1), 50);
    return () => clearInterval(id);
  }, [active]);
  const verdict = ['PERMIT', 'ABSTAIN', 'FORBID'][Math.floor((t / 30) % 3)];
  const cls = verdict === 'PERMIT' ? 'is-permit' : verdict === 'ABSTAIN' ? 'is-abstain' : 'is-forbid';
  return (
    <svg viewBox="0 0 400 400" className="phase-svg">
      {/* Action approaching */}
      <line x1="20" y1="200" x2="160" y2="200" className="phase-action-line" />
      <circle cx={20 + ((t * 4) % 140)} cy="200" r="6" className="phase-action-bead" />
      {/* Tex gate */}
      <g transform="translate(160,140)">
        <rect width="80" height="120" className="phase-gate-tex" />
        <text x="40" y="65" className="phase-gate-tex-label" textAnchor="middle">TEX</text>
        <text x="40" y="82" className="phase-gate-tex-sub" textAnchor="middle">142ms</text>
      </g>
      {/* Three outcomes */}
      <g transform="translate(260,160)">
        <rect width="120" height="20" className={`phase-verdict ${verdict === 'PERMIT' ? 'is-permit-active' : ''}`} />
        <text x="60" y="14" textAnchor="middle" className="phase-verdict-text">PERMIT</text>
      </g>
      <g transform="translate(260,190)">
        <rect width="120" height="20" className={`phase-verdict ${verdict === 'ABSTAIN' ? 'is-abstain-active' : ''}`} />
        <text x="60" y="14" textAnchor="middle" className="phase-verdict-text">ABSTAIN</text>
      </g>
      <g transform="translate(260,220)">
        <rect width="120" height="20" className={`phase-verdict ${verdict === 'FORBID' ? 'is-forbid-active' : ''}`} />
        <text x="60" y="14" textAnchor="middle" className="phase-verdict-text">FORBID</text>
      </g>
      <text x="200" y="380" className={`phase-readout ${cls}`} textAnchor="middle">VERDICT · {verdict}</text>
    </svg>
  );
}

/* Phase 4 — Evidence: hash chain blocks linking */
function InstEvidence({ active }) {
  const [t, setT] = useState(0);
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setT((v) => v + 1), 80);
    return () => clearInterval(id);
  }, [active]);
  const blocks = 5;
  const linked = Math.min(blocks, Math.floor(t / 6));
  return (
    <svg viewBox="0 0 400 400" className="phase-svg">
      {[...Array(blocks)].map((_, i) => {
        const x = 30 + i * 70;
        const isLinked = i < linked;
        return (
          <g key={i}>
            {i > 0 && (
              <line
                x1={x - 18} y1="200" x2={x} y2="200"
                className={`phase-chain-link ${isLinked ? 'is-linked' : ''}`}
              />
            )}
            <rect
              x={x} y="170" width="52" height="60"
              className={`phase-block ${isLinked ? 'is-sealed' : ''}`}
              style={{ animationDelay: `${i * 0.18}s` }}
            />
            <text x={x + 26} y="195" className="phase-block-num" textAnchor="middle">{String(i + 1).padStart(2, '0')}</text>
            <text x={x + 26} y="215" className="phase-block-hash" textAnchor="middle">
              0x{((i * 31337) % 0xfff).toString(16).padStart(3, '0')}
            </text>
          </g>
        );
      })}
      <text x="200" y="380" className="phase-readout" textAnchor="middle">CHAIN · SHA-256 · HMAC-SIGNED</text>
    </svg>
  );
}

/* Phase 5 — Calibration: threshold dial tuning */
function InstCalibration({ active }) {
  const [t, setT] = useState(0);
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setT((v) => v + 1), 50);
    return () => clearInterval(id);
  }, [active]);
  const angle = -Math.PI * 0.6 + Math.sin(t * 0.04) * 0.5;
  const cx = 200, cy = 220, r = 100;
  return (
    <svg viewBox="0 0 400 400" className="phase-svg">
      {/* Arc */}
      <path
        d={`M ${cx + Math.cos(-Math.PI) * r} ${cy + Math.sin(-Math.PI) * r} A ${r} ${r} 0 0 1 ${cx + Math.cos(0) * r} ${cy + Math.sin(0) * r}`}
        className="phase-dial-arc"
      />
      {/* Threshold ticks */}
      {[...Array(11)].map((_, i) => {
        const a = -Math.PI + (i / 10) * Math.PI;
        const r1 = r - 6, r2 = r + 6;
        return (
          <line
            key={i}
            x1={cx + Math.cos(a) * r1} y1={cy + Math.sin(a) * r1}
            x2={cx + Math.cos(a) * r2} y2={cy + Math.sin(a) * r2}
            className={`phase-dial-tick ${i % 5 === 0 ? 'is-major' : ''}`}
          />
        );
      })}
      {/* Needle */}
      <line
        x1={cx} y1={cy}
        x2={cx + Math.cos(angle) * (r - 10)} y2={cy + Math.sin(angle) * (r - 10)}
        className="phase-dial-needle"
      />
      <circle cx={cx} cy={cy} r="6" className="phase-dial-pivot" />
      {/* Threshold labels */}
      <text x={cx - r - 10} y={cy + 6} className="phase-readout-sm" textAnchor="end">PERMIT</text>
      <text x={cx + r + 10} y={cy + 6} className="phase-readout-sm">FORBID</text>
      <text x={cx} y={cy - r - 14} className="phase-readout-sm" textAnchor="middle">ABSTAIN</text>
      <text x="200" y="380" className="phase-readout" textAnchor="middle">THRESHOLDS · TUNED THIS WEEK · 23</text>
    </svg>
  );
}

/* =============================================================
   HOMEPAGE STRIP — "Your first six weeks"
   Full mini-section with all 5 phases (skips phase 0 for cleanliness)
   ============================================================= */
function FirstSixWeeksStrip() {
  // Show phases 01–05 (skip the pre-contract Discovery Call on the homepage strip;
  // it's a sales motion, not a deployment phase. Full timeline lives on /how-it-works.)
  const stripPhases = PHASES.filter((p) => p.id !== '00');
  return (
    <section className="six-weeks" id="six-weeks">
      <div className="sw-head">
        <span className="kicker">
          <span className="kicker-dot" />
          <span>Your first six weeks</span>
        </span>
        <h2 className="sw-h2">
          From signed contract<br />
          <span className="ital">to production-grade enforcement.</span>
        </h2>
        <p className="sw-lede">
          A concierge deployment, run by the people who built the engine. No
          junior consultants. No 6-month implementation projects. No off-the-shelf
          dashboards bolted onto a stack you don't own.
        </p>
      </div>

      <div className="sw-track">
        {stripPhases.map((p, i) => (
          <div key={p.id} className="sw-phase">
            <div className="sw-phase-head">
              <span className="sw-num">{p.id}</span>
              <span className="sw-rail" aria-hidden="true">
                <span className="sw-rail-line" />
                {i < stripPhases.length - 1 && <span className="sw-rail-arrow">→</span>}
              </span>
            </div>
            <div className="sw-duration">
              <span className="sw-dur-main">{p.duration}</span>
              <span className="sw-dur-sub">{p.durationSub}</span>
            </div>
            <h3 className="sw-name">{p.name}</h3>
            <p className="sw-one">{p.one}</p>
            <div className="sw-outcome">
              <span className="sw-outcome-label">Outcome</span>
              <p className="sw-outcome-text">{p.outcome}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="sw-foot">
        <a
          href="/how-it-works"
          className="btn-ghost"
          onClick={(e) => { e.preventDefault(); navigate('/how-it-works'); }}
        >
          <span>See the full deployment timeline</span>
          <span className="btn-arrow">→</span>
        </a>
      </div>
    </section>
  );
}

/* =============================================================
   /how-it-works — Cinematic horizontal-scroll deployment journey
   Vertical scroll drives a horizontal track of phase panels.
   ============================================================= */
/* =============================================================
   HIW JOURNEY — the sticky horizontal-scroll carousel.
   Extracted as a standalone so it can render both inside the
   /how-it-works route page AND inlined into the homepage between
   the control plane intro and the seven-layer stack.
   ============================================================= */
function HiwJourney({ variant = 'standalone' }) {
  const trackRef = useRef(null);
  const stickyRef = useRef(null);
  const [progress, setProgress] = useState(0); // 0..1 across phases
  const [activePhase, setActivePhase] = useState(0);
  const [inView, setInView] = useState(true);

  // Drive horizontal scroll from vertical scroll position.
  // Throttled with rAF so we don't fire setState on every scroll event.
  useEffect(() => {
    let raf = null;
    const tick = () => {
      raf = null;
      const sticky = stickyRef.current;
      if (!sticky) return;
      const rect = sticky.getBoundingClientRect();
      const total = sticky.offsetHeight - window.innerHeight;
      const scrolled = -rect.top;
      const p = Math.max(0, Math.min(1, scrolled / total));
      setProgress(p);
      const phasePosLive = p * (PHASES.length - 1);
      const wholeLive = Math.floor(phasePosLive);
      const fracLive = phasePosLive - wholeLive;
      const idx = fracLive > 0.85
        ? Math.min(PHASES.length - 1, wholeLive + 1)
        : wholeLive;
      setActivePhase(Math.min(PHASES.length - 1, Math.max(0, idx)));
    };
    const onScroll = () => {
      if (raf) return;
      raf = requestAnimationFrame(tick);
    };
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => {
      window.removeEventListener('scroll', onScroll);
      if (raf) cancelAnimationFrame(raf);
    };
  }, []);

  // Pause expensive instrument animations when carousel is fully out of view
  useEffect(() => {
    const el = stickyRef.current;
    if (!el) return;
    const obs = new IntersectionObserver((entries) => {
      entries.forEach((e) => setInView(e.isIntersecting));
    }, { threshold: [0, 0.05] });
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  const phasePos = progress * (PHASES.length - 1);
  const wholeIdx = Math.floor(phasePos);
  const fracIdx = phasePos - wholeIdx;
  const transitionStart = 0.7;
  const eased = fracIdx < transitionStart
    ? 0
    : Math.min(1, (fracIdx - transitionStart) / (1 - transitionStart));
  const translateVw = -((wholeIdx + eased) * 100);

  return (
    <section
      className={`hiw-journey hiw-journey-${variant}`}
      ref={stickyRef}
      style={{ height: `${PHASES.length * 100}vh` }}
    >
      <div className="hiw-sticky">
        {/* Progress rail at top */}
        <div className="hiw-rail">
          <div className="hiw-rail-track">
            <div
              className="hiw-rail-fill"
              style={{ width: `${progress * 100}%` }}
            />
            {PHASES.map((p, i) => (
              <div
                key={p.id}
                className={`hiw-rail-stop ${i <= activePhase ? 'is-passed' : ''} ${i === activePhase ? 'is-active' : ''}`}
                style={{ left: `${(i / (PHASES.length - 1)) * 100}%` }}
              >
                <span className="hiw-rail-dot" />
                <span className="hiw-rail-label">
                  <span className="hiw-rail-id">{p.id}</span>
                  <span className="hiw-rail-name">{p.name}</span>
                </span>
              </div>
            ))}
          </div>
          <div className="hiw-rail-readout">
            <span className="hiw-rail-readout-blink" />
            <span>PHASE {PHASES[activePhase].id} · {PHASES[activePhase].name.toUpperCase()}</span>
            <span className="hiw-rail-readout-pct">{Math.round(progress * 100)}%</span>
          </div>
        </div>

        {/* Phase track */}
        <div
          className="hiw-track"
          ref={trackRef}
          style={{ transform: `translateX(${translateVw}vw)` }}
        >
          {PHASES.map((p, i) => (
            <article
              key={p.id}
              className={`hiw-phase ${i === activePhase ? 'is-active' : ''}`}
            >
              <div className="hiw-phase-grid">
                <div className="hiw-phase-left">
                  <div className="hiw-phase-num-wrap">
                    <span className="hiw-phase-num">{p.id}</span>
                    <span className="hiw-phase-num-rule" />
                  </div>
                  <div className="hiw-phase-duration">
                    <span className="hiw-dur-main">{p.duration}</span>
                    <span className="hiw-dur-sub">{p.durationSub}</span>
                  </div>
                  <h2 className="hiw-phase-name">{p.name}</h2>
                  <p className="hiw-phase-one">{p.one}</p>

                  <div className="hiw-deliverables">
                    <span className="hiw-deliv-label">Deliverables</span>
                    <ul className="hiw-deliv-list">
                      {p.deliverables.map((d, k) => (
                        <li key={k} className="hiw-deliv-item">
                          <span className="hiw-deliv-marker" aria-hidden="true" />
                          <span>{d}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="hiw-outcome">
                    <span className="hiw-outcome-label">What you see at the end</span>
                    <p className="hiw-outcome-text">{p.outcome}</p>
                  </div>
                </div>

                <div className="hiw-phase-right">
                  <div className="hiw-instrument">
                    <PhaseInstrument phase={p} active={i === activePhase && inView} />
                  </div>
                </div>
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

/* =============================================================
   /how-it-works — Cinematic horizontal-scroll deployment journey
   Vertical scroll drives a horizontal track of phase panels.
   ============================================================= */
function HowItWorksPage() {
  const { openTrial } = useTrial();

  return (
    <main className="hiw-page">
      {/* Hero */}
      <section className="hiw-hero">
        <div className="hiw-hero-inner">
          <span className="kicker">
            <span className="kicker-dot" />
            <span>How it works</span>
            <span className="kicker-sep">/</span>
            <span>Concierge deployment · 4–6 weeks</span>
          </span>
          <h1 className="hiw-h1">
            <span className="hiw-h1-line">Six weeks from signed</span>
            <span className="hiw-h1-line ital">to a sealed control plane.</span>
          </h1>
          <p className="hiw-lede">
            Tex is configured to your stack, your rules, your compliance reality —
            by the people who built the engine. No off-the-shelf dashboard. No
            junior consultants. No rip-and-replace. Six phases. One outcome.
          </p>
          <div className="hiw-hero-meta">
            <div className="hiw-meta-item">
              <span className="hiw-meta-num">06</span>
              <span className="hiw-meta-lbl">phases · discovery to handoff</span>
            </div>
            <div className="hiw-meta-item">
              <span className="hiw-meta-num">4–6</span>
              <span className="hiw-meta-lbl">weeks to live enforcement</span>
            </div>
            <div className="hiw-meta-item">
              <span className="hiw-meta-num">142</span>
              <span className="hiw-meta-lbl">ms p95 verdict latency</span>
            </div>
          </div>
          <div className="hiw-hero-scroll" aria-hidden="true">
            <span>Scroll to begin deployment</span>
            <span className="hiw-scroll-arrow">↓</span>
          </div>
        </div>
      </section>

      {/* Sticky horizontal-scroll journey — the same carousel rendered on home */}
      <HiwJourney variant="standalone" />

      {/* What makes this different */}
      <section className="hiw-difference">
        <div className="hiw-diff-grid">
          <div className="hiw-diff-left">
            <span className="kicker">
              <span className="kicker-dot" />
              <span>What makes this different</span>
            </span>
            <h2 className="hiw-diff-h2">
              Most AI security tools<br />
              <span className="ital">ship you a dashboard.</span>
            </h2>
          </div>
          <div className="hiw-diff-right">
            <p className="hiw-diff-body">
              Most AI security tools ship you a dashboard and a quickstart guide.
              We don't.
            </p>
            <p className="hiw-diff-body">
              Tex is configured to your stack, your rules, your compliance reality —
              by the people who built the engine. You get a deployed control plane
              in 4–6 weeks, not a 6-month implementation project run by a junior
              consultant who's never touched your industry.
            </p>
            <p className="hiw-diff-body">
              You author the rules. We compile them, wire them, and seal every
              decision they govern. One implementation, one platform, one ongoing
              relationship — instead of buying eight tools and stitching them
              together yourself.
            </p>
          </div>
        </div>
      </section>

      {/* Closing CTA */}
      <section className="hiw-cta">
        <div className="hiw-cta-inner">
          <h2 className="hiw-cta-h2">
            Ready to map<br />
            <span className="ital">your six weeks?</span>
          </h2>
          <p className="hiw-cta-lede">
            A 30-minute call with the founder. We map your AI agent surface area,
            your compliance obligations, and your existing security stack. You
            leave with a written scope-of-work and pricing.
          </p>
          <div className="hiw-cta-actions">
            <button type="button" onClick={openTrial} className="btn-primary">
              <span>Book the discovery call</span>
              <span className="btn-arrow">→</span>
            </button>
            <a
              href="/"
              className="btn-ghost"
              onClick={(e) => { e.preventDefault(); navigate('/'); }}
            >
              <span>Back to overview</span>
            </a>
          </div>
        </div>
      </section>

      <Footer />
    </main>
  );
}


function HomePage({ active, setActive }) {
  return (
    <main className="page">
      <Hero active={active} setActive={setActive} />
      <ControlPlaneIntro />
      <HomeHowItWorksIntro />
      <HiwJourney variant="inline" />
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
      <FirstSixWeeksStrip />
      <ChainBand />
      <ClosingPanel />
      <Footer />
    </main>
  );
}

function App() {
  const [active, setActive] = useState(0);
  const [trialOpen, setTrialOpen] = useState(false);
  const path = useRoute();
  const onSelect = useCallback((i) => {
    if (window.location.pathname !== '/') {
      navigate('/');
      // Wait for home to mount, then scroll to layer
      setTimeout(() => {
        setActive(i);
        const target = document.getElementById(`layer-${LAYERS[i].id}`);
        if (target) {
          target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      }, 60);
      return;
    }
    setActive(i);
    const target = document.getElementById(`layer-${LAYERS[i].id}`);
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, []);
  const openTrial = useCallback(() => setTrialOpen(true), []);
  const closeTrial = useCallback(() => setTrialOpen(false), []);

  const isHowItWorks = path === '/how-it-works';

  return (
    <TrialContext.Provider value={{ openTrial }}>
      <div className="root-shell">
        <PerspectiveGrid />
        <LayerBar active={active} setActive={onSelect} currentPath={path} />

        {isHowItWorks ? (
          <HowItWorksPage />
        ) : (
          <HomePage active={active} setActive={setActive} />
        )}

        <TrialModal open={trialOpen} onClose={closeTrial} />
      </div>
    </TrialContext.Provider>
  );
}

export default App;
