import React, { useEffect, useMemo, useRef, useState } from 'react';
import texHero from './tex-hero.png';
import './styles.css';

const LAYERS = [
  { id: '01', name: 'Discovery', verb: 'Find every agent', detail: 'Inventory agents, copilots, automations, tools, owners, and execution surfaces.', tone: '#53ffe2' },
  { id: '02', name: 'Identity', verb: 'Bind who is acting', detail: 'Tie action to agent, human owner, tenant, environment, permissions, and trust.', tone: '#6eb7ff' },
  { id: '03', name: 'Authority', verb: 'Define what is allowed', detail: 'Convert policy into live boundaries for access, changes, promises, and escalation.', tone: '#ffe16a' },
  { id: '04', name: 'Judgment', verb: 'Read the real action', detail: 'Inspect the actual email, Slack post, API call, database change, or workflow step.', tone: '#a874ff' },
  { id: '05', name: 'Enforcement', verb: 'Stop, hold, or release', detail: 'Return PERMIT, ABSTAIN, or FORBID before the action reaches production.', tone: '#ff477e' },
  { id: '06', name: 'Evidence', verb: 'Seal the proof', detail: 'Record request, policy, verdict, permit, verification, outcome, and chain hash.', tone: '#47ff9a' },
  { id: '07', name: 'Calibration', verb: 'Improve without chaos', detail: 'Tune thresholds from outcomes without letting the system rewrite its own rules.', tone: '#f2fbff' },
];

const LOOP = ['Intercept', 'Authorize', 'Verify', 'Execute', 'Record', 'Learn'];
const FIVE_SECONDS = ['Find every agent', 'Control every action', 'Prove every decision'];

function useTicker(ms = 1800) {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const timer = setInterval(() => setTick((v) => v + 1), ms);
    return () => clearInterval(timer);
  }, [ms]);
  return tick;
}

function usePointer() {
  const [p, setP] = useState({ x: 0, y: 0 });
  useEffect(() => {
    const move = (e) => setP({ x: (e.clientX / window.innerWidth - 0.5) * 2, y: (e.clientY / window.innerHeight - 0.5) * 2 });
    window.addEventListener('pointermove', move, { passive: true });
    return () => window.removeEventListener('pointermove', move);
  }, []);
  return p;
}

function CinematicField({ active }) {
  const ref = useRef(null);
  const pointer = useRef({ x: 0, y: 0 });

  useEffect(() => {
    const move = (e) => {
      pointer.current.x = (e.clientX / window.innerWidth - 0.5) * 2;
      pointer.current.y = (e.clientY / window.innerHeight - 0.5) * 2;
    };
    window.addEventListener('pointermove', move, { passive: true });
    return () => window.removeEventListener('pointermove', move);
  }, []);

  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas.getContext('2d');
    let raf;
    let t = 0;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const resize = () => {
      canvas.width = Math.floor(innerWidth * dpr);
      canvas.height = Math.floor(innerHeight * dpr);
      canvas.style.width = `${innerWidth}px`;
      canvas.style.height = `${innerHeight}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    window.addEventListener('resize', resize);

    const draw = () => {
      t += 0.006;
      const w = innerWidth;
      const h = innerHeight;
      const layer = LAYERS[active % LAYERS.length];
      ctx.clearRect(0, 0, w, h);

      const base = ctx.createRadialGradient(w * 0.62, h * 0.28, 0, w * 0.62, h * 0.28, Math.max(w, h));
      base.addColorStop(0, `${layer.tone}22`);
      base.addColorStop(0.32, 'rgba(8,14,23,.58)');
      base.addColorStop(1, 'rgba(2,4,10,.96)');
      ctx.fillStyle = base;
      ctx.fillRect(0, 0, w, h);

      const horizon = h * 0.53 + pointer.current.y * 22;
      const vx = w * 0.5 + pointer.current.x * 60;
      ctx.lineWidth = 1;
      for (let i = 0; i < 54; i++) {
        const p = i / 53;
        const y = horizon + Math.pow(p, 2.55) * h * 0.82 + ((t * 130) % 34) * p;
        ctx.strokeStyle = `rgba(83,255,226,${0.05 + 0.15 * (1 - p)})`;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y + Math.sin(t * 2 + i) * 2);
        ctx.stroke();
      }
      for (let i = -36; i <= 36; i++) {
        const spread = i * 72;
        ctx.strokeStyle = `rgba(125,136,255,${0.035 + (Math.abs(i) < 3 ? 0.05 : 0)})`;
        ctx.beginPath();
        ctx.moveTo(vx, horizon);
        ctx.lineTo(vx + spread + pointer.current.x * 20, h + 90);
        ctx.stroke();
      }

      // moving data sparks
      for (let i = 0; i < 95; i++) {
        const z = ((i * 0.041 + t * 0.23) % 1);
        const x = (w * (0.08 + ((i * 89) % 100) / 118)) + Math.sin(i + t) * 22;
        const y = horizon + z * z * h * 0.78;
        const a = Math.max(0, 0.28 - z * 0.2);
        ctx.fillStyle = i % 7 === active ? `${layer.tone}cc` : `rgba(120,255,246,${a})`;
        ctx.fillRect(x, y, 1 + z * 2.4, 1 + z * 2.4);
      }

      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', resize); };
  }, [active]);

  return <canvas className="cinematic-field" ref={ref} aria-hidden="true" />;
}

function Nav() {
  return <nav className="topbar">
    <a className="wordmark" href="#top"><span>T</span><b>Tex</b><i>by VortexBlack</i></a>
    <div className="navlinks"><a href="#system">System</a><a href="#layers">Layers</a><a href="#proof">Proof</a></div>
    <a className="navbutton" href="#trial">2-week trial</a>
  </nav>;
}

function HeroSystem({ active, setActive }) {
  const layer = LAYERS[active];
  const pointer = usePointer();
  return <div className="hero-system" style={{ '--tone': layer.tone, '--mx': pointer.x, '--my': pointer.y }}>
    <div className="core-stage">
      <div className="orbit orbit-a" />
      <div className="orbit orbit-b" />
      <div className="orbit orbit-c" />
      <div className="orbit orbit-d" />
      <div className="data-ray ray-1" />
      <div className="data-ray ray-2" />
      <div className="data-ray ray-3" />
      <div className="avatar-shell">
        <img src={texHero} alt="Tex control system avatar" />
        <div className="avatar-vignette" />
        <div className="scanline" />
      </div>
      {LAYERS.map((item, i) => <button
        key={item.name}
        className={`layer-pin pin-${i + 1} ${i === active ? 'active' : ''}`}
        onMouseEnter={() => setActive(i)}
        onClick={() => setActive(i)}
        style={{ '--pin': item.tone }}
      >
        <span>{item.id}</span><b>{item.name}</b><em>{item.verb}</em>
      </button>)}
    </div>
    <div className="verdict-hud">
      <div className="hud-top"><span>LIVE EVALUATION</span><b>sha256:tx-{active + 1}c9f</b></div>
      <h3>{layer.name}</h3>
      <p>{layer.detail}</p>
      <div className="hud-meter"><i /><i /><i /><i /><i /></div>
      <strong>{layer.verb}</strong>
    </div>
  </div>;
}

function LayerConsole({ active, setActive }) {
  const layer = LAYERS[active];
  return <section id="layers" className="section layer-console" style={{ '--tone': layer.tone }}>
    <div className="section-intro compact">
      <span className="eyebrow">Seven-layer system loop</span>
      <h2>Every action passes through the same control spine.</h2>
      <p>Discovery → Identity → Authority → Judgment → Enforcement → Evidence → Calibration.</p>
    </div>
    <div className="console-grid">
      <div className="spine">
        {LAYERS.map((l, i) => <button key={l.name} onMouseEnter={() => setActive(i)} onClick={() => setActive(i)} className={i === active ? 'active' : ''} style={{ '--pin': l.tone }}>
          <span>{l.id}</span><b>{l.name}</b><em>{l.verb}</em>
        </button>)}
      </div>
      <div className="active-command">
        <div className="command-top"><span>ACTIVE LAYER</span><b>{layer.id}</b></div>
        <h3>{layer.name}</h3>
        <h4>{layer.verb}</h4>
        <p>{layer.detail}</p>
        <div className="code-readout">
          <span>policy.snapshot.locked</span>
          <span>runtime.verdict.pending</span>
          <span>chain.hash.sealed</span>
        </div>
      </div>
      <div className="buyer-box">
        <span className="eyebrow">Buyer takeaway</span>
        <p>Tex is not a dashboard. It is the runtime authority layer that decides whether an AI agent is allowed to act before the action reaches the real world.</p>
        <ul>{FIVE_SECONDS.map(x => <li key={x}>{x}</li>)}</ul>
      </div>
    </div>
  </section>;
}

function ProofLoop({ active }) {
  return <section id="proof" className="section proof-loop">
    <div className="loop-card">
      <div className="section-intro slim">
        <span className="eyebrow">Cryptographically-linked loop</span>
        <h2>Every decision becomes evidence.</h2>
        <p>Tex records request, policy, verdict, permit, execution state, outcome, and the next hash.</p>
      </div>
      <div className="loop-track">
        {LOOP.map((item, i) => <div key={item} className={(active % LOOP.length) === i ? 'active' : ''}>
          <span>{String(i + 1).padStart(2, '0')}</span><b>{item}</b><em>{i === active % LOOP.length ? 'live pulse' : 'linked'}</em>
        </div>)}
      </div>
    </div>
  </section>;
}

function Comparison() {
  const rows = [
    ['Posture', 'sees agents', 'slice'],
    ['Identity', 'names actors', 'slice'],
    ['Guardrails', 'scan text', 'slice'],
    ['DLP / CASB', 'watch leakage', 'slice'],
    ['Monitoring', 'records after', 'late'],
    ['Tex', 'controls lifecycle', 'system'],
  ];
  return <section id="system" className="section comparison">
    <div className="section-intro">
      <span className="eyebrow">Not another point product</span>
      <h2>Other tools protect slices. Tex controls the system.</h2>
      <p>One homepage sentence buyers should remember: Tex controls whether AI agents can take real-world actions — before they execute.</p>
    </div>
    <div className="slice-grid">
      {rows.map(([a,b,c], i) => <div key={a} className={a === 'Tex' ? 'tex' : ''}>
        <span>{String(i + 1).padStart(2, '0')}</span><b>{a}</b><em>{b}</em><strong>{c}</strong>
      </div>)}
    </div>
  </section>;
}

function Trial() {
  return <section id="trial" className="section trial">
    <div className="trial-panel">
      <span className="eyebrow">Tex by VortexBlack</span>
      <h2>Start with a 2-week Agent Control Audit.</h2>
      <p>Inventory agents, map authority, run real actions through the seven-layer loop, and export the proof chain.</p>
      <a className="primary" href="mailto:founder@vortexblack.ai?subject=Activate%20Tex%202-week%20trial">Activate 2-week trial</a>
    </div>
  </section>;
}

export default function App() {
  const tick = useTicker(1600);
  const [selected, setSelected] = useState(null);
  const active = selected ?? tick % LAYERS.length;
  const activeLayer = useMemo(() => LAYERS[active], [active]);
  const hold = (i) => { setSelected(i); window.clearTimeout(window.__texLayerHold); window.__texLayerHold = window.setTimeout(() => setSelected(null), 9000); };

  return <main id="top" className="site" style={{ '--tone': activeLayer.tone }}>
    <CinematicField active={active} />
    <div className="noise" aria-hidden="true" />
    <div className="aurora" aria-hidden="true" />
    <Nav />
    <section className="hero section">
      <div className="hero-copy">
        <span className="eyebrow">Tex by VortexBlack</span>
        <h1>The command layer for AI agents.</h1>
        <p>Tex finds agents, binds identity, defines authority, judges actions, enforces decisions, seals proof, and calibrates from outcomes.</p>
        <div className="hero-sentence"><b>In 5 seconds:</b> one system controls the full AI-agent lifecycle before actions reach the real world.</div>
        <div className="hero-cta"><a className="primary" href="#trial">Activate 2-week trial</a><a className="secondary" href="#layers">See the 7-layer loop</a></div>
      </div>
      <HeroSystem active={active} setActive={hold} />
    </section>
    <Comparison />
    <LayerConsole active={active} setActive={hold} />
    <ProofLoop active={active} />
    <Trial />
    <footer><b>Tex by VortexBlack</b><span>Central control system for AI agents.</span></footer>
  </main>;
}
