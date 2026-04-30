import React, { useEffect, useMemo, useRef, useState } from 'react';
import texHero from './tex-hero.png';
import './styles.css';

const layers = [
  { id: '01', name: 'Discovery', verb: 'Find every agent', detail: 'Inventory every agent, workflow, bot, copilot, and shadow automation.', color: '#5fffe2' },
  { id: '02', name: 'Identity', verb: 'Bind actor + owner', detail: 'Tie each action to agent, human owner, tenant, environment, and trust level.', color: '#61a8ff' },
  { id: '03', name: 'Authority', verb: 'Define allowed power', detail: 'Convert policy into live execution boundaries.', color: '#ffd466' },
  { id: '04', name: 'Judgment', verb: 'Read the real action', detail: 'Inspect the actual message, tool call, file update, API request, or promise.', color: '#ae7cff' },
  { id: '05', name: 'Enforcement', verb: 'Permit / abstain / forbid', detail: 'Stop, hold, or release before the action reaches the real world.', color: '#ff4e88' },
  { id: '06', name: 'Evidence', verb: 'Seal the proof', detail: 'Hash-chain the request, policy, verdict, permit, verification, and outcome.', color: '#67ff9f' },
  { id: '07', name: 'Calibration', verb: 'Improve without chaos', detail: 'Tune thresholds from outcomes without self-rewriting the rules.', color: '#ffffff' },
];

const loop = ['Intercept', 'Authorize', 'Verify', 'Execute', 'Record', 'Learn'];

function useActiveLayer() {
  const [active, setActive] = useState(4);
  useEffect(() => {
    const id = setInterval(() => setActive(v => (v + 1) % layers.length), 2200);
    return () => clearInterval(id);
  }, []);
  return [active, setActive];
}

function Atmosphere({ active }) {
  const ref = useRef(null);
  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas.getContext('2d');
    let raf;
    let t = 0;
    let mx = 0, my = 0;
    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(innerWidth * dpr);
      canvas.height = Math.floor(innerHeight * dpr);
      canvas.style.width = innerWidth + 'px';
      canvas.style.height = innerHeight + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    const move = e => { mx = e.clientX / innerWidth - .5; my = e.clientY / innerHeight - .5; };
    resize();
    addEventListener('resize', resize);
    addEventListener('pointermove', move);

    const draw = () => {
      t += 0.006;
      const w = innerWidth, h = innerHeight;
      ctx.clearRect(0, 0, w, h);
      const bg = ctx.createRadialGradient(w*.72 + mx*90, h*.28 + my*50, 0, w*.72, h*.28, w*.85);
      bg.addColorStop(0, 'rgba(73,255,225,.16)');
      bg.addColorStop(.24, 'rgba(107,88,255,.12)');
      bg.addColorStop(.6, 'rgba(6,10,18,.18)');
      bg.addColorStop(1, 'rgba(2,4,9,0)');
      ctx.fillStyle = bg; ctx.fillRect(0,0,w,h);

      const horizon = h * .53 + my * 35;
      const center = w * .55 + mx * 70;
      ctx.lineWidth = 1;
      for (let i = 0; i < 48; i++) {
        const p = i / 47;
        const y = horizon + Math.pow(p, 2.35) * h * .76 + ((t * 90) % 26) * p;
        ctx.strokeStyle = `rgba(85,255,231,${.12 * (1 - p)})`;
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
      }
      for (let i = -34; i <= 34; i++) {
        const x = center + i * 88;
        ctx.strokeStyle = `rgba(85,255,231,${Math.abs(i) < 4 ? .08 : .035})`;
        ctx.beginPath(); ctx.moveTo(center, horizon); ctx.lineTo(x, h + 80); ctx.stroke();
      }
      const color = layers[active].color;
      for (let k = 0; k < 60; k++) {
        const x = (Math.sin(k * 17.13 + t * 4) * .5 + .5) * w;
        const y = (Math.cos(k * 9.21 + t * 2.8) * .5 + .5) * h;
        ctx.fillStyle = k % 9 === 0 ? color : 'rgba(175,255,255,.16)';
        ctx.globalAlpha = k % 9 === 0 ? .65 : .26;
        ctx.fillRect(x, y, k % 9 === 0 ? 2.6 : 1.1, k % 9 === 0 ? 2.6 : 1.1);
      }
      ctx.globalAlpha = 1;
      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => { cancelAnimationFrame(raf); removeEventListener('resize', resize); removeEventListener('pointermove', move); };
  }, [active]);
  return <canvas className="atmosphere" ref={ref} aria-hidden="true" />;
}

function ControlCore({ active, setActive }) {
  const activeLayer = layers[active];
  return (
    <div className="core-stage" style={{'--active': activeLayer.color}}>
      <div className="core-halo halo-a" />
      <div className="core-halo halo-b" />
      <div className="core-halo halo-c" />
      <svg className="orbit-svg" viewBox="0 0 760 760" aria-hidden="true">
        <defs>
          <linearGradient id="orbitGradient" x1="0" x2="1">
            <stop offset="0" stopColor="#59ffe6" stopOpacity=".1" />
            <stop offset=".5" stopColor={activeLayer.color} stopOpacity=".8" />
            <stop offset="1" stopColor="#9b5cff" stopOpacity=".15" />
          </linearGradient>
          <filter id="softGlow"><feGaussianBlur stdDeviation="5" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
        </defs>
        <circle cx="380" cy="380" r="292" className="orbit-path" />
        <circle cx="380" cy="380" r="222" className="orbit-path inner" />
        <circle cx="380" cy="380" r="156" className="orbit-path micro" />
        <path className="signal-ring" d="M88 380a292 292 0 1 1 584 0a292 292 0 1 1 -584 0" />
        <line x1="380" y1="88" x2="380" y2="672" className="axis" />
        <line x1="88" y1="380" x2="672" y2="380" className="axis" />
      </svg>
      <img className="tex-avatar" src={texHero} alt="Tex AI control system avatar" />
      <div className="core-plate">
        <span>Tex by VortexBlack</span>
        <strong>CONTROL CORE</strong>
      </div>
      {layers.map((layer, i) => {
        const angle = (-92 + i * 360 / layers.length) * Math.PI / 180;
        const radius = 312;
        const x = Math.cos(angle) * radius;
        const y = Math.sin(angle) * radius;
        return (
          <button
            type="button"
            key={layer.id}
            className={`orbit-node ${i === active ? 'active' : ''}`}
            style={{ transform: `translate(${x}px, ${y}px)`, '--node': layer.color }}
            onMouseEnter={() => setActive(i)}
          >
            <b>{layer.id}</b>
            <span>{layer.name}</span>
            <small>{layer.verb}</small>
          </button>
        );
      })}
      <div className="verdict-console">
        <div className="console-top"><span>LIVE AUTHORIZATION</span><code>tx:{activeLayer.id}-7f{active + 3}a</code></div>
        <h3>{activeLayer.name}</h3>
        <p>{activeLayer.detail}</p>
        <div className="verdict-row">
          <span>PERMIT</span><span>ABSTAIN</span><span>FORBID</span>
        </div>
        <div className="scan-bars"><i/><i/><i/><i/><i/></div>
      </div>
    </div>
  );
}

function ProofRail() {
  return (
    <section className="proof-rail" id="proof">
      <div className="section-kicker">Cryptographically-linked loop</div>
      <div className="rail-head">
        <h2>Every action becomes a decision record.</h2>
        <p>Tex does not just watch. It intercepts the action, authorizes it, verifies the permit, records the result, and learns from outcomes.</p>
      </div>
      <div className="rail-track">
        {loop.map((item, i) => (
          <div className="rail-step" key={item}>
            <span>{String(i + 1).padStart(2, '0')}</span>
            <strong>{item}</strong>
            <small>{['request captured','policy verdict','permit checked','action released','hash sealed','threshold tuned'][i]}</small>
          </div>
        ))}
      </div>
    </section>
  );
}

function LayerMatrix({ active, setActive }) {
  return (
    <section className="layer-matrix" id="layers">
      <div className="section-kicker">Seven-layer control system</div>
      <div className="matrix-layout">
        <div className="matrix-copy">
          <h2>One control plane above the agent ecosystem.</h2>
          <p>Buyers understand the difference in five seconds: point tools each protect a slice. Tex connects discovery, identity, authority, judgment, enforcement, evidence, and calibration into one runtime control loop.</p>
        </div>
        <div className="matrix-board">
          {layers.map((layer, i) => (
            <button key={layer.id} type="button" onMouseEnter={() => setActive(i)} className={`matrix-row ${i === active ? 'active' : ''}`} style={{'--row': layer.color}}>
              <span>{layer.id}</span>
              <strong>{layer.name}</strong>
              <em>{layer.verb}</em>
            </button>
          ))}
        </div>
      </div>
    </section>
  );
}

function Difference() {
  const rows = [
    ['Posture tools', 'See agents', 'No runtime authority'],
    ['Identity tools', 'Name actors', 'No action judgment'],
    ['Prompt guardrails', 'Scan text', 'No full proof chain'],
    ['Monitoring', 'Record events', 'After the fact'],
    ['Tex', 'Controls the lifecycle', 'Seven-layer authority loop'],
  ];
  return (
    <section className="difference" id="system">
      <div className="section-kicker">Not another dashboard</div>
      <h2>Tex controls whether AI agents can act before they execute.</h2>
      <div className="difference-grid">
        {rows.map((r, i) => <div className={`diff-row ${i === rows.length - 1 ? 'tex-row' : ''}`} key={r[0]}><span>{r[0]}</span><strong>{r[1]}</strong><em>{r[2]}</em></div>)}
      </div>
    </section>
  );
}

function App() {
  const [active, setActive] = useActiveLayer();
  const activeLayer = layers[active];
  return (
    <main className="site-shell" style={{'--active': activeLayer.color}}>
      <Atmosphere active={active} />
      <nav className="nav-shell">
        <a className="brand" href="#top"><span>T</span><strong>Tex</strong><em>by VortexBlack</em></a>
        <div className="nav-links"><a href="#system">System</a><a href="#layers">Layers</a><a href="#proof">Proof</a></div>
        <a className="trial" href="#trial">2-week trial</a>
      </nav>

      <section className="hero" id="top">
        <div className="hero-copy">
          <div className="section-kicker">Tex by VortexBlack</div>
          <h1>AI agents do not act until Tex authorizes them.</h1>
          <p className="hero-lede">A seven-layer control system that finds agents, binds identity, defines authority, judges real actions, enforces decisions, seals evidence, and calibrates from outcomes.</p>
          <div className="instant-line"><b>In five seconds:</b><span>Tex is the runtime control layer between AI agents and the real world.</span></div>
          <div className="hero-actions"><a href="#trial" className="primary">Activate 2-week trial</a><a href="#layers" className="secondary">Watch the loop</a></div>
        </div>
        <ControlCore active={active} setActive={setActive} />
      </section>

      <Difference />
      <LayerMatrix active={active} setActive={setActive} />
      <ProofRail />

      <section className="trial-panel" id="trial">
        <div>
          <div className="section-kicker">Start with the audit</div>
          <h2>Tex by VortexBlack gives buyers one answer: who controls your agents?</h2>
          <p>Inventory the agents, map authority, run real actions through the seven layers, and export the proof bundle.</p>
        </div>
        <div className="trial-cards"><span><b>01</b>Inventory</span><span><b>02</b>Control</span><span><b>03</b>Proof</span></div>
      </section>
      <footer><strong>Tex by VortexBlack</strong><span>Central control system for AI agents.</span></footer>
    </main>
  );
}

export default App;
