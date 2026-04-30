import React, { useEffect, useMemo, useRef, useState } from 'react';
import texHero from './tex-hero.png';
import './styles.css';

const layers = [
  { n:'01', key:'discovery', name:'Discovery', command:'Find every agent', buyer:'Reveals every AI agent, copilot, workflow, bot, tool call, and shadow automation before it becomes unmanaged risk.', system:'Agent inventory • SaaS/cloud/code connectors • owner mapping • lifecycle status', color:'#55f7ff', verb:'FOUND' },
  { n:'02', key:'identity', name:'Identity', command:'Know who is acting', buyer:'Ties each action to the agent, human owner, system, tenant, environment, permissions, and trust level.', system:'Agent identity • ownership • environment • trust scoring • behavior ledger', color:'#58a8ff', verb:'VERIFIED' },
  { n:'03', key:'authority', name:'Authority', command:'Define what is allowed', buyer:'Turns policy into live boundaries: what an agent can access, say, change, delete, promise, trigger, or escalate.', system:'Versioned policy snapshots • criticality • allow/deny rules • approvals', color:'#ffd166', verb:'BOUND' },
  { n:'04', key:'judgment', name:'Judgment', command:'Read the real action', buyer:'Inspects the actual email, Slack post, API call, database change, workflow trigger, or customer promise before release.', system:'Deterministic checks • retrieval grounding • specialist judges • semantic fusion', color:'#a66cff', verb:'INSPECTED' },
  { n:'05', key:'enforcement', name:'Enforcement', command:'Stop, hold, or release', buyer:'Returns PERMIT, ABSTAIN, or FORBID while the action is still stoppable — before damage reaches the world.', system:'Runtime verdicts • permits • nonce verification • gateway adapters', color:'#ff4d7d', verb:'CONTROLLED' },
  { n:'06', key:'evidence', name:'Evidence', command:'Seal the proof', buyer:'Creates a defensible record of what happened, why it happened, which policy decided it, and whether execution matched the permit.', system:'Hash-chained evidence • decision records • permits • outcomes • export bundles', color:'#4effa9', verb:'SEALED' },
  { n:'07', key:'calibration', name:'Calibration', command:'Improve without chaos', buyer:'Learns from outcomes, overrides, false permits, and false forbids without letting the system rewrite its own rules.', system:'Outcome feedback • threshold tuning • replay • locked policy versions', color:'#ffffff', verb:'CALIBRATED' },
];

const threatRows = [
  ['Shadow agents', 'Teams connect agents before security knows they exist.', 'Discovery'],
  ['Real privileges', 'Agents touch customers, data, files, cloud tools, and workflows.', 'Identity'],
  ['Policy gaps', 'Rules live in docs while agents act in production.', 'Authority'],
  ['Content risk', 'The danger is often inside the exact action being released.', 'Judgment'],
  ['Late detection', 'Monitoring tells you after the blast radius already exists.', 'Enforcement'],
  ['Weak proof', 'Screenshots and logs do not create defensible evidence.', 'Evidence'],
  ['Static controls', 'Systems drift unless outcomes sharpen the next decision.', 'Calibration'],
];

const competitors = [
  ['Posture tools', 'see agents', 'one layer'],
  ['Identity tools', 'name actors', 'one layer'],
  ['Prompt guardrails', 'scan content', 'one layer'],
  ['DLP / CASB', 'watch leakage', 'one layer'],
  ['Monitoring', 'record events', 'one layer'],
  ['Tex', 'connects the full lifecycle', 'seven layers'],
];

function useTicker(speed = 1700) {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick(v => v + 1), speed);
    return () => clearInterval(id);
  }, [speed]);
  return tick;
}

function GridField({ activeLayer }) {
  const canvasRef = useRef(null);
  const mouse = useRef({ x: 0, y: 0 });

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    let raf;
    let t = 0;
    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(window.innerWidth * dpr);
      canvas.height = Math.floor(window.innerHeight * dpr);
      canvas.style.width = `${window.innerWidth}px`;
      canvas.style.height = `${window.innerHeight}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    const move = (e) => {
      mouse.current.x = (e.clientX / window.innerWidth - 0.5) * 2;
      mouse.current.y = (e.clientY / window.innerHeight - 0.5) * 2;
    };
    resize();
    window.addEventListener('resize', resize);
    window.addEventListener('pointermove', move);

    const draw = () => {
      t += 0.008;
      const w = window.innerWidth;
      const h = window.innerHeight;
      ctx.clearRect(0, 0, w, h);

      const grad = ctx.createLinearGradient(0, 0, w, h);
      grad.addColorStop(0, 'rgba(18, 197, 228, .22)');
      grad.addColorStop(0.45, 'rgba(12, 19, 42, .05)');
      grad.addColorStop(1, 'rgba(130, 55, 255, .24)');
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, w, h);

      const horizon = h * 0.37 + mouse.current.y * 18;
      const center = w * 0.52 + mouse.current.x * 34;
      ctx.lineWidth = 1;

      // perspective floor horizontal lines
      for (let i = 0; i < 42; i++) {
        const p = i / 41;
        const y = horizon + Math.pow(p, 2.08) * h * 0.9 + ((t * 52) % 22) * p;
        const alpha = 0.14 * (1 - p * 0.36);
        ctx.strokeStyle = `rgba(92, 242, 255, ${alpha})`;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y + Math.sin(t + i) * 2);
        ctx.stroke();
      }

      // vanishing lines
      for (let i = -28; i <= 28; i++) {
        const startX = center + i * 86 + Math.sin(t * 0.7 + i) * 8;
        ctx.strokeStyle = `rgba(92, 242, 255, ${0.08 + (Math.abs(i) < 3 ? 0.06 : 0)})`;
        ctx.beginPath();
        ctx.moveTo(center, horizon);
        ctx.lineTo(startX, h + 120);
        ctx.stroke();
      }

      // star nodes
      for (let i = 0; i < 80; i++) {
        const x = (i * 137.7 + t * 18) % w;
        const y = (i * 73.2 + Math.sin(t + i) * 14) % h;
        ctx.fillStyle = `rgba(135,255,255,${0.08 + (i % 7) * 0.012})`;
        ctx.fillRect(x, y, 1.2, 1.2);
      }

      // active shock ring
      const layer = layers[activeLayer % layers.length];
      const pulse = (Math.sin(t * 3) + 1) / 2;
      const cx = w * 0.62 + mouse.current.x * 18;
      const cy = h * 0.42 + mouse.current.y * 12;
      const r = 180 + pulse * 260;
      ctx.strokeStyle = hexToRgba(layer.color, 0.08 + pulse * 0.08);
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.stroke();

      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
      window.removeEventListener('pointermove', move);
    };
  }, [activeLayer]);

  return <canvas ref={canvasRef} className="grid-canvas" aria-hidden="true" />;
}

function hexToRgba(hex, alpha) {
  const clean = hex.replace('#', '');
  const num = parseInt(clean.length === 3 ? clean.split('').map(c => c + c).join('') : clean, 16);
  const r = (num >> 16) & 255;
  const g = (num >> 8) & 255;
  const b = num & 255;
  return `rgba(${r},${g},${b},${alpha})`;
}

function HeroReactor({ active }) {
  const layer = layers[active];
  return (
    <div className="hero-reactor" style={{ '--layer-color': layer.color }}>
      <div className="reactor-shell">
        <div className="halo halo-1" />
        <div className="halo halo-2" />
        <div className="halo halo-3" />
        <div className="guardian-frame">
          <img src={texHero} alt="Tex AI guardian control core" />
          <div className="guardian-scan" />
          <div className="guardian-title"><b>TEX</b><span>guardian control core</span></div>
        </div>
        {layers.map((l, i) => (
          <div key={l.key} className={`reactor-node node-${i+1} ${i === active ? 'active' : ''}`} style={{ '--node-color': l.color }}>
            <span>{l.n}</span><b>{l.name}</b><em>{i === active ? l.verb : l.command}</em>
          </div>
        ))}
        <div className="energy-beam beam-a" />
        <div className="energy-beam beam-b" />
        <div className="energy-beam beam-c" />
      </div>
      <div className="action-card">
        <div className="action-meta"><span>LIVE 7-LAYER EVALUATION</span><b>SHA256:{active}4D2…CODE</b></div>
        <h3>{layer.command}</h3>
        <p>{layer.buyer}</p>
        <div className="verdict-strip"><span>{layer.name}</span><i>{layer.verb}</i></div>
      </div>
    </div>
  );
}

function LayerReactor({ active, setActive }) {
  const layer = layers[active];
  return (
    <section id="layers" className="section layer-reactor-section" style={{ '--layer-color': layer.color }}>
      <div className="section-lockup">
        <div className="kicker"><span /> Seven-layer control system</div>
        <h2>Seven layers. One control loop. Total authority.</h2>
        <p>Buyers understand this in five seconds: Tex surrounds every AI agent from discovery to proof. No fragmented dashboards. No blind handoffs. One live system of control.</p>
      </div>
      <div className="reactor-layout">
        <div className="layer-orbit-map">
          <div className="mini-core"><b>Tex</b><span>{layer.name}</span></div>
          {layers.map((l, i) => (
            <button key={l.key} onMouseEnter={() => setActive(i)} onClick={() => setActive(i)} className={`orbit-button orbit-${i+1} ${i === active ? 'active' : ''}`} style={{ '--node-color': l.color }}>
              <span>{l.n}</span>{l.name}
            </button>
          ))}
          <div className="orbit-line one" /><div className="orbit-line two" /><div className="orbit-line three" />
        </div>
        <div className="layer-command-panel">
          <div className="panel-top"><span>Layer {layer.n}</span><b>{layer.verb}</b></div>
          <h3>{layer.name}</h3>
          <h4>{layer.command}</h4>
          <p>{layer.buyer}</p>
          <div className="system-code">{layer.system}</div>
          <div className="signal-bars"><i/><i/><i/><i/><i/></div>
        </div>
        <div className="layer-side-list">
          {layers.map((l, i) => (
            <button key={l.key} onMouseEnter={() => setActive(i)} onClick={() => setActive(i)} className={i === active ? 'active' : ''}>
              <span>{l.n}</span><b>{l.command}</b><em>{l.name}</em>
            </button>
          ))}
        </div>
      </div>
    </section>
  );
}

export default function App() {
  const tick = useTicker(1550);
  const [manualActive, setManualActive] = useState(null);
  const active = manualActive ?? (tick % layers.length);
  const activeLayer = layers[active];
  const chainHash = useMemo(() => `0x${['9F2A','C7D1','41BE','A604','77E9','B33C','E190'][active]}${['D8C1','04AF','7B22','91EE','F6A0','C114','5A7D'][active]}…VERIFIED`, [active]);

  return (
    <main className="site" style={{ '--layer-color': activeLayer.color }}>
      <GridField activeLayer={active} />
      <div className="ambient" aria-hidden="true"><div/><div/><div/></div>
      <nav className="nav">
        <a href="#top" className="brand"><span>T</span><b>Tex</b></a>
        <div><a href="#system">System</a><a href="#layers">Seven Layers</a><a href="#chain">Chain Hash</a></div>
        <a href="#trial" className="nav-cta">2-week trial</a>
      </nav>

      <section id="top" className="section hero-section">
        <div className="hero-copy">
          <div className="kicker"><span /> The all-inclusive AI agent security system</div>
          <h1>Tex controls the full life of every AI agent.</h1>
          <p>Normal security protects fragments. Tex is built as the first 360° seven-layer control loop: find the agent, identify it, set its authority, judge the real action, enforce the decision, prove it with a chain hash, and calibrate from outcomes.</p>
          <div className="hero-actions"><a href="#trial" className="button primary">Activate 2-week trial</a><a href="#layers" className="button ghost">Watch the seven layers fire</a></div>
          <div className="micro-claims"><span>Find every agent</span><span>Control every action</span><span>Prove every decision</span></div>
        </div>
        <HeroReactor active={active} />
      </section>

      <section id="system" className="section command-story">
        <div className="section-lockup centered">
          <div className="kicker"><span /> What buyers are trying to solve now</div>
          <h2>AI agents are becoming workers. Security is still built for tools.</h2>
          <p>The gap is not “one more scanner.” Companies need one enforceable system that surrounds the agent from unknown existence to verified outcome.</p>
        </div>
        <div className="threat-ring">
          {threatRows.map(([title, copy, tag], i) => (
            <article key={title} className="threat-card" style={{ '--delay': `${i * 70}ms` }}>
              <span>{String(i+1).padStart(2,'0')}</span><h3>{title}</h3><p>{copy}</p><b>{tag}</b>
            </article>
          ))}
        </div>
      </section>

      <section className="section category-break">
        <div className="category-shell">
          <div className="category-copy">
            <div className="kicker"><span /> Not a point product</div>
            <h2>Every other system protects one layer. Tex connects all seven.</h2>
            <p>Zenity-style posture, identity controls, prompt guardrails, DLP, monitoring, and audit trails are useful — but they are slices. Tex is the connective control loop that turns the slices into one enforceable AI security system.</p>
          </div>
          <div className="competitor-array">
            {competitors.map(([name, verb, scope], i) => <div key={name} className={name === 'Tex' ? 'tex-row' : ''}><span>{String(i+1).padStart(2,'0')}</span><b>{name}</b><em>{verb}</em><strong>{scope}</strong></div>)}
          </div>
        </div>
      </section>

      <LayerReactor active={active} setActive={(i) => { setManualActive(i); setTimeout(() => setManualActive(null), 8000); }} />

      <section id="chain" className="section chain-section">
        <div className="chain-copy">
          <div className="kicker"><span /> Cryptographically-linked control loop</div>
          <h2>The chain hash is what turns control into proof.</h2>
          <p>Tex does not leave buyers with “trust us” dashboards. Every decision links request, policy version, layer results, permit, verification, outcome, and next hash into a defensible evidence chain.</p>
        </div>
        <div className="chain-visual">
          {['request','agent identity','policy snapshot','layer verdicts','permit / block','execution check','outcome','next hash'].map((item, i) => (
            <div key={item} className={i === active || i === active + 1 ? 'active' : ''}>
              <span>{String(i+1).padStart(2,'0')}</span><b>{item}</b><em>{i === active ? chainHash : `sha256:${(912804 + i * 8321).toString(16)}…`}</em>
            </div>
          ))}
        </div>
      </section>

      <section className="section backend-section">
        <div className="section-lockup centered">
          <div className="kicker"><span /> Built toward a real backend control plane</div>
          <h2>Not just a homepage. A map of the product you are building.</h2>
          <p>Guardrail endpoints, streaming checks, async decisions, policy snapshots, gateway adapters, MCP entry points, evidence bundles, permits, verification, and outcome calibration all fit inside the same seven-layer story.</p>
        </div>
        <div className="capability-mosaic">
          {['Guardrail endpoint','Gateway adapters','Streaming checks','Policy snapshots','Permit verification','Evidence bundles','Replay contract','Outcome calibration'].map((x,i)=><div key={x} className="mosaic-cell"><span>{String(i+1).padStart(2,'0')}</span><b>{x}</b></div>)}
        </div>
      </section>

      <section id="trial" className="section trial-section">
        <div className="trial-shell">
          <div>
            <div className="kicker"><span /> 2-week live control trial</div>
            <h2>Give buyers the feeling of control before they buy the platform.</h2>
            <p>Position the trial as a live control deployment: discover agents, define policies, run sample actions through the seven layers, export evidence, and show leadership the proof chain.</p>
            <a href="mailto:founder@vortexblack.ai?subject=Activate%20Tex%202-week%20trial" className="button primary">Activate the 2-week trial</a>
          </div>
          <div className="trial-steps">
            <div><span>Week 1</span><b>Discover + define</b><em>Find agents, map authority, create policy boundaries.</em></div>
            <div><span>Week 2</span><b>Control + prove</b><em>Run actions through Tex, issue decisions, export evidence.</em></div>
            <div><span>Outcome</span><b>Executive proof</b><em>Show what was found, stopped, permitted, and sealed.</em></div>
          </div>
        </div>
      </section>

      <footer><b>Tex</b><span>One system. Seven layers. One cryptographically-linked loop.</span></footer>
    </main>
  );
}
