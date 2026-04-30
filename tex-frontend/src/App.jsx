import React, { useEffect, useRef, useState } from 'react';
import texHero from './tex-hero.png';
import './styles.css';

const LAYERS = [
  { id:'01', name:'Discovery', line:'Find every agent', detail:'Inventories agents, copilots, workflow bots, tool calls, and shadow automations before they become unmanaged risk.', color:'#53fff4' },
  { id:'02', name:'Identity', line:'Know who is acting', detail:'Binds every action to the agent, owner, tenant, environment, permissions, trust level, and runtime context.', color:'#5aa8ff' },
  { id:'03', name:'Authority', line:'Define what is allowed', detail:'Turns policy into live boundaries for what agents can access, say, promise, change, delete, trigger, or escalate.', color:'#ffd36a' },
  { id:'04', name:'Judgment', line:'Read the real action', detail:'Inspects the exact email, Slack message, API call, database change, workflow trigger, or customer promise before release.', color:'#a971ff' },
  { id:'05', name:'Enforcement', line:'Stop, hold, or release', detail:'Returns PERMIT, ABSTAIN, or FORBID while the action is still stoppable — before damage reaches production.', color:'#ff4d7e' },
  { id:'06', name:'Evidence', line:'Seal the proof', detail:'Creates a cryptographically-linked record of what happened, why it happened, which policy decided it, and what executed.', color:'#45ff9f' },
  { id:'07', name:'Calibration', line:'Improve without chaos', detail:'Learns from outcomes, overrides, false permits, and false forbids without letting the system rewrite its own rules.', color:'#ffffff' },
];

const COMPARE = [
  ['Posture tools', 'see agents', 'one slice'],
  ['Identity tools', 'name actors', 'one slice'],
  ['Prompt guardrails', 'scan prompts', 'one slice'],
  ['DLP / CASB', 'watch leakage', 'one slice'],
  ['Monitoring', 'record events', 'after-the-fact'],
  ['Tex', 'controls the full lifecycle', 'seven-layer system'],
];

const LOOP = ['Intercept', 'Authorize', 'Verify', 'Execute', 'Record', 'Learn'];

function usePulse() {
  const [active, setActive] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setActive(v => (v + 1) % LAYERS.length), 2100);
    return () => clearInterval(id);
  }, []);
  return [active, setActive];
}

function NeuralField({ active }) {
  const ref = useRef(null);
  const mouse = useRef({ x: 0, y: 0 });
  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas.getContext('2d');
    let raf;
    let t = 0;
    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = innerWidth * dpr;
      canvas.height = innerHeight * dpr;
      canvas.style.width = `${innerWidth}px`;
      canvas.style.height = `${innerHeight}px`;
      ctx.setTransform(dpr,0,0,dpr,0,0);
    };
    const move = e => {
      mouse.current.x = (e.clientX / innerWidth - .5) * 2;
      mouse.current.y = (e.clientY / innerHeight - .5) * 2;
    };
    resize();
    addEventListener('resize', resize);
    addEventListener('pointermove', move);
    const draw = () => {
      t += .008;
      const w = innerWidth, h = innerHeight;
      ctx.clearRect(0,0,w,h);
      const bg = ctx.createRadialGradient(w*.62, h*.38, 80, w*.62, h*.38, w*.9);
      bg.addColorStop(0, 'rgba(60,255,244,.14)');
      bg.addColorStop(.38, 'rgba(21,22,58,.13)');
      bg.addColorStop(1, 'rgba(1,4,10,0)');
      ctx.fillStyle = bg; ctx.fillRect(0,0,w,h);
      const horizon = h*.46 + mouse.current.y*24;
      const cx = w*.5 + mouse.current.x*35;
      for (let i=0;i<54;i++) {
        const p = i/53;
        const y = horizon + Math.pow(p,2.35)*h*.72 + ((t*70)%28)*p;
        ctx.strokeStyle = `rgba(77,255,244,${.04 + .13*(1-p)})`;
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(w,y + Math.sin(t+i)*2); ctx.stroke();
      }
      for (let i=-38;i<=38;i++) {
        const x = cx + i*70 + Math.sin(t+i)*5;
        ctx.strokeStyle = `rgba(145,96,255,${.04 + (Math.abs(i)<4?.05:0)})`;
        ctx.beginPath(); ctx.moveTo(cx,horizon); ctx.lineTo(x,h+80); ctx.stroke();
      }
      for (let i=0;i<120;i++) {
        const x = (i*139.17 + t*26) % w;
        const y = (i*71.9 + Math.sin(t*2+i)*18) % h;
        ctx.fillStyle = `rgba(210,255,255,${.06 + (i%5)*.018})`;
        ctx.fillRect(x,y,1.4,1.4);
      }
      const layer = LAYERS[active];
      const pulse = (Math.sin(t*4)+1)/2;
      ctx.strokeStyle = hexToRgba(layer.color, .07 + pulse*.08);
      ctx.lineWidth = 2;
      ctx.beginPath(); ctx.arc(w*.5, h*.43, 210+pulse*150, 0, Math.PI*2); ctx.stroke();
      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => { cancelAnimationFrame(raf); removeEventListener('resize', resize); removeEventListener('pointermove', move); };
  }, [active]);
  return <canvas className="neural-field" ref={ref} aria-hidden="true" />;
}

function hexToRgba(hex, a) {
  const n = parseInt(hex.replace('#',''),16);
  return `rgba(${(n>>16)&255},${(n>>8)&255},${n&255},${a})`;
}

function TopNav() {
  return <header className="nav">
    <a className="brand" href="#top"><span>T</span><b>Tex</b><em>by VortexBlack</em></a>
    <nav><a href="#system">System</a><a href="#layers">Seven Layers</a><a href="#proof">Chain Hash</a></nav>
    <a className="navButton" href="#trial">2-week trial</a>
  </header>;
}

function Hero({ active, setActive }) {
  const layer = LAYERS[active];
  return <section id="top" className="hero" style={{'--accent': layer.color}}>
    <div className="heroBrief">
      <div className="eyebrow"><span/> TEX BY VORTEXBLACK</div>
      <h1>The central control system for AI agents.</h1>
      <p>Tex finds every agent, identifies who is acting, defines authority, judges the real action, enforces the decision, seals the evidence, and calibrates from outcomes.</p>
      <div className="fiveSecond">
        <b>Buyers get it in 5 seconds:</b>
        <span>One system controls the full AI agent lifecycle — not fragments.</span>
      </div>
      <div className="heroActions"><a href="#trial">Activate 2-week trial</a><a href="#layers">See the seven layers</a></div>
    </div>
    <div className="commandCore" aria-label="Tex central seven layer control system">
      <div className="orbit orbitA"/><div className="orbit orbitB"/><div className="orbit orbitC"/>
      <div className="coreRays"/>
      <div className="texBody"><img src={texHero} alt="Tex by VortexBlack central control system"/><div className="scanline"/><div className="coreLabel"><b>Tex</b><span>central authority core</span></div></div>
      {LAYERS.map((l,i) => <button key={l.name} onMouseEnter={()=>setActive(i)} onFocus={()=>setActive(i)} onClick={()=>setActive(i)} className={`node node${i+1} ${i===active?'active':''}`} style={{'--node':l.color}}><small>{l.id}</small><b>{l.name}</b><span>{l.line}</span></button>)}
      <div className="verdictCard">
        <div><span>LIVE SEVEN-LAYER EVALUATION</span><b>SHA256:TX-{active+1}4D2-CODE</b></div>
        <h3>{layer.line}</h3>
        <p>{layer.detail}</p>
        <footer><strong>{layer.name}</strong><em>{active < 4 ? 'ANALYZING' : active === 4 ? 'FORBID / ABSTAIN / PERMIT' : 'SEALED'}</em></footer>
      </div>
    </div>
  </section>;
}

function SystemSection() {
  return <section id="system" className="section splitPanel">
    <div><div className="eyebrow"><span/> NOT A POINT PRODUCT</div><h2>Other tools protect slices. Tex connects the whole system.</h2><p>Posture, identity, guardrails, DLP, monitoring, and audit logs are useful — but they leave handoffs. Tex is the control loop that turns them into one enforceable AI security system.</p></div>
    <div className="compareStack">{COMPARE.map((r,i)=><div key={r[0]} className={r[0]==='Tex'?'texRow':''}><span>{String(i+1).padStart(2,'0')}</span><b>{r[0]}</b><em>{r[1]}</em><strong>{r[2]}</strong></div>)}</div>
  </section>;
}

function LayersSection({ active, setActive }) {
  const layer = LAYERS[active];
  return <section id="layers" className="section layersDeck" style={{'--accent':layer.color}}>
    <div className="sectionHead"><div className="eyebrow"><span/> THE 7-LAYER CONTROL STACK</div><h2>Tex sits above the agent ecosystem and governs every action path.</h2></div>
    <div className="deckGrid">
      <div className="stackRail">{LAYERS.map((l,i)=><button key={l.name} onClick={()=>setActive(i)} onMouseEnter={()=>setActive(i)} className={i===active?'active':''} style={{'--node':l.color}}><span>{l.id}</span><b>{l.name}</b><em>{l.line}</em></button>)}</div>
      <div className="layerStage">
        <div className="stageCore"><span>ACTIVE LAYER</span><b>{layer.id}</b></div>
        <h3>{layer.name}</h3><h4>{layer.line}</h4><p>{layer.detail}</p>
        <div className="signalStrip"><i/><i/><i/><i/><i/><i/><i/></div>
      </div>
      <div className="buyerProof">
        <h3>What the buyer understands</h3>
        <p>Tex is not just watching agents. It is the runtime authority layer that controls what they are allowed to do before actions hit the real world.</p>
        <ul><li>Find every agent</li><li>Bind identity and ownership</li><li>Evaluate the actual action</li><li>Enforce before execution</li><li>Seal proof for audit</li></ul>
      </div>
    </div>
  </section>;
}

function ProofSection() {
  return <section id="proof" className="section proof">
    <div><div className="eyebrow"><span/> CRYPTOGRAPHICALLY-LINKED LOOP</div><h2>Every decision becomes evidence.</h2><p>Tex does not just say “blocked” or “allowed.” It records the request, policy, verdict, permit, verification, execution state, outcome, and calibration event into a chain buyers can trust.</p></div>
    <div className="loopChain">{LOOP.map((x,i)=><div key={x}><span>{String(i+1).padStart(2,'0')}</span><b>{x}</b><em>{i===0?'request captured':i===1?'policy verdict':i===2?'permit checked':i===3?'action released':i===4?'hash sealed':'threshold tuned'}</em></div>)}</div>
  </section>;
}

function Trial() {
  return <section id="trial" className="section trial">
    <div><div className="eyebrow"><span/> START WITH THE AUDIT</div><h2>Tex by VortexBlack gives buyers one clear answer: who controls your agents?</h2><p>The trial should feel concrete: inventory the agents, map authority, run actions through the seven layers, and export the proof.</p><a href="mailto:contact@vortexblack.ai?subject=Tex%202-week%20trial">Activate 2-week trial</a></div>
    <div className="trialCards"><div><span>01</span><b>Inventory</b><em>Find agents and owners.</em></div><div><span>02</span><b>Control</b><em>Run real actions through Tex.</em></div><div><span>03</span><b>Proof</b><em>Export the evidence bundle.</em></div></div>
  </section>;
}

export default function App(){
  const [active, setActive] = usePulse();
  return <main><NeuralField active={active}/><div className="noise"/><TopNav/><Hero active={active} setActive={setActive}/><SystemSection/><LayersSection active={active} setActive={setActive}/><ProofSection/><Trial/><footer className="siteFooter"><b>Tex by VortexBlack</b><span>Central control system for AI agents.</span></footer></main>;
}
