import React, { useEffect, useMemo, useState } from 'react';
import texHero from './tex-hero.png';
import './styles.css';

const layers = [
  { id:'01', name:'Discovery', short:'Find every agent', detail:'Inventory every AI agent, workflow, bot, tool call, and shadow automation before it acts outside control.', signal:'AGENTS FOUND', color:'#49f5ff' },
  { id:'02', name:'Identity', short:'Know who is acting', detail:'Bind each action to an agent, owner, tenant, environment, permissions, and trust level.', signal:'ACTOR BOUND', color:'#77a7ff' },
  { id:'03', name:'Authority', short:'Define what is allowed', detail:'Convert policy into live boundaries for what agents may access, change, promise, delete, or escalate.', signal:'POLICY LOADED', color:'#ffd66b' },
  { id:'04', name:'Judgment', short:'Read the real action', detail:'Evaluate the exact email, Slack post, API call, database change, or workflow before it is released.', signal:'ACTION READ', color:'#b577ff' },
  { id:'05', name:'Enforcement', short:'Stop, hold, or release', detail:'Return PERMIT, ABSTAIN, or FORBID while the action is still stoppable.', signal:'VERDICT ISSUED', color:'#ff4d86' },
  { id:'06', name:'Evidence', short:'Seal the proof', detail:'Record request, policy, verdict, permit, verification, execution state, and outcome in a hash-linked trail.', signal:'PROOF SEALED', color:'#5cffb0' },
  { id:'07', name:'Calibration', short:'Improve without chaos', detail:'Tune thresholds from outcomes and overrides without allowing the system to rewrite its own rules.', signal:'THRESHOLD TUNED', color:'#f2fbff' },
];

const loop = ['Intercept','Authorize','Verify','Execute','Record','Learn'];

function useActiveLayer() {
  const [active, setActive] = useState(4);
  useEffect(() => {
    const id = setInterval(() => setActive(v => (v + 1) % layers.length), 2800);
    return () => clearInterval(id);
  }, []);
  return [active, setActive];
}

function Nav() {
  return <header className="nav-shell">
    <a className="brand" href="#top" aria-label="Tex by VortexBlack home"><span>T</span><b>Tex</b><i>by VortexBlack</i></a>
    <nav><a href="#system">System</a><a href="#layers">Seven Layers</a><a href="#evidence">Chain Hash</a></nav>
    <a className="nav-pill" href="#trial">2-week trial</a>
  </header>
}

function Ambient() {
  return <div className="ambient" aria-hidden="true">
    <div className="aurora a1"/><div className="aurora a2"/><div className="scanline"/><div className="grid-plane"/><div className="noise"/>
  </div>
}

function LayerConstellation({ active, setActive, compact=false }) {
  const activeLayer = layers[active];
  return <div className={compact ? 'constellation compact' : 'constellation'} style={{'--active': activeLayer.color}}>
    <div className="orbit o1"/><div className="orbit o2"/><div className="orbit o3"/>
    <div className="pulse-core"><span>TEX</span><b>CONTROL CORE</b></div>
    {layers.map((l, index) => {
      const angle = (-90 + index * 360 / layers.length) * Math.PI / 180;
      const r = compact ? 38 : 43;
      const x = 50 + Math.cos(angle) * r;
      const y = 50 + Math.sin(angle) * r;
      return <button key={l.name} className={`layer-node ${active === index ? 'active':''}`} onMouseEnter={() => setActive(index)} onClick={() => setActive(index)} style={{left:`${x}%`, top:`${y}%`, '--c': l.color}}>
        <em>{l.id}</em><strong>{l.name}</strong><small>{l.short}</small>
      </button>
    })}
    <svg className="signal-lines" viewBox="0 0 100 100" preserveAspectRatio="none">
      {layers.map((l,index) => {
        const angle = (-90 + index * 360 / layers.length) * Math.PI / 180;
        const x = 50 + Math.cos(angle) * (compact ? 32 : 36);
        const y = 50 + Math.sin(angle) * (compact ? 32 : 36);
        return <line key={l.name} x1="50" y1="50" x2={x} y2={y} className={active===index?'live':''}/>
      })}
    </svg>
  </div>
}

function Hero({ active, setActive }) {
  const l = layers[active];
  return <section id="top" className="hero" style={{'--active': l.color}}>
    <div className="hero-copy">
      <div className="eyebrow"><span/> Tex by VortexBlack</div>
      <h1>The control layer for AI agents.</h1>
      <p className="plain">Tex finds agents, binds identity, defines authority, judges every action, enforces the decision, seals the proof, and calibrates from outcomes.</p>
      <div className="five-second"><b>In 5 seconds:</b><span>One system controls the full AI agent lifecycle — not fragments.</span></div>
      <div className="hero-actions"><a href="#trial" className="primary">Activate 2-week trial</a><a href="#layers" className="secondary">See the seven layers</a></div>
    </div>
    <div className="tex-system-stage">
      <LayerConstellation active={active} setActive={setActive}/>
      <div className="avatar-core">
        <img src={texHero} alt="Tex avatar, central AI agent control system"/>
        <div className="avatar-glow"/>
      </div>
      <div className="verdict-console">
        <div><span>LIVE SEVEN-LAYER EVALUATION</span><b>SHA256:TX-{active+1}A9F</b></div>
        <h2>{l.name}</h2>
        <h3>{l.short}</h3>
        <p>{l.detail}</p>
        <footer><strong>{l.signal}</strong><i>{active === 4 ? 'FORBID / ABSTAIN / PERMIT' : 'CONTROLLED'}</i></footer>
      </div>
    </div>
  </section>
}

function SystemSection() {
  return <section id="system" className="system-panel section">
    <div className="section-title"><div className="eyebrow"><span/> Not a point product</div><h2>Other tools protect slices. Tex connects the system.</h2></div>
    <div className="slice-grid">
      {['Posture tools see agents','Identity tools name actors','Prompt guardrails scan text','DLP watches leakage','Monitoring records events'].map((x,i)=><div className="slice" key={x}><span>{String(i+1).padStart(2,'0')}</span><p>{x}</p><b>one slice</b></div>)}
      <div className="slice tex-slice"><span>06</span><p>Tex controls the full lifecycle</p><b>seven layers</b></div>
    </div>
  </section>
}

function LayersSection({ active, setActive }) {
  const l = layers[active];
  return <section id="layers" className="layers-section section" style={{'--active': l.color}}>
    <div className="section-title narrow"><div className="eyebrow"><span/> Seven-layer system loop</div><h2>Tex sits above the agent ecosystem and governs every action path.</h2></div>
    <div className="layer-workbench">
      <div className="layer-list">{layers.map((layer,i)=><button key={layer.name} onMouseEnter={()=>setActive(i)} onClick={()=>setActive(i)} className={i===active?'active':''} style={{'--c': layer.color}}><span>{layer.id}</span><b>{layer.name}</b><em>{layer.short}</em></button>)}</div>
      <div className="layer-focus"><div className="metric">ACTIVE LAYER <b>{l.id}</b></div><h3>{l.name}</h3><h4>{l.short}</h4><p>{l.detail}</p><div className="thin-bars"><i/><i/><i/><i/><i/><i/><i/></div></div>
      <div className="buyer-card"><h3>Buyer takeaway</h3><p>Tex is not another dashboard. It is the runtime authority layer that decides what an AI agent is allowed to do before the action reaches the real world.</p><ul><li>Find every agent</li><li>Bind identity and ownership</li><li>Evaluate real actions</li><li>Enforce before execution</li><li>Seal proof for audit</li></ul></div>
    </div>
  </section>
}

function EvidenceSection() {
  return <section id="evidence" className="evidence section">
    <div><div className="eyebrow"><span/> Cryptographically-linked loop</div><h2>Every decision becomes evidence.</h2><p>Tex records the request, policy, verdict, permit, verification, execution state, outcome, and calibration event into a chain buyers can trust.</p></div>
    <div className="loop-stack">{loop.map((item,i)=><div key={item} className={i===1||i===4?'hot':''}><span>{String(i+1).padStart(2,'0')}</span><b>{item}</b><em>{['request captured','policy verdict','permit checked','action released','hash sealed','threshold tuned'][i]}</em></div>)}</div>
  </section>
}

function TrialSection() {
  return <section id="trial" className="trial section">
    <div><div className="eyebrow"><span/> Start with the audit</div><h2>Tex by VortexBlack gives buyers one clear answer: who controls your agents?</h2><p>The trial should be concrete: inventory the agents, map authority, run actions through the seven layers, and export the proof.</p><a className="primary" href="mailto:founder@vortexblack.ai">Activate 2-week trial</a></div>
    <div className="trial-steps"><div><span>01</span><b>Inventory</b><p>Find agents and owners.</p></div><div><span>02</span><b>Control</b><p>Run real actions through Tex.</p></div><div><span>03</span><b>Proof</b><p>Export the evidence bundle.</p></div></div>
  </section>
}

export default function App(){
  const [active,setActive] = useActiveLayer();
  return <>
    <Ambient/><Nav/>
    <main>
      <Hero active={active} setActive={setActive}/>
      <SystemSection/>
      <LayersSection active={active} setActive={setActive}/>
      <EvidenceSection/>
      <TrialSection/>
    </main>
    <footer className="site-footer"><b>Tex by VortexBlack</b><span>Central control system for AI agents.</span></footer>
  </>
}
