import React, { useEffect, useMemo, useState } from 'react';
import texHero from './tex-hero.png';
import './styles.css';

const layers = [
  {
    n: '01',
    name: 'Discovery',
    command: 'Find every agent',
    buyer: 'Reveals the agents, copilots, workflows, tools, model endpoints, and shadow automations already moving through the business.',
    proof: 'Agent inventory • tool surface • owner map • active paths',
  },
  {
    n: '02',
    name: 'Identity',
    command: 'Know who is acting',
    buyer: 'Ties every action to the agent, human owner, tenant, system, environment, and trust level before Tex lets it move.',
    proof: 'Agent ID • owner • session • tenant • environment',
  },
  {
    n: '03',
    name: 'Authority',
    command: 'Define what is allowed',
    buyer: 'Turns policy into live limits: what the agent can access, say, change, delete, promise, trigger, or escalate.',
    proof: 'Versioned policy • action scope • criticality • approvals',
  },
  {
    n: '04',
    name: 'Judgment',
    command: 'Read the real action',
    buyer: 'Examines the exact email, Slack post, database write, API call, workflow trigger, or customer commitment before it leaves the system.',
    proof: 'Content spans • deterministic checks • semantic review • specialist signals',
  },
  {
    n: '05',
    name: 'Enforcement',
    command: 'Permit, hold, or block',
    buyer: 'Tex becomes the live gate: safe actions pass, dangerous actions stop, uncertain actions wait for a human.',
    proof: 'PERMIT • ABSTAIN • FORBID • signed permit • nonce verification',
  },
  {
    n: '06',
    name: 'Evidence',
    command: 'Seal the proof',
    buyer: 'Records what happened, why it happened, which policy decided it, and whether the final execution matched the permit.',
    proof: 'Request • verdict • policy version • permit • verification • outcome',
  },
  {
    n: '07',
    name: 'Calibration',
    command: 'Improve without chaos',
    buyer: 'Learns from overrides, outcomes, false permits, and false blocks while keeping rules locked, versioned, and replayable.',
    proof: 'Outcome feedback • threshold tuning • replay • policy snapshots',
  },
];

const marketSignals = [
  ['Shadow AI is spreading', 'Employees and teams connect unapproved agents before security even knows they exist.'],
  ['Agents act with real privileges', 'They can message customers, touch files, update records, invoke tools, and chain workflows.'],
  ['Point tools leave gaps', 'Posture, identity, prompt filters, and monitoring each solve one slice — not the whole action path.'],
  ['Buyers need proof', 'Leadership wants verifiable control, not another dashboard full of events nobody can defend.'],
];

const competitors = [
  ['Posture tools', 'see agents'],
  ['Identity tools', 'name actors'],
  ['Guardrails', 'check content'],
  ['Monitoring', 'watch events'],
  ['Tex', 'connects the full loop'],
];

const chainItems = ['Agent found', 'Identity bound', 'Authority checked', 'Action judged', 'Gate enforced', 'Evidence sealed', 'Outcome calibrated'];

function useActiveLayer() {
  const [active, setActive] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setActive((v) => (v + 1) % layers.length), 1650);
    return () => clearInterval(id);
  }, []);
  return active;
}

export default function App() {
  const active = useActiveLayer();
  const hash = useMemo(() => {
    const left = ['A71F', '0C9E', '44D2', 'E802', 'BB19', '7FA4', 'D31C'][active];
    const right = ['91EE', '3A5B', 'C0DE', 'F17A', '88B0', 'E6D4', '59AF'][active];
    return `sha256:${left}…${right}`;
  }, [active]);
  const current = layers[active];

  return (
    <main className="site-shell">
      <Backdrop />
      <Header />

      <section id="top" className="hero section-x">
        <div className="hero-copy reveal-up">
          <div className="eyebrow"><span /> The all-inclusive AI agent security system</div>
          <h1>Tex is the 360° control loop for AI agents.</h1>
          <p className="hero-lede">
            Normal security sees fragments. Tex connects the whole agent lifecycle: discovery, identity, authority, judgment, enforcement, evidence, and calibration — one cryptographically-linked loop from unknown agent to provable outcome.
          </p>
          <div className="cta-row">
            <a className="btn btn-primary" href="#trial">Activate 2-week trial</a>
            <a className="btn btn-ghost" href="#layers">Enter the seven layers</a>
          </div>
          <div className="power-strip" aria-label="Tex value pillars">
            <span>Find every agent</span>
            <span>Control every action</span>
            <span>Prove every decision</span>
          </div>
        </div>

        <div className="god-panel reveal-up delay-1" aria-label="Tex seven layer control visual">
          <div className="halo halo-outer" />
          <div className="halo halo-mid" />
          <div className="halo halo-inner" />
          <div className="energy-beam beam-a" />
          <div className="energy-beam beam-b" />
          <img className="tex-god" src={texHero} alt="Tex guardian control system" />
          <div className="god-title">
            <strong>TEX</strong>
            <span>Guardian Control Core</span>
          </div>
          {layers.map((layer, i) => (
            <div key={layer.name} className={`sigil sigil-${i + 1} ${i === active ? 'is-active' : ''}`}>
              <b>{layer.n}</b>
              <span>{layer.name}</span>
            </div>
          ))}
          <div className="verdict-card">
            <div className="verdict-top"><span>Layer firing</span><b>{hash}</b></div>
            <h3>{current.command}</h3>
            <p>{current.buyer}</p>
          </div>
        </div>
      </section>

      <section id="why" className="section-x market-section">
        <div className="section-intro centered">
          <div className="eyebrow"><span /> What buyers are trying to solve now</div>
          <h2>AI agents are becoming workers. Security is still built for tools.</h2>
          <p>That gap is the opportunity. Companies do not just need a scanner, a prompt filter, or another log stream. They need one control system that surrounds the agent from discovery to proof.</p>
        </div>
        <div className="signal-grid">
          {marketSignals.map(([title, copy], i) => (
            <article className="signal-card" key={title}>
              <div className="card-number">0{i + 1}</div>
              <h3>{title}</h3>
              <p>{copy}</p>
            </article>
          ))}
        </div>
      </section>

      <section id="system" className="section-x command-section">
        <div className="command-board">
          <div className="command-copy">
            <div className="eyebrow"><span /> Not a point product</div>
            <h2>Tex is built to be the control plane across all agent security.</h2>
            <p>Zenity-style posture, identity controls, prompt guardrails, DLP, monitoring, and audit trails are all useful — but they are slices. Tex is the connective control loop that joins the slices into one enforceable system.</p>
          </div>
          <div className="radar-compare">
            {competitors.map(([name, job], i) => (
              <div className={`radar-row ${name === 'Tex' ? 'tex-row' : ''}`} key={name}>
                <span>{i + 1}</span>
                <b>{name}</b>
                <em>{job}</em>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="layers" className="section-x layers-section">
        <div className="section-intro">
          <div className="eyebrow"><span /> Seven-layer control system</div>
          <h2>Seven layers around the agent. One loop around the business.</h2>
          <p>Each layer is simple enough for a buyer to understand in seconds and strong enough to become product architecture.</p>
        </div>
        <div className="layer-stage">
          <div className="layer-spine">
            {layers.map((l, i) => (
              <button key={l.name} className={`spine-node ${i === active ? 'is-active' : ''}`} type="button">
                <span>{l.n}</span>{l.name}
              </button>
            ))}
          </div>
          <div className="layer-main-card">
            <div className="layer-glow" />
            <div className="layer-meta"><span>{current.n}</span><b>{current.name}</b></div>
            <h3>{current.command}</h3>
            <p>{current.buyer}</p>
            <div className="proof-pill">{current.proof}</div>
          </div>
          <div className="mini-layers">
            {layers.map((l, i) => (
              <article key={l.name} className={i === active ? 'is-active' : ''}>
                <span>{l.n}</span>
                <b>{l.name}</b>
                <em>{l.command}</em>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section id="proof" className="section-x proof-section">
        <div className="proof-copy">
          <div className="eyebrow"><span /> Cryptographically-linked control loop</div>
          <h2>The chain hash is the difference between “trust us” and “prove it.”</h2>
          <p>Every step in Tex produces evidence. Every decision is tied to the request, policy, verdict, permit, verification, outcome, and next chain hash. That is how the control loop becomes defensible.</p>
        </div>
        <div className="chain-machine" aria-label="Cryptographically linked evidence chain">
          {chainItems.map((item, i) => (
            <div className={`chain-link ${i === active ? 'is-active' : ''}`} key={item}>
              <span>{String(i + 1).padStart(2, '0')}</span>
              <b>{item}</b>
              <em>{i === active ? hash : `sha256:${(991733 + i * 4093).toString(16)}…`}</em>
            </div>
          ))}
        </div>
      </section>

      <section className="section-x architecture-section">
        <div className="section-intro centered">
          <div className="eyebrow"><span /> What it becomes</div>
          <h2>The guardian layer for autonomous business systems.</h2>
          <p>Tex is being built toward full coverage: agent discovery, registry, authority, runtime gate, evidence export, replay, and calibration. One system. Seven layers. One chain of control.</p>
        </div>
        <div className="architecture-grid">
          {[
            ['Agent Surface Map', 'Every agent, tool, endpoint, owner, and action path made visible.'],
            ['Authority Kernel', 'Versioned policy decides what agents are allowed to do.'],
            ['Live Runtime Gate', 'Actions pass through PERMIT / ABSTAIN / FORBID before execution.'],
            ['Evidence Vault', 'Decision records become hash-linked proof bundles.'],
            ['Replay Engine', 'Reconstruct exactly why Tex decided what it decided.'],
            ['Calibration Layer', 'Improve thresholds from outcomes without uncontrolled self-rewrite.'],
          ].map(([title, copy]) => (
            <article className="arch-card" key={title}><h3>{title}</h3><p>{copy}</p></article>
          ))}
        </div>
      </section>

      <section id="trial" className="section-x trial-section">
        <div className="trial-shell">
          <div className="trial-copy">
            <div className="eyebrow"><span /> 2-week live control trial</div>
            <h2>Turn your AI agent risk into a visible control map.</h2>
            <p>Start in observe mode. Map your agent surface. Identify high-risk action paths. Then run Tex on selected workflows and see what it would permit, hold, block, and prove.</p>
          </div>
          <div className="trial-steps">
            <div><span>Week 01</span><b>Map the battlefield</b><em>Agents, tools, owners, permissions, risky paths.</em></div>
            <div><span>Week 02</span><b>Run the loop</b><em>Judgments, gates, evidence, chain hash, executive readout.</em></div>
            <a className="btn btn-primary" href="mailto:founder@vortexblack.ai?subject=Tex%202-week%20live%20control%20trial">Activate Tex</a>
          </div>
        </div>
      </section>

      <footer className="footer">
        <div className="brand"><span className="brand-mark">T</span><b>Tex</b></div>
        <p>360° seven-layer control loop for AI agents.</p>
      </footer>
    </main>
  );
}

function Header() {
  return (
    <header className="nav">
      <a className="brand" href="#top"><span className="brand-mark">T</span><b>Tex</b></a>
      <nav>
        <a href="#system">System</a>
        <a href="#layers">Seven Layers</a>
        <a href="#proof">Chain Hash</a>
      </nav>
      <a className="nav-cta" href="#trial">2-week trial</a>
    </header>
  );
}

function Backdrop() {
  return (
    <div className="backdrop" aria-hidden="true">
      <div className="gradient-field" />
      <div className="moving-grid grid-one" />
      <div className="moving-grid grid-two" />
      <div className="starfield" />
      <div className="vertical-scan" />
      <div className="god-light light-a" />
      <div className="god-light light-b" />
    </div>
  );
}
