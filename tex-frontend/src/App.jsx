import React, { useEffect, useMemo, useState } from 'react';
import texHero from './tex-hero.png';
import './styles.css';

const sevenLayers = [
  {
    n: '01',
    name: 'Discover',
    short: 'Find every agent',
    buyer: 'No more invisible AI running through SaaS, cloud, code, and employee tools.',
    system: 'Connectors scan Microsoft, Salesforce, Bedrock, GitHub, OpenAI, MCP, and custom sources.',
  },
  {
    n: '02',
    name: 'Identify',
    short: 'Know who it is',
    buyer: 'Every action is tied to an agent, owner, system, tenant, environment, and trust level.',
    system: 'Agent identity, lifecycle status, capability surface, attestations, and behavioral ledger.',
  },
  {
    n: '03',
    name: 'Authorize',
    short: 'Set the limits',
    buyer: 'Define exactly what each agent can do before it can touch customers, data, or systems.',
    system: 'Versioned policy snapshots, action criticality, channel criticality, and environment criticality.',
  },
  {
    n: '04',
    name: 'Judge',
    short: 'Read the real action',
    buyer: 'Tex inspects the actual message, API call, database update, promise, deletion, or workflow trigger.',
    system: 'Deterministic checks, retrieval grounding, specialists, semantic analysis, and fusion scoring.',
  },
  {
    n: '05',
    name: 'Enforce',
    short: 'Stop or release',
    buyer: 'Safe actions pass. Risky actions stop. Unclear actions wait for a human instead of guessing.',
    system: 'Runtime verdicts: PERMIT, ABSTAIN, FORBID — returned before execution.',
  },
  {
    n: '06',
    name: 'Prove',
    short: 'Seal the evidence',
    buyer: 'Every decision produces proof your security, legal, compliance, and customers can inspect.',
    system: 'Hash-chained evidence with original request, policy version, verdict, permit, verification, and outcome.',
  },
  {
    n: '07',
    name: 'Calibrate',
    short: 'Improve safely',
    buyer: 'Tex gets sharper from outcomes and overrides without allowing the system to rewrite its own rules.',
    system: 'Outcome feedback adjusts thresholds and recommendations between locked policy versions.',
  },
];

const loop = ['Discover', 'Identify', 'Authorize', 'Judge', 'Enforce', 'Prove', 'Calibrate'];

const marketNeeds = [
  ['Visibility', 'Find shadow agents before they become shadow risk.'],
  ['Runtime Control', 'Stop bad actions while they are still stoppable.'],
  ['Policy Enforcement', 'Turn rules into decisions, not PDFs nobody reads.'],
  ['Evidence', 'Give auditors and buyers a chain of proof, not screenshots.'],
];

const pointTools = [
  ['Agent posture', 'Shows what exists, but often stops at dashboards.'],
  ['Identity & access', 'Controls permissions, but not the exact action being attempted.'],
  ['Prompt guardrails', 'Inspect content, but not the full agent, policy, behavior, and proof loop.'],
  ['Monitoring', 'Explains what happened after the action already reached the world.'],
];

function usePulse() {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick((v) => v + 1), 1800);
    return () => clearInterval(id);
  }, []);
  return tick;
}

export default function App() {
  const tick = usePulse();
  const active = tick % sevenLayers.length;
  const hash = useMemo(() => `0x${['9F2A', 'C7D1', '41BE', 'A604', '77E9', 'B33C', 'E190'][active]}…${['D8C1', '04AF', '7B22', '91EE', 'F6A0', 'C114', '5A7D'][active]}`, [active]);

  return (
    <main className="shell">
      <div className="world" aria-hidden="true">
        <div className="aurora aurora-a" />
        <div className="aurora aurora-b" />
        <div className="matrix-grid" />
        <div className="depth-lines" />
        <div className="scanline" />
      </div>

      <nav className="topbar">
        <a className="brand" href="#top" aria-label="Tex home"><span className="brand-glyph">T</span><span>Tex</span></a>
        <div className="navlinks">
          <a href="#system">System</a>
          <a href="#layers">7 layers</a>
          <a href="#proof">Proof</a>
          <a href="#trial">Trial</a>
        </div>
        <a className="top-cta" href="#trial">Activate 2-week trial</a>
      </nav>

      <section id="top" className="section hero">
        <div className="hero-copy">
          <div className="kicker"><span /> AI agent security has a missing control layer</div>
          <h1>The first 360° control loop for AI agents.</h1>
          <p className="lede">Most AI security products solve one slice: discovery, identity, guardrails, monitoring, or audit. Tex is built as one complete loop — find every agent, control what it can do, stop unsafe actions, and seal every decision in cryptographic proof.</p>
          <div className="hero-buttons">
            <a className="btn primary" href="#trial">Start the 2-week live control trial</a>
            <a className="btn secondary" href="#layers">See the seven layers</a>
          </div>
          <div className="hero-proof">
            <span>360° agent visibility</span>
            <span>PERMIT / ABSTAIN / FORBID</span>
            <span>Hash-chained evidence</span>
          </div>
        </div>

        <div className="control-orb" aria-label="Seven layer Tex control loop">
          <div className="orb-glass">
            <div className="ring ring-1" />
            <div className="ring ring-2" />
            <div className="ring ring-3" />
            <img className="tex-avatar" src={texHero} alt="Tex control system" />
            <div className="core-label"><strong>Tex</strong><span>360° loop active</span></div>
            {loop.map((item, i) => (
              <div key={item} className={`orbit-node node-${i + 1} ${i === active ? 'active' : ''}`}>
                <b>{String(i + 1).padStart(2, '0')}</b>{item}
              </div>
            ))}
          </div>
          <div className="decision-rail">
            <div className="rail-top"><span>live chain</span><b>{hash}</b></div>
            <div className="rail-body">
              <span className="status-dot" />
              <p><b>{sevenLayers[active].name}</b> layer firing</p>
              <em>{sevenLayers[active].short}</em>
            </div>
          </div>
        </div>
      </section>

      <section id="system" className="section split-section">
        <div>
          <div className="kicker"><span /> Built for what buyers are asking for now</div>
          <h2>Visibility is not enough. Guardrails are not enough. Logs are not enough.</h2>
          <p className="lede">AI agents now touch data, customers, internal tools, cloud resources, and workflow systems. Buyers need one thing above everything else: a way to know what exists, control what acts, and prove what happened.</p>
        </div>
        <div className="need-grid">
          {marketNeeds.map(([title, copy]) => <article key={title} className="need-card"><h3>{title}</h3><p>{copy}</p></article>)}
        </div>
      </section>

      <section className="section comparison">
        <div className="compare-shell">
          <div className="compare-left">
            <div className="kicker"><span /> The category break</div>
            <h2>Point tools cover fragments. Tex connects the whole chain.</h2>
          </div>
          <div className="fragment-list">
            {pointTools.map(([title, copy]) => <div key={title} className="fragment"><strong>{title}</strong><span>{copy}</span></div>)}
          </div>
          <div className="tex-stack">
            <div className="stack-header">Tex 360° control loop</div>
            {sevenLayers.map((l, i) => <div key={l.name} className={`stack-row ${i === active ? 'active' : ''}`}><span>{l.n}</span><b>{l.name}</b><em>{l.short}</em></div>)}
          </div>
        </div>
      </section>

      <section id="layers" className="section layers-section">
        <div className="section-head">
          <div className="kicker"><span /> Seven-layer AI security system</div>
          <h2>Tex is built to control the full path from unknown agent to provable outcome.</h2>
          <p className="lede">This is the difference: each layer feeds the next. Discovery is not just a dashboard. Identity is not just a login. Evidence is not just a log. Everything becomes part of one decision loop.</p>
        </div>
        <div className="layer-grid">
          {sevenLayers.map((l, i) => (
            <article key={l.name} className={`layer ${i === active ? 'active' : ''}`}>
              <div className="layer-meta"><span>{l.n}</span><i /></div>
              <h3>{l.name}</h3>
              <strong>{l.short}</strong>
              <p>{l.buyer}</p>
              <small>{l.system}</small>
            </article>
          ))}
        </div>
      </section>

      <section id="proof" className="section proof-section">
        <div className="proof-copy">
          <div className="kicker"><span /> Cryptographically-linked control loop</div>
          <h2>Every decision becomes part of a chain you can verify.</h2>
          <p className="lede">Tex does not just say “approved” or “blocked.” It records the original request, policy version, evidence streams, verdict, permit, verification, outcome, and chain hash — so proof survives beyond the dashboard.</p>
        </div>
        <div className="hash-panel">
          <div className="hash-title"><span>Evidence chain</span><b>verifiable</b></div>
          {['Original action', 'Policy snapshot', 'Seven-layer evaluation', 'Runtime verdict', 'Permit / hold / block', 'Outcome feedback', 'Next chain hash'].map((item, i) => (
            <div className={`hash-row ${i === active ? 'active' : ''}`} key={item}>
              <span>{String(i + 1).padStart(2, '0')}</span><b>{item}</b><em>{i === active ? hash : `sha256:${(812904 + i * 7311).toString(16)}…`}</em>
            </div>
          ))}
        </div>
      </section>

      <section className="section backend-relevant">
        <div className="kicker"><span /> Matches where Tex is going</div>
        <h2>The backend is becoming a full agent security operating system.</h2>
        <div className="capability-grid">
          <Capability title="Discovery connectors" copy="Find agents across SaaS, cloud, coding tools, foundation-model platforms, and MCP surfaces." />
          <Capability title="Agent registry" copy="Promote, quarantine, revoke, and track agents as real governed entities — not loose prompts." />
          <Capability title="Fusion decision engine" copy="Combine identity, capability, behavior, content, policy, and criticality into one verdict." />
          <Capability title="Runtime enforcement" copy="Gate actions through SDKs, REST, gateways, webhooks, streaming checks, and async paths." />
          <Capability title="Evidence bundles" copy="Export the decision trail with chain hash, policy version, and verification status." />
          <Capability title="Calibration loop" copy="Learn from outcomes while keeping policy authority locked, versioned, and replayable." />
        </div>
      </section>

      <section id="trial" className="section trial-section">
        <div className="trial-card">
          <div>
            <div className="kicker"><span /> 2-week live control trial</div>
            <h2>See what Tex would find, stop, hold, and prove in your environment.</h2>
            <p>Run Tex in observe mode first, then move selected paths into gate mode. In two weeks, you should know your agent surface, your riskiest action paths, your policy gaps, and what proof Tex can generate.</p>
          </div>
          <div className="trial-plan">
            <div><span>Week 1</span><b>Map the agent surface</b><em>Discover agents, owners, tools, permissions, and high-risk paths.</em></div>
            <div><span>Week 2</span><b>Run the control loop</b><em>Classify actions, test verdicts, export evidence, and choose live gates.</em></div>
            <a className="btn primary trial-btn" href="mailto:founder@vortexblack.ai?subject=Tex%202-week%20live%20control%20trial">Activate the trial</a>
          </div>
        </div>
      </section>

      <footer className="footer">
        <div className="brand"><span className="brand-glyph">T</span><span>Tex</span></div>
        <p>First 360° seven-layer control loop for AI agents.</p>
      </footer>
    </main>
  );
}

function Capability({ title, copy }) {
  return <article className="capability"><h3>{title}</h3><p>{copy}</p></article>;
}
