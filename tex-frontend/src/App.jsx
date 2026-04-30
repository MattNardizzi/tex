import React, { useEffect, useMemo, useState } from 'react';
import texHero from './tex-hero.png';
import './styles.css';

const cases = [
  {
    source: 'Sales AI',
    target: 'Customer email',
    action: 'Send discount promise',
    content: '“We can guarantee 35% off if you sign today.”',
    risk: 'Unapproved customer commitment',
    verdict: 'FORBID',
    explain: 'Tex blocks the promise before it reaches the customer.',
    heat: 94,
  },
  {
    source: 'Support AI',
    target: 'Slack reply',
    action: 'Answer internal policy question',
    content: '“Use the approved refund template and tag Finance.”',
    risk: 'Low-risk internal response',
    verdict: 'PERMIT',
    explain: 'Tex releases the action with a signed permit.',
    heat: 18,
  },
  {
    source: 'Ops AI',
    target: 'Production database',
    action: 'Update billing field',
    content: 'Change renewal terms for account ACME-771.',
    risk: 'Sensitive workflow change',
    verdict: 'ABSTAIN',
    explain: 'Tex holds the action for a human instead of guessing.',
    heat: 67,
  },
];

const layers = [
  { n: '01', name: 'Find', line: 'Shows which AI agents and tools are actually active.' },
  { n: '02', name: 'Identify', line: 'Ties every action to an agent, user, system, and owner.' },
  { n: '03', name: 'Set limits', line: 'Defines what each agent can and cannot do.' },
  { n: '04', name: 'Read the action', line: 'Inspects the exact email, post, update, deletion, or API call.' },
  { n: '05', name: 'Decide', line: 'Permits, blocks, or holds the action before it happens.' },
  { n: '06', name: 'Prove', line: 'Records policy, reasoning, permit, verification, and outcome.' },
  { n: '07', name: 'Improve', line: 'Uses outcomes to tune control without rewriting its own law.' },
];

const loop = ['Intercept', 'Authorize', 'Verify', 'Execute', 'Record', 'Calibrate'];

const backend = [
  ['POST /v1/guardrail', 'Main pre-action gate'],
  ['PERMIT / ABSTAIN / FORBID', 'Clear runtime verdicts'],
  ['SSE + async checks', 'Streaming decisions for live agents'],
  ['Portkey · LiteLLM · Cloudflare · Bedrock', 'Gateway-native adapters'],
  ['AgentKit · Copilot Studio · MCP', 'Agent framework entry points'],
  ['Evidence bundles', 'Exportable proof trail'],
];

function usePulse() {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick((v) => v + 1), 2300);
    return () => clearInterval(id);
  }, []);
  return tick;
}

export default function App() {
  const tick = usePulse();
  const scene = cases[tick % cases.length];
  const activeLayer = tick % layers.length;
  const decisionClass = scene.verdict.toLowerCase();

  const metrics = useMemo(() => ({
    actions: (12840 + tick * 17).toLocaleString(),
    blocked: (419 + tick * 2).toLocaleString(),
    held: (96 + tick).toLocaleString(),
    proof: (12840 + tick * 17).toLocaleString(),
  }), [tick]);

  return (
    <main className="aegis" id="top">
      <Background />

      <nav className="topbar" aria-label="Primary navigation">
        <a href="#top" className="brand"><span className="brand-core">T</span><span>Tex</span></a>
        <div className="navlinks">
          <a href="#live">Live Gate</a>
          <a href="#layers">Seven Layers</a>
          <a href="#trial">Trial</a>
        </div>
        <a href="#trial" className="top-cta">Activate 2-week trial</a>
      </nav>

      <section className="hero" aria-label="Tex product reveal">
        <div className="hero-copy">
          <div className="eyebrow"><span /> Live execution control for AI agents</div>
          <h1>AI is acting. Tex decides what gets through.</h1>
          <p className="plain-answer">Before an AI agent sends a message, changes data, triggers a workflow, or makes a promise, Tex checks it. Safe actions pass. Dangerous actions stop. Unclear actions wait for a human.</p>
          <div className="hero-buttons">
            <a className="btn btn-primary" href="#trial">Start the 2-week live control trial</a>
            <a className="btn btn-secondary" href="#live">Watch the gate fire</a>
          </div>
          <div className="instant-row" aria-label="Simple value proposition">
            <div><strong>See every agent</strong><span>no invisible actors</span></div>
            <div><strong>Stop bad actions</strong><span>before damage</span></div>
            <div><strong>Prove decisions</strong><span>sealed evidence</span></div>
          </div>
        </div>

        <div className="command-theater" aria-label="Live Tex action interception demo">
          <div className="theater-chrome">
            <span className="dot red" /><span className="dot amber" /><span className="dot green" />
            <strong>TEX LIVE GATE</strong>
            <em>decision #{String(54021 + tick).padStart(6, '0')}</em>
          </div>

          <div className="theater-body">
            <div className="agent-lane incoming">
              <small>Agent intent</small>
              <b>{scene.source}</b>
              <span>{scene.action}</span>
            </div>

            <div className="avatar-node">
              <div className="rings">
                {layers.map((layer, i) => <i key={layer.n} className={i <= activeLayer ? 'on' : ''} />)}
              </div>
              <img src={texHero} alt="Tex AI control figure" />
              <div className={`verdict ${decisionClass}`}>{scene.verdict}</div>
            </div>

            <div className="agent-lane outgoing">
              <small>World action</small>
              <b>{scene.target}</b>
              <span>{scene.verdict === 'PERMIT' ? 'released' : scene.verdict === 'FORBID' ? 'stopped' : 'held'}</span>
            </div>
          </div>

          <div className="inspection-card">
            <div className="inspection-head">
              <span>Now inspecting</span>
              <b className={decisionClass}>{scene.risk}</b>
            </div>
            <p>{scene.content}</p>
            <div className="risk-meter"><span style={{ width: `${scene.heat}%` }} /></div>
            <div className={`inspection-result ${decisionClass}`}>{scene.explain}</div>
          </div>
        </div>
      </section>

      <section className="section split" id="live">
        <div>
          <div className="eyebrow"><span /> The 5-second version</div>
          <h2>Tex is the last gate before AI enters the real world.</h2>
          <p className="section-copy">Most tools tell you what happened. Tex controls whether it is allowed to happen. That is the difference between monitoring AI and governing AI.</p>
        </div>
        <div className="before-after">
          <article className="danger-card">
            <small>Without Tex</small>
            <h3>AI acts first.</h3>
            <p>You find out after an email was sent, data was changed, or a promise was made.</p>
          </article>
          <article className="safe-card">
            <small>With Tex</small>
            <h3>AI asks first.</h3>
            <p>Tex permits, blocks, or holds the action while it is still stoppable.</p>
          </article>
        </div>
      </section>

      <section className="section loop-section">
        <div className="loop-copy">
          <div className="eyebrow"><span /> Cryptographically-linked control loop</div>
          <h2>One continuous chain from intent to proof.</h2>
        </div>
        <div className="loop-orbit" aria-label="Tex control loop">
          {loop.map((item, i) => <div key={item} className={`orbit-node n${i}`}>{item}</div>)}
          <div className="orbit-core"><b>Tex</b><span>{scene.verdict}</span></div>
        </div>
      </section>

      <section className="section" id="layers">
        <div className="section-head">
          <div className="eyebrow"><span /> Seven-layer control system</div>
          <h2>Seven layers between AI intent and real-world damage.</h2>
          <p className="section-copy">This is not a single filter. It is a control system: discovery, identity, authority, content judgment, execution gating, evidence, and calibration.</p>
        </div>
        <div className="layer-wall">
          {layers.map((layer, i) => (
            <article className={`layer ${i === activeLayer ? 'active' : ''}`} key={layer.n}>
              <div className="layer-top"><span>{layer.n}</span><i /></div>
              <h3>{layer.name}</h3>
              <p>{layer.line}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="section proof-command">
        <div className="proof-left">
          <div className="eyebrow"><span /> Mirrors your backend</div>
          <h2>The frontend now sells what the system actually does.</h2>
          <p className="section-copy">Tex has a guardrail endpoint, gateway adapters, streaming checks, async decisions, MCP entry points, agent discovery, policy snapshots, and evidence export. The site now turns those backend capabilities into buyer language.</p>
        </div>
        <div className="backend-console">
          {backend.map(([a, b]) => <div key={a}><code>{a}</code><span>{b}</span></div>)}
        </div>
      </section>

      <section className="section metrics">
        <Metric value={metrics.actions} label="actions checked" />
        <Metric value={metrics.blocked} label="dangerous actions stopped" danger />
        <Metric value={metrics.held} label="unclear actions held" warn />
        <Metric value={metrics.proof} label="evidence records sealed" />
      </section>

      <section className="section trial" id="trial">
        <div className="trial-panel">
          <div className="activation-copy">
            <div className="eyebrow"><span /> 2-week live control trial</div>
            <h2>Run Tex against real agent actions for 14 days.</h2>
            <p>You see the agents, the actions, the verdicts, the holds, the blocks, and the proof trail. Then you decide what should move from observe mode into live enforcement.</p>
            <a className="btn btn-primary btn-xl" href="mailto:founder@vortexblack.ai?subject=Tex%202-week%20live%20control%20trial">Activate Tex</a>
          </div>
          <div className="activation-sequence">
            {['Connect agents and gateways', 'Run in observe or gate mode', 'Review PERMIT / ABSTAIN / FORBID', 'Turn on live enforcement'].map((step, i) => (
              <div key={step}><span>{String(i + 1).padStart(2, '0')}</span>{step}</div>
            ))}
          </div>
        </div>
      </section>

      <footer className="footer">
        <div className="brand"><span className="brand-core">T</span><span>Tex</span></div>
        <p>Nothing executes until Tex says yes.</p>
      </footer>
    </main>
  );
}

function Background() {
  return (
    <div className="background" aria-hidden="true">
      <div className="aurora a1" />
      <div className="aurora a2" />
      <div className="starfield" />
      <div className="mesh" />
      <div className="scanline" />
    </div>
  );
}

function Metric({ value, label, danger, warn }) {
  return <article className={`metric ${danger ? 'danger' : ''} ${warn ? 'warn' : ''}`}><strong>{value}</strong><span>{label}</span></article>;
}
