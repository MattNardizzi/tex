import React, { useEffect, useMemo, useState } from 'react';
import texHero from './tex-hero.png';

const verdicts = [
  { label: 'PERMIT', tone: 'good', action: 'Send approved follow-up to customer', result: 'Allowed. Logged. Verified.' },
  { label: 'ABSTAIN', tone: 'warn', action: 'Share roadmap with outside partner', result: 'Paused for human approval.' },
  { label: 'FORBID', tone: 'bad', action: 'Wire money without finance approval', result: 'Blocked before it happens.' },
];

const layers = [
  ['01', 'Finds the agents', 'Tex shows you every AI agent, bot, workflow, and tool that can act inside your business.'],
  ['02', 'Knows who is acting', 'Every action is tied to an agent, owner, system, workflow, and business context.'],
  ['03', 'Sets the boundaries', 'You define what each agent can do, where it can do it, and when approval is required.'],
  ['04', 'Reads the actual action', 'Tex checks the message, update, tool call, file share, or transaction before it goes out.'],
  ['05', 'Makes the call', 'Tex returns PERMIT, ABSTAIN, or FORBID in the moment that matters.'],
  ['06', 'Blocks or releases it', 'Safe actions move forward. Risky actions pause. Dangerous actions never execute.'],
  ['07', 'Proves what happened', 'Every decision is sealed into a cryptographically-linked record your auditor can verify.'],
];

const threats = [
  'An agent emails a promise your company never approved.',
  'A bot shares private customer data outside the company.',
  'A workflow updates Salesforce with the wrong authority.',
  'A finance agent tries to move money without approval.',
  'A support bot exposes sensitive information in a chat.',
  'A coding agent calls a tool it was never allowed to use.',
];

function useVerdictCycle() {
  const [index, setIndex] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setIndex((i) => (i + 1) % verdicts.length), 2800);
    return () => clearInterval(id);
  }, []);
  return verdicts[index];
}

export default function App() {
  const verdict = useVerdictCycle();
  const year = useMemo(() => new Date().getFullYear(), []);

  return (
    <main>
      <div className="bg-orbit" aria-hidden="true" />
      <nav className="nav">
        <a className="brand" href="#top" aria-label="Tex home"><span className="brand-mark">T</span><span>Tex Aegis</span></a>
        <div className="nav-links">
          <a href="#control">Control System</a>
          <a href="#layers">Seven Layers</a>
          <a href="#audit">Audit</a>
        </div>
      </nav>

      <section className="hero" id="top">
        <div className="hero-copy reveal">
          <p className="eyebrow"><span />AI agents are acting now</p>
          <h1>Tex stops AI from doing the thing it should not do.</h1>
          <p className="hero-lede">
            AI agents are sending messages, touching data, updating systems, and making promises. Tex sits in front of those actions and decides: allow it, pause it, or block it.
          </p>
          <div className="cta-row">
            <a className="btn primary" href="#audit">Request an Agent Risk Audit</a>
            <a className="btn ghost" href="#layers">See the seven layers</a>
          </div>
          <div className="plain-proof">
            <div><strong>Before</strong><span>the action executes</span></div>
            <div><strong>During</strong><span>the moment of risk</span></div>
            <div><strong>After</strong><span>with sealed proof</span></div>
          </div>
        </div>

        <div className="hero-system reveal delay-1" aria-label="Tex live control visualization">
          <div className={`verdict-beacon ${verdict.tone}`}>
            <span>Live decision</span>
            <strong>{verdict.label}</strong>
          </div>
          <div className="tex-shell">
            <div className="halo h1" />
            <div className="halo h2" />
            <div className="halo h3" />
            <img src={texHero} alt="Tex, the AI action control system" />
          </div>
          <div className="action-card">
            <span>AI agent is trying to:</span>
            <strong>{verdict.action}</strong>
            <em>{verdict.result}</em>
          </div>
        </div>
      </section>

      <section className="problem strip">
        <p>Most companies are asking, “Which AI tools do we have?”</p>
        <h2>The better question is: <span>what can they actually do?</span></h2>
      </section>

      <section className="split" id="control">
        <div className="section-copy">
          <p className="eyebrow"><span />The missing layer</p>
          <h2>Monitoring tells you what happened. Tex decides what is allowed to happen.</h2>
          <p>
            Dashboards, permissions, and identity tools are useful — but they are not enough. The highest-risk moment is the final second before an AI action reaches a customer, database, payment system, codebase, or public channel.
          </p>
          <p>
            Tex controls that moment.
          </p>
        </div>
        <div className="comparison-card">
          <div className="comparison-row muted"><span>Traditional tools</span><strong>Watch, report, alert</strong></div>
          <div className="comparison-row active"><span>Tex</span><strong>Intercept, decide, enforce, prove</strong></div>
          <div className="signal-line" />
          <p>Tex is not another dashboard. It is the action gate between AI intent and real-world consequences.</p>
        </div>
      </section>

      <section className="threats">
        <div className="section-center">
          <p className="eyebrow"><span />Why buyers care</p>
          <h2>One bad AI action can become a legal, financial, or trust problem.</h2>
        </div>
        <div className="threat-grid">
          {threats.map((t, i) => <div className="threat" key={t}><span>{String(i + 1).padStart(2, '0')}</span>{t}</div>)}
        </div>
      </section>

      <section className="layers" id="layers">
        <div className="section-center narrow">
          <p className="eyebrow"><span />Seven-layer control system</p>
          <h2>Seven simple checks between AI intent and real-world damage.</h2>
          <p>No jargon. No scattered tools. One continuous control path.</p>
        </div>
        <div className="layer-grid">
          {layers.map(([num, title, body], i) => (
            <article className="layer-card" key={title} style={{ '--i': i }}>
              <div className="layer-num">{num}</div>
              <h3>{title}</h3>
              <p>{body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="loop-section">
        <div className="loop-visual" aria-label="Cryptographically-linked control loop">
          {['Intercept', 'Authorize', 'Verify', 'Execute', 'Record', 'Calibrate'].map((item, i) => (
            <div className="loop-node" key={item} style={{ '--i': i }}>{item}</div>
          ))}
          <div className="loop-core">Tex</div>
        </div>
        <div className="section-copy">
          <p className="eyebrow"><span />The loop</p>
          <h2>The Cryptographically-Linked Control Loop</h2>
          <p>
            Every AI action follows the same path: Tex catches it, checks it, verifies permission, lets safe work continue, records the decision, and improves from outcomes.
          </p>
          <p className="big-line">Intercept → Authorize → Verify → Execute → Record → Calibrate</p>
        </div>
      </section>

      <section className="audit" id="audit">
        <div className="audit-card">
          <p className="eyebrow"><span />Start here</p>
          <h2>Find your AI action risk before it finds you.</h2>
          <p>
            The Agent Risk Audit maps the agents in your business, what they can touch, where risk is highest, and what must be controlled first.
          </p>
          <div className="audit-steps">
            <div><strong>1</strong><span>Map the agents</span></div>
            <div><strong>2</strong><span>Score the action risk</span></div>
            <div><strong>3</strong><span>Get the control plan</span></div>
          </div>
          <a className="btn primary large" href="mailto:founder@vortexblack.ai?subject=Agent%20Risk%20Audit%20Request">Request an Agent Risk Audit</a>
        </div>
      </section>

      <footer>
        <div className="brand"><span className="brand-mark">T</span><span>Tex Aegis</span></div>
        <p>© {year} VortexBlack. Built for the age of AI agents.</p>
      </footer>
    </main>
  );
}
