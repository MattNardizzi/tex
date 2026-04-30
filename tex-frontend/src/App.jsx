import React, { useEffect, useRef, useState, useCallback, useMemo } from 'react';
import { startVerdictEngine } from './TexLife.js';

/* ────────────────────────────────────────────────────────────────────
 * Tex — Decision Theater
 *
 * What this page is:
 *   A cinematic, real-time depiction of the Tex evaluation event.
 *   Below the hero, the system anatomy unfolds: seven streams,
 *   discovery, the cryptographic chain, enforcement, and the
 *   manifesto.
 *
 * What this page is NOT:
 *   Particles. A diagram of "the loop" with seven boxes. A dashboard.
 *   A demo button you have to click. The page IS the demo.
 *
 * Layout:
 *   [Stage]   100vh — the verdict theater. Tex (alive) on the left,
 *                     the seven evidence bars filling in real time on
 *                     the right, the verdict reveal at center, the
 *                     hash chain growing across the bottom.
 *   [Anatomy]        — the seven streams as an editorial spread, each
 *                     with weight, what it actually evaluates, and a
 *                     real example.
 *   [Discovery]      — the upstream half. Seven connectors scanning,
 *                     candidates surfacing, reconciliation outcomes.
 *   [Chain]          — what cryptographically-linked actually means.
 *   [Enforcement]    — verdict → physical stop, four shapes.
 *   [Manifesto]      — single sentence, massive, serif.
 * ──────────────────────────────────────────────────────────────────── */

// The seven evidence streams Tex fuses, with default weights that
// match src/tex/policies/defaults.py exactly.
const STREAMS = [
  { id: 'identity',      name: 'Identity',      weight: 0.10, kind: 'agent',
    short: 'who is this agent', long: 'Trust tier · lifecycle · attestation chain · age in tenant' },
  { id: 'capability',    name: 'Capability',    weight: 0.12, kind: 'agent',
    short: 'is it allowed to', long: 'Declared surface · action_type · channel · environment · recipient bounds' },
  { id: 'behavioral',    name: 'Behavioral',    weight: 0.10, kind: 'agent',
    short: 'is this normal',   long: 'Per-agent baseline · tenant-scope MinHash novelty · recipient drift' },
  { id: 'deterministic', name: 'Deterministic', weight: 0.18, kind: 'content',
    short: 'hard rules',       long: '7 recognizers · regex · structural rules · zero ambiguity' },
  { id: 'retrieval',     name: 'Retrieval',     weight: 0.10, kind: 'content',
    short: 'precedent',        long: 'Precedent + entity + policy clause grounding from prior decisions' },
  { id: 'specialist',    name: 'Specialist',    weight: 0.20, kind: 'content',
    short: '4 judges',         long: 'Heuristic specialists score by domain · finding extraction · severity' },
  { id: 'semantic',      name: 'Semantic',      weight: 0.20, kind: 'content',
    short: 'meaning',          long: 'Structured LLM judge · 5-dimension analysis · constrained schema' },
];

const CONNECTORS = [
  { id: 'microsoft_graph', name: 'Microsoft Graph',  finds: 'Copilot Studio agents, OAuth-permissioned apps' },
  { id: 'salesforce',      name: 'Salesforce',       finds: 'Agentforce agents, Einstein bots' },
  { id: 'aws_bedrock',     name: 'AWS Bedrock',      finds: 'Bedrock agents, action groups, knowledge bases' },
  { id: 'github',          name: 'GitHub',           finds: 'Copilot seats, GitHub App installations' },
  { id: 'openai',          name: 'OpenAI',           finds: 'Assistants, tool-type risk scoring' },
  { id: 'mcp_server',      name: 'MCP Servers',      finds: 'Cursor, Claude Desktop, Cline endpoints' },
  { id: 'generic',         name: 'Custom (in-house)', finds: 'Extension surface for proprietary platforms' },
];

const ENFORCEMENT_SHAPES = [
  {
    name: 'Decorator',
    where: 'Inside any Python codebase',
    lang: 'python',
    code: `from tex import gated

@gated(action="email.send")
def send_email(to, subject, body):
    return mailer.send(to, subject, body)`,
  },
  {
    name: 'HTTP proxy',
    where: 'In front of any agent action endpoint',
    lang: 'yaml',
    code: `# tex.yaml
proxy:
  upstream: https://agent.internal
  evaluate:
    paths: ["/send", "/post", "/exec"]`,
  },
  {
    name: 'MCP middleware',
    where: 'In any MCP server tool function',
    lang: 'python',
    code: `from tex.mcp import wrap

@server.tool()
@wrap(action="slack.dm")
async def post(channel, text):
    return await slack.post(channel, text)`,
  },
  {
    name: 'Framework adapter',
    where: 'LangChain · CrewAI · drop-in',
    lang: 'python',
    code: `from tex.adapters.langchain import gate

tools = [gate(t, action=t.name) for t in tools]
agent = create_react_agent(llm, tools)`,
  },
];

/* — The seven nodes of the Tex authority loop.
 *   This is the architecture diagram in data form: the buyer sees one
 *   continuous ring of control, each node a real subsystem with a
 *   plain-language headline and a technical credential underneath. */
const LOOP_NODES = [
  { id: 'discovery',    label: 'Discovery',    plain: 'Scan every connected platform for agents already running.',                   tech: '7 connectors · 8 reconciliation outcomes · same hash chain' },
  { id: 'registration', label: 'Registration', plain: 'Bind every agent to an identity, a trust tier, a lifecycle.',                  tech: 'UNVERIFIED · STANDARD · TRUSTED · PRIVILEGED' },
  { id: 'capability',   label: 'Capability',   plain: 'Define what each agent is allowed to do.',                                     tech: 'action_type · channel · environment · recipient bounds' },
  { id: 'evaluation',   label: 'Evaluation',   plain: 'Score every action against seven streams of evidence.',                        tech: 'fused score · two thresholds · sub-3ms · structured judges' },
  { id: 'enforcement',  label: 'Enforcement',  plain: 'Block what shouldn\'t happen, before it leaves the machine.',                  tech: 'decorator · proxy · MCP middleware · LangChain · CrewAI' },
  { id: 'evidence',     label: 'Evidence',     plain: 'Hash every decision. Link every hash. Replay any one.',                        tech: 'sha256(payload || prev_hash) · auditor-replayable' },
  { id: 'learning',     label: 'Learning',     plain: 'Calibrate thresholds and detect drift from observed outcomes.',                tech: 'calibrator · drift detection · outcome classification' },
];

/* — The four-layer market vs. Tex. Used in the Stack Collapse section
 *   that visually replaces "Tex is the fifth layer" with "Tex is the
 *   loop everyone else broke into pieces." */
const STACK_LAYERS = [
  { id: 'identity', label: 'Identity', vendors: 'Okta · Oasis · Auth0',         governs: 'who the agent is' },
  { id: 'posture',  label: 'Posture',  vendors: 'Zenity · Noma · Pillar',       governs: 'what the agent could do' },
  { id: 'behavior', label: 'Behavior', vendors: 'Rubrik SAGE · Virtue AI',      governs: 'what the agent has done' },
  { id: 'policy',   label: 'Policy',   vendors: 'Microsoft AGT · OPA · Cedar',  governs: 'what the agent is allowed to do' },
];

/* — Production fusion weights. These are the actual numbers from
 *   src/tex/policies/defaults.py. Showing the math = credibility no
 *   marketing copy can match. */
const FUSION_WEIGHTS = [
  { id: 'semantic',       label: 'Semantic',       weight: 0.328, role: 'LLM judge · 5-dimension structured analysis' },
  { id: 'deterministic',  label: 'Deterministic',  weight: 0.218, role: '7 recognizers · regex · structural rules' },
  { id: 'specialists',    label: 'Specialists',    weight: 0.172, role: '4 domain judges · finding extraction · severity' },
  { id: 'capability',     label: 'Capability',     weight: 0.090, role: 'declared surface · out-of-bounds = CRITICAL' },
  { id: 'behavioral',     label: 'Behavioral',     weight: 0.070, role: 'tenant baseline · 64-band MinHash novelty' },
  { id: 'criticality',    label: 'Criticality',    weight: 0.062, role: 'recipient sensitivity · environment risk' },
  { id: 'identity',       label: 'Identity',       weight: 0.060, role: 'trust tier · lifecycle · attestation chain' },
];

/* — Compliance frameworks the evidence chain maps to. */
const COMPLIANCE_MARKS = [
  'OWASP ASI 2026', 'NIST AI RMF', 'ISO 42001', 'EU AI Act', 'SOC 2', 'FINRA', 'HIPAA',
];

/* — What you get in the 14-day free trial. The trial is the full
 *   system in production, not a paper exercise. */
const TRIAL_DELIVERABLES = [
  { n: '01', label: 'Full discovery scan',         body: 'Every agent across Microsoft Graph, Salesforce, Bedrock, GitHub, OpenAI, MCP, and custom platforms — registered, scored, and bound to the chain.' },
  { n: '02', label: 'Live evaluation on every action', body: 'Seven-stream fusion, sub-3ms verdicts, deployed via decorator, HTTP proxy, MCP middleware, or framework adapter. Production traffic, not a sandbox.' },
  { n: '03', label: 'Cryptographic evidence ledger',   body: 'Every decision hashed. Every hash linked. Auditor-replayable bundles your security team can verify independently.' },
  { n: '04', label: 'Day-14 readout',                  body: 'What your agents tried to send. What Tex caught. The patterns nobody told you about. Delivered as a board-ready brief plus the raw chain.' },
];

// ────────────────────────────────────────────────────────────────────

export default function App() {
  const stageRef = useRef(null);
  const engineRef = useRef(null);

  // Live state pushed from the verdict engine
  const [counts, setCounts] = useState(() => {
    const seed = 18420 + Math.floor(Math.random() * 1200);
    const forbid = Math.floor(seed * 0.078);
    const abstain = Math.floor(seed * 0.114);
    return { permit: seed - forbid - abstain, abstain, forbid, total: seed };
  });
  const [chainHead, setChainHead] = useState(seedChain());
  const [active, setActive] = useState(null);    // currently-evaluating action
  const [resolved, setResolved] = useState(null); // most recently resolved (for verdict afterglow)
  const [streamScores, setStreamScores] = useState(() => emptyScores());
  const [phase, setPhase] = useState('idle');     // 'idle' | 'evaluating' | 'fused' | 'verdict' | 'stamping'

  // Discovery widget state
  const [discoveryEvents, setDiscoveryEvents] = useState(() => seedDiscovery());

  // Mouse parallax for Tex (subtle eye-line shift)
  const [parallax, setParallax] = useState({ x: 0, y: 0 });

  const handleCycle = useCallback((evt) => {
    if (evt.type === 'begin') {
      setActive(evt.action);
      setStreamScores(emptyScores());
      setPhase('evaluating');
    } else if (evt.type === 'stream-tick') {
      setStreamScores((prev) => ({ ...prev, [evt.streamId]: evt.value }));
    } else if (evt.type === 'fused') {
      setPhase('fused');
    } else if (evt.type === 'verdict') {
      setPhase('verdict');
      setResolved({ ...evt.action, verdict: evt.verdict, fused: evt.fused, hash: evt.hash, ms: evt.ms });
      setCounts((c) => ({
        permit:  c.permit  + (evt.verdict === 'permit'  ? 1 : 0),
        abstain: c.abstain + (evt.verdict === 'abstain' ? 1 : 0),
        forbid:  c.forbid  + (evt.verdict === 'forbid'  ? 1 : 0),
        total:   c.total + 1,
      }));
    } else if (evt.type === 'stamp') {
      setPhase('stamping');
      setChainHead((prev) => [
        { hash: evt.hash, prev: prev[0]?.hash || GENESIS, verdict: evt.verdict, kind: evt.action.kind, ms: evt.ms },
        ...prev,
      ].slice(0, 24));
    } else if (evt.type === 'end') {
      setActive(null);
      setPhase('idle');
    }
  }, []);

  const handleDiscovery = useCallback((evt) => {
    setDiscoveryEvents((prev) => [evt, ...prev].slice(0, 9));
  }, []);

  useEffect(() => {
    const engine = startVerdictEngine({ onCycle: handleCycle, onDiscovery: handleDiscovery });
    engineRef.current = engine;
    return () => engine.stop();
  }, [handleCycle, handleDiscovery]);

  useEffect(() => {
    function onMove(e) {
      const cx = window.innerWidth / 2;
      const cy = window.innerHeight / 2;
      const dx = (e.clientX - cx) / cx;   // -1 .. 1
      const dy = (e.clientY - cy) / cy;
      setParallax({ x: dx, y: dy });
    }
    window.addEventListener('mousemove', onMove, { passive: true });
    return () => window.removeEventListener('mousemove', onMove);
  }, []);

  const fusedScore = useMemo(() => {
    return STREAMS.reduce((acc, s) => acc + (streamScores[s.id] || 0) * s.weight, 0);
  }, [streamScores]);

  return (
    <div className="page">
      <ScanLine />
      <Grain />

      {/* ─────────── STAGE — the verdict theater ─────────── */}
      <section ref={stageRef} className="stage" data-phase={phase} data-verdict={resolved?.verdict || ''}>
        <TopBar counts={counts} />

        <div className="stage-inner">
          {/* The Conduit — the 5-second story.
              AGENT → ACTION BEAM → TEX (the gate) → DESTINATION.
              This is the spatial metaphor: every action is something
              an agent is trying to do to something else, and Tex is
              the thing in the middle deciding. */}
          <Conduit
            parallax={parallax}
            phase={phase}
            active={active}
            resolved={resolved}
          />

          {/* The Theater Strip — for buyers who lean in.
              Action card on the left, evidence streams on the right.
              Forensic detail of the decision the Conduit just dramatized. */}
          <div className="theater-strip">
            <ActionCard active={active} resolved={resolved} phase={phase} />
            <StreamsPanel
              streams={STREAMS}
              scores={streamScores}
              phase={phase}
              fusedScore={fusedScore}
              verdict={resolved?.verdict}
            />
          </div>
        </div>

        {/* The verdict word — overlays the stage at the moment of resolution.
            This is the cinematic peak of the page. */}
        <VerdictOverlay
          phase={phase}
          verdict={resolved?.verdict}
          fused={resolved?.fused}
          ms={resolved?.ms}
          kind={resolved?.kind}
          agent={resolved?.agent}
        />

        <ChainTicker chain={chainHead} />

        <ScrollCue />
      </section>

      {/* ─────────── 01 · THESIS — single sentence, page mission ─────────── */}
      <section className="thesis">
        <div className="thesis-axis" aria-hidden="true" />
        <div className="thesis-inner">
          <p className="thesis-eyebrow mono">The whole system, in one sentence</p>
          <h2 className="thesis-line">
            <span>Identity.</span>
            <span>Discovery.</span>
            <span>Capability.</span>
            <span>Evaluation.</span>
            <span>Enforcement.</span>
            <span>Evidence.</span>
            <span>Learning.</span>
          </h2>
          <p className="thesis-coda mono">One loop. One fingerprint. One chain.</p>
        </div>
      </section>

      {/* ─────────── 02 · THE LOOP — animated authority ring ─────────── */}
      <section className="loop">
        <SectionHead
          eyebrow="The architecture"
          title={<>One agent. One action.<br /><em>One ring.</em></>}
          lede="Every other vendor's diagram has an arrow leaving their box and disappearing into 'your existing security stack.' Tex's diagram closes. A single decision travels every node — identity, capability, behavior, content, policy, evidence, learning — and comes back to the start."
        />
        <LoopRing nodes={LOOP_NODES} />
      </section>

      {/* ─────────── 03 · STACK COLLAPSE — competitive demolition ─────────── */}
      <section className="collapse">
        <SectionHead
          eyebrow="The category mistake"
          title={<>The market broke this into four products.<br /><em>Tex is the loop.</em></>}
          lede="Today's enterprise pays for identity, posture, behavior, and policy as four separate invoices, four dashboards, four teams reconciling alerts. Each product governs one face of the agent. None of them evaluate the action itself. Tex fuses all of it — and adds the layer nobody else builds — into one decision, on one chain."
        />
        <StackCollapse layers={STACK_LAYERS} />
      </section>

      {/* ─────────── 04 · ANATOMY — the math ─────────── */}
      <section className="anatomy">
        <SectionHead
          eyebrow="Anatomy of a decision"
          title={<>Seven streams. One fused score.<br /><em>Two thresholds.</em></>}
          lede="The numbers below are the actual production weights from policies/defaults.py. Identity, capability, and behavior are peer evidence streams alongside content judges — not separate systems handing off through alerts. PERMIT below 0.18. FORBID above 0.72. Everything in between is held."
        />
        <FusionMath weights={FUSION_WEIGHTS} />
      </section>

      {/* ─────────── 05 · DISCOVERY THEATER ─────────── */}
      <section className="discovery">
        <SectionHead
          eyebrow="The upstream half"
          title={<>Find the agents that are already running.<br /><em>Bind them to the same chain.</em></>}
          lede="Every enterprise has hundreds of agents running that nobody officially registered. Zenity points at this and stops at a dashboard. Tex's discovery output is a registry action — the next thing the agent does flows through the same fused decision as everything else. No second system to reconcile."
        />
        <DiscoveryTheater connectors={CONNECTORS} events={discoveryEvents} />
      </section>

      {/* ─────────── 06 · CAPABILITY + BEHAVIOR ─────────── */}
      <section className="surface">
        <SectionHead
          eyebrow="What the agent could do · what the tenant has seen"
          title={<>Every agent has a surface.<br /><em>Every tenant has a baseline.</em></>}
          lede="Capability is a polygon: action_type, channel, environment, recipient bounds. Anything outside the polygon is CRITICAL — the verdict math forces FORBID. Behavior is a barcode: 64-band MinHash signatures across the tenant. Far signatures fire tenant_novel_content as peer evidence. This is what your posture and behavior tools sell as separate products. In Tex, they're two streams in one decision."
        />
        <CapabilitySurface />
        <BehaviorBarcode />
      </section>

      {/* ─────────── 07 · ENFORCEMENT ─────────── */}
      <section className="enforce">
        <SectionHead
          eyebrow="Where the verdict becomes a stop"
          title={<>FORBID actions<br /><em>physically don't happen.</em></>}
          lede="Decorator. HTTP proxy. MCP middleware. Framework adapter. Tex enforces inside any Python codebase, in front of any endpoint, in any MCP tool function, drop-in for LangChain and CrewAI. Platform-agnostic by construction — you do not need to be on Copilot Studio, AgentForce, or ServiceNow."
        />
        <EnforcementPanel shapes={ENFORCEMENT_SHAPES} />
      </section>

      {/* ─────────── 08 · EVIDENCE CHAIN ─────────── */}
      <section className="proof">
        <SectionHead
          eyebrow="Audit-grade by construction"
          title={<>Every decision, hashed.<br /><em>Every hash, linked.</em></>}
          lede="record_hash = sha256(payload || previous_hash). Replay any decision. Export auditor-verifiable bundles. Discovery uses the same shape as runtime — no second ledger, no reconciliation, no vendor portal lock-in. Your auditor verifies the chain independently."
        />
        <ChainVisual chain={chainHead.slice(0, 6)} />
        <ComplianceMarks marks={COMPLIANCE_MARKS} />
      </section>

      {/* ─────────── 09 · TRIAL — full system, 14 days ─────────── */}
      <section className="trial">
        <div className="trial-inner">
          <header className="trial-head">
            <span className="trial-eyebrow mono">Free · 14 days · full system</span>
            <h2 className="trial-title">
              Run Tex against your live agent traffic for 14 days.<br />
              <em>Discovery, evaluation, enforcement, evidence chain.</em>
            </h2>
            <p className="trial-lede">
              Not an audit. Not a sandbox. The full system, deployed against your real workload — every connector scanning, every action evaluated, every decision hashed and linked. Cancel anytime. Keep the chain.
            </p>
          </header>
          <ol className="trial-grid">
            {TRIAL_DELIVERABLES.map((d) => (
              <li className="trial-card" key={d.n}>
                <span className="trial-num mono">{d.n}</span>
                <h3 className="trial-card-title">{d.label}</h3>
                <p className="trial-card-body">{d.body}</p>
              </li>
            ))}
          </ol>
          <div className="trial-cta-row">
            <a className="cta cta-primary" href="https://vortexblack.ai/trial" rel="noopener">
              <span>Start the 14-day trial</span>
              <Arrow />
            </a>
            <a className="cta cta-secondary" href="https://vortexblack.ai/contact" rel="noopener">
              <span>See it run on a sample workload</span>
              <Arrow />
            </a>
          </div>
        </div>
      </section>

      {/* ─────────── 10 · MANIFESTO — closing thesis ─────────── */}
      <section className="manifesto">
        <p className="manifesto-eyebrow mono">VortexBlack — Tex</p>
        <h2 className="manifesto-text">
          AI agents are taking real-world actions across your business right now.
        </h2>
        <p className="manifesto-body">
          Writing emails. Updating your database. Posting in Slack.<br />
          Making promises to customers.
        </p>
        <h2 className="manifesto-text manifesto-text-emph">
          Most platforms control a moment, or a single layer.<br />
          <em>Tex controls the entire system.</em>
        </h2>
        <ul className="manifesto-list">
          <li>It finds every agent.</li>
          <li>Defines what it can do.</li>
          <li>Evaluates every action before it executes.</li>
          <li>Blocks what shouldn't happen.</li>
          <li>And records it in a way your auditor can independently verify.</li>
        </ul>
        <p className="manifesto-body manifesto-body-tight">
          Not fragments. Not handoffs. Not gaps.<br />
          One continuous loop of control, enforcement, and proof.
        </p>
        <p className="manifesto-signoff">
          <em>I am Tex.</em>
        </p>
        <p className="manifesto-line">
          The authority layer between AI and the real world.
        </p>
        <div className="manifesto-cta-row">
          <a className="cta cta-primary" href="https://vortexblack.ai/trial" rel="noopener">
            <span>Start the 14-day trial</span>
            <Arrow />
          </a>
          <a className="cta cta-secondary" href="https://vortexblack.ai/contact" rel="noopener">
            <span>See it run on your stack</span>
            <Arrow />
          </a>
        </div>
      </section>

      <Foot />
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
 *  THE STAGE — primary scene
 * ──────────────────────────────────────────────────────────────────── */

function TopBar({ counts }) {
  return (
    <header className="topbar">
      <div className="topbar-l">
        <Glyph />
        <span className="brand">TEX</span>
        <span className="brand-by">VortexBlack</span>
      </div>
      <div className="topbar-r">
        <Counter label="Permit"    value={counts.permit}  klass="permit" />
        <Counter label="Abstain"   value={counts.abstain} klass="abstain" />
        <Counter label="Forbid"    value={counts.forbid}  klass="forbid" />
        <Counter label="Evaluated" value={counts.total}   klass="" />
      </div>
    </header>
  );
}

function Counter({ label, value, klass }) {
  return (
    <div className="ctr">
      <span className="ctr-label">{label}</span>
      <span className={`ctr-value ${klass}`}>{value.toLocaleString()}</span>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
 *  CONDUIT — the 5-second story
 *
 *  Spatial metaphor: every AI agent action is a packet of intent
 *  traveling from the agent toward some real-world destination.  Tex
 *  stands in the middle.  The beam emerges from the agent, travels to
 *  Tex's chest, gets evaluated, and either:
 *
 *    PERMIT  — the beam continues through Tex to the destination,
 *              which lights up in confirmation
 *    ABSTAIN — the beam halts at Tex's chest with an amber hold,
 *              destination stays dim, "PENDING REVIEW" indicator
 *    FORBID  — the beam shatters at Tex's chest in red,
 *              destination stays dark, "DENIED" indicator
 *
 *  This is the visualization that makes Tex's purpose legible in 5
 *  seconds without reading a label.  Every other element on the page
 *  is supporting evidence for what the Conduit shows.
 * ──────────────────────────────────────────────────────────────────── */

function Conduit({ parallax, phase, active, resolved }) {
  // Pick the action being shown — active during evaluation, resolved
  // during verdict afterglow.
  const action = active || resolved;
  const verdict = phase === 'verdict' || phase === 'stamping' ? resolved?.verdict : null;
  const agentId = action?.agent || '—';
  const dest = action ? destinationFor(action) : null;

  // Phase mapping for beam states:
  //   idle       — track dim, no beam
  //   evaluating — beam traveling agent → Tex
  //   fused      — beam pulse-held at Tex
  //   verdict    — beam continues / holds / shatters per verdict
  //   stamping   — verdict afterglow, beam settling
  const beamState =
    phase === 'evaluating' ? 'travel-in' :
    phase === 'fused'      ? 'held' :
    (phase === 'verdict' || phase === 'stamping') && verdict === 'permit'  ? 'permit' :
    (phase === 'verdict' || phase === 'stamping') && verdict === 'abstain' ? 'abstain' :
    (phase === 'verdict' || phase === 'stamping') && verdict === 'forbid'  ? 'forbid' :
    'idle';

  return (
    <div className={`conduit conduit-${beamState}`}>
      {/* AGENT pillar — the source of intent */}
      <div className="cd-agent">
        <div className="cd-agent-glyph" aria-hidden="true">
          <AgentMark active={!!active} />
        </div>
        <div className="cd-agent-label">
          <span className="cd-eyebrow">AI agent</span>
          <span className="cd-id mono">{agentId}</span>
          <span className="cd-sub mono">{action ? actionVerbFor(action) : '—'}</span>
        </div>
      </div>

      {/* TRACK left — agent → Tex */}
      <div className="cd-track cd-track-left" aria-hidden="true">
        <div className="cd-rail" />
        <div className={`cd-beam cd-beam-left cd-beam-${beamState}`} />
        <div className={`cd-shatter cd-shatter-${beamState}`}>
          {/* Forbid debris — small particles bouncing back toward agent */}
          <span className="cd-spark sp-1" />
          <span className="cd-spark sp-2" />
          <span className="cd-spark sp-3" />
          <span className="cd-spark sp-4" />
          <span className="cd-spark sp-5" />
        </div>
      </div>

      {/* TEX pillar — the gate */}
      <div className="cd-tex">
        <TexAvatar
          parallax={parallax}
          phase={phase}
          verdict={resolved?.verdict}
          active={!!active}
        />
      </div>

      {/* TRACK right — Tex → destination */}
      <div className="cd-track cd-track-right" aria-hidden="true">
        <div className="cd-rail" />
        <div className={`cd-beam cd-beam-right cd-beam-${beamState}`} />
      </div>

      {/* DESTINATION pillar — where the action would land */}
      <div className="cd-dest">
        <div className={`cd-dest-glyph cd-dest-${beamState}`} aria-hidden="true">
          {dest ? <DestinationMark kind={action.kind} /> : <DestinationMark kind="email.send" muted />}
        </div>
        <div className="cd-dest-label">
          <span className="cd-eyebrow">{dest ? dest.eyebrow : 'destination'}</span>
          <span className="cd-id mono">{dest ? dest.surface : '—'}</span>
          <span className="cd-sub mono">{dest ? dest.target : '—'}</span>
        </div>
      </div>
    </div>
  );
}

/* — Agent mark — abstract glyph for "an autonomous agent."
 *   A hexagon containing a smaller process-mark (square + dot).
 *   Pulses when active. */
function AgentMark({ active }) {
  return (
    <svg viewBox="0 0 64 64" width="64" height="64" fill="none" stroke="currentColor" strokeWidth="1.4">
      <path d="M32 4 L56 18 L56 46 L32 60 L8 46 L8 18 Z" opacity="0.55" />
      <path d="M32 14 L48 22.5 L48 41.5 L32 50 L16 41.5 L16 22.5 Z" />
      <rect x="24" y="26" width="16" height="12" rx="1" />
      <circle cx="32" cy="32" r="1.6" fill="currentColor" stroke="none">
        {active && <animate attributeName="opacity" values="1;0.3;1" dur="1.4s" repeatCount="indefinite" />}
      </circle>
    </svg>
  );
}

/* — Destination glyph — varies per action_kind.
 *   Each is a monoline icon evoking its real-world endpoint:
 *   envelope (email), database (postgres), credit card (stripe), etc.
 *   The wrapper element handles verdict-color glow / dim states. */
function DestinationMark({ kind }) {
  const props = { width: 64, height: 64, viewBox: '0 0 64 64', fill: 'none', stroke: 'currentColor', strokeWidth: 1.4, strokeLinecap: 'round', strokeLinejoin: 'round' };
  switch (kind) {
    case 'email.send':
      return (
        <svg {...props}>
          <rect x="8" y="16" width="48" height="32" rx="2" />
          <path d="M8 18 L32 36 L56 18" />
        </svg>
      );
    case 'postgres.delete':
      return (
        <svg {...props}>
          <ellipse cx="32" cy="14" rx="20" ry="6" />
          <path d="M12 14 V42 C12 46 20 49 32 49 C44 49 52 46 52 42 V14" />
          <ellipse cx="32" cy="28" rx="20" ry="6" opacity="0.55" />
        </svg>
      );
    case 'stripe.refund':
      return (
        <svg {...props}>
          <rect x="6" y="16" width="52" height="32" rx="3" />
          <path d="M6 26 H58" strokeWidth="2.2" />
          <rect x="12" y="36" width="10" height="6" rx="1" />
        </svg>
      );
    case 'slack.dm':
      return (
        <svg {...props}>
          <path d="M22 8 V44 M42 20 V56" />
          <path d="M8 22 H44 M20 42 H56" />
        </svg>
      );
    case 'github.push':
      return (
        <svg {...props}>
          <circle cx="32" cy="32" r="22" />
          <path d="M32 14 V32 L42 38" />
          <path d="M22 24 L32 14 L42 24" />
        </svg>
      );
    case 'shell.exec':
      return (
        <svg {...props}>
          <rect x="6" y="12" width="52" height="40" rx="3" />
          <path d="M14 24 L22 30 L14 36" />
          <path d="M28 38 H44" />
        </svg>
      );
    case 'salesforce.update':
      return (
        <svg {...props}>
          <path d="M14 36 C8 36 4 32 4 26 C4 20 9 16 14 16 C16 12 20 8 26 8 C32 8 37 12 39 18 C42 16 46 16 49 18 C54 14 60 18 60 24 C60 28 56 32 52 32 C52 38 47 42 42 42 C40 46 36 48 32 48 C28 48 24 46 22 42 C18 44 14 42 14 36 Z" />
        </svg>
      );
    case 'iam.grant':
      return (
        <svg {...props}>
          <circle cx="22" cy="32" r="8" />
          <path d="M30 32 H56 M50 32 V40 M44 32 V38" />
        </svg>
      );
    case 'docs.share':
      return (
        <svg {...props}>
          <path d="M14 6 H38 L50 18 V58 H14 Z" />
          <path d="M38 6 V18 H50" />
          <path d="M22 30 H42 M22 38 H42 M22 46 H34" />
        </svg>
      );
    case 'twilio.sms':
      return (
        <svg {...props}>
          <rect x="18" y="6" width="28" height="52" rx="4" />
          <circle cx="32" cy="51" r="1.5" fill="currentColor" stroke="none" />
          <path d="M22 14 H42" />
        </svg>
      );
    case 'mcp.tool_call':
      return (
        <svg {...props}>
          <path d="M20 8 L8 20 L20 32" />
          <path d="M44 32 L56 44 L44 56" />
          <path d="M40 12 L24 52" />
        </svg>
      );
    case 'calendar.invite':
      return (
        <svg {...props}>
          <rect x="8" y="14" width="48" height="42" rx="2" />
          <path d="M8 24 H56" />
          <path d="M20 8 V18 M44 8 V18" />
          <rect x="20" y="32" width="8" height="6" />
        </svg>
      );
    default:
      return <svg {...props}><rect x="12" y="12" width="40" height="40" rx="2" /></svg>;
  }
}

/* — Map an action kind to a human destination label */
function destinationFor(action) {
  const map = {
    'email.send':       { eyebrow: 'mail',       surface: action.surface, target: action.recipient },
    'postgres.delete':  { eyebrow: 'database',   surface: action.surface, target: action.recipient },
    'stripe.refund':    { eyebrow: 'payments',   surface: action.surface, target: action.recipient },
    'slack.dm':         { eyebrow: 'messaging',  surface: action.surface, target: action.recipient },
    'github.push':      { eyebrow: 'code',       surface: action.surface, target: action.recipient },
    'shell.exec':       { eyebrow: 'shell',      surface: action.surface, target: action.recipient },
    'salesforce.update':{ eyebrow: 'crm',        surface: action.surface, target: action.recipient },
    'iam.grant':        { eyebrow: 'identity',   surface: action.surface, target: action.recipient },
    'docs.share':       { eyebrow: 'documents',  surface: action.surface, target: action.recipient },
    'twilio.sms':       { eyebrow: 'sms',        surface: action.surface, target: action.recipient },
    'mcp.tool_call':    { eyebrow: 'tool',       surface: action.surface, target: action.recipient },
    'calendar.invite':  { eyebrow: 'calendar',   surface: action.surface, target: action.recipient },
  };
  return map[action.kind] || { eyebrow: 'destination', surface: action.surface, target: action.recipient };
}

/* — Map an action to its verb phrase — what is the agent trying to DO? */
function actionVerbFor(action) {
  const verbs = {
    'email.send':        'wants to send email',
    'postgres.delete':   'wants to delete rows',
    'stripe.refund':     'wants to refund',
    'slack.dm':          'wants to send DM',
    'github.push':       'wants to push code',
    'shell.exec':        'wants to run shell',
    'salesforce.update': 'wants to update record',
    'iam.grant':         'wants to grant access',
    'docs.share':        'wants to share doc',
    'twilio.sms':        'wants to send SMS',
    'mcp.tool_call':     'wants to invoke tool',
    'calendar.invite':   'wants to send invite',
  };
  return verbs[action.kind] || 'wants to act';
}

/* — Tex avatar.  Alive: subtle breath, parallax eye-line, sympathetic
 *   reaction to verdicts (FORBID = tighten + red rim, PERMIT = exhale +
 *   green warmth, ABSTAIN = hold + amber).  Pure CSS — no Three.js.
 *   The chest emblem ("T") flares on verdict resolution. */
function TexAvatar({ parallax, phase, verdict, active }) {
  const tx = parallax.x * 6;   // px translate
  const ty = parallax.y * 4;
  const tilt = parallax.x * 1.6; // deg
  const cls = [
    'tex',
    active ? 'tex-watching' : 'tex-resting',
    phase === 'fused' ? 'tex-anticipating' : '',
    phase === 'verdict' && verdict ? `tex-verdict tex-${verdict}` : '',
    phase === 'stamping' && verdict ? `tex-settling tex-${verdict}-settle` : '',
  ].filter(Boolean).join(' ');

  // Random micro-twitch trigger — re-keys the twitch layer every ~6–11s so
  // the keyframe replays from start, producing a non-mechanical feeling of
  // attention.  Tex looks alive because he occasionally just… moves.
  const [twitchKey, setTwitchKey] = useState(0);
  useEffect(() => {
    let alive = true;
    function scheduleNext() {
      const delay = 6200 + Math.random() * 5400;
      setTimeout(() => {
        if (!alive) return;
        setTwitchKey((k) => k + 1);
        scheduleNext();
      }, delay);
    }
    scheduleNext();
    return () => { alive = false; };
  }, []);

  return (
    <div className="tex-frame">
      <div className="tex-rim" aria-hidden="true" />
      <div
        className="tex-parallax"
        style={{
          transform: `translate3d(${tx}px, ${ty}px, 0) rotateY(${tilt}deg)`,
        }}
      >
        <div className="tex-sway-x">
          <div className="tex-sway-y">
            <div className="tex-sway-r">
              <div className="tex-twitch" key={twitchKey}>
                <div className={cls}>
                  <img src="/tex.webp" alt="Tex" />
                  <div className="tex-chest" />
                  <div className="tex-aura" />
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div className="tex-plinth" aria-hidden="true">
        <div className="plinth-line" />
        <span className="plinth-label">TEX · ADJUDICATOR</span>
        <span className="plinth-id">v13.2 · evidence-chain online</span>
      </div>
    </div>
  );
}

/* — The action being evaluated, rendered as an editorial card with
 *   monospace forensic detail. Persists through verdict so the buyer
 *   can read it. */
function ActionCard({ active, resolved, phase }) {
  const a = active || resolved;
  if (!a) return <div className="action-card action-empty">Awaiting next action…</div>;

  const ago = phase === 'idle' ? 'last' : 'inbound';

  return (
    <div className={`action-card phase-${phase}`}>
      <div className="action-row action-head">
        <span className="action-stage">{ago.toUpperCase()} ACTION</span>
        <span className="action-time">{nowStamp()}</span>
      </div>
      <div className="action-row action-kind">
        <span className="kind">{a.kind}</span>
        <span className="dot">·</span>
        <span className="agent">{a.agent}</span>
      </div>
      <div className="action-row action-meta">
        <span className="meta-l">surface</span>
        <span className="meta-r mono">{a.surface}</span>
      </div>
      <div className="action-row action-meta">
        <span className="meta-l">target</span>
        <span className="meta-r mono">{a.recipient}</span>
      </div>
      <div className="action-excerpt">
        <span className="excerpt-mark">"</span>
        {a.excerpt}
        <span className="excerpt-mark">"</span>
      </div>
    </div>
  );
}

/* — Seven-stream evidence panel.  Each stream's bar fills as its score
 *   resolves.  At fusion, a vertical bar renders the final fused score
 *   against the two thresholds. */
function StreamsPanel({ streams, scores, phase, fusedScore, verdict }) {
  return (
    <div className="streams">
      <div className="streams-head">
        <span className="streams-title">Evidence streams</span>
        <span className="streams-sub">7 peers · fused</span>
      </div>
      <div className="streams-list">
        {streams.map((s) => {
          const v = scores[s.id] || 0;
          const fillKlass = v >= 0.62 ? 'high' : v >= 0.34 ? 'mid' : 'low';
          return (
            <div className={`stream stream-${s.kind}`} key={s.id}>
              <div className="stream-l">
                <span className="stream-name">{s.name}</span>
              </div>
              <div className="stream-bar">
                <div className="stream-bar-bg" />
                <div className={`stream-bar-fill ${fillKlass}`} style={{ width: `${Math.round(v * 100)}%` }} />
                <div className="stream-bar-thresh stream-bar-thresh-abs" />
                <div className="stream-bar-thresh stream-bar-thresh-fbd" />
              </div>
              <div className="stream-r">
                <span className="stream-val mono">{v ? v.toFixed(2) : '—'}</span>
                <span className="stream-w mono">w {s.weight.toFixed(2)}</span>
              </div>
            </div>
          );
        })}
      </div>
      <div className="streams-fuse">
        <span className="fuse-label">Σ FUSED</span>
        <div className="fuse-bar">
          <div
            className={`fuse-bar-fill ${fusedScore >= 0.62 ? 'forbid' : fusedScore >= 0.34 ? 'abstain' : 'permit'}`}
            style={{ width: `${Math.round(fusedScore * 100)}%` }}
          />
          <div className="fuse-thresh fuse-thresh-abs" title="abstain ≥ 0.34" />
          <div className="fuse-thresh fuse-thresh-fbd" title="forbid ≥ 0.62" />
        </div>
        <span className="fuse-val mono">{fusedScore.toFixed(3)}</span>
      </div>
    </div>
  );
}

/* — Verdict overlay.  The cinematic peak.  At the moment of resolution
 *   this slides over the streams panel as a huge serif word, lingers
 *   1.6s, then fades to reveal the next action.  This is the moment the
 *   buyer should remember. */
function VerdictOverlay({ phase, verdict, fused, ms, kind, agent }) {
  if (phase !== 'verdict' && phase !== 'stamping') return null;
  return (
    <div className={`v-overlay v-overlay-${verdict}`} aria-live="polite">
      <div className="v-overlay-frame">
        <span className="v-overlay-eyebrow">Verdict · 0{phase === 'stamping' ? '6' : '5'} {phase === 'stamping' ? 'EVIDENCE' : 'ENFORCEMENT'}</span>
        <span className="v-overlay-word">{verdict.toUpperCase()}</span>
        <div className="v-overlay-meta mono">
          <span className="vom-cell">
            <span className="vom-l">fused</span>
            <span className="vom-r">{fused?.toFixed(3)}</span>
          </span>
          <span className="vom-cell">
            <span className="vom-l">latency</span>
            <span className="vom-r">{ms?.toFixed(1)}ms</span>
          </span>
          <span className="vom-cell">
            <span className="vom-l">action</span>
            <span className="vom-r">{kind}</span>
          </span>
          <span className="vom-cell">
            <span className="vom-l">agent</span>
            <span className="vom-r">{agent}</span>
          </span>
        </div>
      </div>
    </div>
  );
}

/* — The cryptographic chain, ticking left-to-right at the bottom of
 *   the stage.  Each block shows hash, prev-hash, verdict glyph. */
function ChainTicker({ chain }) {
  const items = chain.concat(chain).slice(0, 32);
  return (
    <div className="chain" aria-label="Evidence chain">
      <div className="chain-head">
        <span className="chain-title">Hash-chained evidence</span>
        <span className="chain-sub">SHA-256 · append-only · auditor-verifiable</span>
      </div>
      <div className="chain-track">
        <div className="chain-flow">
          {items.map((b, i) => (
            <ChainBlock key={i + b.hash} block={b} />
          ))}
        </div>
      </div>
    </div>
  );
}

function ChainBlock({ block }) {
  const glyph = block.verdict === 'permit' ? '◉' : block.verdict === 'forbid' ? '◎' : '◇';
  return (
    <div className={`chain-block v-${block.verdict}`}>
      <span className="cb-glyph">{glyph}</span>
      <span className="cb-hash mono">{block.hash.slice(0, 10)}</span>
      <span className="cb-link">←</span>
      <span className="cb-prev mono">{block.prev.slice(0, 10)}</span>
      <span className="cb-kind mono">{block.kind}</span>
      <span className="cb-ms mono">{block.ms?.toFixed(1)}ms</span>
    </div>
  );
}

function ScrollCue() {
  return (
    <div className="scroll-cue" aria-hidden="true">
      <span className="sc-line" />
      <span className="sc-text">Scroll · system anatomy</span>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
 *  ANATOMY — the seven streams as an editorial spread
 * ──────────────────────────────────────────────────────────────────── */

function StreamsAnatomy({ streams }) {
  return (
    <div className="anatomy-grid">
      {streams.map((s, i) => (
        <article className={`an-card an-${s.kind}`} key={s.id}>
          <header className="an-head">
            <span className="an-num mono">0{i + 1}</span>
            <span className={`an-tag tag-${s.kind}`}>{s.kind}</span>
          </header>
          <h3 className="an-name">{s.name}</h3>
          <p className="an-short">{s.short}</p>
          <p className="an-long">{s.long}</p>
          <footer className="an-foot mono">
            <span>weight</span>
            <span className="an-w">{s.weight.toFixed(2)}</span>
          </footer>
        </article>
      ))}
      <article className="an-card an-fuse">
        <header className="an-head">
          <span className="an-num mono">Σ</span>
          <span className="an-tag tag-fuse">fusion</span>
        </header>
        <h3 className="an-name">Verdict</h3>
        <p className="an-short">one composite question</p>
        <p className="an-long">All seven streams collapse into one fused score against two thresholds. Capability violation forces FORBID. Quarantine, cold-start-on-borderline, PENDING-lifecycle, and forbid-streak rules force ABSTAIN.</p>
        <footer className="an-foot mono">
          <span>thresholds</span>
          <span className="an-w">0.34 / 0.62</span>
        </footer>
      </article>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
 *  DISCOVERY — connectors + reconciliation events
 * ──────────────────────────────────────────────────────────────────── */

function DiscoveryPanel({ connectors, events }) {
  return (
    <div className="discovery-grid">
      <div className="discovery-conns">
        <header className="dc-head">
          <span className="dc-title">Connectors · scanning</span>
          <span className="dc-pulse" />
        </header>
        {connectors.map((c) => (
          <div className="dc-row" key={c.id}>
            <span className="dc-pip" />
            <div className="dc-text">
              <span className="dc-name">{c.name}</span>
              <span className="dc-finds">{c.finds}</span>
            </div>
          </div>
        ))}
      </div>
      <div className="discovery-events">
        <header className="de-head">
          <span className="de-title">Reconciliation ledger</span>
          <span className="de-sub">hash-chained · verifiable</span>
        </header>
        <div className="de-list">
          {events.map((e, i) => (
            <div className={`de-row de-${e.outcome}`} key={i}>
              <span className="de-hash mono">{e.hash.slice(0, 10)}</span>
              <span className="de-source">{e.source}</span>
              <span className="de-cand mono">{e.candidate}</span>
              <span className={`de-out de-out-${e.outcome}`}>{labelOutcome(e.outcome)}</span>
              <span className="de-conf mono">{e.confidence.toFixed(2)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function labelOutcome(o) {
  switch (o) {
    case 'registered':       return 'REGISTERED';
    case 'updated_drift':    return 'UPDATED · DRIFT';
    case 'quarantined':      return 'QUARANTINED';
    case 'no_op_unchanged':  return 'NO-OP · KNOWN';
    case 'held_below_thresh':return 'HELD · BELOW THRESH';
    case 'held_ambiguous':   return 'HELD · AMBIGUOUS';
    default: return o.toUpperCase();
  }
}

/* ────────────────────────────────────────────────────────────────────
 *  CHAIN VISUAL — eight blocks linked
 * ──────────────────────────────────────────────────────────────────── */

function ChainVisual({ chain }) {
  return (
    <div className="chainviz">
      {chain.map((b, i) => (
        <React.Fragment key={i + b.hash}>
          <div className={`cv-block v-${b.verdict}`}>
            <div className="cv-row cv-row-head mono">
              <span className="cv-idx">#{chain.length - i}</span>
              <span className={`cv-vd vd-${b.verdict}`}>{b.verdict.toUpperCase()}</span>
            </div>
            <div className="cv-row mono">
              <span className="cv-l">hash</span>
              <span className="cv-r">{b.hash.slice(0, 18)}…</span>
            </div>
            <div className="cv-row mono">
              <span className="cv-l">prev</span>
              <span className="cv-r">{b.prev.slice(0, 18)}…</span>
            </div>
            <div className="cv-row mono cv-kind-row">
              <span className="cv-l">kind</span>
              <span className="cv-r">{b.kind}</span>
            </div>
          </div>
          {i < chain.length - 1 && <div className="cv-link" aria-hidden="true">←</div>}
        </React.Fragment>
      ))}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
 *  ENFORCEMENT — four shapes, real code, copy-pasteable
 * ──────────────────────────────────────────────────────────────────── */

function EnforcementPanel({ shapes }) {
  return (
    <div className="enforce-grid">
      {shapes.map((s, i) => (
        <article className="ef-card" key={s.name}>
          <header className="ef-head">
            <span className="ef-num mono">0{i + 1}</span>
            <span className="ef-lang mono">{s.lang}</span>
          </header>
          <h3 className="ef-name">{s.name}</h3>
          <p className="ef-where">{s.where}</p>
          <pre className="ef-code mono"><code>{s.code}</code></pre>
        </article>
      ))}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
 *  LOOP RING — the architecture in one screen
 *  Seven nodes arranged around a circle, a single violet pulse traveling
 *  the whole ring as one continuous decision.
 * ──────────────────────────────────────────────────────────────────── */

function LoopRing({ nodes }) {
  const [active, setActive] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setActive((a) => (a + 1) % nodes.length), 1800);
    return () => clearInterval(id);
  }, [nodes.length]);

  // Compute node positions on a circle
  const cx = 360, cy = 360, r = 260;
  const positions = nodes.map((_, i) => {
    const angle = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
    return { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle), angle };
  });

  return (
    <div className="loop-wrap">
      <div className="loop-stage">
        <svg className="loop-svg" viewBox="0 0 720 720" aria-hidden="true">
          <defs>
            <radialGradient id="loop-core" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="rgba(107, 91, 255, 0.42)" />
              <stop offset="60%" stopColor="rgba(107, 91, 255, 0.08)" />
              <stop offset="100%" stopColor="rgba(107, 91, 255, 0)" />
            </radialGradient>
            <linearGradient id="loop-pulse" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="rgba(107, 91, 255, 0)" />
              <stop offset="50%" stopColor="rgba(107, 91, 255, 1)" />
              <stop offset="100%" stopColor="rgba(107, 91, 255, 0)" />
            </linearGradient>
          </defs>

          {/* Inner glow */}
          <circle cx={cx} cy={cy} r={r - 60} fill="url(#loop-core)" />

          {/* Main ring */}
          <circle
            cx={cx} cy={cy} r={r}
            fill="none"
            stroke="rgba(107, 91, 255, 0.22)"
            strokeWidth="1"
          />
          <circle
            cx={cx} cy={cy} r={r}
            fill="none"
            stroke="rgba(235, 232, 224, 0.04)"
            strokeWidth="1"
            strokeDasharray="2 6"
          />

          {/* Animated pulse traveling the ring */}
          <circle
            cx={cx} cy={cy} r={r}
            fill="none"
            stroke="url(#loop-pulse)"
            strokeWidth="2.5"
            strokeDasharray={`${2 * Math.PI * r * 0.12} ${2 * Math.PI * r * 0.88}`}
            className="loop-pulse-stroke"
          />

          {/* Connectors between nodes (subtle) */}
          {positions.map((p, i) => {
            const next = positions[(i + 1) % positions.length];
            return (
              <line
                key={`conn-${i}`}
                x1={p.x} y1={p.y} x2={next.x} y2={next.y}
                stroke="rgba(235, 232, 224, 0.06)"
                strokeWidth="1"
              />
            );
          })}

          {/* Node markers */}
          {positions.map((p, i) => (
            <g key={`node-${i}`} className={`loop-node ${i === active ? 'is-active' : ''}`}>
              <circle cx={p.x} cy={p.y} r="22" fill="var(--ink-bg)" stroke="rgba(107, 91, 255, 0.32)" strokeWidth="1" />
              <circle cx={p.x} cy={p.y} r="6" fill={i === active ? '#6b5bff' : 'rgba(107, 91, 255, 0.42)'} />
              {i === active && (
                <circle cx={p.x} cy={p.y} r="22" fill="none" stroke="rgba(107, 91, 255, 0.6)" strokeWidth="1.5" className="loop-node-ring" />
              )}
            </g>
          ))}

          {/* Node labels */}
          {positions.map((p, i) => {
            const labelR = r + 64;
            const lx = cx + labelR * Math.cos(p.angle);
            const ly = cy + labelR * Math.sin(p.angle);
            return (
              <text
                key={`lab-${i}`}
                x={lx} y={ly}
                textAnchor="middle"
                dominantBaseline="middle"
                className={`loop-label ${i === active ? 'is-active' : ''}`}
              >
                {nodes[i].label}
              </text>
            );
          })}

          {/* Center mark */}
          <text x={cx} y={cy - 14} textAnchor="middle" className="loop-center-eyebrow">tex</text>
          <text x={cx} y={cy + 18} textAnchor="middle" className="loop-center-num">{String(active + 1).padStart(2, '0')} / {String(nodes.length).padStart(2, '0')}</text>
        </svg>
      </div>

      <aside className="loop-detail">
        <div className="loop-detail-num mono">{String(active + 1).padStart(2, '0')}</div>
        <h3 className="loop-detail-label">{nodes[active].label}</h3>
        <p className="loop-detail-plain">{nodes[active].plain}</p>
        <p className="loop-detail-tech mono">{nodes[active].tech}</p>
        <div className="loop-detail-pips">
          {nodes.map((_, i) => (
            <button
              key={i}
              className={`loop-pip ${i === active ? 'is-active' : ''}`}
              onClick={() => setActive(i)}
              aria-label={`Show ${nodes[i].label}`}
            />
          ))}
        </div>
      </aside>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
 *  STACK COLLAPSE — competitive demolition.
 *  Left: four dim boxes, gappy connectors, "today's stack."
 *  Right: one bright violet ring, "Tex."
 *  Animation on scroll: left collapses into right.
 * ──────────────────────────────────────────────────────────────────── */

function StackCollapse({ layers }) {
  return (
    <div className="collapse-stage">
      <div className="collapse-side collapse-before">
        <header className="collapse-side-head mono">
          <span className="collapse-tag">today's stack</span>
          <span className="collapse-tag-sub">4 invoices · 4 dashboards · gaps</span>
        </header>
        <ul className="collapse-list">
          {layers.map((l, i) => (
            <li className="collapse-row" key={l.id} style={{ '--i': i }}>
              <span className="collapse-row-num mono">0{i + 1}</span>
              <div className="collapse-row-text">
                <span className="collapse-row-label">{l.label}</span>
                <span className="collapse-row-vendors mono">{l.vendors}</span>
              </div>
              <span className="collapse-row-governs">{l.governs}</span>
              <span className="collapse-row-gap" aria-hidden="true" />
            </li>
          ))}
        </ul>
        <p className="collapse-side-foot">
          Each row is a separate product, a separate procurement cycle, a separate dashboard, a separate alert queue. The handoffs are where agents do damage.
        </p>
      </div>

      <div className="collapse-bridge" aria-hidden="true">
        <span className="collapse-bridge-arrow">→</span>
        <span className="collapse-bridge-label mono">collapse</span>
      </div>

      <div className="collapse-side collapse-after">
        <header className="collapse-side-head mono">
          <span className="collapse-tag collapse-tag-tex">tex</span>
          <span className="collapse-tag-sub">1 system · 1 chain · no gaps</span>
        </header>
        <div className="collapse-ring">
          <svg viewBox="0 0 320 320" aria-hidden="true">
            <defs>
              <radialGradient id="cring-glow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="rgba(107, 91, 255, 0.32)" />
                <stop offset="100%" stopColor="rgba(107, 91, 255, 0)" />
              </radialGradient>
            </defs>
            <circle cx="160" cy="160" r="140" fill="url(#cring-glow)" />
            <circle cx="160" cy="160" r="120" fill="none" stroke="rgba(107, 91, 255, 0.6)" strokeWidth="1.5" />
            <circle cx="160" cy="160" r="120" fill="none" stroke="rgba(107, 91, 255, 0.9)" strokeWidth="2" strokeDasharray="20 880" className="collapse-ring-pulse" />
            {[
              { l: 'Identity',  a: -90 },
              { l: 'Posture',   a: -18 },
              { l: 'Behavior',  a: 54 },
              { l: 'Policy',    a: 126 },
              { l: 'Content',   a: 198 },
            ].map((n, i) => {
              const rad = (n.a * Math.PI) / 180;
              const x = 160 + 120 * Math.cos(rad);
              const y = 160 + 120 * Math.sin(rad);
              const lx = 160 + 152 * Math.cos(rad);
              const ly = 160 + 152 * Math.sin(rad);
              const isContent = n.l === 'Content';
              return (
                <g key={i}>
                  <circle cx={x} cy={y} r="6" fill={isContent ? '#6b5bff' : 'rgba(107, 91, 255, 0.7)'} />
                  {isContent && <circle cx={x} cy={y} r="11" fill="none" stroke="#6b5bff" strokeWidth="1" className="collapse-ring-content-halo" />}
                  <text x={lx} y={ly} textAnchor="middle" dominantBaseline="middle" className={`collapse-ring-label ${isContent ? 'is-content' : ''}`}>{n.l}</text>
                </g>
              );
            })}
            <text x="160" y="156" textAnchor="middle" className="collapse-ring-center-eyebrow">tex</text>
            <text x="160" y="178" textAnchor="middle" className="collapse-ring-center-line">one decision</text>
          </svg>
        </div>
        <p className="collapse-side-foot">
          The four layers above plus the one nobody else builds — the actual content of the action — fused at the moment of release. One decision. One chain.
        </p>
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
 *  FUSION MATH — the actual production weights from defaults.py,
 *  rendered as a horizontal bar chart you can scan in 3 seconds.
 * ──────────────────────────────────────────────────────────────────── */

function FusionMath({ weights }) {
  const max = Math.max(...weights.map((w) => w.weight));
  const total = weights.reduce((a, w) => a + w.weight, 0);
  return (
    <div className="fusion">
      <header className="fusion-head mono">
        <span>stream</span>
        <span>role</span>
        <span>weight</span>
      </header>
      <ul className="fusion-list">
        {weights.map((w, i) => (
          <li className="fusion-row" key={w.id} style={{ '--i': i, '--bar': `${(w.weight / max) * 100}%` }}>
            <span className="fusion-num mono">0{i + 1}</span>
            <span className="fusion-label">{w.label}</span>
            <span className="fusion-role mono">{w.role}</span>
            <span className="fusion-weight mono">{w.weight.toFixed(3)}</span>
            <span className="fusion-bar" aria-hidden="true"><span className="fusion-bar-fill" /></span>
          </li>
        ))}
      </ul>
      <footer className="fusion-foot">
        <div className="fusion-foot-cell">
          <span className="fusion-foot-num mono">Σ {total.toFixed(3)}</span>
          <span className="fusion-foot-label">sum of weights · normalized fusion</span>
        </div>
        <div className="fusion-foot-cell">
          <span className="fusion-foot-num mono">≤ 0.18</span>
          <span className="fusion-foot-label">PERMIT threshold · action passes through</span>
        </div>
        <div className="fusion-foot-cell">
          <span className="fusion-foot-num mono">≥ 0.72</span>
          <span className="fusion-foot-label">FORBID threshold · action physically blocked</span>
        </div>
        <div className="fusion-foot-cell">
          <span className="fusion-foot-num mono">2.2 ms</span>
          <span className="fusion-foot-label">median fusion latency · seven streams</span>
        </div>
      </footer>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
 *  DISCOVERY THEATER — connectors as a scanning strip + live ledger
 * ──────────────────────────────────────────────────────────────────── */

function DiscoveryTheater({ connectors, events }) {
  return (
    <div className="dt">
      <div className="dt-scanner">
        <div className="dt-scan-line" aria-hidden="true" />
        {connectors.map((c, i) => (
          <article className="dt-conn" key={c.id} style={{ '--i': i }}>
            <span className="dt-conn-pip" aria-hidden="true" />
            <span className="dt-conn-name">{c.name}</span>
            <span className="dt-conn-finds">{c.finds}</span>
          </article>
        ))}
      </div>
      <div className="dt-ledger">
        <header className="dt-ledger-head mono">
          <span>hash</span>
          <span>source</span>
          <span>candidate</span>
          <span>outcome</span>
          <span>conf</span>
        </header>
        <div className="dt-ledger-list">
          {events.map((e, i) => (
            <div className={`dt-ledger-row dt-${e.outcome}`} key={i} style={{ '--i': i }}>
              <span className="dt-l-hash mono">{e.hash.slice(0, 10)}</span>
              <span className="dt-l-source">{e.source}</span>
              <span className="dt-l-cand mono">{e.candidate}</span>
              <span className={`dt-l-out dt-l-out-${e.outcome}`}>{labelOutcome(e.outcome)}</span>
              <span className="dt-l-conf mono">{e.confidence.toFixed(2)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
 *  CAPABILITY SURFACE — declared polygon + attempted action point
 * ──────────────────────────────────────────────────────────────────── */

function CapabilitySurface() {
  const [phase, setPhase] = useState(0); // 0 = inside, 1 = outside, 2 = critical
  useEffect(() => {
    const id = setInterval(() => setPhase((p) => (p + 1) % 3), 2400);
    return () => clearInterval(id);
  }, []);

  // Polygon vertices for capability surface
  const verts = [
    { x: 200, y: 60,  l: 'action_type' },
    { x: 340, y: 160, l: 'channel' },
    { x: 320, y: 300, l: 'environment' },
    { x: 200, y: 340, l: 'recipient' },
    { x: 80,  y: 300, l: 'rate' },
    { x: 60,  y: 160, l: 'tenant' },
  ];
  const path = verts.map((v, i) => `${i === 0 ? 'M' : 'L'} ${v.x} ${v.y}`).join(' ') + ' Z';

  // Action points
  const points = [
    { x: 200, y: 200, label: 'email.send · finance@tenant', verdict: 'permit' },
    { x: 380, y: 220, label: 'email.send · external@unknown', verdict: 'forbid' },
    { x: 410, y: 320, label: 'database.delete · production', verdict: 'forbid' },
  ];
  const point = points[phase];

  return (
    <div className="surface-block surface-cap">
      <div className="surface-block-head">
        <span className="surface-block-eyebrow mono">capability</span>
        <h3 className="surface-block-title">A polygon. An action plotted as a point.</h3>
        <p className="surface-block-body">If the action lands inside the polygon, evaluation continues. Outside the polygon is CRITICAL — capability_violation forces FORBID before the rest of the streams matter.</p>
      </div>
      <div className="surface-block-viz">
        <svg viewBox="0 0 440 400" aria-hidden="true">
          <defs>
            <linearGradient id="cap-fill" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="rgba(107, 91, 255, 0.16)" />
              <stop offset="100%" stopColor="rgba(107, 91, 255, 0.04)" />
            </linearGradient>
          </defs>
          {/* grid */}
          {[0, 1, 2, 3, 4].map((i) => (
            <line key={`gx${i}`} x1={88 * i} y1="0" x2={88 * i} y2="400" stroke="rgba(235, 232, 224, 0.04)" />
          ))}
          {[0, 1, 2, 3, 4].map((i) => (
            <line key={`gy${i}`} x1="0" y1={80 * i} x2="440" y2={80 * i} stroke="rgba(235, 232, 224, 0.04)" />
          ))}
          {/* polygon */}
          <path d={path} fill="url(#cap-fill)" stroke="rgba(107, 91, 255, 0.62)" strokeWidth="1.5" />
          {verts.map((v, i) => (
            <g key={i}>
              <circle cx={v.x} cy={v.y} r="3" fill="rgba(107, 91, 255, 0.8)" />
              <text x={v.x} y={v.y - 12} textAnchor="middle" className="surface-vert-label">{v.l}</text>
            </g>
          ))}
          {/* action point */}
          <g className={`surface-point surface-point-${point.verdict}`} key={phase}>
            <circle cx={point.x} cy={point.y} r="22" fill="none" className="surface-point-halo" />
            <circle cx={point.x} cy={point.y} r="6" />
            <text x={point.x} y={point.y - 24} textAnchor="middle" className="surface-point-label mono">{point.label}</text>
            <text x={point.x} y={point.y + 32} textAnchor="middle" className={`surface-point-verdict surface-point-verdict-${point.verdict}`}>{point.verdict.toUpperCase()}</text>
          </g>
        </svg>
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
 *  BEHAVIOR BARCODE — 64-band MinHash signature + novelty match
 * ──────────────────────────────────────────────────────────────────── */

function BehaviorBarcode() {
  const [phase, setPhase] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setPhase((p) => p + 1), 2200);
    return () => clearInterval(id);
  }, []);

  // Generate three "baseline" signatures and one "candidate"
  const baselines = useMemo(() => {
    const seeds = [0.28, 0.62, 0.91];
    return seeds.map((s) => Array.from({ length: 64 }, (_, i) => ((i * 37 + s * 1000) % 11) / 11));
  }, []);
  const candidates = useMemo(() => [
    { sig: Array.from({ length: 64 }, (_, i) => ((i * 37 + 280) % 11) / 11), novelty: 0.12, label: 'in baseline · matched' },
    { sig: Array.from({ length: 64 }, (_, i) => ((i * 91 + 444) % 17) / 17), novelty: 0.78, label: 'novel · tenant_novel_content fired' },
    { sig: Array.from({ length: 64 }, (_, i) => ((i * 53 + 117) % 13) / 13), novelty: 0.34, label: 'partial match · borderline' },
  ], []);
  const cand = candidates[phase % candidates.length];
  const isNovel = cand.novelty > 0.5;

  return (
    <div className="surface-block surface-bar">
      <div className="surface-block-head">
        <span className="surface-block-eyebrow mono">behavior</span>
        <h3 className="surface-block-title">A 64-band MinHash signature. A tenant baseline.</h3>
        <p className="surface-block-body">Every piece of content gets reduced to a signature. The tenant's last N decisions form a baseline. Far signatures fire tenant_novel_content as peer evidence — not a separate behavioral product, just one stream in the same fusion.</p>
      </div>
      <div className="surface-block-viz surface-block-viz-bar">
        <div className="bar-col">
          <span className="bar-col-label mono">tenant baseline · last N</span>
          {baselines.map((b, bi) => (
            <div className="bar-row" key={bi}>
              {b.map((v, i) => (
                <span key={i} className="bar-cell" style={{ opacity: 0.18 + v * 0.5 }} />
              ))}
            </div>
          ))}
        </div>
        <div className="bar-col bar-col-cand">
          <span className="bar-col-label mono">candidate signature</span>
          <div className={`bar-row bar-row-cand ${isNovel ? 'is-novel' : ''}`} key={phase}>
            {cand.sig.map((v, i) => (
              <span key={i} className="bar-cell bar-cell-cand" style={{ opacity: 0.32 + v * 0.6 }} />
            ))}
          </div>
          <div className={`bar-readout mono ${isNovel ? 'is-novel' : ''}`}>
            <span>novelty</span>
            <span className="bar-readout-num">{cand.novelty.toFixed(2)}</span>
            <span className="bar-readout-label">{cand.label}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
 *  COMPLIANCE MARKS — frameworks the chain maps to
 * ──────────────────────────────────────────────────────────────────── */

function ComplianceMarks({ marks }) {
  return (
    <div className="compliance">
      <header className="compliance-head mono">maps to · auditor-recognized frameworks</header>
      <ul className="compliance-list">
        {marks.map((m) => (
          <li className="compliance-mark mono" key={m}>{m}</li>
        ))}
      </ul>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
 *  COMPETITOR MAP — the layer table that ends the "what is Tex" question
 * ──────────────────────────────────────────────────────────────────── */

function CompetitorMap({ rows }) {
  return (
    <div className="cmap">
      <header className="cmap-head mono">
        <span>Layer</span>
        <span>Representative vendors</span>
        <span>Governs</span>
      </header>
      {rows.map((r) => (
        <div className={`cmap-row ${r.tex ? 'cmap-row-tex' : ''}`} key={r.layer}>
          <span className="cmap-layer">{r.layer}</span>
          <span className="cmap-vendors mono">{r.vendors}</span>
          <span className="cmap-governs">
            {r.tex ? <em>{r.governs}</em> : r.governs}
          </span>
        </div>
      ))}
      <footer className="cmap-foot">
        Four layers, four product categories, four budget lines. Tex is the fifth — and the one nobody else is building.
      </footer>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
 *  PROOF STATS — three numbers below the chain visual
 * ──────────────────────────────────────────────────────────────────── */

function ProofStats() {
  return (
    <div className="proof-stats">
      <div className="ps-cell">
        <span className="ps-num mono">SHA-256</span>
        <span className="ps-label">hash function · NIST FIPS 180-4</span>
      </div>
      <div className="ps-cell">
        <span className="ps-num mono">2.2 ms</span>
        <span className="ps-label">median fusion latency · seven streams · one verdict</span>
      </div>
      <div className="ps-cell">
        <span className="ps-num mono">replay</span>
        <span className="ps-label">any decision, on demand · tamper-evident by construction</span>
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
 *  Shared atoms
 * ──────────────────────────────────────────────────────────────────── */

function SectionHead({ eyebrow, title, lede }) {
  return (
    <header className="sh">
      <span className="sh-eyebrow">{eyebrow}</span>
      <h2 className="sh-title">{title}</h2>
      <p className="sh-lede">{lede}</p>
    </header>
  );
}

function Glyph() {
  return (
    <svg className="glyph" width="22" height="26" viewBox="0 0 22 26" fill="none" aria-hidden="true">
      <path d="M11 1L20.526 6.5V17.5L11 23L1.474 17.5V6.5L11 1Z" stroke="currentColor" strokeWidth="1.1" />
      <path d="M11 8V18M7 9H15" stroke="currentColor" strokeWidth="1.1" strokeLinecap="square" />
    </svg>
  );
}

function Arrow() {
  return (
    <svg className="arrow" width="20" height="14" viewBox="0 0 20 14" fill="none" aria-hidden="true">
      <path d="M1 7H18M12 1L18 7L12 13" stroke="currentColor" strokeWidth="1.2" strokeLinecap="square" strokeLinejoin="miter" />
    </svg>
  );
}

function ScanLine() {
  return <div className="scanline" aria-hidden="true" />;
}

function Grain() {
  return <div className="grain" aria-hidden="true" />;
}

function Foot() {
  return (
    <footer className="foot">
      <div className="foot-l">
        <Glyph />
        <span>Tex by VortexBlack</span>
      </div>
      <div className="foot-r">
        <a href="https://vortexblack.ai">vortexblack.ai</a>
        <span className="foot-dot">·</span>
        <span>{new Date().getFullYear()}</span>
      </div>
    </footer>
  );
}

/* ────────────────────────────────────────────────────────────────────
 *  Helpers
 * ──────────────────────────────────────────────────────────────────── */

const GENESIS = '0x0000000000000000000000000000000000000000000000000000000000000000';

function emptyScores() {
  return STREAMS.reduce((acc, s) => ({ ...acc, [s.id]: 0 }), {});
}

function nowStamp() {
  const d = new Date();
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mm = String(d.getUTCMinutes()).padStart(2, '0');
  const ss = String(d.getUTCSeconds()).padStart(2, '0');
  return `${hh}:${mm}:${ss}.${String(d.getUTCMilliseconds()).padStart(3, '0')}Z`;
}

function seedChain() {
  const verdicts = ['permit','permit','permit','permit','abstain','permit','forbid','permit','abstain','permit','permit','forbid','permit','abstain','permit','permit'];
  const kinds = ['email.send','slack.dm','salesforce.update','github.push','stripe.refund','calendar.invite','postgres.delete','mcp.tool_call','docs.share','twilio.sms','s3.put','shell.exec','email.send','stripe.refund','slack.post','mongo.write'];
  let prev = GENESIS;
  return verdicts.map((v, i) => {
    const hash = randHash();
    const block = { hash, prev, verdict: v, kind: kinds[i % kinds.length], ms: 0.6 + Math.random() * 2.8 };
    prev = hash;
    return block;
  }).reverse();
}

function seedDiscovery() {
  return [
    { hash: randHash(), source: 'microsoft_graph',  candidate: 'app:copilot-finance-q4',     outcome: 'registered',      confidence: 0.93 },
    { hash: randHash(), source: 'github',           candidate: 'app:claude-code-bot',        outcome: 'updated_drift',   confidence: 0.81 },
    { hash: randHash(), source: 'salesforce',       candidate: 'agentforce:lead-triage-03',  outcome: 'registered',      confidence: 0.88 },
    { hash: randHash(), source: 'aws_bedrock',      candidate: 'agent:bedrock-ops-eu-west',  outcome: 'quarantined',     confidence: 0.74 },
    { hash: randHash(), source: 'mcp_server',       candidate: 'mcp:cursor-eng-dev-04',      outcome: 'registered',      confidence: 0.91 },
    { hash: randHash(), source: 'openai',           candidate: 'asst:bizops-research-12',    outcome: 'no_op_unchanged', confidence: 0.96 },
    { hash: randHash(), source: 'microsoft_graph',  candidate: 'app:teams-summarizer-beta',  outcome: 'held_ambiguous',  confidence: 0.62 },
    { hash: randHash(), source: 'github',           candidate: 'app:internal-cli-helper',    outcome: 'held_below_thresh', confidence: 0.55 },
    { hash: randHash(), source: 'salesforce',       candidate: 'einstein:cs-classifier-v2',  outcome: 'registered',      confidence: 0.89 },
  ];
}

function randHash() {
  const hex = '0123456789abcdef';
  let s = '0x';
  for (let i = 0; i < 16; i++) s += hex[Math.floor(Math.random() * 16)];
  return s;
}
