import React from "react";
import { X, ExternalLink } from "lucide-react";

export default function AboutSheet({ onClose }) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-arcade-bg/90 backdrop-blur-sm safe-top"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-[780px] max-h-[88vh] overflow-y-auto bg-paper border-2 border-ink ink-shadow"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b-2 border-ink bg-ink text-paper sticky top-0 z-10">
          <div className="flex items-baseline gap-3">
            <span className="font-mono text-[10px] uppercase tracking-[0.28em] text-paper-dim">
              About
            </span>
            <span className="font-display font-black text-[18px]">
              What is Tex, really?
            </span>
          </div>
          <button onClick={onClose} className="p-1.5 hover:bg-paper/10 rounded-full">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Lede */}
        <div className="px-6 py-6 border-b-2 border-ink bg-paper-dim">
          <p className="font-display font-bold text-[26px] leading-[1.2] text-ink">
            Tex is the <em className="font-accent italic text-signal not-italic italic">last-mile content gate</em> for AI agent actions.
          </p>
          <p className="mt-3 text-[15px] leading-[1.6] text-ink-mid">
            It reads the content an AI agent is about to release — an email, an API payload,
            a Slack post, a database query — and returns <span className="font-mono text-[13px] font-bold">PERMIT</span>,{" "}
            <span className="font-mono text-[13px] font-bold">ABSTAIN</span>, or{" "}
            <span className="font-mono text-[13px] font-bold">FORBID</span>, with a full evidence
            chain behind the call.
          </p>
        </div>

        {/* What it's not */}
        <Section title="What Tex is not">
          <p className="text-[14px] leading-[1.6] text-ink-mid">
            Not identity. Not permissions. Not behavioral monitoring. Not a tool-access firewall.
            Those layers exist — Microsoft's{" "}
            <code className="font-mono text-[12px] bg-paper-deep px-1 py-0.5">Agent Governance Toolkit</code>,
            Noma, Zenity, Cisco, CrowdStrike — and Tex composes with them. Tex owns one
            specific question: <em className="font-accent italic">this content, right now — should it go out?</em>
          </p>
        </Section>

        {/* Architecture */}
        <Section title="How it works">
          <ol className="space-y-3">
            {PIPELINE.map((step, i) => (
              <li key={i} className="flex gap-3">
                <div className="flex-shrink-0 w-7 h-7 border-2 border-ink bg-paper flex items-center justify-center font-mono text-[12px] font-bold">
                  {i + 1}
                </div>
                <div className="flex-1">
                  <div className="font-display font-bold text-[15px] text-ink">
                    {step.name}
                  </div>
                  <div className="text-[13px] leading-[1.55] text-ink-mid mt-0.5">
                    {step.description}
                  </div>
                </div>
              </li>
            ))}
          </ol>
        </Section>

        {/* OWASP + positioning */}
        <Section title="Why this matters now">
          <p className="text-[14px] leading-[1.6] text-ink-mid">
            OWASP's 2026 Top 10 for Agentic Applications names sensitive data disclosure and
            missing guardrails as top risks. 48.9% of organizations are blind to machine-to-machine
            traffic. 47% of companies have delayed production releases over agent risk. The gap
            between "AI agents that ship" and "AI agents that shouldn't ship" is exactly where
            Tex lives.
          </p>
        </Section>

        {/* For buyers */}
        <Section title="For security & AI teams">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <BuyerCard
              title="Integrate"
              body="Drop Tex in front of any AI agent action. FastAPI backend, REST endpoints, OpenAI + Anthropic semantic adapters."
            />
            <BuyerCard
              title="Observe"
              body="Every verdict ships with reasoning, confidence, OWASP ASI tags, and a SHA-256 evidence hash. Audit-ready."
            />
            <BuyerCard
              title="Tune"
              body="Immutable policy snapshots with versioning. Calibrate thresholds against real outcomes. Default + strict presets."
            />
            <BuyerCard
              title="Compose"
              body="Sits alongside AGT, Noma, Lakera. Owns the content layer. Doesn't overlap with identity or tool-access."
            />
          </div>
        </Section>

        {/* CTA */}
        <div className="p-6 bg-signal text-paper flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-t-2 border-ink">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.28em] opacity-80">
              Interested
            </div>
            <div className="font-display font-black text-[22px] leading-tight mt-0.5">
              Talk to the builder.
            </div>
            <div className="font-accent italic text-[14px] opacity-90 mt-1">
              Solo founder. Fast conversations. Real product, not vapor.
            </div>
          </div>
          <div className="flex flex-col sm:flex-row gap-2">
            <a
              href="https://texaegis.com"
              target="_blank"
              rel="noreferrer noopener"
              className="flex items-center justify-center gap-2 bg-paper text-ink px-5 py-3 font-mono text-[11px] uppercase tracking-[0.24em] font-bold hover:bg-ink hover:text-paper transition-colors border-2 border-ink"
            >
              texaegis.com
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
            <a
              href="https://www.linkedin.com/company/vortexblack"
              target="_blank"
              rel="noreferrer noopener"
              className="flex items-center justify-center gap-2 bg-ink text-paper px-5 py-3 font-mono text-[11px] uppercase tracking-[0.24em] font-bold hover:bg-paper hover:text-ink transition-colors border-2 border-ink"
            >
              LinkedIn
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}

const PIPELINE = [
  {
    name: "Deterministic recognizers",
    description:
      "Regex + lexicon catch the cheap stuff first: secrets, credentials, blocked terms, destructive SQL. Cheap, fast, auditable.",
  },
  {
    name: "Retrieval grounding",
    description:
      "Pulls in policy clauses, sensitive entities, and similar precedents. Gives later layers real context, not just the raw string.",
  },
  {
    name: "Specialist judges",
    description:
      "Four heuristic scorers — secrets exposure, external sharing, unauthorized commitment, destructive intent. Each returns a risk score.",
  },
  {
    name: "Semantic judge",
    description:
      "LLM with strict JSON schema scores five independent dimensions. This is where intent beats keywords.",
  },
  {
    name: "Fusion & routing",
    description:
      "Weighted fusion + policy criticality + abstention logic. Produces the final PERMIT / ABSTAIN / FORBID with confidence.",
  },
  {
    name: "Evidence chain",
    description:
      "Every decision written to a SHA-256 hash-chained JSONL log. Replayable. Signable. Compliance-ready.",
  },
];

function Section({ title, children }) {
  return (
    <section className="px-6 py-5 border-b-2 border-ink">
      <h3 className="font-mono text-[10px] uppercase tracking-[0.28em] text-ink-mid mb-3">
        {title}
      </h3>
      {children}
    </section>
  );
}

function BuyerCard({ title, body }) {
  return (
    <div className="border-2 border-ink/20 bg-paper-dim p-3">
      <div className="font-display font-bold text-[15px] text-ink mb-1">{title}</div>
      <div className="font-accent italic text-[13px] leading-[1.5] text-ink-mid">
        {body}
      </div>
    </div>
  );
}
