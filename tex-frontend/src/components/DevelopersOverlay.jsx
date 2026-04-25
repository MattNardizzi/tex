import React, { useState } from "react";
import ComplianceStrip from "./ComplianceStrip.jsx";

/*
  DevelopersOverlay — primary engineering-leader funnel.

  The arena's primary audience is AI platform / agent-builder
  engineering leaders. This overlay converts them. Three CTAs in a
  ladder:
    1. Get API key + 1,000 free evals/month
    2. Book a 30-min architecture review
    3. Skim the integration snippet for their stack

  Code samples are minimal but real. They mirror /api/evaluate exactly.
*/

const SNIPPETS = {
  curl: `curl -X POST https://api.texaegis.com/api/evaluate \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $TEX_API_KEY" \\
  -d '{
    "action_type": "outbound_email",
    "channel": "email",
    "content": "<your agent output here>",
    "recipient": "customer@example.com",
    "environment": "production"
  }'`,

  python: `from tex import TexClient

tex = TexClient(api_key=os.environ["TEX_API_KEY"])

verdict = tex.evaluate(
    action_type="outbound_email",
    channel="email",
    content=agent_output,
    recipient="customer@example.com",
)

if verdict.verdict == "PERMIT":
    send_email(agent_output)
elif verdict.verdict == "ABSTAIN":
    queue_for_human_review(agent_output, verdict.evidence)
else:
    log_blocked(verdict.asi_findings)`,

  langgraph: `from langgraph.graph import StateGraph
from tex.langgraph import TexAdjudicator

graph = StateGraph(AgentState)
graph.add_node("agent", run_agent)
graph.add_node("tex_gate", TexAdjudicator(api_key=TEX_KEY))
graph.add_edge("agent", "tex_gate")
graph.add_conditional_edges(
    "tex_gate",
    lambda s: s["verdict"],
    {"PERMIT": "send", "ABSTAIN": "human", "FORBID": END},
)`,

  crewai: `from crewai import Agent, Crew
from tex.crewai import TexGate

billing_agent = Agent(
    role="Billing",
    output_filter=TexGate(api_key=TEX_KEY),
)

crew = Crew(agents=[billing_agent])
crew.kickoff()
# Every output the agent produces is adjudicated by Tex
# before it reaches a downstream tool, channel, or recipient.`,

  kong: `# Kong AI Gateway plugin — drops Tex inline at the gateway
plugins:
  - name: tex-aegis
    config:
      api_key: \${TEX_API_KEY}
      mode: enforce        # enforce | shadow | observe
      action_types:
        - outbound_email
        - slack_message
        - tool_call
      on_forbid: block_and_log
      on_abstain: route_to_review`,
};

export default function DevelopersOverlay({ onClose, onOpenAsi }) {
  const [tab, setTab] = useState("curl");

  return (
    <div style={{
      position: "fixed",
      inset: 0,
      background: "rgba(6, 7, 14, 0.92)",
      backdropFilter: "blur(12px)",
      zIndex: 80,
      overflowY: "auto",
      padding: "32px 16px",
    }}>
      <div className="panel rise" style={{
        maxWidth: 820,
        margin: "0 auto",
        padding: 0,
        borderColor: "var(--cyan)",
      }}>
        <div style={{
          padding: "24px 28px 20px",
          borderBottom: "1px solid var(--hairline-2)",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          gap: 12,
          flexWrap: "wrap",
        }}>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 6 }}>
              FOR ENGINEERING LEADERS
            </div>
            <div className="display" style={{ fontSize: 32, lineHeight: 1.05 }}>
              DROP TEX{" "}
              <span className="glow-cyan" style={{ color: "var(--cyan)" }}>BETWEEN</span>{" "}
              YOUR AGENT AND THE WORLD.
            </div>
          </div>
          <button onClick={onClose} className="micro" style={{
            color: "var(--ink-faint)",
            padding: 4,
          }}>✕ CLOSE</button>
        </div>

        <div style={{ padding: "24px 28px" }}>
          <p style={{ fontSize: 15, color: "var(--ink-dim)", lineHeight: 1.6, marginBottom: 18 }}>
            One POST per agent output. PERMIT / ABSTAIN / FORBID with full
            OWASP ASI 2026 findings and signed evidence. Sub-200ms.
            Vendor-neutral, model-agnostic, framework-agnostic — works
            with LangGraph, CrewAI, AutoGen, ADK, or your own stack.
          </p>

          {/* Conversion ladder */}
          <div style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 12,
            marginBottom: 22,
          }} className="dev-cta-grid">
            <div style={{
              padding: "16px 18px",
              border: "1px solid rgba(95, 240, 255, 0.45)",
              borderRadius: 8,
              background: "rgba(95, 240, 255, 0.06)",
            }}>
              <div className="kicker" style={{ color: "var(--cyan)" }}>★ START HERE</div>
              <div className="display" style={{ fontSize: 17, marginTop: 6, lineHeight: 1.15 }}>
                GET AN API KEY
              </div>
              <div style={{ fontSize: 12, color: "var(--ink-dim)", marginTop: 6, lineHeight: 1.5 }}>
                1,000 free evaluations / month. No credit card. Production-ready.
              </div>
              <a
                href="mailto:matthew@vortexblack.com?subject=Tex%20API%20key%20%E2%80%94%20engineering%20access&body=Hi%20Matt%2C%0A%0AI'd%20like%20a%20Tex%20Aegis%20API%20key%20for%20evaluation.%0A%0AStack%3A%20%0AAgent%20framework%3A%20%0AUse%20case%3A%20"
                className="btn-primary"
                style={{ marginTop: 12, display: "inline-flex" }}
              >
                REQUEST API KEY →
              </a>
            </div>
            <div style={{
              padding: "16px 18px",
              border: "1px solid var(--hairline-2)",
              borderRadius: 8,
              background: "var(--bg-2)",
            }}>
              <div className="kicker" style={{ color: "var(--ink-dim)" }}>30-MIN ARCH REVIEW</div>
              <div className="display" style={{ fontSize: 17, marginTop: 6, lineHeight: 1.15 }}>
                TALK TO THE BUILDER
              </div>
              <div style={{ fontSize: 12, color: "var(--ink-dim)", marginTop: 6, lineHeight: 1.5 }}>
                Walk through your agent stack, where Tex slots in,
                latency targets, deployment shape.
              </div>
              <a
                href="mailto:matthew@vortexblack.com?subject=Tex%20%E2%80%94%2030-min%20architecture%20review"
                className="btn-ghost"
                style={{ marginTop: 12, display: "inline-flex" }}
              >
                BOOK 30 MIN
              </a>
            </div>
          </div>

          {/* Snippet tabs */}
          <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 8 }}>
            INTEGRATION
          </div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 10 }}>
            {Object.keys(SNIPPETS).map((k) => (
              <button
                key={k}
                onClick={() => setTab(k)}
                className="micro"
                style={{
                  padding: "6px 10px",
                  border: `1px solid ${tab === k ? "var(--cyan)" : "var(--hairline-2)"}`,
                  borderRadius: 4,
                  background: tab === k ? "rgba(95, 240, 255, 0.08)" : "transparent",
                  color: tab === k ? "var(--cyan)" : "var(--ink-dim)",
                  cursor: "pointer",
                }}
              >
                {k.toUpperCase()}
              </button>
            ))}
          </div>
          <pre className="mono" style={{
            margin: 0,
            padding: "14px 16px",
            background: "var(--bg-2)",
            border: "1px solid var(--hairline-2)",
            borderRadius: 6,
            fontSize: 12,
            lineHeight: 1.6,
            color: "var(--ink)",
            overflowX: "auto",
            whiteSpace: "pre",
          }}>
            {SNIPPETS[tab]}
          </pre>

          {/* Architecture pitch */}
          <div style={{
            padding: "16px 20px",
            background: "var(--bg-2)",
            border: "1px solid var(--hairline-2)",
            borderRadius: 8,
            marginTop: 22,
            marginBottom: 16,
          }}>
            <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 10 }}>
              WHY TEX VS BEDROCK GUARDRAILS / AZURE CONTENT SAFETY / NEMO
            </div>
            <ul style={{ margin: 0, padding: 0, listStyle: "none", display: "grid", gap: 8 }}>
              <Bullet text="Three-state verdict (PERMIT / ABSTAIN / FORBID) — competitors are binary block/allow." />
              <Bullet text="Six-layer pipeline: deterministic → retrieval → specialists → semantic → router → evidence." />
              <Bullet text="OWASP ASI 2026 findings tagged on every decision — no hyperscaler offers this today." />
              <Bullet text="SHA-256 hash-chained, HMAC-signed evidence — survives offline auditor verification." />
              <Bullet text="Vendor-neutral — works with any LLM, any agent framework, any cloud." />
            </ul>
          </div>

          <div className="kicker" style={{ color: "var(--ink-faint)", marginBottom: 8 }}>
            EVIDENCE COVERAGE
          </div>
          <ComplianceStrip />

          <div style={{ display: "flex", gap: 10, marginTop: 22, flexWrap: "wrap" }}>
            <button onClick={onOpenAsi} className="btn-ghost">
              SEE OWASP ASI MAPPING →
            </button>
            <a
              href="https://texaegis.com"
              target="_blank"
              rel="noreferrer"
              className="micro"
              style={{ color: "var(--ink-faint)", padding: "10px 14px", marginLeft: "auto" }}
            >
              TEXAEGIS.COM →
            </a>
          </div>
        </div>
      </div>

      <style>{`
        @media (max-width: 600px) {
          .dev-cta-grid { grid-template-columns: 1fr !important; }
        }
      `}</style>
    </div>
  );
}

function Bullet({ text }) {
  return (
    <li style={{ display: "flex", gap: 10, fontSize: 13, color: "var(--ink-dim)", lineHeight: 1.5 }}>
      <span style={{ color: "var(--cyan)", flexShrink: 0 }}>▸</span>
      <span>{text}</span>
    </li>
  );
}
