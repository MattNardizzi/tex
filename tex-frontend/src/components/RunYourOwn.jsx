import React, { useState } from "react";
import OwaspFindings from "./OwaspFindings.jsx";
import LayerAnatomy from "./LayerAnatomy.jsx";
import { layerProfile } from "../lib/stealthScore.js";
import { evaluateCustom } from "../lib/apiClient.js";

/*
  RunYourOwn — paste arbitrary content, pick a context, get a real Tex
  verdict. The single highest-converting feature for engineering
  leaders, because it lets them put their own agent's output in front
  of Tex without writing any code.

  Reuses /api/evaluate. Same backend, no game framing, no leaderboard.
*/

const ACTION_TYPES = [
  { value: "outbound_email", label: "Outbound email", channel: "email" },
  { value: "slack_message", label: "Slack / chat message", channel: "slack" },
  { value: "agent_message", label: "Agent-to-agent (A2A)", channel: "a2a" },
  { value: "tool_call", label: "Tool call / API output", channel: "api" },
  { value: "database_query", label: "Database query", channel: "api" },
];

export default function RunYourOwn({ onClose }) {
  const [content, setContent] = useState("");
  const [actionType, setActionType] = useState("outbound_email");
  const [recipient, setRecipient] = useState("");
  const [strict, setStrict] = useState(false);
  const [sending, setSending] = useState(false);
  const [decision, setDecision] = useState(null);
  const [err, setErr] = useState("");

  const ctx = ACTION_TYPES.find((a) => a.value === actionType) || ACTION_TYPES[0];

  async function run() {
    if (sending) return;
    const text = content.trim();
    if (!text) return;
    setErr("");
    setSending(true);
    setDecision(null);
    try {
      const d = await evaluateCustom({
        content: text,
        action_type: ctx.value,
        channel: ctx.channel,
        recipient: recipient || null,
        environment: "production",
        policy_id: strict ? "strict-v1" : null,
      });
      setDecision(d);
    } catch (e) {
      setErr(e.message || "Tex API error");
    } finally {
      setSending(false);
    }
  }

  function downloadEvidence() {
    if (!decision) return;
    const bundle = {
      tex_evidence_bundle_version: "1.0",
      generated_at: new Date().toISOString(),
      mode: "run_your_own_v1",
      decision_id: decision.decision_id,
      verdict: decision.verdict,
      confidence: decision.confidence,
      final_score: decision.final_score,
      policy_version: decision.policy_version,
      latency_ms: decision.total_ms,
      evidence: decision.evidence,
      asi_findings: decision.asi_findings,
      router: decision.router,
      deterministic: decision.deterministic,
      semantic: decision.semantic,
      specialists: decision.specialists,
      input: { content, action_type: ctx.value, channel: ctx.channel, recipient },
    };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `tex-evidence-${decision.decision_id || "sample"}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  const verdict = decision?.verdict;
  const tone =
    verdict === "PERMIT"
      ? "var(--green)"
      : verdict === "ABSTAIN"
      ? "var(--yellow)"
      : verdict === "FORBID"
      ? "var(--red)"
      : "var(--ink-faint)";

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
      }}>
        <div style={{
          padding: "24px 28px 20px",
          borderBottom: "1px solid var(--hairline-2)",
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "space-between",
          gap: 12,
        }}>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 6 }}>
              RUN YOUR OWN ATTACK
            </div>
            <div className="display" style={{ fontSize: 28, lineHeight: 1.05 }}>
              PASTE YOUR AGENT'S OUTPUT.{" "}
              <span className="glow-cyan" style={{ color: "var(--cyan)" }}>SEE WHAT TEX SAYS.</span>
            </div>
          </div>
          <button onClick={onClose} className="micro" style={{ color: "var(--ink-faint)", padding: 4 }}>✕ CLOSE</button>
        </div>

        <div style={{ padding: "24px 28px" }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }} className="ryo-meta-grid">
            <div>
              <div className="kicker" style={{ color: "var(--ink-faint)", marginBottom: 6 }}>CONTEXT</div>
              <select
                value={actionType}
                onChange={(e) => setActionType(e.target.value)}
                className="tex-input"
                style={{ width: "100%" }}
              >
                {ACTION_TYPES.map((a) => (
                  <option key={a.value} value={a.value}>{a.label}</option>
                ))}
              </select>
            </div>
            <div>
              <div className="kicker" style={{ color: "var(--ink-faint)", marginBottom: 6 }}>RECIPIENT (OPTIONAL)</div>
              <input
                type="text"
                value={recipient}
                onChange={(e) => setRecipient(e.target.value)}
                placeholder="e.g. customer@example.com"
                className="tex-input"
                style={{ width: "100%" }}
              />
            </div>
          </div>

          <div className="kicker" style={{ color: "var(--ink-faint)", marginBottom: 6 }}>AGENT OUTPUT</div>
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value.slice(0, 4000))}
            placeholder="Paste the actual content your agent is about to send. Tex will adjudicate it exactly as it would in production."
            rows={8}
            className="tex-input"
            style={{ width: "100%", minHeight: 160 }}
          />

          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 8, flexWrap: "wrap", gap: 8 }}>
            <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "var(--ink-dim)", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={strict}
                onChange={(e) => setStrict(e.target.checked)}
              />
              <span className="micro">USE STRICT POLICY (strict-v1)</span>
            </label>
            <span className="micro" style={{ color: "var(--ink-faint)" }}>{content.length}/4000</span>
          </div>

          <div style={{ marginTop: 16, display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button
              onClick={run}
              disabled={sending || !content.trim()}
              className="btn-primary"
            >
              {sending ? "ADJUDICATING…" : "ADJUDICATE →"}
            </button>
            {decision && (
              <button onClick={downloadEvidence} className="btn-ghost">
                ⬇ DOWNLOAD EVIDENCE BUNDLE
              </button>
            )}
            <span className="micro" style={{ color: "var(--ink-faint)", marginLeft: "auto", alignSelf: "center" }}>
              EVERY EVALUATION HITS THE LIVE TEX API
            </span>
          </div>

          {err && (
            <div style={{
              marginTop: 14,
              padding: "10px 14px",
              border: "1px solid var(--red)",
              borderRadius: 6,
              color: "var(--red)",
              fontSize: 13,
            }}>
              {err}
            </div>
          )}

          {decision && (
            <div className="rise" style={{ marginTop: 24 }}>
              <div style={{
                padding: "14px 16px",
                border: `1px solid ${tone}`,
                borderRadius: 8,
                background: `${tone}0E`,
                marginBottom: 16,
              }}>
                <div className="kicker" style={{ color: tone, marginBottom: 4 }}>VERDICT</div>
                <div className="display" style={{ fontSize: 30, color: tone, lineHeight: 1 }}>
                  {decision.verdict}
                </div>
                <div className="mono tabular" style={{ fontSize: 11, color: "var(--ink-faint)", marginTop: 6 }}>
                  {decision.total_ms}ms · confidence {(decision.confidence * 100).toFixed(0)}% · policy {decision.policy_version}
                </div>
              </div>

              <div style={{ marginBottom: 16 }}>
                <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 8 }}>
                  TEX PIPELINE
                </div>
                <LayerAnatomy profile={layerProfile(decision)} size="md" showWeights />
              </div>
              <OwaspFindings findings={decision.asi_findings || []} verdict={decision.verdict} />

              <div style={{
                padding: "12px 14px",
                border: "1px solid rgba(255, 225, 74, 0.3)",
                borderRadius: 6,
                background: "rgba(255, 225, 74, 0.04)",
              }}>
                <div className="mono" style={{ fontSize: 11, color: "var(--ink-dim)", lineHeight: 1.7, wordBreak: "break-all" }}>
                  <div><strong style={{ color: "var(--ink)" }}>decision_id:</strong> {decision.decision_id}</div>
                  <div><strong style={{ color: "var(--ink)" }}>evidence_hash:</strong> {decision.evidence?.evidence_hash || "—"}</div>
                  <div><strong style={{ color: "var(--ink)" }}>chain_valid:</strong> {decision.evidence?.chain_valid ? "true" : "false"}</div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <style>{`
        @media (max-width: 600px) {
          .ryo-meta-grid { grid-template-columns: 1fr !important; }
        }
      `}</style>
    </div>
  );
}
