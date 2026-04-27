import React from "react";

/*
  WhatIsTex — short explainer, surfaced from the Hub footer.
  No more LayerAnatomy / INCIDENTS dependencies.
  This page exists for the curious buyer who clicks "WHAT IS TEX".
*/

export default function WhatIsTex({ onBack }) {
  return (
    <div className="page" style={{ padding: "var(--pad-page)", maxWidth: 880, margin: "0 auto" }}>
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        paddingBottom: 14,
        borderBottom: "1px solid var(--hairline-2)",
        marginBottom: 32,
      }}>
        <div className="kicker" style={{ color: "var(--cyan)" }}>
          UNDER THE HOOD
        </div>
        <button onClick={onBack} className="micro" style={{
          color: "var(--ink-faint)",
          padding: "8px 12px",
          border: "1px solid var(--hairline-2)",
          borderRadius: 4,
        }}>
          ← BACK
        </button>
      </div>

      <h1 className="display rise" style={{
        fontSize: "clamp(40px, 8vw, 88px)",
        margin: 0,
        lineHeight: 0.9,
        marginBottom: 20,
      }}>
        <span style={{ color: "var(--ink)" }}>THE GATE</span>
        <br />
        <span style={{
          background: "linear-gradient(90deg, var(--pink), var(--cyan))",
          WebkitBackgroundClip: "text",
          WebkitTextFillColor: "transparent",
          backgroundClip: "text",
        }}>
          BETWEEN AI AND THE REAL WORLD.
        </span>
      </h1>

      <p className="rise-2" style={{
        color: "var(--ink-dim)",
        fontSize: 18,
        lineHeight: 1.6,
        maxWidth: 640,
        marginBottom: 36,
      }}>
        Tex is an outbound content governance platform for AI agents. Every action your agent
        takes &mdash; emails, Slack messages, CRM writes, API calls, deployments &mdash; passes
        through Tex first. Tex returns one of three verdicts in <span style={{ color: "var(--cyan)" }}>~180ms</span>:
        <strong style={{ color: "var(--green)" }}> PERMIT</strong>,
        <strong style={{ color: "var(--yellow)" }}> ABSTAIN</strong>, or
        <strong style={{ color: "var(--red)" }}> FORBID</strong>.
      </p>

      <div className="rise-3" style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
        gap: 14,
        marginBottom: 36,
      }}>
        <Pillar
          color="var(--green)"
          label="PERMIT"
          body="Clean. Ship it. The action goes through with a signed permit."
        />
        <Pillar
          color="var(--yellow)"
          label="ABSTAIN"
          body="Uncertain. Hold for human review. Defer rather than guess."
        />
        <Pillar
          color="var(--red)"
          label="FORBID"
          body="Leak, breach, or unauthorized commitment. Block before send."
        />
      </div>

      <div className="rise-4 panel" style={{ padding: 22, marginBottom: 36 }}>
        <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 12 }}>
          WHAT TEX CATCHES
        </div>
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: 14,
          color: "var(--ink-dim)",
          fontSize: 13,
          lineHeight: 1.5,
        }}>
          <Catch title="Secrets" body="API keys, passwords, tokens leaking into outbound content." />
          <Catch title="PII" body="SSNs, payment data, regulated identifiers." />
          <Catch title="Commitments" body="Off-list discounts, roadmap promises, legal opinions." />
          <Catch title="Confidentiality" body="Pre-announcement disclosures, M&amp;A leaks, customer references." />
          <Catch title="Prompt injection" body="Override instructions embedded in agent inputs." />
          <Catch title="Destructive ops" body="Bulk deletes, irreversible writes, unsafe permissions." />
        </div>
      </div>

      <div className="rise-4" style={{
        padding: 22,
        background: "linear-gradient(135deg, rgba(255, 61, 122, 0.06) 0%, rgba(95, 240, 255, 0.04) 100%)",
        border: "1px solid rgba(255, 61, 122, 0.25)",
        borderRadius: 8,
        marginBottom: 28,
      }}>
        <div className="kicker" style={{ color: "var(--pink)", marginBottom: 8 }}>
          WHO IT'S FOR
        </div>
        <div style={{ color: "var(--ink-dim)", fontSize: 14, lineHeight: 1.6 }}>
          Teams running AI SDRs, AI CS agents, autonomous code agents, or any workflow where
          a model is allowed to send something on its own. If your agent can email a customer,
          touch a CRM, or open a PR, you need a gate.
        </div>
      </div>

      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        <a href="https://texaegis.com" className="btn-primary" target="_blank" rel="noreferrer">
          VISIT TEXAEGIS.COM →
        </a>
        <button onClick={onBack} className="btn-ghost">
          ← BACK TO ARENA
        </button>
      </div>

      <div style={{
        marginTop: 36,
        paddingTop: 18,
        borderTop: "1px solid var(--hairline-2)",
        color: "var(--ink-faint)",
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        letterSpacing: "0.14em",
        textTransform: "uppercase",
      }}>
        VortexBlack · Tex Aegis
      </div>
    </div>
  );
}

function Pillar({ color, label, body }) {
  return (
    <div style={{
      padding: 16,
      border: `1px solid ${color}`,
      background: `${color}0D`,
      borderRadius: 6,
    }}>
      <div className="display" style={{ fontSize: 22, color, letterSpacing: "0.06em", marginBottom: 6 }}>
        {label}
      </div>
      <div style={{ color: "var(--ink-dim)", fontSize: 13, lineHeight: 1.5 }}>
        {body}
      </div>
    </div>
  );
}

function Catch({ title, body }) {
  return (
    <div>
      <div className="mono" style={{ color: "var(--ink)", fontSize: 12, fontWeight: 600, marginBottom: 4 }}>
        {title}
      </div>
      <div style={{ color: "var(--ink-faint)", fontSize: 12, lineHeight: 1.5 }}>
        {body}
      </div>
    </div>
  );
}
