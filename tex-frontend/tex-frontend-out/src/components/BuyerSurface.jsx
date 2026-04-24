import React from "react";

export default function BuyerSurface({ onClose }) {
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
        maxWidth: 720,
        margin: "0 auto",
        padding: "32px 36px",
      }}>
        <button onClick={onClose} style={{
          float: "right",
          color: "var(--ink-faint)",
          fontFamily: "var(--font-mono)",
          fontSize: 12,
          padding: 4,
        }}>✕ CLOSE</button>

        <div className="kicker" style={{ color: "var(--yellow)", marginBottom: 6 }}>
          FOR BUYERS
        </div>
        <div className="display" style={{ fontSize: 40, lineHeight: 1, marginBottom: 16 }}>
          EVERYONE LOGS IT.<br/>
          <span className="glow-yellow" style={{ color: "var(--yellow)" }}>TEX PROVES IT.</span>
        </div>
        <p style={{ fontSize: 15, color: "var(--ink-dim)", lineHeight: 1.6, marginBottom: 20 }}>
          Tex is a content-layer adjudication gate for AI agents. Every verdict
          produces a <strong style={{ color: "var(--ink)" }}>SHA-256 hash-chained, HMAC-signed evidence bundle</strong>
          {" "}— the same artifact your EU AI Act auditor will ask for on Aug 2, 2026.
        </p>

        <div style={{
          padding: "16px 20px",
          background: "var(--bg-2)",
          border: "1px solid var(--hairline-2)",
          borderRadius: 8,
          marginBottom: 20,
        }}>
          <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 10 }}>WHAT TEX DOES</div>
          <ul style={{ margin: 0, padding: 0, listStyle: "none", display: "grid", gap: 10 }}>
            <Bullet text="Six-layer pipeline: deterministic → retrieval → specialists → semantic → router → evidence" />
            <Bullet text="Adjudicates outbound AI content in under 200ms" />
            <Bullet text="PERMIT / ABSTAIN / FORBID with full reasoning + ASI 2026 findings" />
            <Bullet text="Tamper-proof audit bundle, replayable, portable, cryptographically signed" />
            <Bullet text="Drop-in API — one POST to /api/evaluate, no code changes to your agents" />
          </ul>
        </div>

        <div style={{
          padding: "16px 20px",
          border: "1px solid rgba(255, 225, 74, 0.3)",
          borderRadius: 8,
          background: "rgba(255, 225, 74, 0.05)",
          marginBottom: 24,
        }}>
          <div className="kicker" style={{ color: "var(--yellow)", marginBottom: 6 }}>WHO BUYS TEX</div>
          <ul style={{ margin: 0, padding: 0, listStyle: "none", display: "grid", gap: 6, color: "var(--ink-dim)", fontSize: 14 }}>
            <li>→ Banks, insurers, hospitals deploying outbound AI to customers</li>
            <li>→ EU AI Act high-risk deployments (deadline Aug 2, 2026 — 100 days out)</li>
            <li>→ Any legal team that wants signed logs when an AI causes a lawsuit</li>
          </ul>
        </div>

        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <a href="mailto:matthew@vortexblack.com?subject=Tex%20pilot%20%E2%80%94%2020-min%20walkthrough" className="btn-primary">
            BOOK A 20-MIN WALKTHROUGH
          </a>
          <a href="https://texaegis.com" target="_blank" rel="noreferrer" className="btn-ghost">
            TEXAEGIS.COM →
          </a>
        </div>
      </div>
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
