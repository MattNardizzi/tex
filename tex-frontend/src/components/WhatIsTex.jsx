import React from "react";
import LayerAnatomy from "./LayerAnatomy.jsx";
import { INCIDENTS, ASI_CHAPTERS } from "../lib/incidents.js";

/*
  WhatIsTex — the serious-infrastructure page.
  ────────────────────────────────────────────
  Pulled off the Hub so the homepage stays focused on "play and share".
  This page is where the curious 5% who want to understand the product land.
*/

const DEMO_PROFILE = { deterministic: true, retrieval: false, specialists: true, semantic: true, router: false };

export default function WhatIsTex({ onClose, onOpenAsi, onPlay }) {
  return (
    <div style={{
      minHeight: "100vh",
      maxWidth: 1100,
      margin: "0 auto",
      padding: "var(--pad-page)",
      width: "100%",
    }}>
      {/* Top bar */}
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        paddingBottom: 14,
        borderBottom: "1px solid var(--hairline-2)",
        marginBottom: 28,
        gap: 12,
        flexWrap: "wrap",
      }}>
        <button onClick={onClose} className="micro" style={{
          color: "var(--ink-faint)",
          padding: "8px 12px",
          border: "1px solid var(--hairline-2)",
          borderRadius: 4,
        }}>
          ← BACK
        </button>
        <div className="kicker" style={{ color: "var(--violet)" }}>
          UNDER THE HOOD
        </div>
        <div style={{ width: 80 }} className="hide-mobile" />
      </div>

      {/* Hero */}
      <div className="rise" style={{ marginBottom: 40 }}>
        <h1 className="display" style={{
          fontSize: "clamp(38px, 7vw, 64px)",
          margin: 0,
          lineHeight: 0.95,
          color: "var(--ink)",
        }}>
          WHAT IS <span style={{ color: "var(--cyan)" }}>TEX</span>?
        </h1>
        <p style={{
          maxWidth: 640,
          color: "var(--ink-dim)",
          fontSize: "clamp(15px, 2vw, 17px)",
          lineHeight: 1.6,
          marginTop: 18,
        }}>
          Tex is a real AI agent governance layer. It evaluates outbound agent actions —
          emails, Slack messages, API calls, database writes — at the moment of release,
          and returns one of three verdicts: <strong style={{ color: "var(--green)" }}>PERMIT</strong>,
          {" "}<strong style={{ color: "var(--yellow)" }}>ABSTAIN</strong>, or
          {" "}<strong style={{ color: "var(--red)" }}>FORBID</strong>.
          Every decision is signed and chained. The arena is a real call to a real Tex deployment.
        </p>
      </div>

      {/* Pipeline visualization */}
      <div className="panel rise-2" style={{
        padding: 24,
        marginBottom: 40,
        background: "linear-gradient(180deg, var(--bg-1), var(--bg-0))",
      }}>
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "baseline",
          marginBottom: 16,
          gap: 8,
          flexWrap: "wrap",
        }}>
          <div className="kicker" style={{ color: "var(--cyan)" }}>
            TEX // EVALUATION PIPELINE
          </div>
          <span className="micro" style={{ color: "var(--ink-faint)" }}>
            5 LAYERS · WEIGHTED · DETERMINISTIC + LLM
          </span>
        </div>
        <LayerAnatomy profile={DEMO_PROFILE} size="md" showWeights />
        <div style={{
          marginTop: 16,
          paddingTop: 14,
          borderTop: "1px solid var(--hairline)",
          display: "flex",
          justifyContent: "space-between",
          gap: 10,
          flexWrap: "wrap",
        }}>
          <Mini label="VERDICTS" value="PERMIT / ABSTAIN / FORBID" color="var(--ink)" />
          <Mini label="LATENCY" value="~180ms" color="var(--cyan)" />
          <Mini label="EVIDENCE" value="HMAC SIGNED" color="var(--violet)" />
        </div>
      </div>

      {/* How it works */}
      <div className="rise-2" style={{ marginBottom: 40 }}>
        <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 16 }}>
          HOW IT WORKS
        </div>
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: "clamp(16px, 3vw, 28px)",
        }}>
          <Step n="01" title="Agent emits action"
                text="An AI agent — SDR, marketing bot, support agent — is about to do a thing. Send an email. Post to Slack. Hit a database." />
          <Step n="02" title="Tex intercepts"
                text="Before the action ships, Tex evaluates it across 5 layers: regex, retrieval, specialists, semantic, router. Each contributes a weighted score." />
          <Step n="03" title="Verdict"
                text="PERMIT, ABSTAIN, or FORBID — with a confidence score, fired-layer profile, and signed evidence record for audit." />
          <Step n="04" title="Action proceeds (or doesn't)"
                text="The agent gets a structured response. Permitted actions ship. Forbidden ones don't. Abstains route to human review." />
        </div>
      </div>

      {/* Trust strip */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
        gap: 12,
        marginBottom: 40,
      }}>
        <Trust label="OWASP ASI 2026"
               text="Mapped to the ten Agentic Security Initiative categories." />
        <Trust label="SIGNED EVIDENCE"
               text="Every decision produces an HMAC-signed evidence chain." />
        <Trust label="HEXAGONAL"
               text="Production-grade Python backend. Six-layer evaluation pipeline." />
        <Trust label="DETERMINISTIC + LLM"
               text="Regex recognizers, retrieval grounding, narrow specialists, and structured semantic adjudication." />
      </div>

      {/* Stats */}
      <div style={{
        padding: "20px 22px",
        background: "var(--bg-1)",
        border: "1px solid var(--hairline-2)",
        borderRadius: 6,
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
        gap: 18,
        marginBottom: 32,
      }}>
        <Stat label="INCIDENTS" value={INCIDENTS.length} />
        <Stat label="ASI CATEGORIES" value={ASI_CHAPTERS.length} />
        <Stat label="LAYERS" value="5" accent="var(--pink)" />
        <Stat label="VERDICT TYPES" value="3" accent="var(--cyan)" />
      </div>

      {/* CTAs */}
      <div style={{
        display: "flex",
        gap: 10,
        flexWrap: "wrap",
        marginBottom: 40,
      }}>
        <button onClick={onPlay} className="btn-big">
          TRY THE ARENA →
        </button>
        <button onClick={onOpenAsi} className="btn-ghost">
          OWASP ASI REFERENCE
        </button>
      </div>
    </div>
  );
}

function Step({ n, title, text }) {
  return (
    <div>
      <div className="display" style={{
        fontSize: 28,
        color: "var(--cyan)",
        opacity: 0.4,
        lineHeight: 1,
        marginBottom: 8,
      }}>
        {n}
      </div>
      <div className="display" style={{
        fontSize: 16,
        color: "var(--ink)",
        marginBottom: 6,
        letterSpacing: "0.04em",
      }}>
        {title}
      </div>
      <div style={{ color: "var(--ink-dim)", fontSize: 13, lineHeight: 1.55 }}>
        {text}
      </div>
    </div>
  );
}

function Trust({ label, text }) {
  return (
    <div style={{
      padding: "12px 14px",
      borderLeft: "2px solid var(--violet)",
      background: "rgba(179, 136, 255, 0.04)",
    }}>
      <div className="kicker" style={{ color: "var(--violet)", marginBottom: 4 }}>
        {label}
      </div>
      <div style={{ color: "var(--ink-dim)", fontSize: 12, lineHeight: 1.5 }}>
        {text}
      </div>
    </div>
  );
}

function Stat({ label, value, accent }) {
  return (
    <div>
      <div className="display tabular" style={{
        fontSize: "clamp(22px, 4vw, 30px)",
        color: accent || "var(--ink)",
        lineHeight: 1,
      }}>
        {value}
      </div>
      <div className="micro" style={{ color: "var(--ink-faint)", marginTop: 4 }}>
        {label}
      </div>
    </div>
  );
}

function Mini({ label, value, color }) {
  return (
    <div>
      <div className="micro" style={{ color: "var(--ink-faint)" }}>{label}</div>
      <div className="mono" style={{ fontSize: 11, color, fontWeight: 600, marginTop: 2 }}>
        {value}
      </div>
    </div>
  );
}
