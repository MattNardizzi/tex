import React from "react";
import { THexSvg } from "./Hub.jsx";

/*
  WhatIsTex v13 — scrolling cinematic explainer
  ─────────────────────────────────────────────
  4 sections that explain Tex to non-technical readers:
    1. The problem — agents act, no one is watching outbound
    2. The gate — Tex evaluates every action before release
    3. The verdict — PERMIT / ABSTAIN / FORBID
    4. The receipt — every decision is signed and audit-ready
*/

export default function WhatIsTex({ onBack, onPlayDaily }) {
  return (
    <div className="what-stage">
      <div className="hub-grid-bg" />
      <div className="hub-haze" />

      <div className="what-frame">
        {/* Top bar */}
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          paddingBottom: 14,
          borderBottom: "1px solid var(--rule-2)",
          marginBottom: 24,
          gap: 12,
          flexWrap: "wrap",
          paddingTop: 10,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <HexMark />
            <div style={{ lineHeight: 1.2 }}>
              <div className="display" style={{ fontSize: 20, color: "var(--ink)", letterSpacing: "0.08em" }}>
                WHAT IS TEX
              </div>
              <div className="micro" style={{ color: "var(--ink-faint)" }}>
                AI ACTION GOVERNANCE / VORTEXBLACK
              </div>
            </div>
          </div>
          <button onClick={onBack} className="bail-btn">← BACK</button>
        </div>

        {/* Hero */}
        <div className="rise" style={{ padding: "60px 0 80px 0" }}>
          <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 18 }}>▸ TEX // AEGIS</div>
          <h1 style={{
            fontFamily: "var(--font-display)",
            fontSize: "clamp(56px, 11vw, 144px)",
            lineHeight: 0.85,
            letterSpacing: "-0.005em",
            textTransform: "uppercase",
            margin: 0,
          }}>
            THE&nbsp;GATE&nbsp;BETWEEN<br />
            <span style={{
              background: "linear-gradient(90deg, var(--pink) 0%, var(--yellow) 50%, var(--cyan) 100%)",
              backgroundSize: "200% 100%",
              WebkitBackgroundClip: "text",
              backgroundClip: "text",
              WebkitTextFillColor: "transparent",
              animation: "holo-shift 6s ease-in-out infinite",
              filter: "drop-shadow(0 0 20px rgba(255, 61, 122, 0.25))",
            }}>
              AI&nbsp;AND&nbsp;THE&nbsp;REAL&nbsp;WORLD.
            </span>
          </h1>
          <p style={{
            maxWidth: 640,
            color: "var(--ink-dim)",
            fontSize: "clamp(16px, 2vw, 19px)",
            lineHeight: 1.6,
            marginTop: 28,
          }}>
            AI agents are sending emails, hitting APIs, writing to your database, posting publicly.
            Identity governance can't see <span style={{ color: "var(--ink)", fontWeight: 600 }}>what they're saying</span>.
            Tex is the content gate that does.
          </p>
        </div>

        {/* Section 1 — The problem */}
        <Section
          number="01"
          title="THE PROBLEM"
          body={<>
            Your AI SDR sends 10,000 emails this week. Identity governance approved the <b>action</b> — &lsquo;send email&rsquo;.
            No one approved <b>what was inside the emails</b>. Last week one of them quoted internal pricing
            to a competitor's procurement team. You found out from a screenshot on Twitter.
          </>}
          visual={<ProblemVisual />}
        />

        {/* Section 2 — The gate */}
        <Section
          number="02"
          title="THE GATE"
          body={<>
            Tex sits between every agent and the world. <b>Before any outbound action releases</b>,
            Tex inspects the actual content — words, fields, attachments, payloads — through a
            six-layer evaluation pipeline. PII, secrets, intent, brand-safety, deceptive promises, escalations.
            Average latency: <b>178ms</b>.
          </>}
          visual={<GateVisual />}
        />

        {/* Section 3 — The verdict */}
        <Section
          number="03"
          title="THREE VERDICTS"
          body={<>
            Every action gets exactly one of three: <b style={{ color: "var(--green)" }}>PERMIT</b> (clean — release),
            &nbsp;<b style={{ color: "var(--yellow)" }}>ABSTAIN</b> (uncertain — escalate to human),
            &nbsp;<b style={{ color: "var(--red)" }}>FORBID</b> (blocked — never released).
            Your agent's logs show what happened. Your compliance team gets the receipt.
          </>}
          visual={<VerdictsVisual />}
        />

        {/* Section 4 — The receipt */}
        <Section
          number="04"
          title="THE RECEIPT"
          body={<>
            Every Tex verdict is HMAC-signed and hash-chained — tamper-evident, audit-ready.
            When the SOC 2 auditor asks &lsquo;why did your AI send this&rsquo;, you don't shrug.
            You hand them a permit token with the layer-by-layer evidence trail.
          </>}
          visual={<ReceiptVisual />}
        />

        {/* CTA */}
        <div style={{
          padding: "80px 0 100px 0",
          textAlign: "center",
          borderTop: "1px solid var(--rule-2)",
        }}>
          <div className="kicker" style={{ color: "var(--pink)", marginBottom: 18 }}>
            ▸ SEE IT IN ACTION
          </div>
          <h2 style={{
            fontFamily: "var(--font-display)",
            fontSize: "clamp(40px, 6vw, 76px)",
            lineHeight: 0.92,
            letterSpacing: "-0.005em",
            textTransform: "uppercase",
            margin: "0 0 28px 0",
          }}>
            WORK A SHIFT.<br />
            <span style={{ color: "var(--ink-mid)" }}>SEE WHAT TEX SEES.</span>
          </h2>
          <button onClick={onPlayDaily} className="btn-cta breathe">
            ▸ START SHIFT
            <Arrow />
          </button>
        </div>
      </div>
    </div>
  );
}

function Section({ number, title, body, visual }) {
  return (
    <div className="what-section">
      <div>
        <div className="what-num">▸ {number}</div>
        <h2 className="what-h">{title}</h2>
        <div className="what-body">{body}</div>
      </div>
      <div>{visual}</div>
    </div>
  );
}

/* ─── Visuals (illustrative, not interactive game elements) ─── */

function ProblemVisual() {
  // Stream of cards flying off the page with no inspection
  return (
    <div style={{
      position: "relative",
      aspectRatio: "1 / 1",
      maxWidth: 460,
      margin: "0 auto",
      width: "100%",
    }}>
      <div className="panel" style={{
        position: "absolute", inset: 0,
        padding: 16,
        background: "var(--bg-panel)",
        overflow: "hidden",
      }}>
        <div className="micro" style={{ color: "var(--ink-faint)", marginBottom: 14 }}>
          OUTBOUND · UNINSPECTED
        </div>
        {[
          { glyph: "✉", body: "Hey Linda, I noticed your team uses Salesforce. Our internal pricing is 30% lower…", color: "var(--red)" },
          { glyph: "⚙", body: "POST /api/v1/customers/all { include: ['ssn', 'card'] }", color: "var(--red)" },
          { glyph: "💬", body: "Yes, I can guarantee your refund will process in under 24 hours.", color: "var(--yellow)" },
          { glyph: "📊", body: "UPDATE pricing SET tier='enterprise' WHERE id IN (3, 7, 11);", color: "var(--red)" },
        ].map((row, i) => (
          <div key={i} style={{
            display: "flex", alignItems: "center", gap: 10,
            padding: "10px 12px",
            marginBottom: 8,
            background: "var(--bg-card)",
            border: `1px solid ${row.color}`,
            borderRadius: 3,
            opacity: 1 - i * 0.15,
          }}>
            <span className="card-glyph" style={{ color: row.color, borderColor: row.color }}>{row.glyph}</span>
            <span className="mono" style={{
              fontSize: 11, color: "var(--ink-dim)",
              flex: 1, minWidth: 0,
              overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            }}>{row.body}</span>
            <span className="micro" style={{ color: row.color, fontSize: 8 }}>RELEASED</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function GateVisual() {
  return (
    <div style={{
      position: "relative",
      aspectRatio: "1 / 1",
      maxWidth: 460,
      margin: "0 auto",
      width: "100%",
      padding: 16,
      background: "var(--bg-panel)",
      border: "1px solid var(--rule-cyan)",
      borderRadius: 4,
    }}>
      <div className="micro" style={{ color: "var(--cyan)", marginBottom: 12 }}>
        ▸ SIX-LAYER PIPELINE
      </div>
      {[
        { l: "DETERMINISTIC GATE", d: "Regex / known-bad / forbidden patterns" },
        { l: "ENTITY EXTRACTION", d: "PII, secrets, financial data, codes" },
        { l: "SEMANTIC INTENT", d: "What is this action actually doing?" },
        { l: "BRAND & TONE", d: "Promises, deception, off-brand voice" },
        { l: "POLICY MATCH", d: "Org rules · sector · jurisdiction" },
        { l: "EVIDENCE SIGN", d: "HMAC + hash-chain · audit ready" },
      ].map((layer, i) => (
        <div key={i} style={{
          display: "flex", alignItems: "center", gap: 12,
          padding: "9px 10px",
          marginBottom: 6,
          background: "var(--bg-card)",
          border: "1px solid var(--rule-2)",
          borderRadius: 3,
        }}>
          <span className="display" style={{ color: "var(--cyan)", fontSize: 14, width: 22 }}>0{i + 1}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="micro" style={{ color: "var(--ink)", fontSize: 10 }}>{layer.l}</div>
            <div className="mono" style={{ color: "var(--ink-faint)", fontSize: 10, marginTop: 1 }}>{layer.d}</div>
          </div>
        </div>
      ))}
      <div style={{
        marginTop: 12,
        padding: "8px 12px",
        background: "rgba(95, 240, 255, 0.06)",
        border: "1px solid var(--rule-cyan)",
        borderRadius: 3,
        textAlign: "center",
        color: "var(--cyan)",
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        letterSpacing: "0.16em",
        textTransform: "uppercase",
        fontWeight: 700,
      }}>
        178MS · END-TO-END
      </div>
    </div>
  );
}

function VerdictsVisual() {
  const items = [
    { v: "PERMIT", c: "var(--green)", body: "Status check email — clean.", glyph: "✓" },
    { v: "ABSTAIN", c: "var(--yellow)", body: "Refund language unclear — escalate.", glyph: "?" },
    { v: "FORBID", c: "var(--red)", body: "Internal pricing in outbound email.", glyph: "✕" },
  ];
  return (
    <div style={{
      display: "flex",
      flexDirection: "column",
      gap: 14,
      maxWidth: 460,
      margin: "0 auto",
      width: "100%",
    }}>
      {items.map((it) => (
        <div key={it.v} style={{
          padding: "16px 18px",
          background: "var(--bg-panel)",
          border: `1px solid ${it.c}`,
          borderRadius: 4,
          boxShadow: `0 0 24px ${it.c.replace("var(--", "rgba(95, 240, 255, ")
            .replace(")", "")}`,
          position: "relative",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <div style={{
              width: 36, height: 36,
              borderRadius: "50%",
              border: `1.5px solid ${it.c}`,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 18, color: it.c,
              fontWeight: 700,
              flexShrink: 0,
            }}>
              {it.glyph}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="display" style={{ color: it.c, fontSize: 24, letterSpacing: "0.08em" }}>
                ▸ {it.v}
              </div>
              <div className="mono" style={{ color: "var(--ink-dim)", fontSize: 12, marginTop: 4 }}>
                {it.body}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

function ReceiptVisual() {
  return (
    <div style={{
      maxWidth: 460,
      margin: "0 auto",
      width: "100%",
      background: "var(--bg-panel)",
      border: "1px solid var(--rule-cyan)",
      borderRadius: 4,
      padding: 18,
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      lineHeight: 1.7,
    }}>
      <div className="micro" style={{ color: "var(--cyan)", marginBottom: 12 }}>
        ▸ TEX PERMIT TOKEN
      </div>
      <div style={{ color: "var(--ink-mid)" }}>
        <div><span style={{ color: "var(--ink-faint)" }}>action_id:</span> <span style={{ color: "var(--ink)" }}>act_4f8a1c…</span></div>
        <div><span style={{ color: "var(--ink-faint)" }}>verdict:</span> <span style={{ color: "var(--red)" }}>FORBID</span></div>
        <div><span style={{ color: "var(--ink-faint)" }}>layer:</span> <span style={{ color: "var(--ink)" }}>semantic_intent</span></div>
        <div><span style={{ color: "var(--ink-faint)" }}>reason:</span> <span style={{ color: "var(--ink)" }}>internal_pricing_disclosure</span></div>
        <div><span style={{ color: "var(--ink-faint)" }}>evidence:</span> <span style={{ color: "var(--ink-dim)" }}>"30% lower" → competitor_quote</span></div>
        <div><span style={{ color: "var(--ink-faint)" }}>latency:</span> <span style={{ color: "var(--cyan)" }}>178ms</span></div>
        <div><span style={{ color: "var(--ink-faint)" }}>chain_prev:</span> <span style={{ color: "var(--ink-dim)" }}>0x9f3c…a8</span></div>
        <div><span style={{ color: "var(--ink-faint)" }}>hmac:</span> <span style={{ color: "var(--ink-dim)" }}>0x4a91…7b</span></div>
      </div>
      <div style={{
        marginTop: 14,
        paddingTop: 12,
        borderTop: "1px solid var(--rule-2)",
        color: "var(--cyan)",
        fontSize: 10,
        letterSpacing: "0.14em",
        textTransform: "uppercase",
      }}>
        ✓ TAMPER-EVIDENT · AUDIT-READY
      </div>
    </div>
  );
}

function HexMark() {
  return (
    <div style={{
      width: 28, height: 32,
      filter: "drop-shadow(0 0 8px var(--pink-soft))",
    }}>
      <svg viewBox="0 0 28 32" width="100%" height="100%">
        <polygon points="14,2 26,9 26,23 14,30 2,23 2,9" fill="none" stroke="var(--pink)" strokeWidth="1.5" />
        <polygon points="14,8 21,12 21,20 14,24 7,20 7,12" fill="var(--pink)" />
      </svg>
    </div>
  );
}

function Arrow() {
  return (
    <svg width="20" height="14" viewBox="0 0 20 14" fill="none">
      <path d="M0 7H18M18 7L12 1M18 7L12 13" stroke="currentColor" strokeWidth="2" strokeLinecap="square" />
    </svg>
  );
}
