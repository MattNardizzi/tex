import React, { useState } from "react";
import LayerAnatomy from "./LayerAnatomy.jsx";
import ScorePanel from "./ScorePanel.jsx";
import { nearMissCopy } from "../lib/stealthScore.js";
import { downloadShareImage } from "../lib/shareImage.js";
import { OWASP_ASI } from "../lib/owaspAsi.js";

/*
  VerdictReveal v10
  ─────────────────
  Full-screen end-of-round payoff. The screenshot moment.

  Layout (desktop):
    ┌─────────────────────────┬───────────────────────┐
    │  ScorePanel (big total) │  Layer Anatomy (large)│
    │                         │  Near-miss copy       │
    │  Player message with    │  ASI mapping          │
    │  triggered spans hi-lit │  RP delta             │
    └─────────────────────────┴───────────────────────┘
    [SHARE] [PLAY AGAIN] [HOME]

  Layout (mobile): stacked vertically.
*/

export default function VerdictReveal({
  result,
  score,
  intent,
  rpDelta,
  player,
  onPlayAgain,
  onPickAnother,
  onHome,
}) {
  const { incident, bestAttempt } = result;
  const message = bestAttempt?.text || "";
  const decision = bestAttempt?.decision;

  const near = nearMissCopy(score);
  const [sharing, setSharing] = useState(false);

  async function handleShare() {
    setSharing(true);
    try {
      await downloadShareImage({ incident, score, handle: player.handle });
    } finally {
      setSharing(false);
    }
  }

  return (
    <div style={{
      minHeight: "100vh",
      maxWidth: 1280,
      margin: "0 auto",
      padding: "var(--pad-page)",
      width: "100%",
    }}>
      {/* Top bar */}
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        marginBottom: 24,
        gap: 12,
        flexWrap: "wrap",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{
            width: 7, height: 7, borderRadius: "50%",
            background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan-glow)",
          }} className="pulse" />
          <span className="kicker" style={{ color: "var(--cyan)" }}>
            ROUND COMPLETE
          </span>
          <span className="micro" style={{ color: "var(--ink-faint)" }}>
            · {incident.name.toUpperCase()}
          </span>
        </div>
        {!score.forfeit && rpDelta !== 0 && (
          <div className="kicker" style={{
            color: rpDelta > 0 ? "var(--green)" : "var(--red)",
          }}>
            {rpDelta > 0 ? "+" : ""}{rpDelta} RP
          </div>
        )}
      </div>

      {/* Two-column grid */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "minmax(0, 1.1fr) minmax(0, 1fr)",
        gap: 22,
        alignItems: "start",
      }} className="verdict-grid">

        {/* LEFT — score + message */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <ScorePanel score={score} intent={intent} />

          {/* Message with span highlighting */}
          {!score.forfeit && message && (
            <div className="panel rise-2" style={{ padding: "16px 18px" }}>
              <div className="kicker" style={{ color: "var(--pink)", marginBottom: 10 }}>
                YOUR ATTACK · BEST ATTEMPT
              </div>
              <HighlightedMessage text={message} decision={decision} />
            </div>
          )}

          {/* Intent explainer */}
          <div className="panel rise-2" style={{ padding: "14px 18px" }}>
            <div className="kicker" style={{
              color: intent.attempted ? "var(--cyan)" : "var(--yellow)",
              marginBottom: 8,
            }}>
              INTENT JUDGE
            </div>
            <div style={{ color: "var(--ink-dim)", fontSize: 13, lineHeight: 1.5 }}>
              {intent.explainer}
            </div>
            {intent.reasons && intent.reasons.length > 0 && (
              <div style={{ marginTop: 10, display: "flex", gap: 6, flexWrap: "wrap" }}>
                {intent.reasons.slice(0, 5).map((r, i) => (
                  <span key={i} className="mono" style={{
                    fontSize: 10,
                    padding: "2px 8px",
                    background: "rgba(95, 240, 255, 0.06)",
                    border: "1px solid rgba(95, 240, 255, 0.25)",
                    borderRadius: 3,
                    color: "var(--cyan)",
                  }}>
                    {r.rule}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* RIGHT — anatomy + near-miss */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

          {/* Layer Anatomy (LARGE) */}
          <div className="panel rise-2" style={{ padding: "18px 20px" }}>
            <div style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "baseline",
              marginBottom: 12,
              gap: 10,
              flexWrap: "wrap",
            }}>
              <span className="kicker" style={{ color: "var(--cyan)" }}>
                TEX PIPELINE — LAYER ANATOMY
              </span>
              <span className="micro" style={{ color: "var(--ink-faint)" }}>
                FIRED = CAUGHT · DARK = SLIPPED
              </span>
            </div>
            <LayerAnatomy
              profile={score.profile}
              size="lg"
              showWeights
            />
          </div>

          {/* Near-miss surgical copy */}
          {near && (
            <div className="panel rise-3" style={{
              padding: "18px 20px",
              borderColor: score.verdict === "PERMIT"
                ? "rgba(95, 250, 159, 0.3)"
                : score.verdict === "ABSTAIN"
                ? "rgba(255, 225, 74, 0.3)"
                : "rgba(255, 75, 75, 0.25)",
            }}>
              <div className="kicker" style={{
                color:
                  score.verdict === "PERMIT" ? "var(--green)" :
                  score.verdict === "ABSTAIN" ? "var(--yellow)" :
                  "var(--red)",
                marginBottom: 8,
              }}>
                {near.headline}
              </div>
              <div style={{
                color: "var(--ink)",
                fontSize: 14,
                lineHeight: 1.55,
                marginBottom: near.suggestion ? 10 : 0,
              }}>
                {near.detail}
              </div>
              {near.suggestion && (
                <div style={{
                  paddingTop: 10,
                  borderTop: "1px solid var(--hairline)",
                  color: "var(--ink-dim)",
                  fontSize: 13,
                  lineHeight: 1.55,
                  fontStyle: "italic",
                }}>
                  → {near.suggestion}
                </div>
              )}
            </div>
          )}

          {/* ASI mapping */}
          {(incident.asi || []).length > 0 && (
            <div className="panel rise-3" style={{ padding: "16px 18px" }}>
              <div className="kicker" style={{ color: "var(--violet)", marginBottom: 10 }}>
                OWASP ASI 2026 MAPPING
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {incident.asi.map((c) => (
                  <div key={c} style={{ display: "flex", gap: 10, alignItems: "baseline" }}>
                    <span className="mono" style={{
                      color: "var(--violet)",
                      fontWeight: 600,
                      fontSize: 12,
                      flexShrink: 0,
                      minWidth: 50,
                    }}>
                      {c}
                    </span>
                    <span style={{ color: "var(--ink-dim)", fontSize: 12, lineHeight: 1.5 }}>
                      <strong style={{ color: "var(--ink)" }}>{OWASP_ASI[c]?.title || c}</strong> — {OWASP_ASI[c]?.short || ""}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Action bar */}
      <div style={{
        marginTop: 24,
        padding: 18,
        background: "var(--bg-1)",
        border: "1px solid var(--hairline-2)",
        borderRadius: 10,
        display: "flex",
        gap: 10,
        flexWrap: "wrap",
        justifyContent: "space-between",
        alignItems: "center",
      }} className="rise-3">
        <div className="micro" style={{ color: "var(--ink-faint)" }}>
          {decision?.evidence?.evidence_hash
            ? `EVIDENCE ${decision.evidence.evidence_hash.slice(0, 12)}…`
            : "SIGNED EVIDENCE · OWASP ASI 2026"}
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button onClick={handleShare} disabled={sharing} className="btn-ghost">
            {sharing ? "GENERATING…" : "↗ SHARE"}
          </button>
          <button onClick={onPickAnother} className="btn-ghost">
            PICK ANOTHER
          </button>
          <button onClick={onPlayAgain} className="btn-primary">
            REPLAY THIS ROUND
          </button>
          <button onClick={onHome} className="btn-ghost">
            ← HOME
          </button>
        </div>
      </div>

      <style>{`
        @media (max-width: 900px) {
          .verdict-grid {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </div>
  );
}

/**
 * Highlights spans of the player's message that triggered findings.
 * Backend returns matched_text on each finding; we replace it inline.
 */
function HighlightedMessage({ text, decision }) {
  const findings = decision?.deterministic?.findings || [];
  const matchedTexts = [...new Set(
    findings.map((f) => f.matched_text).filter(Boolean)
  )];

  if (matchedTexts.length === 0) {
    return (
      <div className="mono" style={{
        fontSize: 13,
        lineHeight: 1.6,
        color: "var(--ink-dim)",
        whiteSpace: "pre-wrap",
        wordBreak: "break-word",
      }}>
        {text}
      </div>
    );
  }

  // Build escaped pattern that matches any of the spans
  const escaped = matchedTexts
    .filter((s) => s && s.length >= 2)
    .map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .sort((a, b) => b.length - a.length); // longest first

  if (escaped.length === 0) {
    return (
      <div className="mono" style={{ fontSize: 13, lineHeight: 1.6, color: "var(--ink-dim)", whiteSpace: "pre-wrap" }}>
        {text}
      </div>
    );
  }

  let pattern;
  try {
    pattern = new RegExp(`(${escaped.join("|")})`, "gi");
  } catch {
    return (
      <div className="mono" style={{ fontSize: 13, lineHeight: 1.6, color: "var(--ink-dim)", whiteSpace: "pre-wrap" }}>
        {text}
      </div>
    );
  }

  const parts = text.split(pattern);

  return (
    <div className="mono" style={{
      fontSize: 13,
      lineHeight: 1.65,
      color: "var(--ink)",
      whiteSpace: "pre-wrap",
      wordBreak: "break-word",
    }}>
      {parts.map((part, i) => {
        if (!part) return null;
        const isMatch = escaped.some((m) => m.toLowerCase() === part.toLowerCase());
        if (isMatch) {
          return <span key={i} className="span-fired">{part}</span>;
        }
        return <span key={i}>{part}</span>;
      })}
    </div>
  );
}
