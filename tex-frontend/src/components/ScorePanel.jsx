import React from "react";
import { LAYER_LABELS } from "../lib/stealthScore.js";

/*
  ScorePanel — the headline number on the verdict screen.

  Shows three side-by-side panels:
    - INTENT   : did the player attempt the goal? (gate)
    - VERDICT  : Tex's PERMIT/ABSTAIN/FORBID
    - STEALTH  : weighted layer-firing score (the headline)

  Big total in the center. Forfeit state collapses to "FORFEIT".
*/

export default function ScorePanel({ score, intent, animated = true }) {
  if (score.forfeit) {
    return <ForfeitPanel intent={intent} />;
  }

  const verdict = score.verdict;
  const verdictColor =
    verdict === "PERMIT" ? "var(--green)" :
    verdict === "ABSTAIN" ? "var(--yellow)" :
    "var(--red)";
  const verdictGlow =
    verdict === "PERMIT" ? "var(--green-glow)" :
    verdict === "ABSTAIN" ? "var(--yellow-glow)" :
    "var(--red-glow)";

  return (
    <div className={`panel ${animated ? "rise" : ""}`} style={{
      padding: "20px 24px",
      background: "linear-gradient(180deg, var(--bg-1), var(--bg-0))",
    }}>
      <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 14 }}>
        ROUND RESULT
      </div>

      {/* Big number */}
      <div className={animated ? "count-up" : ""} style={{
        display: "flex",
        alignItems: "baseline",
        justifyContent: "space-between",
        gap: 14,
        marginBottom: 18,
        flexWrap: "wrap",
      }}>
        <div>
          <div className="display tabular" style={{
            fontSize: "clamp(56px, 12vw, 96px)",
            color: verdictColor,
            textShadow: `0 0 32px ${verdictGlow}`,
            lineHeight: 0.85,
          }}>
            {score.total}
          </div>
          <div className="micro" style={{ color: "var(--ink-faint)", marginTop: 4 }}>
            STEALTH SCORE
          </div>
        </div>
        <div style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "flex-end",
          gap: 4,
          minWidth: 110,
        }}>
          <span className="display" style={{ fontSize: 24, color: verdictColor, lineHeight: 1 }}>
            {verdict}
          </span>
          <span className="micro" style={{ color: "var(--ink-faint)" }}>
            TEX VERDICT
          </span>
        </div>
      </div>

      {/* Three breakdown cells */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(3, 1fr)",
        gap: 10,
        paddingTop: 16,
        borderTop: "1px solid var(--hairline)",
      }} className="breakdown-grid">
        <BreakdownCell
          label="INTENT"
          value={`${(intent.score * 100).toFixed(0)}%`}
          color={intent.attempted ? "var(--cyan)" : "var(--ink-faint)"}
          sub={intent.attempted ? "CONFIRMED" : "FAILED"}
        />
        <BreakdownCell
          label="STEALTH"
          value={`${(score.stealthRaw * 100).toFixed(0)}%`}
          color={
            score.stealthRaw >= 0.7 ? "var(--green)" :
            score.stealthRaw >= 0.4 ? "var(--yellow)" :
            "var(--red)"
          }
          sub={`×${score.verdictMultiplier.toFixed(2)} verdict`}
        />
        <BreakdownCell
          label="TIER"
          value={`×${score.tierMultiplier.toFixed(1)}`}
          color="var(--violet)"
          sub="DIFFICULTY"
        />
      </div>

      <style>{`
        @media (max-width: 540px) {
          .breakdown-grid {
            grid-template-columns: 1fr 1fr !important;
          }
          .breakdown-grid > :nth-child(3) {
            grid-column: 1 / -1 !important;
          }
        }
      `}</style>
    </div>
  );
}

function BreakdownCell({ label, value, color, sub }) {
  return (
    <div style={{
      padding: "10px 12px",
      background: "var(--bg-2)",
      borderRadius: 6,
      border: "1px solid var(--hairline)",
    }}>
      <div className="micro" style={{ color: "var(--ink-faint)" }}>{label}</div>
      <div className="display tabular" style={{
        fontSize: 24,
        color,
        marginTop: 2,
        lineHeight: 1,
      }}>
        {value}
      </div>
      <div className="micro" style={{
        color: "var(--ink-faint)",
        marginTop: 4,
        fontSize: 9,
      }}>
        {sub}
      </div>
    </div>
  );
}

function ForfeitPanel({ intent }) {
  return (
    <div className="panel rise" style={{
      padding: "24px",
      borderColor: "rgba(255, 225, 74, 0.3)",
      background: "linear-gradient(180deg, rgba(255, 225, 74, 0.04), var(--bg-0))",
    }}>
      <div className="kicker" style={{ color: "var(--yellow)", marginBottom: 12 }}>
        FORFEIT · INTENT GATE FAILED
      </div>
      <div className="display" style={{
        fontSize: "clamp(32px, 7vw, 48px)",
        color: "var(--yellow)",
        lineHeight: 1,
        marginBottom: 12,
      }}>
        DOES NOT COUNT
      </div>
      <p style={{
        color: "var(--ink-dim)",
        fontSize: 14,
        lineHeight: 1.55,
        margin: 0,
      }}>
        {intent.explainer}
      </p>
      <div className="micro" style={{
        marginTop: 14,
        color: "var(--ink-faint)",
      }}>
        ATTEMPTS UNCHANGED · TRY AGAIN WITH A REAL ATTACK
      </div>
    </div>
  );
}
