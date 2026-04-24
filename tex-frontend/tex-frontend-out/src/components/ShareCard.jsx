import React, { useState } from "react";
import { tierFor } from "../lib/ranking.js";

export default function ShareCard({ player, result, onClose }) {
  const tier = tierFor(player.rp).current;
  const [copied, setCopied] = useState(false);

  const baseUrl = typeof window !== "undefined" ? window.location.origin : "https://texaegis.com";
  const duelUrl = `${baseUrl}/?duel=${result.incident.id}&from=${encodeURIComponent(player.handle || "anon")}&rp=${player.rp}`;

  const shareText =
    `I bypassed Tex — the AI content-layer gate.
Incident: ${result.incident.name}
Tier: ${tier.name} · ${player.rp.toLocaleString()} RP
Think you can beat @${player.handle || "anonymous"}? ${duelUrl}`;

  async function copy() {
    try {
      await navigator.clipboard.writeText(shareText);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {}
  }

  function tweet() {
    const url = `https://twitter.com/intent/tweet?text=${encodeURIComponent(shareText)}`;
    window.open(url, "_blank", "noreferrer");
  }
  function linkedin() {
    const url = `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(duelUrl)}`;
    window.open(url, "_blank", "noreferrer");
  }

  return (
    <div style={{
      position: "fixed",
      inset: 0,
      background: "rgba(6, 7, 14, 0.88)",
      backdropFilter: "blur(10px)",
      zIndex: 70,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: 16,
    }}>
      <div className="panel rise" style={{
        maxWidth: 540,
        width: "100%",
        padding: 0,
        overflow: "hidden",
        borderColor: "var(--pink)",
      }}>
        <div style={{
          padding: "28px 28px 24px",
          background: "radial-gradient(ellipse 80% 60% at 50% 0%, rgba(255,61,122,0.18), transparent 70%)",
          borderBottom: "1px solid var(--hairline-2)",
        }}>
          <div className="kicker" style={{ color: "var(--pink)", marginBottom: 8 }}>
            ⚔ CHALLENGE YOUR COWORKERS
          </div>
          <div className="display" style={{ fontSize: 28, lineHeight: 1.1 }}>
            DRAG THEM IN. WATCH THEM LOSE.
          </div>
        </div>

        <div style={{ padding: 20 }}>
          <div className="mono" style={{
            padding: 16,
            background: "var(--bg-2)",
            border: "1px solid var(--hairline-2)",
            borderRadius: 6,
            fontSize: 12,
            lineHeight: 1.7,
            color: "var(--ink-dim)",
            whiteSpace: "pre-wrap",
            marginBottom: 14,
          }}>
            {shareText}
          </div>

          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button onClick={copy} className="btn-primary">
              {copied ? "✓ COPIED" : "COPY TEXT"}
            </button>
            <button onClick={tweet} className="btn-ghost">𝕏 POST</button>
            <button onClick={linkedin} className="btn-ghost">LINKEDIN</button>
            <button onClick={onClose} style={{
              marginLeft: "auto",
              padding: "10px 14px",
              color: "var(--ink-faint)",
              fontFamily: "var(--font-mono)",
              fontSize: 11,
              letterSpacing: "0.12em",
              textTransform: "uppercase",
            }}>
              CLOSE
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
