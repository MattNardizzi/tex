import React, { useState, useRef, useEffect } from "react";

export default function HandlePrompt({ initial = "", onSave, onSkip }) {
  const [value, setValue] = useState(initial);
  const ref = useRef(null);
  useEffect(() => { ref.current?.focus(); }, []);

  function save() {
    const cleaned = value.replace(/[^a-zA-Z0-9_.]/g, "").slice(0, 24);
    if (cleaned.length < 2) return;
    onSave(cleaned);
  }

  return (
    <div style={{
      position: "fixed",
      inset: 0,
      background: "rgba(6, 7, 14, 0.85)",
      backdropFilter: "blur(8px)",
      zIndex: 60,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: 16,
    }}>
      <div className="panel rise" style={{
        maxWidth: 420,
        width: "100%",
        padding: 24,
        borderColor: "var(--pink)",
        boxShadow: "0 0 48px var(--pink-glow)",
      }}>
        <div className="kicker" style={{ color: "var(--pink)", marginBottom: 6 }}>
          ⚔ YOU BYPASSED TEX
        </div>
        <div className="display" style={{ fontSize: 22, marginBottom: 14, lineHeight: 1.1 }}>
          CLAIM YOUR HANDLE
        </div>
        <div style={{ color: "var(--ink-dim)", fontSize: 13, lineHeight: 1.5, marginBottom: 16 }}>
          Post your rank to the season leaderboard. Send a duel link to your security friends.
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 0, border: "1px solid var(--hairline-2)", borderRadius: 6, background: "var(--bg-2)" }}>
          <span className="mono" style={{ padding: "12px 4px 12px 14px", color: "var(--ink-faint)" }}>@</span>
          <input
            ref={ref}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="yourhandle"
            onKeyDown={(e) => e.key === "Enter" && save()}
            style={{
              flex: 1,
              background: "transparent",
              border: "none",
              outline: "none",
              padding: "12px 14px 12px 0",
              fontFamily: "var(--font-mono)",
              fontSize: 14,
              color: "var(--ink)",
            }}
            maxLength={24}
          />
        </div>
        <div className="micro" style={{ color: "var(--ink-faint)", marginTop: 8 }}>
          LETTERS, NUMBERS, . AND _ · 2–24 CHARS
        </div>
        <div style={{ marginTop: 18, display: "flex", gap: 10 }}>
          <button onClick={save} disabled={value.length < 2} className="btn-primary">
            CLAIM IT →
          </button>
          <button onClick={onSkip} className="micro" style={{ color: "var(--ink-faint)", padding: "10px 14px" }}>
            SKIP
          </button>
        </div>
      </div>
    </div>
  );
}
