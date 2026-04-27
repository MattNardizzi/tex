import React, { useEffect, useState, useRef } from "react";
import { submitDailyScore, getDailyLeaderboard, getHandle, setHandle } from "../lib/leaderboard.js";
import { todayKey } from "../lib/dailyShift.js";
import { SURFACES } from "../lib/messages.js";
import { rankUpSfx } from "../lib/sounds.js";

/*
  ShiftReport — the screenshot moment.
  ─────────────────────────────────────
  This is what the player shares. Every element on this page has been
  weighed for "would a stranger scrolling LinkedIn click in?"

  The headline payload:
    "I was 10x slower than Tex" → quantified self-burn
    Breach footnotes: "Tex would have caught it in 180ms" → product flex

  We ALSO lock the player's first daily submission here so they
  can't farm scores on the daily leaderboard.
*/

export default function ShiftReport({ result, mode = "daily", onPlayAgain, onHome }) {
  const [submitted, setSubmitted] = useState(null); // saved entry on first submit
  const [rank, setRank] = useState(null);
  const [handle, setHandleLocal] = useState(getHandle());
  const [showHandlePrompt, setShowHandlePrompt] = useState(false);
  const submittedRef = useRef(false);

  // Submit on first mount (daily only)
  useEffect(() => {
    if (mode !== "daily" || submittedRef.current) return;
    submittedRef.current = true;
    if (!handle) {
      setShowHandlePrompt(true);
    } else {
      const entry = submitDailyScore({ score: result, handle });
      setSubmitted(entry);
      const lb = getDailyLeaderboard();
      setRank(lb.myRank);
      rankUpSfx();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function handleConfirmHandle(h) {
    const cleaned = setHandle(h);
    setHandleLocal(cleaned);
    setShowHandlePrompt(false);
    const entry = submitDailyScore({ score: result, handle: cleaned });
    setSubmitted(entry);
    const lb = getDailyLeaderboard();
    setRank(lb.myRank);
    rankUpSfx();
  }

  const verdictRating = ratingMeta(result.rating);

  return (
    <div style={{
      minHeight: "100vh",
      width: "100%",
      padding: "var(--pad-page)",
      maxWidth: 980,
      margin: "0 auto",
    }}>
      {/* ── Header ─────────────────────────────────────────────────── */}
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
        <div className="kicker" style={{ color: verdictRating.color }}>
          SHIFT REPORT · {mode === "daily" ? `DAILY · ${todayKey()}` : "TRAINING"}
        </div>
        <button onClick={onHome} className="micro" style={{
          color: "var(--ink-faint)",
          padding: "8px 12px",
          border: "1px solid var(--hairline-2)",
          borderRadius: 4,
        }}>
          ← HOME
        </button>
      </div>

      {/* ── Headline ───────────────────────────────────────────────── */}
      <div className="rise" style={{ marginBottom: 28 }}>
        <div className="micro" style={{ color: "var(--ink-faint)", marginBottom: 8 }}>
          FINAL SCORE
        </div>
        <div className="display punch" style={{
          fontSize: "clamp(64px, 14vw, 160px)",
          lineHeight: 0.85,
          color: verdictRating.color,
          textShadow: `0 0 32px ${verdictRating.glow}`,
        }}>
          {result.total}
        </div>
        <div style={{
          marginTop: 14,
          display: "flex",
          alignItems: "baseline",
          gap: 14,
          flexWrap: "wrap",
        }}>
          <span className="display" style={{
            fontSize: "clamp(20px, 4vw, 32px)",
            color: verdictRating.color,
            letterSpacing: "0.06em",
          }}>
            RATING · {result.rating}
          </span>
          {rank && (
            <span className="micro" style={{
              color: "var(--ink)",
              padding: "6px 12px",
              border: "1px solid var(--pink)",
              background: "rgba(255, 61, 122, 0.08)",
              borderRadius: 4,
            }}>
              YOU RANKED <span className="tabular" style={{ color: "var(--pink)", fontWeight: 700 }}>#{rank}</span> ON TODAY'S BOARD
            </span>
          )}
        </div>
      </div>

      {/* ── The roast — quantified self-burn ───────────────────────── */}
      <div className="rise-2 panel" style={{
        padding: "20px 24px",
        marginBottom: 28,
        background: "linear-gradient(135deg, rgba(255, 61, 122, 0.06) 0%, rgba(95, 240, 255, 0.04) 100%)",
        border: "1px solid rgba(255, 61, 122, 0.25)",
      }}>
        <div className="kicker" style={{ color: "var(--pink)", marginBottom: 10 }}>
          THE TAPE
        </div>
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
          gap: 18,
        }}>
          <Stat label="ACTIONS" value={result.counts.totalSeen} color="var(--ink)" />
          <Stat label="CAUGHT" value={result.counts.forbid - result.counts.falsePositives} color="var(--green)" />
          <Stat label="MISSED" value={result.counts.breaches} color="var(--red)" pulse={result.counts.breaches > 0} />
          <Stat label="FALSE POSITIVES" value={result.counts.falsePositives} color="var(--yellow)" />
          <Stat label="ACCURACY" value={`${Math.round(result.accuracy * 100)}%`} color="var(--cyan)" />
          <Stat label="AVG RESPONSE" value={`${(result.avgResponseMs / 1000).toFixed(1)}s`} color="var(--ink-dim)" />
        </div>

        {/* The marketing payload line */}
        <div style={{
          marginTop: 22,
          paddingTop: 18,
          borderTop: "1px solid var(--hairline)",
          display: "flex",
          alignItems: "baseline",
          gap: 12,
          flexWrap: "wrap",
        }}>
          <span className="micro" style={{ color: "var(--ink-faint)" }}>TEX</span>
          <span className="mono tabular" style={{ color: "var(--cyan)", fontSize: 14 }}>180ms</span>
          <span className="micro" style={{ color: "var(--ink-faint)" }}>YOU</span>
          <span className="mono tabular" style={{ color: "var(--pink)", fontSize: 14 }}>
            {result.avgResponseMs}ms
          </span>
          <span style={{
            color: "var(--ink-dim)",
            fontSize: 13,
            marginLeft: "auto",
          }}>
            You're <span className="display" style={{ color: "var(--pink)", fontSize: 22 }}>
              {Math.max(1, Math.round(result.avgResponseMs / 180))}x
            </span> slower than Tex.
          </span>
        </div>
      </div>

      {/* ── Breaches: the "would have caught it" footnotes ─────────── */}
      {result.breaches.length > 0 && (
        <div className="rise-3" style={{ marginBottom: 28 }}>
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            marginBottom: 12,
          }}>
            <span style={{
              width: 6, height: 6, borderRadius: "50%",
              background: "var(--red)", boxShadow: "0 0 8px var(--red-glow)",
            }} />
            <span className="kicker" style={{ color: "var(--red)" }}>
              {result.breaches.length} BREACH{result.breaches.length === 1 ? "" : "ES"} · TEX WOULD HAVE CAUGHT
            </span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {result.breaches.map((b, i) => (
              <BreachCard key={i} scored={b} />
            ))}
          </div>
        </div>
      )}

      {/* ── Actions ────────────────────────────────────────────────── */}
      <div className="rise-4" style={{
        display: "flex",
        gap: 12,
        flexWrap: "wrap",
        marginBottom: 28,
      }}>
        <button onClick={() => copyShareText(result, rank)} className="btn-primary">
          COPY POST
        </button>
        <button onClick={onPlayAgain} className="btn-ghost">
          {mode === "daily" ? "TRAINING MODE →" : "PLAY AGAIN →"}
        </button>
        <button onClick={onHome} className="btn-ghost">
          HOME →
        </button>
      </div>

      {/* ── Per-card detail ────────────────────────────────────────── */}
      <details className="rise-4">
        <summary style={{
          cursor: "pointer",
          padding: "12px 16px",
          background: "var(--bg-1)",
          border: "1px solid var(--hairline-2)",
          borderRadius: 6,
          color: "var(--ink-dim)",
          fontFamily: "var(--font-mono)",
          fontSize: 12,
          letterSpacing: "0.14em",
          textTransform: "uppercase",
        }}>
          REVIEW ALL {result.perCard.length} DECISIONS
        </summary>
        <div style={{
          marginTop: 12,
          display: "flex",
          flexDirection: "column",
          gap: 6,
          maxHeight: 480,
          overflowY: "auto",
          padding: 4,
        }}>
          {result.perCard.map((p, i) => <DecisionRow key={i} scored={p} />)}
        </div>
      </details>

      {/* ── Handle prompt ──────────────────────────────────────────── */}
      {showHandlePrompt && (
        <HandlePrompt
          onSave={handleConfirmHandle}
          onSkip={() => {
            setShowHandlePrompt(false);
            const entry = submitDailyScore({ score: result, handle: "anonymous" });
            setSubmitted(entry);
            const lb = getDailyLeaderboard();
            setRank(lb.myRank);
          }}
        />
      )}
    </div>
  );
}

/* ─── Pieces ──────────────────────────────────────────────────────── */

function Stat({ label, value, color, pulse }) {
  return (
    <div>
      <div className="micro" style={{ color: "var(--ink-faint)", marginBottom: 4 }}>{label}</div>
      <div
        className={`display ${pulse ? "pulse" : ""}`}
        style={{ fontSize: 30, color, letterSpacing: "0.04em" }}
      >
        {value}
      </div>
    </div>
  );
}

function BreachCard({ scored }) {
  const m = scored.message;
  const surface = SURFACES[m.surface] || SURFACES.email;
  return (
    <div style={{
      padding: "12px 14px",
      border: "1px solid rgba(255, 75, 75, 0.35)",
      background: "rgba(255, 75, 75, 0.05)",
      borderRadius: 6,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
        <span className="card-glyph" style={{
          background: "rgba(255, 75, 75, 0.12)",
          borderColor: "rgba(255, 75, 75, 0.3)",
          color: "var(--red)",
        }}>{surface.glyph}</span>
        <span className="micro" style={{ color: "var(--red)" }}>
          {surface.label} · MISSED
        </span>
        <span className="micro" style={{ color: "var(--ink-faint)", marginLeft: "auto" }}>
          {m.category.replace(/_/g, " ").toUpperCase()}
        </span>
      </div>
      <div className="mono" style={{ color: "var(--ink)", fontSize: 12, lineHeight: 1.5, marginBottom: 6 }}>
        "{truncate(m.body, 140)}"
      </div>
      <div style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        paddingTop: 8,
        borderTop: "1px solid rgba(255, 75, 75, 0.18)",
        color: "var(--cyan)",
        fontSize: 12,
        fontFamily: "var(--font-mono)",
      }}>
        <span style={{
          width: 5, height: 5, borderRadius: "50%",
          background: "var(--cyan)", boxShadow: "0 0 6px var(--cyan-glow)",
        }} />
        <span>{m.texReason || "Tex blocked this in production."}</span>
      </div>
    </div>
  );
}

function DecisionRow({ scored }) {
  const m = scored.message;
  const surface = SURFACES[m.surface] || SURFACES.email;
  const correct = scored.outcome.startsWith("correct");
  const c = correct ? "var(--green)" : scored.isBreach ? "var(--red)" : "var(--yellow)";
  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "auto auto 1fr auto auto",
      gap: 10,
      alignItems: "center",
      padding: "8px 12px",
      background: "var(--bg-1)",
      border: `1px solid ${correct ? "var(--hairline)" : "rgba(255, 75, 75, 0.25)"}`,
      borderRadius: 4,
    }}>
      <span className="card-glyph" style={{ width: 18, height: 18, fontSize: 11 }}>{surface.glyph}</span>
      <span className="micro" style={{ color: "var(--ink-faint)", fontSize: 9 }}>
        {surface.short.toUpperCase()}
      </span>
      <span className="mono" style={{
        fontSize: 11, color: "var(--ink-dim)",
        whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", minWidth: 0,
      }}>
        {truncate(m.body, 80)}
      </span>
      <span className="micro" style={{ color: c, fontWeight: 600 }}>
        {scored.decision.playerVerdict} → {m.correctVerdict}
      </span>
      <span className="mono tabular" style={{ color: c, fontSize: 11 }}>
        {scored.delta >= 0 ? "+" : ""}{scored.delta}
      </span>
    </div>
  );
}

function HandlePrompt({ onSave, onSkip }) {
  const [v, setV] = useState("");
  return (
    <div style={{
      position: "fixed",
      inset: 0,
      background: "rgba(6, 7, 14, 0.85)",
      backdropFilter: "blur(8px)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      zIndex: 100,
      padding: 20,
    }}>
      <div className="panel rise" style={{
        padding: 24,
        maxWidth: 420,
        width: "100%",
        border: "1px solid rgba(255, 61, 122, 0.35)",
      }}>
        <div className="kicker" style={{ color: "var(--pink)", marginBottom: 8 }}>
          SAVE YOUR RANK
        </div>
        <div className="display" style={{ fontSize: 24, color: "var(--ink)", marginBottom: 14 }}>
          PICK A HANDLE.
        </div>
        <input
          autoFocus
          value={v}
          onChange={(e) => setV(e.target.value.replace(/[^a-z0-9_]/gi, "").slice(0, 18))}
          placeholder="@handle"
          style={{
            width: "100%",
            padding: "12px 14px",
            background: "var(--bg-2)",
            border: "1px solid var(--hairline-2)",
            color: "var(--ink)",
            fontFamily: "var(--font-mono)",
            fontSize: 14,
            borderRadius: 4,
            outline: "none",
            marginBottom: 14,
          }}
          onKeyDown={(e) => { if (e.key === "Enter" && v.trim()) onSave(v.trim()); }}
        />
        <div style={{ display: "flex", gap: 10 }}>
          <button onClick={() => v.trim() && onSave(v.trim())} className="btn-primary" disabled={!v.trim()}>
            SAVE →
          </button>
          <button onClick={onSkip} className="btn-ghost">
            SKIP
          </button>
        </div>
      </div>
    </div>
  );
}

/* ─── Helpers ─────────────────────────────────────────────────────── */
function truncate(s, n) {
  if (!s) return "";
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

function ratingMeta(rating) {
  if (rating === "WARDEN")   return { color: "var(--green)",  glow: "var(--green-glow)"  };
  if (rating === "ANALYST")  return { color: "var(--cyan)",   glow: "var(--cyan-glow)"   };
  if (rating === "OPERATOR") return { color: "var(--yellow)", glow: "var(--yellow-glow)" };
  return                       { color: "var(--pink)",   glow: "var(--pink-glow)"   };
}

function copyShareText(result, rank) {
  const slowdown = Math.max(1, Math.round(result.avgResponseMs / 180));
  const lines = [
    `Just ran a shift at the Tex gate.`,
    ``,
    `Score: ${result.total}`,
    `Rating: ${result.rating}`,
    `Caught: ${result.counts.forbid - result.counts.falsePositives}`,
    `Missed: ${result.counts.breaches}${result.counts.breaches > 0 ? " ← Tex would have caught these in 180ms" : ""}`,
    `I am ${slowdown}x slower than Tex.`,
    ``,
    rank ? `Today's leaderboard: #${rank}` : ``,
    `texaegis.com`,
  ].filter(Boolean);
  const text = lines.join("\n");
  if (typeof navigator !== "undefined" && navigator.clipboard) {
    navigator.clipboard.writeText(text);
  }
}
