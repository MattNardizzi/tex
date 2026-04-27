import React, { useEffect, useState } from "react";
import {
  hasPlayedToday, todayResult, getDailyLeaderboard, getHandle,
} from "../lib/leaderboard.js";
import { msUntilNextShift, formatCountdown } from "../lib/dailyShift.js";

/*
  Hub v11 — Daily Shift entry
  ───────────────────────────
  Hero with Tex avatar + headline. Two CTAs:
    · TODAY'S SHIFT  (the daily, real-score, leaderboard run — ONCE per UTC day)
    · TRAINING       (unlimited practice, doesn't count)

  Below: live daily leaderboard (top 10) + countdown to next shift.

  Footer link to /what-is-tex for the curious.
*/

export default function Hub({ player, onPlayDaily, onPlayTraining, onOpenWhatIsTex, onOpenAsi }) {
  const [played, setPlayed] = useState(false);
  const [result, setResult] = useState(null);
  const [leaderboard, setLeaderboard] = useState({ entries: [], myRank: null, total: 0 });
  const [countdownMs, setCountdownMs] = useState(msUntilNextShift());
  const [handle, setHandleState] = useState("");

  useEffect(() => {
    setPlayed(hasPlayedToday());
    setResult(todayResult());
    setLeaderboard(getDailyLeaderboard());
    setHandleState(getHandle());
  }, []);

  useEffect(() => {
    const id = setInterval(() => setCountdownMs(msUntilNextShift()), 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <div style={{
      minHeight: "100vh",
      width: "100%",
      position: "relative",
      overflow: "hidden",
    }}>
      {/* Ambient grid */}
      <div style={{
        position: "fixed",
        inset: 0,
        pointerEvents: "none",
        backgroundImage: `
          repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(168,174,201,0.025) 39px, rgba(168,174,201,0.025) 40px),
          repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(168,174,201,0.025) 39px, rgba(168,174,201,0.025) 40px)
        `,
        zIndex: 0,
      }} />

      <div className="page" style={{
        padding: "var(--pad-page)",
        position: "relative",
        zIndex: 1,
      }}>
        {/* ── Brand bar ────────────────────────────────────────────── */}
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          paddingBottom: 14,
          borderBottom: "1px solid var(--hairline-2)",
          marginBottom: "clamp(20px, 4vw, 36px)",
          gap: 12,
          flexWrap: "wrap",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <BrandMark />
            <div style={{ lineHeight: 1.2 }}>
              <div className="display" style={{ fontSize: 18, color: "var(--ink)", letterSpacing: "0.06em" }}>
                TEX ARENA
              </div>
              <div className="micro" style={{ color: "var(--ink-faint)" }}>
                AI AGENT GOVERNANCE · DAILY SHIFT
              </div>
            </div>
          </div>

          {handle && (
            <div style={{
              padding: "6px 12px",
              border: "1px solid rgba(255, 61, 122, 0.3)",
              borderRadius: 4,
              background: "rgba(255, 61, 122, 0.05)",
            }}>
              <div className="micro" style={{ color: "var(--ink-faint)", marginBottom: 1 }}>
                YOU
              </div>
              <div className="mono" style={{ fontSize: 12, color: "var(--pink)", fontWeight: 600 }}>
                @{handle}
              </div>
            </div>
          )}
        </div>

        {/* ── HERO ─────────────────────────────────────────────────── */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "minmax(0, 1.1fr) minmax(0, 1fr)",
          gap: "clamp(24px, 5vw, 64px)",
          alignItems: "center",
          minHeight: "min(72vh, 720px)",
        }} className="hero-grid">

          <div className="rise" style={{ minWidth: 0 }}>
            <div style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              padding: "5px 11px",
              border: "1px solid rgba(95, 240, 255, 0.35)",
              borderRadius: 999,
              marginBottom: 22,
              background: "rgba(95, 240, 255, 0.04)",
            }}>
              <span style={{
                width: 6, height: 6, borderRadius: "50%",
                background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan-glow)",
              }} className="pulse" />
              <span className="micro" style={{ color: "var(--cyan)" }}>
                TODAY'S SHIFT · LIVE
              </span>
            </div>

            <h1 className="display" style={{
              fontSize: "clamp(56px, 11vw, 128px)",
              margin: 0,
              lineHeight: 0.85,
              letterSpacing: "-0.01em",
            }}>
              <span style={{ color: "var(--ink)" }}>WORK</span>
              <br />
              <span style={{
                background: "linear-gradient(90deg, var(--pink) 0%, var(--yellow) 50%, var(--cyan) 100%)",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
                backgroundClip: "text",
              }}>
                THE GATE.
              </span>
            </h1>

            <p style={{
              maxWidth: 460,
              color: "var(--ink-dim)",
              fontSize: "clamp(16px, 2vw, 19px)",
              lineHeight: 1.5,
              margin: "22px 0 28px 0",
            }}>
              You're <span style={{ color: "var(--ink)", fontWeight: 600 }}>Tex's operator</span>.
              {" "}Outbound AI agent actions are coming down the line. Read fast. Decide faster.
              <br />
              Permit the clean ones. Block the leaks.
            </p>

            {/* CTAs */}
            <div style={{ display: "flex", flexDirection: "column", gap: 12, alignItems: "flex-start" }}>
              <button
                onClick={onPlayDaily}
                className="btn-big"
                disabled={played}
                style={{ fontSize: 17, padding: "18px 32px" }}
              >
                {played ? "SHIFT COMPLETE" : "PLAY TODAY'S SHIFT →"}
              </button>

              <button onClick={onPlayTraining} className="btn-ghost" style={{ fontSize: 12 }}>
                {played ? "PLAY AGAIN (TRAINING) →" : "TRAINING MODE →"}
              </button>
            </div>

            <div style={{ marginTop: 18, display: "flex", gap: 14, flexWrap: "wrap", alignItems: "center" }}>
              <div className="micro" style={{ color: "var(--ink-faint)" }}>
                90 SECONDS · 32 ACTIONS · ONE SHOT PER DAY
              </div>
              {played && result && (
                <div className="micro" style={{
                  color: "var(--pink)",
                  padding: "4px 10px",
                  border: "1px solid rgba(255, 61, 122, 0.3)",
                  borderRadius: 4,
                  background: "rgba(255, 61, 122, 0.05)",
                }}>
                  YOU · {result.total} PTS · {result.rating}
                </div>
              )}
            </div>

            <div className="micro" style={{
              color: "var(--ink-faint)",
              marginTop: 14,
              letterSpacing: "0.16em",
            }}>
              NEXT SHIFT IN <span className="tabular" style={{ color: "var(--cyan)" }}>{formatCountdown(countdownMs)}</span>
            </div>
          </div>

          {/* Right: Tex avatar */}
          <div className="rise-2" style={{
            position: "relative",
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
            minWidth: 0,
          }}>
            <TexAvatar />
          </div>
        </div>

        {/* ── DAILY LEADERBOARD ────────────────────────────────────── */}
        <div style={{
          marginTop: "clamp(40px, 7vw, 80px)",
          marginBottom: "clamp(32px, 5vw, 56px)",
        }}>
          <div style={{
            display: "flex",
            alignItems: "baseline",
            justifyContent: "space-between",
            marginBottom: 14,
            gap: 12,
            flexWrap: "wrap",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{
                width: 6, height: 6, borderRadius: "50%",
                background: "var(--pink)", boxShadow: "0 0 8px var(--pink-glow)",
              }} className="pulse" />
              <span className="kicker" style={{ color: "var(--pink)" }}>
                TODAY'S BOARD · TOP 10
              </span>
            </div>
            {leaderboard.myRank && (
              <span className="micro" style={{ color: "var(--ink-faint)" }}>
                YOU RANK <span className="tabular" style={{ color: "var(--pink)" }}>#{leaderboard.myRank}</span> OF {leaderboard.total}
              </span>
            )}
          </div>
          <Leaderboard entries={leaderboard.entries.slice(0, 10)} />
        </div>

        {/* ── "What is Tex" link ───────────────────────────────────── */}
        <div style={{
          padding: "20px 22px",
          background: "var(--bg-1)",
          border: "1px solid var(--hairline-2)",
          borderRadius: 6,
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 14,
          flexWrap: "wrap",
          marginBottom: "clamp(28px, 5vw, 48px)",
        }}>
          <div style={{ minWidth: 0 }}>
            <div className="kicker" style={{ color: "var(--violet)", marginBottom: 4 }}>
              UNDER THE HOOD
            </div>
            <div style={{ color: "var(--ink-dim)", fontSize: 14, lineHeight: 1.5 }}>
              The game uses real Tex governance categories — secrets, PII, commitments, regulated content, prompt injection.
              <br className="hide-mobile" />
              The product evaluates these in production at <span style={{ color: "var(--cyan)" }}>~180ms</span>. You're not even close.
            </div>
          </div>
          <button onClick={onOpenWhatIsTex} className="btn-ghost" style={{
            fontSize: 13,
            padding: "10px 16px",
            whiteSpace: "nowrap",
          }}>
            WHAT IS TEX →
          </button>
        </div>

        {/* ── Footer ───────────────────────────────────────────────── */}
        <div style={{
          paddingTop: 20,
          borderTop: "1px solid var(--hairline-2)",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 14,
          flexWrap: "wrap",
        }}>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <BrandMark size={14} />
            <span className="micro" style={{ color: "var(--ink-faint)" }}>
              VORTEXBLACK · TEX AEGIS
            </span>
          </div>
          {onOpenAsi && (
            <button onClick={onOpenAsi} className="micro" style={{
              color: "var(--cyan)",
              padding: "6px 10px",
              border: "1px solid rgba(95, 240, 255, 0.25)",
              borderRadius: 4,
            }}>
              OWASP ASI REFERENCE →
            </button>
          )}
        </div>
      </div>

      <style>{`
        @media (max-width: 900px) {
          .hero-grid {
            grid-template-columns: 1fr !important;
            min-height: auto !important;
          }
          .hero-grid > div:first-child {
            order: 2;
          }
          .hero-grid > div:last-child {
            order: 1;
          }
        }
        @media (max-width: 600px) {
          .hide-mobile { display: none !important; }
        }
      `}</style>
    </div>
  );
}

/* ─── Tex avatar ─────────────────────────────────────────────────── */
function TexAvatar() {
  return (
    <div style={{
      position: "relative",
      width: "100%",
      maxWidth: 540,
      aspectRatio: "4 / 5",
    }}>
      <div style={{
        position: "absolute",
        inset: "-4%",
        background: "radial-gradient(ellipse at center 35%, rgba(95, 240, 255, 0.15), transparent 60%)",
        filter: "blur(20px)",
        pointerEvents: "none",
      }} />
      <div style={{
        position: "relative",
        width: "100%",
        height: "100%",
        borderRadius: 8,
        overflow: "hidden",
        background: "var(--bg-0)",
        border: "1px solid var(--hairline-2)",
        boxShadow: "0 0 40px rgba(95, 240, 255, 0.08), inset 0 0 60px rgba(0,0,0,0.4)",
      }}>
        <img
          src="/tex/tex-aegis.jpg"
          alt="Tex"
          style={{
            width: "100%",
            height: "100%",
            objectFit: "cover",
            objectPosition: "center 18%",
            display: "block",
          }}
        />
        <div className="scan" style={{ top: 0 }} />
        <div style={{
          position: "absolute",
          bottom: 12,
          left: 14,
          padding: "5px 10px",
          background: "rgba(0, 0, 0, 0.55)",
          backdropFilter: "blur(6px)",
          border: "1px solid rgba(95, 240, 255, 0.35)",
          borderRadius: 4,
        }}>
          <div className="micro" style={{ color: "var(--cyan)", fontSize: 9 }}>
            TEX // AEGIS
          </div>
          <div className="mono" style={{ color: "var(--ink)", fontSize: 11, fontWeight: 600, marginTop: 1 }}>
            STATUS: WATCHING
          </div>
        </div>
      </div>
    </div>
  );
}

/* ─── Leaderboard ────────────────────────────────────────────────── */
function Leaderboard({ entries }) {
  return (
    <div className="panel" style={{ padding: 4, overflow: "hidden" }}>
      {entries.map((e, i) => (
        <div key={e.handle + i} style={{
          display: "grid",
          gridTemplateColumns: "44px 1fr auto auto auto",
          alignItems: "center",
          gap: 12,
          padding: "10px 14px",
          borderTop: i === 0 ? "none" : "1px solid var(--hairline)",
          background: e.you ? "rgba(255, 61, 122, 0.06)" : "transparent",
        }}>
          <span className="display" style={{
            fontSize: 16,
            color: i === 0 ? "var(--yellow)" : i < 3 ? "var(--ink)" : "var(--ink-faint)",
          }}>
            #{i + 1}
          </span>
          <span className="mono" style={{
            fontSize: 12,
            color: e.you ? "var(--pink)" : "var(--ink)",
            fontWeight: e.you ? 700 : 500,
          }}>
            @{e.handle}{e.you ? " · YOU" : ""}
          </span>
          <span className="micro hide-mobile" style={{ color: "var(--ink-faint)" }}>
            {e.rating}
          </span>
          <span className="micro" style={{ color: "var(--red)" }}>
            {e.breaches} BREACH{e.breaches === 1 ? "" : "ES"}
          </span>
          <span className="display tabular" style={{
            fontSize: 18,
            color: e.you ? "var(--pink)" : "var(--cyan)",
          }}>
            {e.total}
          </span>
        </div>
      ))}
    </div>
  );
}

/* ─── BrandMark ──────────────────────────────────────────────────── */
function BrandMark({ size = 22 }) {
  return (
    <div style={{
      width: size,
      height: size,
      position: "relative",
      flexShrink: 0,
    }}>
      <div style={{
        position: "absolute",
        inset: 0,
        border: "1.5px solid var(--pink)",
        transform: "rotate(45deg)",
        boxShadow: "0 0 10px var(--pink-glow)",
      }} />
      <div style={{
        position: "absolute",
        inset: size * 0.28,
        background: "var(--pink)",
        transform: "rotate(45deg)",
      }} />
    </div>
  );
}
