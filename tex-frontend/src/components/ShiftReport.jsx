import React, { useEffect, useState, useRef } from "react";
import {
  submitDailyScore, getDailyLeaderboard, getHandle, setHandle,
  submitArcadeScore, fetchDailyLeaderboard,
} from "../lib/leaderboard.js";
import { todayKey } from "../lib/dailyShift.js";
import { SURFACES } from "../lib/messages.js";
import { rankUpSfx } from "../lib/sounds.js";

/*
  ShiftReport v13 — cinema-style score card
  ─────────────────────────────────────────
  - Letterbox bars slide in
  - Score punches in massive, slowdown line is the centerpiece
  - Breach footnotes show what Tex would have caught
  - Copy-share generates LinkedIn-ready text
*/

export default function ShiftReport({ result, mode = "daily", onPlayAgain, onHome, onOpenWhatIsTex }) {
  const [, setSubmitted] = useState(null);
  const [rank, setRank] = useState(null);
  const [handle, setHandleLocal] = useState(getHandle());
  const [showHandlePrompt, setShowHandlePrompt] = useState(false);
  const [copied, setCopied] = useState(false);
  const [submitState, setSubmitState] = useState("idle"); // idle | sending | ok | err
  const [submitNote, setSubmitNote] = useState("");
  const submittedRef = useRef(false);

  // Push the run to the backend. Optimistic local first, then remote.
  async function pushScoreToBackend(cleanedHandle) {
    setSubmitState("sending");
    // Optimistic local entry so the leaderboard renders the player
    // immediately even if the backend is slow.
    const local = submitDailyScore({ score: result, handle: cleanedHandle });
    setSubmitted(local);

    if (mode === "arcade") {
      const resp = await submitArcadeScore({
        result,
        handle: cleanedHandle,
      });
      if (resp.ok) {
        setSubmitState("ok");
        setSubmitNote(resp.label || "");
        setRank(resp.your_rank);
        // Refetch the live list so the rendered leaderboard reflects
        // the new authoritative state.
        const live = await fetchDailyLeaderboard(undefined, cleanedHandle);
        if (live) setRank(live.myRank ?? resp.your_rank);
      } else {
        setSubmitState("err");
        setSubmitNote(`couldn't post score: ${resp.error}`);
        // Fall back to local-only ranking so the UI still shows something.
        const lb = getDailyLeaderboard();
        setRank(lb.myRank);
      }
    } else {
      // Non-arcade modes (legacy/training) — local-only as before.
      const lb = getDailyLeaderboard();
      setRank(lb.myRank);
    }
    rankUpSfx();
  }

  useEffect(() => {
    if (mode === "training" || submittedRef.current) return;
    submittedRef.current = true;
    if (!handle) {
      setShowHandlePrompt(true);
    } else {
      pushScoreToBackend(handle);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function handleConfirmHandle(h) {
    const cleaned = setHandle(h);
    setHandleLocal(cleaned);
    setShowHandlePrompt(false);
    pushScoreToBackend(cleaned);
  }

  const verdictMeta = ratingMeta(result.rating);
  const slowdown = Math.max(1, Math.round(result.avgResponseMs / 178));

  return (
    <div className="report-stage">
      <div className="hub-haze" />
      <div className="hub-grid-bg" />
      <div className="report-letterbox top" />
      <div className="report-letterbox bottom" />

      <div className="report-frame">
        {/* Top bar */}
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          paddingBottom: 14,
          borderBottom: "1px solid var(--rule-2)",
          marginBottom: 36,
          gap: 12,
          flexWrap: "wrap",
        }}>
          <div className="kicker" style={{ color: verdictMeta.color }}>
            ▸ SHIFT REPORT · {mode === "daily" ? `DAILY · ${todayKey()}` : mode === "arcade" ? "ARCADE · GATE DEFENSE" : "TRAINING"}
          </div>
          <button onClick={onHome} className="bail-btn">← HOME</button>
        </div>

        {/* Score punch-in */}
        <div className="rise" style={{ marginBottom: 10 }}>
          <div className="micro" style={{ color: "var(--ink-faint)", marginBottom: 14 }}>
            FINAL SCORE
          </div>
          <div className="report-score punch" style={{
            color: verdictMeta.color,
            textShadow: `0 0 50px ${verdictMeta.glow}, 0 0 140px ${verdictMeta.glow}`,
          }}>
            {result.total >= 0 ? result.total : `−${Math.abs(result.total)}`}
          </div>
          <div style={{
            marginTop: 18,
            display: "flex",
            alignItems: "center",
            gap: 14,
            flexWrap: "wrap",
          }}>
            <span className="display" style={{
              fontSize: "clamp(28px, 4.5vw, 44px)",
              color: verdictMeta.color,
              letterSpacing: "0.08em",
            }}>
              ▸ {result.rating}
            </span>
            {rank && (
              <span style={{
                padding: "10px 16px",
                border: "1px solid var(--pink)",
                background: "rgba(255, 61, 122, 0.06)",
                borderRadius: 3,
                fontFamily: "var(--font-mono)",
                fontSize: 11,
                letterSpacing: "0.16em",
                textTransform: "uppercase",
                fontWeight: 700,
              }}>
                RANK <span className="tabular" style={{ color: "var(--pink)", fontSize: 16 }}>#{rank}</span> ON TODAY'S BOARD
              </span>
            )}
            {mode === "arcade" && submitState !== "idle" && (
              <span style={{
                padding: "8px 12px",
                border: "1px solid " + (submitState === "ok"
                  ? "var(--green)"
                  : submitState === "err"
                    ? "rgba(255, 71, 71, 0.5)"
                    : "var(--rule-cyan)"),
                background: submitState === "ok"
                  ? "rgba(95, 250, 159, 0.06)"
                  : submitState === "err"
                    ? "rgba(255, 71, 71, 0.05)"
                    : "rgba(95, 240, 255, 0.04)",
                borderRadius: 3,
                fontFamily: "var(--font-mono)",
                fontSize: 10,
                letterSpacing: "0.16em",
                textTransform: "uppercase",
                color: submitState === "ok"
                  ? "var(--green)"
                  : submitState === "err"
                    ? "var(--red)"
                    : "var(--cyan)",
              }}>
                {submitState === "sending" && "POSTING SCORE…"}
                {submitState === "ok" && `POSTED${submitNote ? " · " + submitNote : ""}`}
                {submitState === "err" && (submitNote || "score not posted")}
              </span>
            )}
          </div>
        </div>

        {/* THE CENTERPIECE — slowdown vs Tex (or survival time for arcade) */}
        {mode === "arcade" ? (
          <div className="rise-2" style={{
            margin: "44px 0 36px 0",
            padding: "28px 32px",
            border: "1px solid var(--rule-pink)",
            borderRadius: 4,
            background:
              "linear-gradient(135deg, rgba(255, 216, 61, 0.07) 0%, rgba(95, 240, 255, 0.05) 100%), var(--bg-panel)",
            position: "relative",
            overflow: "hidden",
          }}>
            <div style={{
              position: "absolute", top: 0, left: 0, right: 0, height: 1,
              background: "linear-gradient(90deg, transparent, var(--yellow), transparent)",
            }} />
            <div className="kicker" style={{ color: "var(--yellow)", marginBottom: 12 }}>
              ▸ TIME ON THE GATE
            </div>
            <div style={{
              display: "flex",
              alignItems: "baseline",
              gap: "clamp(20px, 4vw, 56px)",
              flexWrap: "wrap",
            }}>
              <div>
                <div className="micro" style={{ color: "var(--ink-faint)", marginBottom: 4 }}>SURVIVED</div>
                <div className="display tabular" style={{
                  fontSize: "clamp(56px, 9vw, 96px)",
                  color: "var(--cyan)",
                  lineHeight: 1,
                }}>
                  {Math.floor((result._arcadeSurvivedMs || 0) / 1000)}<span style={{ fontSize: "0.4em", opacity: 0.7 }}>S</span>
                </div>
              </div>
              <div>
                <div className="micro" style={{ color: "var(--ink-faint)", marginBottom: 4 }}>PEAK SPEED</div>
                <div className="display tabular" style={{
                  fontSize: "clamp(56px, 9vw, 96px)",
                  color: "var(--yellow)",
                  lineHeight: 1,
                }}>
                  {(result._arcadePeakSpeed || 1).toFixed(1)}<span style={{ fontSize: "0.4em", opacity: 0.7 }}>×</span>
                </div>
              </div>
            </div>

            {/* Action buttons — all six live inside the score panel so the
                player sees them at peak attention, immediately after the
                score figures, instead of buried at the bottom of the page.
                Order is intentional: trial (primary conversion), leaderboard,
                explainer, replay, copy-share, home. flexWrap handles narrow
                viewports. */}
            <div style={{
              marginTop: 22,
              paddingTop: 22,
              borderTop: "1px solid var(--rule-2)",
              display: "flex",
              gap: 10,
              flexWrap: "wrap",
            }}>
              <a
                href="mailto:matt@texaegis.com?subject=Tex%20%E2%80%94%20Free%20Two-Week%20Integration%20Trial&body=Hi%20Matt%2C%20we%27d%20like%20to%20try%20Tex%20for%20two%20weeks.%0A%0ACompany%3A%20%5B%5D%0AAI%20stack%20%2F%20gateway%3A%20%5B%5D%20(Portkey%2C%20LiteLLM%2C%20MCP%2C%20AgentKit%2C%20custom%2C%20etc.)%0ASurfaces%20we%27d%20put%20Tex%20in%20front%20of%3A%20%5B%5D%20(email%2C%20Slack%2C%20DB%2C%20deploys%2C%20etc.)%0AVolume%2Fday%3A%20%5B%5D"
                className="btn-cta"
                aria-label="Start a free two-week Tex integration trial"
                style={{
                  padding: "12px 18px",
                  minHeight: 44,
                  fontSize: "clamp(13px, 1.5vw, 15px)",
                  textDecoration: "none",
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                FREE 2-WEEK TRIAL →
              </a>
              <a
                href="/#leaderboard"
                className="btn-leaderboard"
                aria-label="View today's arcade leaderboard"
                style={{
                  padding: "12px 18px",
                  minHeight: 44,
                  fontSize: "clamp(13px, 1.5vw, 15px)",
                }}
              >
                <span className="btn-leaderboard-label">LEADERBOARD →</span>
                <span className="btn-leaderboard-meta">today's top operators</span>
              </a>
              <button
                onClick={onOpenWhatIsTex}
                className="btn-explainer"
                aria-label="What is Tex"
                style={{
                  padding: "12px 18px",
                  minHeight: 44,
                  fontSize: "clamp(13px, 1.5vw, 15px)",
                }}
              >
                <span className="btn-explainer-label">WHAT IS TEX? →</span>
                <span className="btn-explainer-meta">5 things that make Tex different</span>
              </button>
              <button
                onClick={onPlayAgain}
                className="btn-replay"
                aria-label="Play again"
                style={{
                  padding: "12px 18px",
                  minHeight: 44,
                  fontSize: "clamp(13px, 1.5vw, 15px)",
                }}
              >
                <span className="btn-replay-label">PLAY AGAIN →</span>
                <span className="btn-replay-meta">defend the gate again</span>
              </button>
              <button
                onClick={() => copyShareText(result, rank, setCopied)}
                className="btn-ghost"
                style={{
                  padding: "12px 18px",
                  minHeight: 44,
                  fontSize: "clamp(13px, 1.5vw, 15px)",
                }}
              >
                {copied ? "✓ COPIED" : "COPY POST"}
              </button>
              <button
                onClick={onHome}
                className="btn-ghost"
                style={{
                  padding: "12px 18px",
                  minHeight: 44,
                  fontSize: "clamp(13px, 1.5vw, 15px)",
                }}
              >
                HOME →
              </button>
            </div>

            <div style={{
              marginTop: 18,
              paddingTop: 18,
              borderTop: "1px solid var(--rule-2)",
              color: "var(--ink-dim)",
              fontSize: "clamp(14px, 2vw, 17px)",
              lineHeight: 1.5,
            }}>
              Tex evaluates every action in <b style={{ color: "var(--cyan)" }}>178ms</b> and never gets tired.
              <br />You held the gate for <b style={{ color: "var(--ink)" }}>{Math.floor((result._arcadeSurvivedMs || 0) / 1000)} seconds</b> against {result.counts?.totalSeen || 0} actions.
            </div>
          </div>
        ) : (
        <div className="rise-2" style={{
          margin: "44px 0 36px 0",
          padding: "28px 32px",
          border: "1px solid var(--rule-pink)",
          borderRadius: 4,
          background:
            "linear-gradient(135deg, rgba(255, 61, 122, 0.07) 0%, rgba(95, 240, 255, 0.05) 100%), var(--bg-panel)",
          position: "relative",
          overflow: "hidden",
        }}>
          {/* Top hairline */}
          <div style={{
            position: "absolute", top: 0, left: 0, right: 0, height: 1,
            background: "linear-gradient(90deg, transparent, var(--pink), transparent)",
          }} />
          <div className="kicker" style={{ color: "var(--pink)", marginBottom: 12 }}>
            ▸ TEX VS YOU
          </div>
          <div style={{
            display: "flex",
            alignItems: "baseline",
            gap: "clamp(20px, 4vw, 56px)",
            flexWrap: "wrap",
          }}>
            <div>
              <div className="micro" style={{ color: "var(--ink-faint)", marginBottom: 4 }}>TEX</div>
              <div className="display tabular" style={{
                fontSize: "clamp(56px, 9vw, 96px)",
                color: "var(--cyan)",
                lineHeight: 1,
              }}>
                178<span style={{ fontSize: "0.4em", opacity: 0.7 }}>MS</span>
              </div>
            </div>
            <div>
              <div className="micro" style={{ color: "var(--ink-faint)", marginBottom: 4 }}>YOU</div>
              <div className="display tabular" style={{
                fontSize: "clamp(56px, 9vw, 96px)",
                color: "var(--pink)",
                lineHeight: 1,
              }}>
                {result.avgResponseMs}<span style={{ fontSize: "0.4em", opacity: 0.7 }}>MS</span>
              </div>
            </div>
          </div>
          <div style={{
            marginTop: 18,
            paddingTop: 18,
            borderTop: "1px solid var(--rule-2)",
            display: "flex",
            alignItems: "baseline",
            gap: 12,
            flexWrap: "wrap",
          }}>
            <span style={{ color: "var(--ink-dim)", fontSize: "clamp(15px, 2vw, 18px)" }}>
              You're
            </span>
            <span className="display" style={{
              fontSize: "clamp(40px, 7vw, 72px)",
              color: "var(--pink)",
              letterSpacing: "0.04em",
              textShadow: "0 0 20px var(--pink-soft)",
            }}>
              {slowdown}×
            </span>
            <span style={{ color: "var(--ink-dim)", fontSize: "clamp(15px, 2vw, 18px)" }}>
              slower than Tex.
            </span>
          </div>
        </div>
        )}

        {/* Stats grid */}
        <div className="rise-3" style={{ marginBottom: 36 }}>
          <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 14 }}>
            ▸ THE TAPE
          </div>
          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
            gap: 22,
            padding: "22px 26px",
            border: "1px solid var(--rule-2)",
            borderRadius: 4,
            background: "var(--bg-panel)",
          }}>
            <Stat label="ACTIONS"         value={result.counts.totalSeen} color="var(--ink)" />
            <Stat label="CAUGHT"          value={result.counts.forbid - result.counts.falsePositives} color="var(--green)" />
            <Stat label="MISSED"          value={result.counts.breaches} color="var(--red)" pulse={result.counts.breaches > 0} />
            <Stat label="FALSE POSITIVES" value={result.counts.falsePositives} color="var(--yellow)" />
            <Stat label="ACCURACY"        value={`${Math.round(result.accuracy * 100)}%`} color="var(--cyan)" />
            <Stat label="AVG RESPONSE"    value={`${(result.avgResponseMs / 1000).toFixed(1)}s`} color="var(--ink-dim)" />
          </div>
        </div>

        {/* Breaches */}
        {result.breaches.length > 0 && (
          <div className="rise-4" style={{ marginBottom: 32 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
              <span style={{
                width: 6, height: 6, borderRadius: "50%",
                background: "var(--red)", boxShadow: "0 0 8px var(--red-soft)",
              }} className="pulse" />
              <span className="kicker" style={{ color: "var(--red)" }}>
                ▸ {result.breaches.length} BREACH{result.breaches.length === 1 ? "" : "ES"} · TEX WOULD HAVE CAUGHT
              </span>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {result.breaches.map((b, i) => <BreachCard key={i} scored={b} />)}
            </div>
          </div>
        )}

        {/* Fallback action row — only renders for non-arcade modes
            (daily/training). Arcade has its full button row inside the
            "Time on the Gate" panel above. */}
        {mode !== "arcade" && (
          <div className="rise-5" style={{
            display: "flex",
            gap: 12,
            flexWrap: "wrap",
            marginBottom: 28,
          }}>
            <button onClick={() => copyShareText(result, rank, setCopied)} className="btn-ghost" style={{
              padding: "14px 26px",
              minHeight: 48,
              fontSize: "clamp(15px, 2vw, 18px)",
            }}>
              {copied ? "✓ COPIED" : "COPY POST"}
            </button>
            <button onClick={onPlayAgain} className="btn-ghost">
              {mode === "daily" ? "TRAINING MODE →" : "PLAY AGAIN →"}
            </button>
            <button onClick={onHome} className="btn-ghost">
              HOME →
            </button>
          </div>
        )}

        {/* Per-card detail collapsible */}
        <details className="rise-5" style={{ marginBottom: 28 }}>
          <summary style={{
            cursor: "pointer",
            padding: "12px 16px",
            background: "var(--bg-panel)",
            border: "1px solid var(--rule-2)",
            borderRadius: 4,
            color: "var(--ink-dim)",
            fontFamily: "var(--font-mono)",
            fontSize: 11,
            letterSpacing: "0.18em",
            textTransform: "uppercase",
            fontWeight: 600,
          }}>
            ▾ REVIEW ALL {result.perCard.length} DECISIONS
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
      </div>

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

function Stat({ label, value, color, pulse }) {
  return (
    <div>
      <div className="micro" style={{ color: "var(--ink-faint)", marginBottom: 6 }}>{label}</div>
      <div
        className={`display ${pulse ? "pulse" : ""}`}
        style={{ fontSize: 36, color, letterSpacing: "0.04em", lineHeight: 1 }}
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
      padding: "14px 16px",
      border: "1px solid rgba(255, 71, 71, 0.35)",
      background: "rgba(255, 71, 71, 0.04)",
      borderRadius: 4,
      position: "relative",
    }}>
      <div style={{
        position: "absolute", top: 0, bottom: 0, left: 0,
        width: 2, background: "var(--red)", boxShadow: "0 0 6px var(--red-soft)",
      }} />
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
        <span className="card-glyph" style={{
          background: "rgba(255, 71, 71, 0.12)",
          borderColor: "rgba(255, 71, 71, 0.3)",
          color: "var(--red)",
        }}>{surface.glyph}</span>
        <span className="micro" style={{ color: "var(--red)" }}>
          {surface.label} · MISSED
        </span>
        <span className="micro" style={{ color: "var(--ink-faint)", marginLeft: "auto" }}>
          {m.category.replace(/_/g, " ").toUpperCase()}
        </span>
      </div>
      <div className="mono" style={{ color: "var(--ink)", fontSize: 12, lineHeight: 1.55, marginBottom: 8 }}>
        "{truncate(m.body, 160)}"
      </div>
      <div style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        paddingTop: 10,
        borderTop: "1px solid rgba(255, 71, 71, 0.18)",
        color: "var(--cyan)",
        fontSize: 12,
        fontFamily: "var(--font-mono)",
      }}>
        <span style={{
          width: 5, height: 5, borderRadius: "50%",
          background: "var(--cyan)", boxShadow: "0 0 6px var(--cyan-soft)",
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
      background: "var(--bg-panel)",
      border: `1px solid ${correct ? "var(--rule-1)" : "rgba(255, 71, 71, 0.25)"}`,
      borderRadius: 3,
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
      <span className="micro" style={{ color: c, fontWeight: 700 }}>
        {scored.decision.playerVerdict} → {m.correctVerdict}
      </span>
      <span className="mono tabular" style={{ color: c, fontSize: 11, fontWeight: 700 }}>
        {scored.delta >= 0 ? "+" : ""}{scored.delta}
      </span>
    </div>
  );
}

function HandlePrompt({ onSave, onSkip }) {
  const [v, setV] = useState("");
  return (
    <div style={{
      position: "fixed", inset: 0,
      background: "rgba(3, 4, 10, 0.88)", backdropFilter: "blur(8px)",
      display: "flex", alignItems: "center", justifyContent: "center",
      zIndex: 200, padding: 20,
    }}>
      <div className="panel rise" style={{
        padding: 28,
        maxWidth: 440,
        width: "100%",
        borderColor: "rgba(255, 61, 122, 0.35)",
      }}>
        <div className="kicker" style={{ color: "var(--pink)", marginBottom: 10 }}>
          ▸ SAVE YOUR RANK
        </div>
        <div className="display" style={{
          fontSize: 32, color: "var(--ink)", marginBottom: 18, letterSpacing: "0.04em",
        }}>
          PICK A HANDLE.
        </div>
        <input
          autoFocus
          value={v}
          onChange={(e) => setV(e.target.value.replace(/[^a-z0-9_]/gi, "").slice(0, 18))}
          placeholder="@handle"
          style={{
            width: "100%",
            padding: "14px 16px",
            background: "var(--bg-deep)",
            border: "1px solid var(--rule-3)",
            color: "var(--ink)",
            fontFamily: "var(--font-mono)",
            fontSize: 15,
            borderRadius: 3,
            outline: "none",
            marginBottom: 16,
            letterSpacing: "0.04em",
          }}
          onKeyDown={(e) => { if (e.key === "Enter" && v.trim()) onSave(v.trim()); }}
        />
        <div style={{ display: "flex", gap: 12 }}>
          <button onClick={() => v.trim() && onSave(v.trim())} className="btn-cta"
            style={{ padding: "14px 22px", minHeight: 48, fontSize: 14 }}
            disabled={!v.trim()}>
            SAVE →
          </button>
          <button onClick={onSkip} className="btn-ghost">SKIP</button>
        </div>
      </div>
    </div>
  );
}

function truncate(s, n) {
  if (!s) return "";
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

function ratingMeta(rating) {
  if (rating === "WARDEN")   return { color: "var(--green)",  glow: "var(--green-soft)"  };
  if (rating === "ANALYST")  return { color: "var(--cyan)",   glow: "var(--cyan-soft)"   };
  if (rating === "OPERATOR") return { color: "var(--yellow)", glow: "var(--yellow-soft)" };
  return                       { color: "var(--pink)",   glow: "var(--pink-soft)"   };
}

function copyShareText(result, rank, setCopied) {
  const slowdown = Math.max(1, Math.round(result.avgResponseMs / 178));
  const lines = [
    `Just worked the gate at Tex Arena.`,
    ``,
    `Score: ${result.total}`,
    `Rating: ${result.rating}`,
    `Caught: ${result.counts.forbid - result.counts.falsePositives}`,
    `Missed: ${result.counts.breaches}${result.counts.breaches > 0 ? " — Tex would've caught these in 178ms" : ""}`,
    `I am ${slowdown}× slower than Tex.`,
    ``,
    rank ? `Today's leaderboard: #${rank}` : ``,
    `Try it: texaegis.com`,
  ].filter(Boolean);
  const text = lines.join("\n");
  if (typeof navigator !== "undefined" && navigator.clipboard) {
    navigator.clipboard.writeText(text);
    setCopied?.(true);
    setTimeout(() => setCopied?.(false), 2000);
  }
}
