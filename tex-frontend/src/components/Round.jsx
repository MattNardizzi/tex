import React, { useEffect, useRef, useState } from "react";
import { evaluateAttack } from "../lib/apiClient.js";
import { sendSfx, winSfx, loseSfx, partialSfx } from "../lib/sounds.js";
import { judgeIntent } from "../lib/intentJudge.js";
import { computeRoundScore, layerProfile } from "../lib/stealthScore.js";
import LayerAnatomy from "./LayerAnatomy.jsx";

/*
  Round v10 — adversarial puzzle, no clock
  ─────────────────────────────────────────
  - 5 attempts, no timer
  - Intent Judge gates every submission (forfeits don't count)
  - Layer Anatomy lights up live as Tex evaluates
  - Round ends when:
      (a) intent passed AND verdict === PERMIT  → BYPASS, immediate finish
      (b) 5 real (non-forfeit) attempts used    → finish with best score
      (c) player hits BAIL                      → forfeit round
  - Result passed to onComplete includes best score across attempts
*/

const MAX_ATTEMPTS = 5;

export default function Round({ incident, onComplete, onBail, mode = "ranked" }) {
  const [attempts, setAttempts] = useState([]);    // [{ text, decision, intent, score, latencyMs }]
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [err, setErr] = useState("");
  const [done, setDone] = useState(false);
  const [evaluating, setEvaluating] = useState(false);
  const [livePreview, setLivePreview] = useState(null); // most recent attempt's score for the live anatomy

  const inputRef = useRef(null);
  const scrollerRef = useRef(null);

  useEffect(() => { inputRef.current?.focus(); }, []);

  useEffect(() => {
    if (scrollerRef.current) {
      scrollerRef.current.scrollTop = scrollerRef.current.scrollHeight;
    }
  }, [attempts, sending]);

  // Count only non-forfeit attempts toward the budget
  const realAttempts = attempts.filter((a) => !a.score.forfeit);
  const attemptsLeft = Math.max(0, MAX_ATTEMPTS - realAttempts.length);

  async function handleSend() {
    if (sending || done) return;
    const text = input.trim();
    if (!text) return;

    setErr("");
    setSending(true);
    setEvaluating(true);
    setLivePreview(null);
    sendSfx();

    // 1. Intent Judge runs first (instant, deterministic)
    const intent = judgeIntent(text, incident);

    try {
      const t0 = performance.now();
      const decision = await evaluateAttack({
        content: text,
        incident,
        attempt: realAttempts.length + 1,
      });
      const latencyMs = decision.total_ms || Math.round(performance.now() - t0);

      const score = computeRoundScore({
        intent,
        decision,
        tier: incident.tier || 2,
      });

      const entry = { text, decision, intent, score, latencyMs };
      const newAttempts = [...attempts, entry];

      setAttempts(newAttempts);
      setInput("");
      setEvaluating(false);
      setSending(false);
      setLivePreview(score);

      // ── Outcome routing ─────────────────────────────────────────
      if (score.forfeit) {
        // Forfeit: doesn't count, don't end round, just show explainer
        partialSfx();
        return;
      }

      if (score.verdict === "PERMIT") {
        setDone(true);
        winSfx();
        finishRound(newAttempts, "PERMIT");
        return;
      }

      if (score.verdict === "ABSTAIN") partialSfx();
      else loseSfx();

      const newReal = newAttempts.filter((a) => !a.score.forfeit);
      if (newReal.length >= MAX_ATTEMPTS) {
        setDone(true);
        finishRound(newAttempts, null);
      }
    } catch (e) {
      setSending(false);
      setEvaluating(false);
      setErr(e.message || "Tex API error");
    }
  }

  function finishRound(allAttempts, forcedVerdict) {
    // Pick the best attempt by score
    const real = allAttempts.filter((a) => !a.score.forfeit);
    let best = real[0];
    for (const a of real) {
      if (a.score.total > (best?.score.total || 0)) best = a;
    }
    if (!best) {
      // No real attempts — return a forfeit-style result
      best = allAttempts[allAttempts.length - 1] || null;
    }

    setTimeout(() => onComplete({
      incident,
      attempts: allAttempts,
      bestAttempt: best,
      finalVerdict: forcedVerdict || best?.score.verdict || "ABSTAIN",
      mode,
    }), 700);
  }

  function onKey(e) {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      handleSend();
    }
  }

  return (
    <div style={{
      minHeight: "100vh",
      display: "flex",
      flexDirection: "column",
      maxWidth: 1100,
      margin: "0 auto",
      padding: "var(--pad-page)",
      width: "100%",
      paddingTop: "calc(var(--pad-page) + 8px)",
    }}>
      {/* ── Top bar ─────────────────────────────────────── */}
      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        paddingBottom: 14,
        borderBottom: "1px solid var(--hairline-2)",
        marginBottom: 18,
        gap: 12,
        flexWrap: "wrap",
      }}>
        <button onClick={onBail} className="micro" style={{
          color: "var(--ink-faint)",
          padding: "8px 12px",
          border: "1px solid var(--hairline-2)",
          borderRadius: 4,
        }}>
          ← BAIL
        </button>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <div style={{
            width: 6, height: 6, borderRadius: "50%",
            background: "var(--pink)", boxShadow: "0 0 8px var(--pink-glow)",
          }} className="pulse" />
          <span className="kicker" style={{ color: "var(--pink)" }}>
            {mode === "daily" ? "DAILY · LIVE" : "LIVE ROUND"}
          </span>
        </div>
        <AttemptBudget total={MAX_ATTEMPTS} used={realAttempts.length} />
      </div>

      {/* ── Incident card ───────────────────────────────── */}
      <div className="panel rise" style={{ padding: "18px 22px", marginBottom: 16 }}>
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "baseline",
          flexWrap: "wrap",
          gap: 10,
          marginBottom: 8,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <TierPips tier={incident.tier} />
            <span className="kicker" style={{ color: "var(--cyan)" }}>
              {incident.name.toUpperCase()}
            </span>
          </div>
          {(incident.asi || []).length > 0 && (
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
              {incident.asi.map((c) => (
                <span key={c} className="mono" style={{
                  fontSize: 9,
                  padding: "2px 6px",
                  border: "1px solid rgba(95, 240, 255, 0.35)",
                  borderRadius: 3,
                  color: "var(--cyan)",
                  background: "rgba(95, 240, 255, 0.05)",
                }}>
                  {c}
                </span>
              ))}
            </div>
          )}
        </div>
        <div className="display" style={{
          fontSize: "clamp(20px, 4.5vw, 28px)",
          marginBottom: 8,
          lineHeight: 1.05,
        }}>
          {incident.goal}
        </div>
        <div style={{ color: "var(--ink-dim)", fontSize: 13, lineHeight: 1.5 }}>
          {incident.setup}
        </div>
        <div style={{
          marginTop: 12,
          paddingTop: 12,
          borderTop: "1px solid var(--hairline)",
          display: "flex",
          gap: 14,
          flexWrap: "wrap",
        }}>
          <Meta label="CHANNEL" value={incident.channel.toUpperCase()} />
          <Meta label="ACTION" value={incident.action_type.replace(/_/g, " ").toUpperCase()} />
          <Meta label="ENV" value={incident.environment.toUpperCase()} />
          {incident.recipient && <Meta label="TO" value={incident.recipient} />}
        </div>
      </div>

      {/* ── Live Layer Anatomy ──────────────────────────── */}
      <div style={{ marginBottom: 16 }}>
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "baseline",
          marginBottom: 8,
          gap: 10,
          flexWrap: "wrap",
        }}>
          <span className="kicker" style={{ color: "var(--cyan)" }}>
            TEX PIPELINE
          </span>
          <span className="micro" style={{ color: "var(--ink-faint)" }}>
            {evaluating ? "ADJUDICATING…" : livePreview ? "LAST ATTEMPT" : "AWAITING INPUT"}
          </span>
        </div>
        <LayerAnatomy
          profile={livePreview?.profile || null}
          evaluating={evaluating}
          showWeights
        />
      </div>

      {/* ── Hint bar ─────────────────────────────────────── */}
      <div style={{
        padding: "10px 14px",
        borderLeft: "3px solid var(--yellow)",
        background: "rgba(255, 225, 74, 0.05)",
        borderRadius: 4,
        marginBottom: 16,
        display: "flex",
        alignItems: "center",
        gap: 10,
        flexWrap: "wrap",
      }}>
        <span className="kicker" style={{ color: "var(--yellow)" }}>WATCH FOR</span>
        <span style={{ color: "var(--ink-dim)", fontSize: 13 }}>{incident.hint}</span>
      </div>

      {/* ── Transcript ──────────────────────────────────── */}
      {attempts.length > 0 && (
        <div
          ref={scrollerRef}
          style={{
            flex: 1,
            minHeight: 160,
            maxHeight: 360,
            overflowY: "auto",
            marginBottom: 14,
            padding: "4px 2px",
            display: "flex",
            flexDirection: "column",
            gap: 12,
          }}
        >
          {attempts.map((a, i) => <AttemptBlock key={i} n={i + 1} attempt={a} />)}
          {sending && <ThinkingIndicator />}
        </div>
      )}
      {attempts.length === 0 && sending && <ThinkingIndicator />}

      {err && (
        <div style={{
          padding: "10px 14px",
          border: "1px solid var(--red)",
          borderRadius: 6,
          color: "var(--red)",
          fontSize: 13,
          marginBottom: 12,
        }}>
          {err}
        </div>
      )}

      {/* ── Input ───────────────────────────────────────── */}
      {!done && (
        <>
          <div className="panel" style={{
            padding: 8,
            display: "flex",
            gap: 8,
            alignItems: "stretch",
            flexDirection: "row",
            flexWrap: "wrap",
          }}>
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value.slice(0, 1500))}
              onKeyDown={onKey}
              placeholder={
                attempts.length === 0
                  ? `Craft your attack. ${incident.goal} ⌘/Ctrl+Enter to send.`
                  : `Refine. ${attemptsLeft} ${attemptsLeft === 1 ? "attempt" : "attempts"} left.`
              }
              rows={3}
              disabled={sending || attemptsLeft === 0 || done}
              className="tex-input"
              style={{ flex: 1, minWidth: 200, minHeight: 72 }}
            />
            <button
              onClick={handleSend}
              disabled={sending || !input.trim() || attemptsLeft === 0 || done}
              className="btn-primary"
              style={{ padding: "12px 22px", fontSize: 12, minWidth: 110 }}
            >
              {sending ? "SENDING" : "ATTACK →"}
            </button>
          </div>
          <div style={{
            marginTop: 8,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: 6,
          }}>
            <span className="micro" style={{ color: "var(--ink-faint)" }}>
              {input.length}/1500
            </span>
            <span className="micro" style={{ color: "var(--ink-faint)" }}>
              FORFEITS DON'T COUNT · LIVE TEX API
            </span>
          </div>
        </>
      )}
    </div>
  );
}

function TierPips({ tier }) {
  const color = tier === 1 ? "var(--cyan)" : tier === 2 ? "var(--yellow)" : "var(--pink)";
  return (
    <div style={{ display: "flex", gap: 1, color }}>
      {[1, 2, 3].map((n) => (
        <span key={n} className={`tier-pip ${n <= tier ? "on" : ""}`} />
      ))}
    </div>
  );
}

function AttemptBudget({ total, used }) {
  return (
    <div style={{ display: "flex", gap: 5, alignItems: "center" }}>
      <span className="micro" style={{ color: "var(--ink-faint)", marginRight: 4 }}>
        ATTEMPTS
      </span>
      {Array.from({ length: total }).map((_, i) => (
        <span key={i} style={{
          width: 9,
          height: 9,
          borderRadius: "50%",
          background: i < total - used ? "var(--cyan)" : "var(--hairline-2)",
          boxShadow: i < total - used ? "0 0 8px var(--cyan-glow)" : "none",
          transition: "all 0.3s ease",
        }} />
      ))}
    </div>
  );
}

function Meta({ label, value }) {
  return (
    <div>
      <div className="micro" style={{ color: "var(--ink-faint)" }}>{label}</div>
      <div className="mono" style={{ fontSize: 11, color: "var(--ink-dim)", marginTop: 2 }}>
        {value}
      </div>
    </div>
  );
}

function AttemptBlock({ n, attempt }) {
  const { text, score, intent, latencyMs } = attempt;

  if (score.forfeit) {
    return (
      <div className="rise">
        <div style={{
          padding: "10px 12px",
          border: "1px solid rgba(255, 225, 74, 0.35)",
          borderRadius: 6,
          background: "rgba(255, 225, 74, 0.04)",
        }}>
          <div className="micro" style={{ color: "var(--yellow)", marginBottom: 6 }}>
            ATTEMPT #{n} · FORFEIT — DOES NOT COUNT
          </div>
          <div className="mono" style={{ fontSize: 13, lineHeight: 1.5, color: "var(--ink-dim)", whiteSpace: "pre-wrap" }}>
            {text}
          </div>
          <div style={{ marginTop: 6, color: "var(--ink-faint)", fontSize: 11, fontFamily: "var(--font-mono)" }}>
            {intent.explainer}
          </div>
        </div>
      </div>
    );
  }

  const v = score.verdict;
  const c = v === "PERMIT" ? "var(--green)" : v === "ABSTAIN" ? "var(--yellow)" : "var(--red)";
  const bg = v === "PERMIT" ? "rgba(95, 250, 159, 0.07)" : v === "ABSTAIN" ? "rgba(255, 225, 74, 0.07)" : "rgba(255, 75, 75, 0.07)";

  return (
    <div className="rise">
      <div style={{
        padding: "10px 12px",
        border: "1px solid rgba(255, 61, 122, 0.25)",
        borderRadius: 6,
        background: "rgba(255, 61, 122, 0.04)",
      }}>
        <div className="micro" style={{ color: "var(--pink)", marginBottom: 6 }}>
          YOUR ATTACK · #{n}
        </div>
        <div className="mono" style={{ fontSize: 13, lineHeight: 1.5, color: "var(--ink)", whiteSpace: "pre-wrap" }}>
          {text}
        </div>
      </div>

      <div style={{
        marginTop: 6,
        padding: "10px 14px",
        border: `1px solid ${c}`,
        borderRadius: 6,
        background: bg,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 12,
        flexWrap: "wrap",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <span style={{
            width: 8, height: 8, borderRadius: "50%", background: c, boxShadow: `0 0 8px ${c}`,
          }} />
          <span className="kicker" style={{ color: c }}>TEX · {v}</span>
          <span className="display" style={{ fontSize: 13, color: c, letterSpacing: "0.05em" }}>
            {score.total} PTS
          </span>
        </div>
        <div className="mono tabular" style={{ fontSize: 11, color: "var(--ink-faint)" }}>
          {latencyMs}ms · STEALTH {(score.stealth * 100).toFixed(0)}%
        </div>
      </div>
    </div>
  );
}

function ThinkingIndicator() {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 10,
      padding: "8px 4px",
      color: "var(--cyan)",
    }}>
      <span style={{
        width: 8, height: 8, borderRadius: "50%", background: "var(--cyan)",
        boxShadow: "0 0 10px var(--cyan-glow)",
      }} className="pulse" />
      <span className="kicker">TEX IS ADJUDICATING</span>
    </div>
  );
}
