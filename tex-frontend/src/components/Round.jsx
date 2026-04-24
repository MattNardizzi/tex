import React, { useEffect, useRef, useState } from "react";
import { evaluateAttack } from "../lib/apiClient.js";
import { sendSfx, tickSfx, winSfx, loseSfx, partialSfx } from "../lib/sounds.js";

/*
  Round v8 — "You vs Tex"
  ────────────────────────
  One opponent. You type an attack. It goes to /api/evaluate (real).
  Tex returns PERMIT / ABSTAIN / FORBID. You have:
    - 60 seconds (timer starts on first attempt)
    - 3 attempts max
  Round ends when:
    - PERMIT (you bypassed Tex — big win)
    - 3 FORBIDs/ABSTAINs used up
    - Timer expires
*/

const MAX_ATTEMPTS = 3;
const TIME_LIMIT = 60;

export default function Round({ incident, onComplete, onBail }) {
  const [attempts, setAttempts] = useState([]); // { text, decision, latencyMs }
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [err, setErr] = useState("");
  const [timerStarted, setTimerStarted] = useState(false);
  const [secondsLeft, setSecondsLeft] = useState(TIME_LIMIT);
  const [done, setDone] = useState(false);

  const inputRef = useRef(null);
  const scrollerRef = useRef(null);

  useEffect(() => { inputRef.current?.focus(); }, []);

  // Timer
  useEffect(() => {
    if (!timerStarted || done) return;
    if (secondsLeft <= 0) {
      handleTimeout();
      return;
    }
    if (secondsLeft <= 10) tickSfx();
    const t = setTimeout(() => setSecondsLeft((s) => s - 1), 1000);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [secondsLeft, timerStarted, done]);

  useEffect(() => {
    if (scrollerRef.current) scrollerRef.current.scrollTop = scrollerRef.current.scrollHeight;
  }, [attempts, sending]);

  async function handleSend() {
    if (sending || done) return;
    const text = input.trim();
    if (!text) return;
    if (attempts.length >= MAX_ATTEMPTS) return;

    setErr("");
    setSending(true);
    sendSfx();
    if (!timerStarted) setTimerStarted(true);
    const attemptNo = attempts.length + 1;

    try {
      const t0 = performance.now();
      const decision = await evaluateAttack({
        content: text,
        incident,
        attempt: attemptNo,
      });
      const latencyMs = decision.total_ms || Math.round(performance.now() - t0);

      const entry = { text, decision, latencyMs };
      const newAttempts = [...attempts, entry];
      setAttempts(newAttempts);
      setInput("");
      setSending(false);

      // Win: PERMIT = you bypassed Tex
      if (decision.verdict === "PERMIT") {
        setDone(true);
        winSfx();
        setTimeout(() => onComplete({
          incident,
          verdict: "PERMIT",
          attempts: newAttempts,
          secondsLeft,
          finalAttempt: entry,
        }), 900);
        return;
      }

      // If ABSTAIN and this is the last attempt, partial credit
      if (decision.verdict === "ABSTAIN") partialSfx();

      // Out of attempts → round over, Tex won
      if (newAttempts.length >= MAX_ATTEMPTS) {
        // Best outcome: did we ever get ABSTAIN? (partial credit)
        const bestVerdict = newAttempts.some((a) => a.decision.verdict === "ABSTAIN")
          ? "ABSTAIN"
          : "FORBID";
        setDone(true);
        if (bestVerdict === "FORBID") loseSfx();
        setTimeout(() => onComplete({
          incident,
          verdict: bestVerdict,
          attempts: newAttempts,
          secondsLeft,
          finalAttempt: newAttempts[newAttempts.length - 1],
        }), 900);
      }
    } catch (e) {
      setSending(false);
      setErr(e.message || "Tex API error");
    }
  }

  function handleTimeout() {
    setDone(true);
    loseSfx();
    const bestVerdict = attempts.some((a) => a.decision.verdict === "ABSTAIN")
      ? "ABSTAIN"
      : "FORBID";
    setTimeout(() => onComplete({
      incident,
      verdict: bestVerdict,
      attempts,
      secondsLeft: 0,
      timeout: true,
      finalAttempt: attempts[attempts.length - 1] || null,
    }), 700);
  }

  function onKey(e) {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      handleSend();
    }
  }

  const attemptsLeft = MAX_ATTEMPTS - attempts.length;
  const timerColor =
    !timerStarted ? "var(--ink-faint)" :
    secondsLeft <= 10 ? "var(--red)" :
    secondsLeft <= 25 ? "var(--yellow)" :
    "var(--cyan)";

  return (
    <div style={{
      minHeight: "100vh",
      display: "flex",
      flexDirection: "column",
      maxWidth: 1100,
      margin: "0 auto",
      padding: "24px 32px 40px",
      width: "100%",
    }}>
      {/* Top bar */}
      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        paddingBottom: 16,
        borderBottom: "1px solid var(--hairline-2)",
        marginBottom: 24,
      }}>
        <button onClick={onBail} className="micro" style={{
          color: "var(--ink-faint)",
          padding: "6px 10px",
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
          <span className="kicker" style={{ color: "var(--pink)" }}>LIVE ROUND</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
          <AttemptPips total={MAX_ATTEMPTS} used={attempts.length} />
          <Timer seconds={secondsLeft} color={timerColor} started={timerStarted} />
        </div>
      </div>

      {/* Incident card */}
      <div className="panel rise" style={{ padding: "20px 24px", marginBottom: 20 }}>
        <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 6 }}>
          INCIDENT · {incident.name.toUpperCase()}
        </div>
        <div className="display" style={{ fontSize: 32, marginBottom: 8, lineHeight: 1.05 }}>
          {incident.goal}
        </div>
        <div style={{ color: "var(--ink-dim)", fontSize: 14, lineHeight: 1.5 }}>
          {incident.setup}
        </div>
        <div style={{
          marginTop: 14,
          paddingTop: 14,
          borderTop: "1px solid var(--hairline)",
          display: "flex",
          gap: 16,
          flexWrap: "wrap",
        }}>
          <Meta label="CHANNEL" value={incident.channel.toUpperCase()} />
          <Meta label="ACTION" value={incident.action_type.replace(/_/g, " ").toUpperCase()} />
          <Meta label="ENV" value={incident.environment.toUpperCase()} />
          {incident.recipient && <Meta label="TO" value={incident.recipient} />}
        </div>
      </div>

      {/* Hint bar */}
      <div style={{
        padding: "12px 16px",
        borderLeft: "3px solid var(--yellow)",
        background: "rgba(255, 225, 74, 0.05)",
        borderRadius: 4,
        marginBottom: 20,
        display: "flex",
        alignItems: "center",
        gap: 10,
      }}>
        <span className="kicker" style={{ color: "var(--yellow)" }}>TEX WATCHES FOR</span>
        <span style={{ color: "var(--ink-dim)", fontSize: 13 }}>{incident.hint}</span>
      </div>

      {/* Transcript */}
      {attempts.length > 0 && (
        <div
          ref={scrollerRef}
          style={{
            flex: 1,
            minHeight: 200,
            maxHeight: 360,
            overflowY: "auto",
            marginBottom: 16,
            padding: "8px 4px",
            display: "flex",
            flexDirection: "column",
            gap: 14,
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

      {/* Input */}
      {!done && (
        <div className="panel" style={{
          padding: 8,
          display: "flex",
          gap: 8,
          alignItems: "flex-end",
        }}>
          <textarea
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value.slice(0, 1500))}
            onKeyDown={onKey}
            placeholder={
              attempts.length === 0
                ? `Write the attack message. ⌘/Ctrl+Enter to send. Tex sees everything.`
                : `Attempt ${attempts.length + 1} of ${MAX_ATTEMPTS} — refine your approach.`
            }
            rows={3}
            disabled={sending || attemptsLeft === 0 || done}
            className="tex-input"
            style={{ flex: 1, minHeight: 64 }}
          />
          <button
            onClick={handleSend}
            disabled={sending || !input.trim() || attemptsLeft === 0 || done}
            className="btn-primary"
            style={{ padding: "12px 22px", fontSize: 12, alignSelf: "stretch" }}
          >
            {sending ? "SENDING" : "ATTACK →"}
          </button>
        </div>
      )}
      <div style={{
        marginTop: 8,
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
      }}>
        <span className="micro" style={{ color: "var(--ink-faint)" }}>
          {input.length}/1500
        </span>
        <span className="micro" style={{ color: "var(--ink-faint)" }}>
          EVERY ATTEMPT HITS THE LIVE TEX API
        </span>
      </div>
    </div>
  );
}

function Timer({ seconds, color, started }) {
  const mm = String(Math.floor(seconds / 60)).padStart(1, "0");
  const ss = String(seconds % 60).padStart(2, "0");
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 8,
      padding: "6px 12px",
      border: `1px solid ${color}`,
      borderRadius: 6,
      background: `${color}0E`,
    }}>
      <span className="micro" style={{ color: "var(--ink-faint)" }}>
        {started ? "TIME" : "CLOCK"}
      </span>
      <span className="display tabular" style={{ fontSize: 18, color, letterSpacing: "0.05em" }}>
        {started ? `${mm}:${ss}` : "60s"}
      </span>
    </div>
  );
}

function AttemptPips({ total, used }) {
  return (
    <div style={{ display: "flex", gap: 5, alignItems: "center" }}>
      <span className="micro" style={{ color: "var(--ink-faint)", marginRight: 4 }}>ATTEMPTS</span>
      {Array.from({ length: total }).map((_, i) => (
        <span key={i} style={{
          width: 9,
          height: 9,
          borderRadius: "50%",
          background: i < total - used ? "var(--cyan)" : "var(--hairline-2)",
          boxShadow: i < total - used ? "0 0 8px var(--cyan-glow)" : "none",
        }} />
      ))}
    </div>
  );
}

function Meta({ label, value }) {
  return (
    <div>
      <div className="micro" style={{ color: "var(--ink-faint)" }}>{label}</div>
      <div className="mono" style={{ fontSize: 12, color: "var(--ink-dim)", marginTop: 2 }}>{value}</div>
    </div>
  );
}

function AttemptBlock({ n, attempt }) {
  const { text, decision, latencyMs } = attempt;
  const v = decision.verdict;
  const c = v === "PERMIT" ? "var(--green)" : v === "ABSTAIN" ? "var(--yellow)" : "var(--red)";
  const bg = v === "PERMIT" ? "rgba(95, 250, 159, 0.07)" : v === "ABSTAIN" ? "rgba(255, 225, 74, 0.07)" : "rgba(255, 75, 75, 0.07)";
  const label = v === "PERMIT" ? "BYPASS — YOU WON" : v === "ABSTAIN" ? "ESCALATED — CLOSE" : "BLOCKED";

  return (
    <div className="rise">
      {/* Player attack */}
      <div style={{
        padding: "12px 14px",
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

      {/* Tex verdict */}
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
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{
            width: 8, height: 8, borderRadius: "50%", background: c, boxShadow: `0 0 8px ${c}`,
          }} />
          <span className="kicker" style={{ color: c }}>TEX · {v}</span>
          <span className="display" style={{ fontSize: 13, color: c, letterSpacing: "0.05em" }}>
            {label}
          </span>
        </div>
        <div className="mono tabular" style={{ fontSize: 11, color: "var(--ink-faint)" }}>
          {latencyMs}ms · {decision.asi_findings?.length || 0} ASI · {decision.confidence ? (decision.confidence * 100).toFixed(0) + "%" : "—"}
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
