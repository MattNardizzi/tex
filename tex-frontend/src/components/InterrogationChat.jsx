import React, { useEffect, useRef, useState } from "react";
import { Send, Clock, User, Bot, Sparkles, Zap } from "lucide-react";
import { agentReplyFor } from "../lib/agentSim.js";
import { evaluateAgentReply } from "../lib/apiClient.js";
import { punchSound } from "../lib/sound.js";

/*
  InterrogationChat v7 — "Real interrogation, real Tex"
  ──────────────────────────────────────────────────────
  Invariants:
    • Every agent reply is sent to the REAL Tex /evaluate endpoint.
      There is no client-side simulation of verdicts. If the backend
      says PERMIT, it's PERMIT.
    • The only client-side logic is the intent classifier that picks
      which scripted agent reply to send. Once the reply is selected,
      it goes over the wire and Tex decides everything.
    • Timer only starts after the first question is sent. Thinking
      time is not penalized.
    • Session ends on first FORBID/ABSTAIN (win), 3 PERMITs (miss),
      or timeout (miss). The full transcript is passed to the parent
      via onCatch or onSessionEnd so the verdict screen can show
      context, not just a verdict.
*/

const QUESTION_LIMIT = 3;
const TIME_LIMIT_SECONDS = 60;

export default function InterrogationChat({
  caseDef,
  onCatch,       // (decision, meta, transcript) => void
  onSessionEnd,  // (info, transcript) => void
}) {
  const [transcript, setTranscript] = useState([]);
  const [pendingInput, setPendingInput] = useState("");
  const [questionsAsked, setQuestionsAsked] = useState(0);
  const [isProcessing, setIsProcessing] = useState(false);
  const [timerStarted, setTimerStarted] = useState(false);
  const [secondsLeft, setSecondsLeft] = useState(TIME_LIMIT_SECONDS);
  const [sessionOver, setSessionOver] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  const scrollerRef = useRef(null);
  const inputRef = useRef(null);
  const sessionIdRef = useRef(0);
  const transcriptRef = useRef([]);

  // Keep ref in sync so callbacks always have the latest transcript
  useEffect(() => { transcriptRef.current = transcript; }, [transcript]);

  // Reset on case change
  useEffect(() => {
    sessionIdRef.current += 1;
    setTranscript([]);
    transcriptRef.current = [];
    setPendingInput("");
    setQuestionsAsked(0);
    setIsProcessing(false);
    setTimerStarted(false);
    setSecondsLeft(TIME_LIMIT_SECONDS);
    setSessionOver(false);
    setErrorMsg("");
    setTimeout(() => inputRef.current?.focus(), 80);
  }, [caseDef.id]);

  // Timer — only runs after first question
  useEffect(() => {
    if (!timerStarted || sessionOver) return;
    if (secondsLeft <= 0) {
      setSessionOver(true);
      onSessionEnd?.(
        { reason: "timeout", questionsUsed: questionsAsked },
        transcriptRef.current
      );
      return;
    }
    const t = setTimeout(() => setSecondsLeft((s) => Math.max(0, s - 1)), 1000);
    return () => clearTimeout(t);
  }, [secondsLeft, sessionOver, questionsAsked, onSessionEnd, timerStarted]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (scrollerRef.current) {
      scrollerRef.current.scrollTop = scrollerRef.current.scrollHeight;
    }
  }, [transcript, isProcessing]);

  const questionsLeft = QUESTION_LIMIT - questionsAsked;
  const canSubmit =
    !sessionOver && !isProcessing && questionsLeft > 0 && pendingInput.trim().length > 0;

  async function submitQuestion() {
    if (!canSubmit) return;
    const myId = sessionIdRef.current;
    const question = pendingInput.trim().slice(0, 400);
    punchSound();
    setErrorMsg("");
    setPendingInput("");
    if (!timerStarted) setTimerStarted(true);

    setTranscript((t) => [...t, { role: "player", text: question }]);
    setQuestionsAsked((n) => n + 1);
    setIsProcessing(true);

    // Pick the agent's reply from the case's scripted library.
    // NOTE: This is pre-written content. The VERDICT is not decided
    // here — the reply goes to the real Tex backend next.
    const reply = agentReplyFor(caseDef, question);
    await delay(420 + Math.random() * 280);
    if (sessionIdRef.current !== myId) return;

    setTranscript((t) => [...t, {
      role: "agent",
      text: reply.text,
      intent: reply.intent,
    }]);

    await delay(140);
    if (sessionIdRef.current !== myId) return;

    // Ship the agent's reply to the REAL Tex API. No simulation.
    const t0 = performance.now();
    try {
      const decision = await evaluateAgentReply({
        caseDef,
        agentReplyText: reply.text,
      });
      if (sessionIdRef.current !== myId) return;

      const catchMs = decision.latency?.total_ms
        ?? decision.elapsed_ms
        ?? Math.round(performance.now() - t0);

      setTranscript((t) => [
        ...t,
        {
          role: "tex",
          verdict: decision.verdict,
          latencyMs: catchMs,
          tell: reply.tell,
          findings: decision.asi_findings || [],
          decision,
        },
      ]);

      if (decision.verdict === "FORBID" || decision.verdict === "ABSTAIN") {
        setSessionOver(true);
        setIsProcessing(false);
        // Give the transcript a moment to render
        setTimeout(() => {
          onCatch?.(
            decision,
            {
              catchMs,
              questionsUsed: questionsAsked + 1,
              agentReply: reply.text,
            },
            transcriptRef.current
          );
        }, 900);
        return;
      }

      // PERMIT — continue if questions remain
      setIsProcessing(false);
      if (questionsAsked + 1 >= QUESTION_LIMIT) {
        setSessionOver(true);
        setTimeout(() => {
          onSessionEnd?.(
            { reason: "questions_exhausted", questionsUsed: QUESTION_LIMIT },
            transcriptRef.current
          );
        }, 900);
      }
    } catch (err) {
      if (sessionIdRef.current !== myId) return;
      setErrorMsg(err instanceof Error ? err.message : "Tex API error");
      setIsProcessing(false);
    }
  }

  function onKeyDown(e) {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      submitQuestion();
    }
  }

  const timerTone =
    !timerStarted ? "var(--color-ink-faint)" :
    secondsLeft <= 10 ? "var(--color-red)" :
    secondsLeft <= 25 ? "var(--color-yellow)" :
    "var(--color-cyan)";

  const timerDisplay = !timerStarted
    ? "60s"
    : `${String(Math.floor(secondsLeft / 60)).padStart(1, "0")}:${String(secondsLeft % 60).padStart(2, "0")}`;

  const transcriptEmpty = transcript.length === 0;

  return (
    <section className="panel overflow-hidden flex flex-col">
      {/* Header: persona + live meters */}
      <div className="px-4 sm:px-5 py-2.5 border-b border-[var(--color-hairline-2)] flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="t-micro text-[var(--color-pink)] shrink-0">INTERROGATING</span>
          <span className="t-micro text-[var(--color-ink-faint)] shrink-0">·</span>
          <span className="t-micro text-[var(--color-ink-dim)] truncate">{caseDef.persona}</span>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {/* Question pips */}
          <div className="flex items-center gap-1" aria-label={`${questionsLeft} questions left`}>
            {Array.from({ length: QUESTION_LIMIT }).map((_, i) => (
              <span
                key={i}
                className="inline-block w-1.5 h-1.5 rounded-full transition-all"
                style={{
                  background: i < questionsLeft ? "var(--color-cyan)" : "var(--color-hairline-2)",
                  boxShadow: i < questionsLeft ? "0 0 8px rgba(95,240,255,0.7)" : "none",
                }}
              />
            ))}
          </div>
          {/* Timer */}
          <div className="flex items-center gap-1 tabular-nums" style={{ color: timerTone }}>
            <Clock className="w-3.5 h-3.5" />
            <span className="t-display text-[14px]" style={{ letterSpacing: "0.04em" }}>
              {timerDisplay}
            </span>
          </div>
        </div>
      </div>

      {/* Transcript area */}
      {transcriptEmpty ? (
        <div className="px-5 py-6 flex-1 flex flex-col items-center justify-center text-center">
          <Zap className="w-8 h-8 text-[var(--color-cyan)] mb-3 pulse-ring-cyan" />
          <div
            className="text-[14px] text-[var(--color-ink-dim)] max-w-[420px] mx-auto leading-[1.5]"
          >
            <span className="text-[var(--color-ink)] font-bold">{caseDef.persona}</span> is online.
            Ask your first question to start the clock.
          </div>
          <div className="mt-2 t-micro text-[var(--color-ink-faint)]">
            Every reply is judged by the live Tex API.
          </div>
        </div>
      ) : (
        <div
          ref={scrollerRef}
          className="overflow-y-auto p-4 space-y-3 flex-1"
          style={{ maxHeight: "460px", minHeight: "180px" }}
        >
          {transcript.map((entry, i) => (
            <TranscriptLine key={i} entry={entry} />
          ))}
          {isProcessing && (
            <div className="flex items-center gap-2 t-micro text-[var(--color-cyan)] rise-in">
              <Sparkles className="w-3.5 h-3.5 pulse-ring-cyan" />
              <span className="caret">Tex is reading the reply</span>
            </div>
          )}
        </div>
      )}

      {errorMsg && (
        <div className="border-t border-[var(--color-red)] px-4 py-2 t-micro text-[var(--color-red)]">
          {errorMsg}
        </div>
      )}

      {/* Input */}
      <div className="border-t border-[var(--color-hairline-2)] p-3 bg-[var(--color-bg-2)]">
        <div className="flex items-end gap-2">
          <textarea
            ref={inputRef}
            value={pendingInput}
            onChange={(e) => setPendingInput(e.target.value.slice(0, 400))}
            onKeyDown={onKeyDown}
            rows={2}
            placeholder={
              sessionOver
                ? "Session over."
                : questionsLeft === 0
                ? "No questions left."
                : transcriptEmpty
                ? `Ask your first question — ⌘+Enter to send`
                : `Ask a question (${questionsLeft} left) — ⌘+Enter to send`
            }
            disabled={sessionOver || isProcessing || questionsLeft === 0}
            className="flex-1 font-mono text-[13px] bg-[var(--color-bg-3)] border border-[var(--color-hairline-2)] rounded-sm px-3 py-2 text-[var(--color-ink)] placeholder:text-[var(--color-ink-faint)] resize-none focus:outline-none focus:border-[var(--color-cyan)]"
            style={{ fontFamily: "var(--font-mono)" }}
          />
          <button
            onClick={submitQuestion}
            disabled={!canSubmit}
            className="btn-primary text-[13px] px-4 py-2 inline-flex items-center gap-1.5 h-[46px]"
            style={{ opacity: canSubmit ? 1 : 0.4 }}
          >
            <Send className="w-3.5 h-3.5" />
            ASK
          </button>
        </div>
        <div className="mt-1.5 t-micro text-[var(--color-ink-faint)] flex items-center justify-between gap-2">
          <span className="tabular-nums">{pendingInput.length}/400</span>
          <span className="italic truncate" style={{ fontFamily: "var(--font-serif)" }}>
            The agent&rsquo;s reply is what Tex judges.
          </span>
        </div>
      </div>
    </section>
  );
}

function TranscriptLine({ entry }) {
  if (entry.role === "player") {
    return (
      <div className="flex items-start gap-2 justify-end rise-in">
        <div
          className="max-w-[80%] px-3 py-2 rounded-sm text-[13px] leading-[1.5]"
          style={{
            background: "rgba(255,61,122,0.14)",
            border: "1px solid rgba(255,61,122,0.35)",
            color: "var(--color-ink)",
          }}
        >
          {entry.text}
        </div>
        <div className="shrink-0 w-6 h-6 rounded-sm flex items-center justify-center" style={{ background: "rgba(255,61,122,0.15)" }}>
          <User className="w-3.5 h-3.5 text-[var(--color-pink)]" />
        </div>
      </div>
    );
  }
  if (entry.role === "agent") {
    return (
      <div className="flex items-start gap-2 rise-in">
        <div className="shrink-0 w-6 h-6 rounded-sm flex items-center justify-center" style={{ background: "rgba(168,178,240,0.1)" }}>
          <Bot className="w-3.5 h-3.5 text-[var(--color-ink-dim)]" />
        </div>
        <div
          className="max-w-[80%] px-3 py-2 rounded-sm text-[13px] leading-[1.5]"
          style={{
            background: "var(--color-bg-2)",
            border: "1px solid var(--color-hairline-2)",
            color: "var(--color-ink)",
          }}
        >
          {entry.text}
        </div>
      </div>
    );
  }
  if (entry.role === "tex") {
    const color =
      entry.verdict === "FORBID" ? "var(--color-red)" :
      entry.verdict === "ABSTAIN" ? "var(--color-yellow)" :
      "var(--color-permit)";
    const bg =
      entry.verdict === "FORBID" ? "rgba(255,59,59,0.08)" :
      entry.verdict === "ABSTAIN" ? "rgba(255,225,74,0.08)" :
      "rgba(59,255,158,0.06)";
    const label =
      entry.verdict === "FORBID" ? "BLOCKED" :
      entry.verdict === "ABSTAIN" ? "ESCALATED" :
      "LET THROUGH";
    return (
      <div className="flex justify-center rise-in">
        <div
          className="max-w-[92%] px-3 py-2.5 rounded-sm border text-center"
          style={{ background: bg, borderColor: color, boxShadow: `0 0 18px ${color}33` }}
        >
          <div className="t-micro flex items-center justify-center gap-1.5" style={{ color }}>
            <span className="inline-block w-1 h-1 rounded-full" style={{ background: color }} />
            TEX · {entry.verdict} · {entry.latencyMs}ms
          </div>
          <div className="t-display text-[15px] mt-1" style={{ color, letterSpacing: "0.02em" }}>
            {label}
          </div>
          {entry.tell && entry.verdict !== "PERMIT" && (
            <div
              className="text-[11px] text-[var(--color-ink-dim)] mt-1 italic max-w-[400px] mx-auto"
              style={{ fontFamily: "var(--font-serif)" }}
            >
              {entry.tell}
            </div>
          )}
        </div>
      </div>
    );
  }
  return null;
}

function delay(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
