import React, { useEffect, useRef, useState } from "react";
import { Send, Clock, User, Bot, Sparkles } from "lucide-react";
import { agentReplyFor } from "../lib/agentSim.js";
import { evaluateAgentReply } from "../lib/apiClient.js";
import { punchSound } from "../lib/sound.js";

/*
  InterrogationChat v6.1
  ──────────────────────
  Changes from v6:
    • Timer does NOT start until the player sends their first question.
      No more "already down to 45s before I've typed anything."
    • Transcript area grows from a small initial height as messages are
      added. No dead empty panel waiting to be filled.
    • Timer displays as "60s — starts on your first question" before play.
*/

const QUESTION_LIMIT = 3;
const TIME_LIMIT_SECONDS = 60;

export default function InterrogationChat({
  caseDef,
  onCatch,
  onSessionEnd,
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

  // Reset on case change
  useEffect(() => {
    sessionIdRef.current += 1;
    setTranscript([]);
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
      onSessionEnd?.({ reason: "timeout", questionsUsed: questionsAsked });
      return;
    }
    const t = setTimeout(() => setSecondsLeft((s) => Math.max(0, s - 1)), 1000);
    return () => clearTimeout(t);
  }, [secondsLeft, sessionOver, questionsAsked, onSessionEnd, timerStarted]);

  // Auto-scroll
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

    // Kick the timer on the FIRST question only
    if (!timerStarted) setTimerStarted(true);

    setTranscript((t) => [...t, { role: "player", text: question }]);
    setQuestionsAsked((n) => n + 1);
    setIsProcessing(true);

    const reply = agentReplyFor(caseDef, question);
    await delay(420 + Math.random() * 280);
    if (sessionIdRef.current !== myId) return;

    setTranscript((t) => [...t, { role: "agent", text: reply.text, intent: reply.intent }]);

    await delay(180);
    if (sessionIdRef.current !== myId) return;

    const t0 = performance.now();
    try {
      const decision = await evaluateAgentReply({
        caseDef,
        agentReplyText: reply.text,
      });
      if (sessionIdRef.current !== myId) return;

      const catchMs = Math.round(performance.now() - t0);

      setTranscript((t) => [
        ...t,
        {
          role: "tex",
          verdict: decision.verdict,
          text:
            decision.verdict === "FORBID" ? "BLOCKED" :
            decision.verdict === "ABSTAIN" ? "ESCALATED FOR REVIEW" :
            "LET THROUGH",
          latencyMs: decision.latency?.total_ms ?? decision.elapsed_ms ?? catchMs,
          tell: reply.tell,
          decision,
        },
      ]);

      if (decision.verdict === "FORBID" || decision.verdict === "ABSTAIN") {
        setSessionOver(true);
        setIsProcessing(false);
        onCatch?.(decision, {
          catchMs: decision.latency?.total_ms ?? decision.elapsed_ms ?? catchMs,
          questionsUsed: questionsAsked + 1,
          agentReply: reply.text,
        });
        return;
      }

      setIsProcessing(false);
      if (questionsAsked + 1 >= QUESTION_LIMIT) {
        setSessionOver(true);
        onSessionEnd?.({ reason: "questions_exhausted", questionsUsed: QUESTION_LIMIT });
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
    <section className="panel overflow-hidden">
      {/* Header */}
      <div className="px-4 sm:px-5 py-2.5 border-b border-[var(--color-hairline-2)] flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="t-micro text-[var(--color-pink)]">INTERROGATION</span>
          <span className="t-micro text-[var(--color-ink-faint)]">·</span>
          <span className="t-micro text-[var(--color-ink-dim)]">{caseDef.persona}</span>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1" aria-label={`${questionsLeft} questions left`}>
            {Array.from({ length: QUESTION_LIMIT }).map((_, i) => (
              <span
                key={i}
                className="inline-block w-1.5 h-1.5 rounded-full"
                style={{
                  background: i < questionsLeft ? "var(--color-cyan)" : "var(--color-hairline-2)",
                  boxShadow: i < questionsLeft ? "0 0 8px rgba(95,240,255,0.7)" : "none",
                }}
              />
            ))}
          </div>
          <div className="flex items-center gap-1 tabular-nums" style={{ color: timerTone }}>
            <Clock className="w-3.5 h-3.5" />
            <span className="t-display text-[14px]" style={{ letterSpacing: "0.04em" }}>
              {timerDisplay}
            </span>
          </div>
        </div>
      </div>

      {/* Transcript — shrinks/grows with content */}
      {transcriptEmpty ? (
        <div className="px-5 py-6 text-center">
          <div
            className="text-[13px] italic text-[var(--color-ink-dim)] max-w-[440px] mx-auto leading-[1.5]"
            style={{ fontFamily: "var(--font-serif)" }}
          >
            <span className="text-[var(--color-ink)] font-bold not-italic">{caseDef.persona}</span> is online.
            You have {QUESTION_LIMIT} questions. The 60-second clock starts when you send your first one.
          </div>
          <div className="mt-3 t-micro text-[var(--color-ink-faint)]">
            Ask below &darr;
          </div>
        </div>
      ) : (
        <div
          ref={scrollerRef}
          className="overflow-y-auto p-4 space-y-3"
          style={{ maxHeight: "420px", minHeight: "160px" }}
        >
          {transcript.map((entry, i) => (
            <TranscriptLine key={i} entry={entry} />
          ))}
          {isProcessing && (
            <div className="flex items-center gap-2 t-micro text-[var(--color-cyan)]">
              <Sparkles className="w-3 h-3 pulse-ring-cyan" />
              Tex is reading the reply...
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
      <div className="border-t border-[var(--color-hairline-2)] p-3">
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
            className="flex-1 font-mono text-[13px] bg-[var(--color-bg-2)] border border-[var(--color-hairline-2)] rounded-sm px-3 py-2 text-[var(--color-ink)] placeholder:text-[var(--color-ink-faint)] resize-none"
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
        <div className="mt-1.5 t-micro text-[var(--color-ink-faint)] flex items-center justify-between">
          <span>{pendingInput.length}/400</span>
          <span className="italic" style={{ fontFamily: "var(--font-serif)" }}>
            The agent&rsquo;s reply is what Tex judges &mdash; make it say something bad.
          </span>
        </div>
      </div>
    </section>
  );
}

function TranscriptLine({ entry }) {
  if (entry.role === "player") {
    return (
      <div className="flex items-start gap-2 justify-end">
        <div
          className="max-w-[85%] px-3 py-2 rounded-sm text-[13px] leading-[1.5]"
          style={{
            background: "rgba(255,61,122,0.12)",
            border: "1px solid rgba(255,61,122,0.35)",
            color: "var(--color-ink)",
          }}
        >
          {entry.text}
        </div>
        <User className="w-4 h-4 mt-1 text-[var(--color-pink)]" />
      </div>
    );
  }
  if (entry.role === "agent") {
    return (
      <div className="flex items-start gap-2">
        <Bot className="w-4 h-4 mt-1 text-[var(--color-ink-dim)]" />
        <div
          className="max-w-[85%] px-3 py-2 rounded-sm text-[13px] leading-[1.5]"
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
      entry.verdict === "FORBID" ? "rgba(255,59,59,0.10)" :
      entry.verdict === "ABSTAIN" ? "rgba(255,225,74,0.10)" :
      "rgba(59,255,158,0.08)";
    return (
      <div className="flex items-start gap-2 justify-center">
        <div
          className="max-w-[90%] px-3 py-2 rounded-sm text-[13px] leading-[1.5] border text-center"
          style={{ background: bg, borderColor: color, color: "var(--color-ink)" }}
        >
          <div className="t-micro" style={{ color }}>
            TEX &middot; {entry.verdict} &middot; {entry.latencyMs}ms
          </div>
          <div className="t-display text-[15px] mt-0.5" style={{ color }}>
            {entry.text}
          </div>
          {entry.tell && entry.verdict !== "PERMIT" && (
            <div
              className="text-[11px] text-[var(--color-ink-dim)] mt-1 italic"
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
