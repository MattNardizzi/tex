import React, { useEffect, useState } from "react";
import { thinkBlip } from "../lib/sound";

/*
  TEX THINKING — v3 "Referee Deliberating"
  ----------------------------------------
  Clean two-column panel: Tex's face in cyan spotlight on the left,
  six-layer pipeline progressing on the right. Each layer activates
  with a blip sound.
*/

const LAYERS = [
  { key: "deterministic", label: "Pattern scan",    sub: "recognizers + blocked terms" },
  { key: "retrieval",     label: "Policy lookup",   sub: "clauses + entities" },
  { key: "specialists",   label: "Risk judges",     sub: "four specialist scores" },
  { key: "semantic",      label: "Semantic judge",  sub: "LLM content analysis" },
  { key: "router",        label: "Fusion",          sub: "score fusion + verdict" },
  { key: "evidence",      label: "Evidence chain",  sub: "SHA-256 anchoring" },
];

export default function TexThinking({ visible }) {
  const [activeIndex, setActiveIndex] = useState(0);

  useEffect(() => {
    if (!visible) return;
    setActiveIndex(0);
    let i = 0;
    const interval = setInterval(() => {
      i += 1;
      if (i >= LAYERS.length) {
        clearInterval(interval);
        return;
      }
      setActiveIndex(i);
      thinkBlip();
    }, 340);
    return () => clearInterval(interval);
  }, [visible]);

  if (!visible) return null;

  return (
    <section
      className="panel relative overflow-hidden rise-in"
      style={{
        borderColor: "var(--color-cyan-deep)",
        boxShadow: "0 0 0 1px var(--color-cyan-deep), 0 0 32px rgba(95, 240, 255, 0.18)",
      }}
    >
      {/* Scanning beam */}
      <div
        className="absolute inset-x-0 h-24 scan-bar pointer-events-none z-10"
        style={{
          background: "linear-gradient(180deg, transparent 0%, rgba(95, 240, 255, 0.12) 50%, transparent 100%)",
        }}
      />

      {/* Header */}
      <div
        className="relative z-20 flex items-center justify-between px-4 py-2.5 border-b"
        style={{
          borderColor: "var(--color-cyan-deep)",
          background: "linear-gradient(90deg, rgba(95, 240, 255, 0.08) 0%, transparent 70%)",
        }}
      >
        <div className="flex items-center gap-2">
          <span
            className="w-1.5 h-1.5 rounded-full animate-pulse"
            style={{ background: "var(--color-cyan)", boxShadow: "0 0 6px var(--color-cyan)" }}
          />
          <span className="t-micro text-[var(--color-cyan)]">Tex is deliberating</span>
        </div>
        <span className="t-micro text-[var(--color-ink-dim)]">
          {Math.min(activeIndex + 1, LAYERS.length)} / {LAYERS.length}
        </span>
      </div>

      {/* Body */}
      <div className="relative z-10 grid grid-cols-1 sm:grid-cols-[200px_1fr]">
        {/* Tex face */}
        <div
          className="relative overflow-hidden order-2 sm:order-1 sm:border-r border-[var(--color-hairline-2)] flex items-center justify-center"
          style={{
            background: "radial-gradient(circle at 50% 45%, rgba(95, 240, 255, 0.2) 0%, transparent 55%), var(--color-bg-3)",
            minHeight: "160px",
          }}
        >
          <img
            src="/tex/tex-face.png"
            alt="Tex deliberating"
            className="w-full h-full object-cover object-top"
            style={{ filter: "drop-shadow(0 0 16px rgba(95, 240, 255, 0.5))", maxHeight: "280px" }}
          />
          <div
            className="absolute left-1/2 top-[42%] -translate-x-1/2 -translate-y-1/2 w-14 h-14 rounded-full pulse-ring-cyan pointer-events-none"
          />
        </div>

        {/* Layer list */}
        <ul className="order-1 sm:order-2 divide-y divide-[var(--color-hairline)]">
          {LAYERS.map((layer, i) => {
            const state = i < activeIndex ? "done" : i === activeIndex ? "active" : "pending";
            return (
              <li
                key={layer.key}
                className={`px-4 py-2.5 flex items-center gap-3 transition-opacity ${state === "pending" ? "opacity-30" : "opacity-100"}`}
              >
                <StatusDot state={state} />
                <div className="flex-1 flex items-baseline gap-3 min-w-0">
                  <span
                    className="t-label leading-none"
                    style={{
                      color: state === "active" ? "#fff" : "var(--color-ink-dim)",
                      textShadow: state === "active" ? "0 0 6px rgba(95, 240, 255, 0.4)" : "none",
                    }}
                  >
                    {layer.label}
                  </span>
                  <span className="t-micro text-[var(--color-ink-faint)] truncate hidden sm:inline">
                    {layer.sub}
                  </span>
                </div>
                <span className="t-micro text-[var(--color-ink-faint)] flex-shrink-0">
                  {state === "done" ? "✓" : state === "active" ? "···" : ""}
                </span>
              </li>
            );
          })}
        </ul>
      </div>
    </section>
  );
}

function StatusDot({ state }) {
  if (state === "done") {
    return (
      <span
        className="w-2 h-2 rounded-full flex-shrink-0"
        style={{ background: "var(--color-cyan)", boxShadow: "0 0 6px var(--color-cyan)" }}
      />
    );
  }
  if (state === "active") {
    return (
      <span
        className="w-2 h-2 rounded-full flex-shrink-0 pulse-ring-cyan"
        style={{ background: "var(--color-pink)", boxShadow: "0 0 6px var(--color-pink)" }}
      />
    );
  }
  return <span className="w-2 h-2 rounded-full border border-[var(--color-hairline-2)] flex-shrink-0" />;
}
