import React, { useState } from "react";
import { Lightbulb, RotateCcw, ArrowUpRight } from "lucide-react";

/*
  ATTACK COMPOSER — v3 "Red Corner"
  ----------------------------------
  Terminal-feel textarea. Hints expand inline. Submit is a wide
  pink button with the current opponent's name — no cartoon glove.
  Keyboard: ⌘+Enter submits.
*/

export default function AttackComposer({
  round,
  value,
  onChange,
  onSubmit,
  onReset,
  isEvaluating,
  disabled,
}) {
  const [showHints, setShowHints] = useState(false);
  const charCount = value.length;
  const minChars = 8;
  const ready = charCount >= minChars && !isEvaluating && !disabled;

  return (
    <section className="panel overflow-hidden relative">
      {/* Top bar */}
      <div
        className="relative flex items-center justify-between px-4 py-2.5 border-b border-[var(--color-hairline-2)]"
        style={{
          background: "linear-gradient(90deg, rgba(255, 61, 122, 0.08) 0%, transparent 60%)",
        }}
      >
        <div className="flex items-center gap-2">
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-[var(--color-pink)]" />
          <span className="t-micro text-[var(--color-pink-soft)]">Red Corner · Your Strike</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowHints((s) => !s)}
            className="inline-flex items-center gap-1.5 px-2 py-1 t-micro text-[var(--color-ink-dim)] hover:text-[var(--color-cyan)] transition-colors"
          >
            <Lightbulb className="w-3 h-3" />
            {showHints ? "Hide hints" : "Hints"}
          </button>
          {value && (
            <button
              onClick={onReset}
              className="inline-flex items-center gap-1.5 px-2 py-1 t-micro text-[var(--color-ink-faint)] hover:text-[var(--color-pink)] transition-colors"
            >
              <RotateCcw className="w-3 h-3" />
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Hints */}
      {showHints && (
        <div
          className="px-4 py-3 border-b border-[var(--color-hairline)] rise-in"
          style={{ background: "rgba(95, 240, 255, 0.04)" }}
        >
          <div className="t-micro text-[var(--color-cyan)] mb-2 inline-flex items-center gap-1.5">
            <span>★</span> Coach's whisper
          </div>
          <ul className="space-y-2">
            {round.hints.map((hint, i) => (
              <li key={i} className="text-[12px] sm:text-[13px] leading-[1.55] text-[var(--color-ink-dim)] flex gap-2">
                <span className="text-[var(--color-cyan)] flex-shrink-0">→</span>
                <span className="italic" style={{ fontFamily: "var(--font-serif)" }}>
                  {hint}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Textarea */}
      <div className="relative">
        <textarea
          value={value}
          onChange={(e) => onChange(e.target.value)}
          disabled={isEvaluating || disabled}
          onKeyDown={(e) => {
            if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && ready) {
              e.preventDefault();
              onSubmit();
            }
          }}
          placeholder="Type the content you want to sneak past Tex. Be clever. Be dangerous."
          rows={8}
          className="w-full resize-none px-4 py-4 font-mono text-[13px] leading-[1.65] text-[var(--color-ink)] bg-transparent placeholder:text-[var(--color-ink-faint)] focus:outline-none focus:bg-[var(--color-bg-3)] disabled:opacity-60 transition-colors"
          style={{ fontFamily: "var(--font-mono)" }}
        />

        {/* Bottom meta */}
        <div className="px-4 py-2 flex items-center justify-between border-t border-[var(--color-hairline)]">
          <div className="flex items-center gap-3">
            <span className="t-micro text-[var(--color-ink-faint)]">{charCount} chars</span>
            {charCount > 0 && charCount < minChars && (
              <span className="t-micro text-[var(--color-pink)]">min {minChars}</span>
            )}
          </div>
          <div className="t-micro text-[var(--color-ink-faint)] hidden sm:block">
            ⌘ + Enter to throw
          </div>
        </div>
      </div>

      {/* THROW button — full width, clear call */}
      <button
        onClick={onSubmit}
        disabled={!ready}
        className={`
          w-full relative group overflow-hidden transition-all border-t
          ${ready ? "cursor-pointer" : "cursor-not-allowed"}
        `}
        style={{
          background: ready
            ? "linear-gradient(180deg, #ff4e87 0%, var(--color-pink) 50%, var(--color-pink-deep) 100%)"
            : "var(--color-bg-3)",
          borderColor: ready ? "var(--color-pink-deep)" : "var(--color-hairline-2)",
          boxShadow: ready
            ? "0 -1px 0 rgba(255, 255, 255, 0.1) inset, 0 12px 32px rgba(255, 61, 122, 0.25)"
            : "none",
        }}
      >
        <div className="px-5 py-4 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <span
              className="t-display text-[22px] sm:text-[26px] leading-none"
              style={{
                color: ready ? "#fff" : "var(--color-ink-faint)",
                letterSpacing: "0.04em",
                textShadow: ready ? "0 2px 0 rgba(0,0,0,0.25)" : "none",
              }}
            >
              {isEvaluating ? "Incoming…" : "Throw punch"}
            </span>
            {ready && !isEvaluating && (
              <span className="t-micro text-white/90">
                → vs {round.name.replace("The ", "")}
              </span>
            )}
          </div>

          {ready && !isEvaluating && (
            <ArrowUpRight className="w-5 h-5 text-white transition-transform group-hover:translate-x-1 group-hover:-translate-y-1" strokeWidth={2.5} />
          )}
        </div>

        {/* Shimmer on hover */}
        {ready && !isEvaluating && (
          <span className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700 pointer-events-none" />
        )}
      </button>
    </section>
  );
}
