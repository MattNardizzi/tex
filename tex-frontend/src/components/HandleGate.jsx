import React, { useState } from "react";
import { ArrowRight, X } from "lucide-react";

export default function HandleGate({ onSet, onSkip }) {
  const [handle, setHandle] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    const cleaned = handle
      .replace(/[^a-zA-Z0-9_-]/g, "")
      .slice(0, 24)
      .toLowerCase();
    if (cleaned.length >= 2) onSet(cleaned);
    else onSkip();
  };

  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center p-4 safe-top safe-bottom"
      onClick={onSkip}
      style={{
        background: "radial-gradient(ellipse at center, rgba(10, 5, 7, 0.9) 0%, rgba(10, 5, 7, 0.98) 80%)",
        backdropFilter: "blur(12px)",
      }}
    >
      <form
        onSubmit={handleSubmit}
        onClick={(e) => e.stopPropagation()}
        className="panel w-full max-w-[460px] relative overflow-hidden rise-in"
        style={{
          borderColor: "var(--color-cyan-deep)",
          boxShadow: "0 0 0 1px var(--color-cyan-deep), 0 24px 60px rgba(0,0,0,0.5), 0 0 40px rgba(95, 240, 255, 0.18)",
        }}
      >
        <button
          type="button"
          onClick={onSkip}
          className="absolute top-3 right-3 z-10 p-1.5 text-[var(--color-ink-dim)] hover:text-[var(--color-ink)] transition-colors"
          aria-label="Skip"
        >
          <X className="w-4 h-4" />
        </button>

        <div className="px-5 py-4 border-b border-[var(--color-hairline)]">
          <div className="t-kicker text-[var(--color-cyan)] mb-1.5">Pick a handle</div>
          <div
            className="t-display text-[28px] leading-none text-[var(--color-ink)]"
            style={{ letterSpacing: "-0.01em", textShadow: "0 0 12px rgba(95, 240, 255, 0.3)" }}
          >
            Sign the card
          </div>
          <p
            className="mt-2 text-[13px] italic text-[var(--color-ink-dim)] leading-snug"
            style={{ fontFamily: "var(--font-serif)" }}
          >
            Put your name on your fight card. Optional, skippable, stored on this device only.
          </p>
        </div>

        <div className="p-5 flex items-center gap-2">
          <span className="font-mono text-[16px] text-[var(--color-cyan)]">@</span>
          <input
            autoFocus
            type="text"
            value={handle}
            maxLength={24}
            onChange={(e) => setHandle(e.target.value)}
            placeholder="your-handle"
            className="flex-1 font-mono text-[14px] text-[var(--color-ink)] bg-[var(--color-bg)] border border-[var(--color-hairline-2)] px-3 py-2 focus:outline-none focus:border-[var(--color-cyan)] rounded-sm"
            style={{ fontFamily: "var(--font-mono)" }}
          />
        </div>

        <div className="grid grid-cols-2 border-t border-[var(--color-hairline)]">
          <button
            type="button"
            onClick={onSkip}
            className="py-3 t-label text-[var(--color-ink-dim)] hover:bg-[var(--color-bg-3)] hover:text-[var(--color-ink)] transition-colors border-r border-[var(--color-hairline)]"
          >
            Skip
          </button>
          <button
            type="submit"
            className="inline-flex items-center justify-center gap-2 py-3 transition-all"
            style={{
              background: "var(--color-cyan)",
              color: "var(--color-bg)",
              fontFamily: "var(--font-display)",
              fontSize: "15px",
              letterSpacing: "0.04em",
              textTransform: "uppercase",
            }}
          >
            Ready
            <ArrowRight className="w-4 h-4" strokeWidth={2.5} />
          </button>
        </div>
      </form>
    </div>
  );
}
