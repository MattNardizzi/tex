import React from "react";
import { Trophy, AlertTriangle } from "lucide-react";

/*
  CaseFile — "who am I interrogating, what are they about to do"
  ─────────────────────────────────────────────────────────────────
  Replaces the verbose BriefCard. Three things only: the suspect's
  persona, what they're about to do, and the best result so far on
  this case. No hints list, no ASI vocabulary, no rules restated —
  the hero already taught the rules.
*/

export default function CaseFile({ caseDef, perCase }) {
  const idLabel = String(caseDef.id).padStart(3, "0");
  const bestScore = perCase?.bestScore || 0;
  const bestMs = perCase?.bestCatchMs;

  return (
    <section
      className="panel overflow-hidden"
      style={{
        background:
          "linear-gradient(135deg, rgba(255,61,122,0.05) 0%, rgba(95,240,255,0.04) 100%)",
      }}
    >
      {/* Header strip */}
      <div className="px-4 sm:px-5 py-2.5 border-b border-[var(--color-hairline-2)] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="t-micro text-[var(--color-pink)]">CASE FILE</span>
          <span className="t-micro text-[var(--color-ink-faint)]">·</span>
          <span className="t-micro text-[var(--color-ink-faint)]">#{idLabel}</span>
          {caseDef.isBounty && (
            <span className="t-micro glow-gold inline-flex items-center gap-1 ml-1">
              <Trophy className="w-3 h-3" /> BOUNTY
            </span>
          )}
        </div>
        {bestScore > 0 && (
          <div className="t-micro text-[var(--color-ink-faint)]">
            YOUR BEST: <span className="text-[var(--color-ink)]">{bestScore.toLocaleString()}</span>
            {bestMs != null ? <span className="ml-1">· {bestMs}ms</span> : null}
          </div>
        )}
      </div>

      {/* Body */}
      <div className="px-4 sm:px-5 py-4 sm:py-5">
        <div className="t-kicker text-[var(--color-ink-faint)] mb-1.5">THE SUSPECT</div>
        <h2
          className="t-display text-[28px] sm:text-[34px] leading-[1.02] text-[var(--color-ink)]"
          style={{ letterSpacing: "-0.01em" }}
        >
          {caseDef.name}
        </h2>
        <div
          className="mt-1 text-[13px] sm:text-[14px] italic text-[var(--color-ink-dim)]"
          style={{ fontFamily: "var(--font-serif)" }}
        >
          {caseDef.persona} &mdash; {caseDef.tagline}
        </div>

        <div className="mt-4 flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 text-[var(--color-pink)] shrink-0 mt-0.5" />
          <p className="text-[14px] leading-[1.55] text-[var(--color-ink-dim)]">
            {caseDef.intro}
          </p>
        </div>
      </div>
    </section>
  );
}
