import React from "react";
import { X, Target, Brain, Coffee, ArrowRight } from "lucide-react";
import { BOUNTY_AMOUNT } from "../lib/rounds";

/*
  HOW TO PLAY — first-visit overlay.
  Editorial modal: three numbered cards, verdict legend, one CTA.
*/

export default function HowToPlayOverlay({ onDismiss }) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 safe-top safe-bottom"
      onClick={onDismiss}
      role="dialog"
      aria-modal="true"
      style={{
        background: "radial-gradient(ellipse at center, rgba(10, 5, 7, 0.92) 0%, rgba(10, 5, 7, 0.98) 70%)",
        backdropFilter: "blur(16px)",
      }}
    >
      <div
        className="panel relative w-full max-w-[720px] overflow-hidden rise-in"
        onClick={(e) => e.stopPropagation()}
        style={{
          boxShadow: "0 24px 80px rgba(0, 0, 0, 0.6), 0 0 0 1px var(--color-hairline-2)",
        }}
      >
        {/* Close */}
        <button
          onClick={onDismiss}
          className="absolute top-3 right-3 z-20 p-1.5 text-[var(--color-ink-dim)] hover:text-[var(--color-ink)] transition-colors"
          aria-label="Close"
        >
          <X className="w-4 h-4" />
        </button>

        {/* Header */}
        <div className="px-6 sm:px-8 pt-7 pb-4 border-b border-[var(--color-hairline)]">
          <div className="t-kicker text-[var(--color-cyan)] mb-2">
            New challenger approaches
          </div>
          <h2
            className="t-display text-[40px] sm:text-[52px] leading-[0.9] text-[var(--color-ink)]"
            style={{ letterSpacing: "-0.01em" }}
          >
            How to play
          </h2>
        </div>

        {/* Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-px bg-[var(--color-hairline)]">
          <Card
            n="01"
            icon={<Target className="w-5 h-5" />}
            title="Pick a round"
            body="Seven opponents, rising difficulty. Start with The Intern."
            accent="var(--color-pink)"
          />
          <Card
            n="02"
            icon={<Brain className="w-5 h-5" />}
            title="Trick Tex"
            body="Write content that shouldn't get through — secrets, malicious code, unauthorized promises."
            accent="var(--color-cyan)"
          />
          <Card
            n="03"
            icon={<Coffee className="w-5 h-5" />}
            title={`Win $${BOUNTY_AMOUNT}`}
            body={`Beat The Warden (Round 7) with content a human would call malicious — we send you a $${BOUNTY_AMOUNT} Starbucks gift card.`}
            accent="var(--color-gold)"
          />
        </div>

        {/* Verdict legend */}
        <div className="px-6 sm:px-8 py-4 border-y border-[var(--color-hairline)]">
          <div className="t-micro text-[var(--color-ink-faint)] mb-3">
            Three ways a fight ends
          </div>
          <div className="grid grid-cols-3 gap-3">
            <Verdict label="PERMIT" outcome="You win" color="var(--color-permit)" />
            <Verdict label="ABSTAIN" outcome="Draw" color="var(--color-gold)" />
            <Verdict label="FORBID" outcome="Tex wins" color="var(--color-red)" />
          </div>
        </div>

        {/* CTA */}
        <div className="px-6 sm:px-8 py-5">
          <button
            onClick={onDismiss}
            className="btn-primary w-full justify-center"
          >
            Let me at him
            <ArrowRight className="w-5 h-5" strokeWidth={2.5} />
          </button>
          <div className="text-center t-micro text-[var(--color-ink-faint)] mt-3">
            Free · No login · Progress saved on this device
          </div>
        </div>
      </div>
    </div>
  );
}

function Card({ n, icon, title, body, accent }) {
  return (
    <div className="bg-[var(--color-bg-2)] p-5 relative">
      <div className="flex items-start justify-between mb-3">
        <span
          className="t-display text-[26px] leading-none"
          style={{ color: accent, letterSpacing: "0.02em" }}
        >
          {n}
        </span>
        <span style={{ color: accent, opacity: 0.9 }}>{icon}</span>
      </div>
      <div
        className="t-display text-[20px] leading-[0.95] text-[var(--color-ink)] mb-2"
        style={{ letterSpacing: "0.01em" }}
      >
        {title}
      </div>
      <div className="text-[12px] text-[var(--color-ink-dim)] leading-[1.5]">
        {body}
      </div>
    </div>
  );
}

function Verdict({ label, outcome, color }) {
  return (
    <div>
      <div
        className="t-display text-[14px] leading-none"
        style={{
          color: "#fff",
          textShadow: `0 0 10px ${color}`,
          letterSpacing: "0.02em",
        }}
      >
        {label}
      </div>
      <div className="t-micro text-[var(--color-ink-faint)] mt-1">= {outcome}</div>
    </div>
  );
}
