import React from "react";
import { Play, Shield, Zap, Trophy } from "lucide-react";
import { CLEARANCE_TIERS, tierFor } from "../lib/scoring.js";
import { BOUNTY_CASE_ID } from "../lib/cases.js";

/*
  ArenaHero v7 — "The Promise"
  ────────────────────────────
  Job of this screen: answer WHY the player is here in under 5 seconds.
  A CISO, a security engineer, or a LinkedIn scroller lands and must
  immediately see:
    1. What they are — an investigator catching AI agents before breaches
    2. What they win — a Clearance Tier badge they actually want
    3. How to start — one button, labeled with the first case

  Layout:
    Left  (60%): headline + promise + rules block + CTA + reward preview
    Right (40%): Tex portrait card, bordered, fixed size, UNDEFEATED label

  No absolute layers. No full-bleed image that stretches the stage. Tex
  is a framed portrait at a sensible max-height. The hero has a
  min-height of 92vh so the whole promise lives on one screen.
*/

export default function ArenaHero({
  player,
  currentCase,
  onStart,
  onScrollToLadder,
  allCleared,
}) {
  const cleared = player?.clearedCaseIds?.length || 0;
  const bountyCaught = player?.clearedCaseIds?.includes(BOUNTY_CASE_ID);
  const tier = tierFor(cleared, bountyCaught);
  const nextTier = tier.next;

  const ctaLabel = allCleared
    ? "REPLAY ANY CASE →"
    : cleared > 0
    ? `RESUME → CASE ${String(currentCase.id).padStart(3, "0")}`
    : `START CASE 001 → THE NEW INTERN`;

  const cleanProgress = nextTier
    ? Math.min(1, cleared / nextTier.min)
    : 1;
  const needed = nextTier ? Math.max(0, nextTier.min - cleared) : 0;

  return (
    <section
      className="relative stage overflow-hidden"
      style={{ minHeight: "min(92vh, 860px)" }}
    >
      <div className="relative mx-auto max-w-[1400px] px-5 sm:px-8 lg:px-12 pt-10 pb-10 sm:pt-12 sm:pb-14">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 lg:gap-10 items-center">
          {/* LEFT — Promise, Rules, CTA */}
          <div className="lg:col-span-7 rise-in">
            <div className="t-kicker text-[var(--color-cyan)] mb-3 flex items-center gap-2">
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-[var(--color-cyan)] pulse-ring-cyan" />
              TEX ARENA · INTERROGATION MODE · LIVE
            </div>

            {/* The Promise — answers WHY in one sentence */}
            <h1
              className="t-display text-[40px] sm:text-[56px] lg:text-[72px] leading-[0.92] tracking-[-0.02em] text-[var(--color-ink)]"
              style={{ fontFamily: "var(--font-display)" }}
            >
              <span className="block">CAN YOU CATCH</span>
              <span className="block mt-1">
                <span className="glow-pink">THE&nbsp;AI</span>{" "}
                <span className="text-[var(--color-ink-dim)]">BEFORE IT</span>
              </span>
              <span className="block mt-1 glow-cyan">COSTS YOUR COMPANY?</span>
            </h1>

            <p
              className="mt-4 text-[15px] sm:text-[17px] leading-[1.5] text-[var(--color-ink-dim)] max-w-[640px] italic"
              style={{ fontFamily: "var(--font-serif)" }}
            >
              Every case is a real breach pattern: wire fraud, data exfil,
              memory poisoning. You get <span className="not-italic text-[var(--color-ink)] font-bold">3 questions</span> to
              make the agent slip. If it does, Tex blocks it in milliseconds —
              in production, that's the difference between a breach and a Tuesday.
            </p>

            {/* THE PRIZE — what they're playing for, visible above the fold */}
            <div
              className="mt-6 panel px-4 py-3.5 max-w-[640px] flex items-start gap-3"
              style={{
                background: "linear-gradient(90deg, rgba(255,225,74,0.08) 0%, rgba(6,7,20,0.6) 80%)",
                borderColor: "rgba(255, 225, 74, 0.3)",
              }}
            >
              <Trophy className="w-5 h-5 mt-0.5 text-[var(--color-yellow)] shrink-0" />
              <div className="min-w-0 flex-1">
                <div className="t-kicker text-[var(--color-yellow)]">THE REWARD</div>
                <div className="mt-1 text-[14px] leading-[1.5] text-[var(--color-ink)]">
                  Clear all 7 cases to earn a <span className="glow-gold font-bold">CHIEF INVESTIGATOR</span> badge.
                  Catch <span className="glow-gold font-bold">The Warden</span> — nobody has — and
                  you're in the Hall of Fame.
                </div>
              </div>
            </div>

            {/* CTA row */}
            <div className="mt-6 flex flex-wrap items-center gap-3">
              <button
                onClick={onStart}
                className="btn-primary text-[14px] sm:text-[15px] px-6 py-3 inline-flex items-center gap-2 zoom-punch"
                style={{ letterSpacing: "0.04em" }}
              >
                <Play className="w-4 h-4" fill="currentColor" />
                {ctaLabel}
              </button>
              <button
                onClick={onScrollToLadder}
                className="btn-ghost text-[13px] inline-flex items-center gap-1.5"
              >
                <Shield className="w-3.5 h-3.5" />
                See all 7 cases
              </button>
            </div>

            {/* Rules — one line, minimal */}
            <p className="mt-4 t-micro text-[var(--color-ink-faint)] max-w-[640px] leading-[1.8]">
              3 questions · 60 seconds · catch on Q1 for a <span className="glow-gold">3× bonus</span>
              <span className="mx-2 opacity-50">·</span>
              every verdict comes from the live Tex API
            </p>
          </div>

          {/* RIGHT — Tex portrait, bounded */}
          <div className="lg:col-span-5 rise-2 relative">
            <div
              className="relative mx-auto max-w-[440px] overflow-hidden"
              style={{
                border: "1px solid rgba(95, 240, 255, 0.3)",
                borderRadius: "2px",
                background: "linear-gradient(180deg, rgba(6,7,20,0.2) 0%, rgba(6,7,20,0.6) 100%)",
              }}
            >
              {/* Scan bar */}
              <div
                className="absolute inset-x-0 top-0 h-[1px] bg-[var(--color-cyan)] opacity-60 scan-bar z-10"
                style={{ boxShadow: "0 0 12px rgba(95,240,255,0.6)" }}
              />

              {/* Live pip */}
              <div className="absolute top-3 left-3 z-10 t-micro text-[var(--color-cyan)] flex items-center gap-1.5">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-[var(--color-cyan)] pulse-ring-cyan" />
                TEX · LIVE
              </div>

              {/* Image — aspect-locked so it never stretches the hero */}
              <div className="relative w-full" style={{ aspectRatio: "4 / 5" }}>
                <img
                  src="/tex/tex-full.png"
                  alt="Tex — AI content adjudication gate"
                  className="absolute inset-0 w-full h-full object-cover object-top tex-float"
                  onError={(e) => { e.currentTarget.src = "/tex/tex-avatar.png"; }}
                />
              </div>

              {/* Bottom info strip */}
              <div className="absolute bottom-0 inset-x-0 p-3.5 bg-gradient-to-t from-[rgba(6,7,20,0.95)] to-transparent">
                <div className="flex items-end justify-between gap-3">
                  <div>
                    <div className="t-kicker text-[var(--color-cyan)] opacity-90">THE UNDEFEATED</div>
                    <div
                      className="t-display text-[28px] sm:text-[32px] leading-none text-[var(--color-ink)] mt-0.5"
                      style={{
                        letterSpacing: "0.02em",
                        textShadow: "0 0 18px rgba(95,240,255,0.35)",
                      }}
                    >
                      TEX
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="t-micro text-[var(--color-ink-faint)]">RECORD</div>
                    <div className="t-display text-[14px] text-[var(--color-ink)] mt-0.5 tabular-nums">
                      ∞–0–0
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Small progress chip under the portrait — your current tier */}
            <div className="mt-4 max-w-[440px] mx-auto">
              <div
                className="panel px-3 py-2.5 flex items-center gap-3"
                style={{
                  borderColor: "rgba(168, 178, 240, 0.2)",
                  background: "rgba(6,7,20,0.6)",
                }}
              >
                <div
                  className="shrink-0 w-8 h-8 rounded-sm flex items-center justify-center"
                  style={{
                    background: tier.current.color,
                    color: "#060714",
                    fontFamily: "var(--font-display)",
                    fontSize: "12px",
                    letterSpacing: "0.04em",
                    boxShadow: `0 0 16px ${tier.current.glowColor}`,
                  }}
                >
                  {tier.current.short}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="t-micro text-[var(--color-ink-faint)]">YOUR CLEARANCE</div>
                  <div
                    className="t-display text-[14px] mt-0.5 truncate"
                    style={{ color: tier.current.color, letterSpacing: "0.03em" }}
                  >
                    {tier.current.name}
                  </div>
                </div>
                {nextTier ? (
                  <div className="text-right shrink-0">
                    <div className="t-micro text-[var(--color-ink-faint)]">NEXT</div>
                    <div className="t-display text-[14px] mt-0.5 text-[var(--color-ink)]">
                      {needed} case{needed !== 1 ? "s" : ""}
                    </div>
                  </div>
                ) : (
                  <div className="text-right shrink-0">
                    <div className="t-micro glow-gold">MAXED</div>
                  </div>
                )}
              </div>
              {nextTier && (
                <div className="h-[2px] bg-[var(--color-bg-3)] mt-1 rounded-full overflow-hidden">
                  <div
                    className="h-full transition-all duration-700"
                    style={{
                      width: `${Math.round(cleanProgress * 100)}%`,
                      background: `linear-gradient(90deg, ${tier.current.color}, ${nextTier.color})`,
                      boxShadow: `0 0 8px ${nextTier.glowColor}`,
                    }}
                  />
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
