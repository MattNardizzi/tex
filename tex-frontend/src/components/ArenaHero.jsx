import React from "react";
import { Volume2, VolumeX, ArrowRight, Briefcase } from "lucide-react";
import { BOUNTY_AMOUNT, ASI_COVERED_COUNT, ASI_TOTAL_COUNT } from "../lib/rounds";

/*
  ARENA HERO — v4 "ASI-first poster"
  ─────────────────────────────────────
  Same boxing-promotion treatment. Two new pieces in this revision:

   1. Live counter is now "ASI 2026 findings attributed" — the thing
      nobody else in the landscape has. Pulled from per-player local
      storage; aggregated across sessions via the player object that
      App.jsx passes in.

   2. "I'm a buyer, not a player" button, rendered beside the primary
      CTA. Sends the visitor to the buyer surface without burning them
      through the arena.
*/

export default function ArenaHero({
  onStartPlaying,
  onOpenBuyerSurface,
  onToggleSound,
  soundOn,
  onAbout,
  totalAttempts,
  asiFindingsCount,
  asiCategoriesSeenCount,
  bountyClaimed,
}) {
  return (
    <section className="stage grain-warm relative safe-top">
      <TopBar onToggleSound={onToggleSound} soundOn={soundOn} onAbout={onAbout} />

      <Ticker />

      <div className="relative mx-auto max-w-[1400px] px-5 sm:px-8 lg:px-12 pt-8 sm:pt-12 lg:pt-10 pb-0">
        <div className="grid grid-cols-1 lg:grid-cols-[1.15fr_1fr] gap-6 lg:gap-12 items-end min-h-[72vh] lg:min-h-[78vh]">

          {/* LEFT — Copy */}
          <div className="relative z-10 order-2 lg:order-1 pb-10 sm:pb-16 lg:pb-20">
            <div className="mb-5 sm:mb-7 rise-1">
              <span className="chip-gold">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#1a0d00]" />
                WIN&nbsp;${BOUNTY_AMOUNT}&nbsp;STARBUCKS
              </span>
              <span className="chip-ghost ml-2 align-middle hidden sm:inline-flex">
                {bountyClaimed ? "Claimed" : "Unclaimed"}
              </span>
            </div>

            <div
              className="t-kicker mb-3 sm:mb-4 rise-2 glow-cyan"
              style={{ color: "var(--color-cyan)" }}
            >
              Red-Team Challenge · 7 Rounds · OWASP ASI 2026
            </div>

            <h1
              className="t-display text-[64px] xs:text-[76px] sm:text-[108px] md:text-[132px] lg:text-[124px] xl:text-[148px] leading-[0.86] text-white rise-3"
              style={{
                letterSpacing: "-0.02em",
                textShadow:
                  "0 2px 0 rgba(0,0,0,0.5), 0 18px 40px rgba(0,0,0,0.6)",
              }}
            >
              Can&nbsp;you
              <br />
              <span className="relative inline-block">
                <span className="relative z-10">beat&nbsp;Tex?</span>
                <span
                  className="absolute left-0 right-0 bottom-[0.08em] h-[0.12em] -z-0"
                  style={{
                    background:
                      "linear-gradient(90deg, var(--color-pink), transparent 70%)",
                    opacity: 0.65,
                  }}
                />
              </span>
            </h1>

            <p className="mt-5 sm:mt-7 max-w-[48ch] text-[15px] sm:text-[17px] leading-[1.55] text-[var(--color-ink-dim)] rise-4">
              Tex is a content gate for AI agents. Try to sneak a malicious
              message past him — every loss is mapped to{" "}
              <span className="text-[var(--color-ink)]">
                OWASP ASI 2026
              </span>
              , the new standard for agent risk.{" "}
              <span className="text-[var(--color-ink)]">
                Pull it off on Round 7 and we send you a ${BOUNTY_AMOUNT}{" "}
                Starbucks card.
              </span>
            </p>

            {/* CTA row */}
            <div className="mt-7 sm:mt-9 flex flex-col sm:flex-row items-stretch sm:items-center gap-3 rise-5">
              <button onClick={onStartPlaying} className="btn-primary group relative">
                Step in the ring
                <ArrowRight
                  className="w-5 h-5 transition-transform group-hover:translate-x-1"
                  strokeWidth={2.5}
                />
              </button>

              <button
                onClick={onOpenBuyerSurface}
                className="btn-ghost inline-flex items-center justify-center gap-2"
                style={{
                  borderColor: "var(--color-cyan)",
                  color: "var(--color-cyan)",
                }}
              >
                <Briefcase className="w-4 h-4" strokeWidth={2.2} />
                I'm a buyer, not a player
              </button>
            </div>

            {/* Live counter — ASI findings edition */}
            <div className="mt-5 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[11px] font-mono uppercase tracking-[0.22em] rise-5">
              <span className="inline-flex items-center gap-1.5 text-[var(--color-ink-dim)]">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-[var(--color-permit)] animate-pulse" />
                Live
              </span>
              <span className="text-[var(--color-ink-faint)]">·</span>
              <span className="text-[var(--color-ink-dim)]">
                {formatCount(asiFindingsCount)}{" "}
                <span className="text-[var(--color-ink-faint)]">
                  ASI findings attributed
                </span>
              </span>
              <span className="text-[var(--color-ink-faint)]">·</span>
              <span className="text-[var(--color-ink-dim)]">
                {formatCount(totalAttempts)}{" "}
                <span className="text-[var(--color-ink-faint)]">attacks</span>
              </span>
              <span className="text-[var(--color-ink-faint)]">·</span>
              <span className="text-[var(--color-ink-dim)]">
                <span className="text-[var(--color-gold)]">
                  {asiCategoriesSeenCount || 0}
                </span>
                <span className="text-[var(--color-ink-faint)]">
                  /{ASI_COVERED_COUNT} you've seen
                </span>
              </span>
            </div>

            {/* Rules strip */}
            <div className="mt-8 sm:mt-10 grid grid-cols-3 gap-0 border-y border-[var(--color-hairline-2)] rise-5">
              <RuleBeat n="01" label="Pick an opponent" />
              <RuleBeat
                n="02"
                label="Send an attack. Tex returns a verdict in &lt; 2ms"
                withDivider
              />
              <RuleBeat
                n="03"
                label={`Every loss = a real OWASP ASI category. Beat Round 7 → $${BOUNTY_AMOUNT}`}
                withDivider
                highlight
              />
            </div>

            <p
              className="mt-4 text-[11px] text-[var(--color-ink-faint)] italic"
              style={{ fontFamily: "var(--font-serif)" }}
            >
              Tex covers {ASI_COVERED_COUNT} of {ASI_TOTAL_COUNT} OWASP ASI
              2026 categories at the content layer. The other{" "}
              {ASI_TOTAL_COUNT - ASI_COVERED_COUNT} belong to the identity
              and infrastructure layers.
            </p>
          </div>

          {/* RIGHT — Tex on gold spotlight stage */}
          <div className="relative order-1 lg:order-2 h-[360px] sm:h-[500px] lg:h-auto lg:self-stretch flex items-end justify-center">
            <TexStage />
          </div>
        </div>
      </div>

      <div className="relative">
        <div className="h-px bg-gradient-to-r from-transparent via-[var(--color-gold-deep)] to-transparent opacity-60" />
      </div>
    </section>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function TopBar({ onToggleSound, soundOn, onAbout }) {
  return (
    <div className="relative z-20 mx-auto max-w-[1400px] px-5 sm:px-8 lg:px-12 pt-4 sm:pt-5 flex items-center justify-between">
      <div className="flex items-center gap-2">
        <span className="inline-block w-1.5 h-1.5 rounded-full bg-[var(--color-permit)] animate-pulse" />
        <span className="t-label text-[var(--color-ink-dim)]">
          Tex Arena{" "}
          <span className="text-[var(--color-ink-faint)]">· Live</span>
        </span>
      </div>
      <div className="flex items-center gap-2 sm:gap-3">
        <button
          onClick={onAbout}
          className="t-label text-[var(--color-ink-dim)] hover:text-[var(--color-ink)] transition-colors"
        >
          What is Tex?
        </button>
        <button
          onClick={onToggleSound}
          className="p-1.5 border border-[var(--color-hairline-2)] text-[var(--color-ink-dim)] hover:text-[var(--color-ink)] hover:border-[var(--color-ink-dim)] transition-colors rounded-sm"
          aria-label={soundOn ? "Mute sound" : "Enable sound"}
        >
          {soundOn ? (
            <Volume2 className="w-3.5 h-3.5" />
          ) : (
            <VolumeX className="w-3.5 h-3.5" />
          )}
        </button>
      </div>
    </div>
  );
}

function Ticker() {
  const phrases = [
    "NOBODY HAS BEATEN TEX",
    "$10 STARBUCKS BOUNTY",
    "7 OPPONENTS · 1 BELT",
    "FREE TO PLAY · NO LOGIN",
    "OWASP ASI 2026 · CONTENT LAYER",
    "EVERY LOSS · ONE REAL ASI FINDING",
  ];
  const all = [...phrases, ...phrases, ...phrases];
  return (
    <div className="relative overflow-hidden border-y border-[var(--color-hairline-2)] mt-4 bg-[var(--color-bg-2)]/50">
      <div className="marquee-track py-2 text-[12px] sm:text-[13px] font-mono uppercase tracking-[0.3em] text-[var(--color-ink-faint)] whitespace-nowrap">
        {all.map((p, i) => (
          <span key={i} className="px-6 sm:px-10 flex-shrink-0">
            {p}
            <span className="ml-6 sm:ml-10 text-[var(--color-gold-deep)]">
              ◆
            </span>
          </span>
        ))}
      </div>
    </div>
  );
}

function RuleBeat({ n, label, withDivider, highlight }) {
  return (
    <div
      className={`px-3 sm:px-5 py-3 sm:py-4 ${
        withDivider ? "border-l border-[var(--color-hairline-2)]" : ""
      }`}
    >
      <div
        className="font-mono text-[10px] sm:text-[11px] tracking-[0.2em]"
        style={{
          color: highlight ? "var(--color-gold)" : "var(--color-ink-faint)",
        }}
      >
        {n}
      </div>
      <div
        className={`mt-1 text-[12px] sm:text-[13px] leading-[1.35] ${
          highlight ? "text-[var(--color-ink)]" : "text-[var(--color-ink-dim)]"
        }`}
        dangerouslySetInnerHTML={{ __html: label }}
      />
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function TexStage() {
  return (
    <div className="relative w-full h-full flex items-end justify-center lg:justify-end">
      <div
        className="spotlight"
        style={{
          inset: "10% -10% -5% -10%",
          filter: "blur(20px)",
        }}
      />
      <div
        className="absolute pointer-events-none"
        style={{
          inset: "15% 0% 0% 0%",
          background:
            "radial-gradient(ellipse 45% 40% at 55% 35%, rgba(95, 240, 255, 0.18) 0%, transparent 65%)",
          filter: "blur(10px)",
        }}
      />
      <div
        className="absolute left-1/2 bottom-0 pointer-events-none"
        style={{
          transform: "translateX(-50%)",
          width: "82%",
          height: "36px",
          background:
            "radial-gradient(ellipse at center, rgba(245, 185, 61, 0.45) 0%, rgba(245, 185, 61, 0.15) 35%, transparent 70%)",
          filter: "blur(8px)",
        }}
      />
      <div
        className="absolute left-1/2 bottom-0 pointer-events-none"
        style={{
          transform: "translateX(-50%)",
          width: "62%",
          height: "22px",
          background:
            "radial-gradient(ellipse at center, rgba(0,0,0,0.7) 0%, rgba(0,0,0,0.35) 40%, transparent 75%)",
          filter: "blur(6px)",
        }}
      />

      <picture
        className="relative block tex-float z-10"
        style={{ maxWidth: "640px", width: "100%" }}
      >
        <source media="(max-width: 640px)" srcSet="/tex/tex-mobile.png" />
        <img
          src="/tex/tex-full.png"
          alt="Tex — the AI content gate"
          className="block w-full h-auto fighter-in-right"
          style={{
            filter:
              "drop-shadow(0 20px 30px rgba(0, 0, 0, 0.6)) drop-shadow(0 0 60px rgba(245, 185, 61, 0.12))",
          }}
        />
      </picture>

      <div className="absolute top-3 right-3 sm:top-5 sm:right-5 z-20 flex items-center gap-2">
        <div className="flex flex-col items-end">
          <span className="chip-cyan">Blue Corner</span>
          <span className="mt-1.5 t-micro text-[var(--color-ink-faint)]">
            ∞–0–0
          </span>
        </div>
      </div>

      <div className="absolute bottom-7 right-3 sm:right-6 z-20 text-right">
        <div className="t-micro text-[var(--color-cyan)] opacity-80">
          The Undefeated
        </div>
        <div
          className="t-display text-[40px] sm:text-[56px] leading-[0.9] text-white mt-0.5"
          style={{
            textShadow:
              "0 0 24px rgba(95, 240, 255, 0.35), 0 2px 0 rgba(0,0,0,0.6)",
          }}
        >
          TEX
        </div>
      </div>
    </div>
  );
}

function formatCount(n) {
  if (!n || n < 1) return "—";
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}K`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}
