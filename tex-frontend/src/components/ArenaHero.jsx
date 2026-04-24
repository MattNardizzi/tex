import React from "react";
import { Volume2, VolumeX, ArrowRight, Briefcase, Trophy } from "lucide-react";
import {
  ASI_COVERED_COUNT,
  ASI_TOTAL_COUNT,
  symbolicBountyAmount,
} from "../lib/rounds";

/*
  ARENA HERO — v5 "NEON ARCADE / CABINET MODE"
  ─────────────────────────────────────
  Key changes from v4:
    • Starbucks is gone. The reward is Hall of Fame + Founding Bypass
      certificate + Founders' Tier API access.
    • Ticker is now HIGH-CONTRAST, larger, and the copy cycles through
      hooks aimed at builders/CISOs, not casual scrollers.
    • Scanlines + synthwave grid-floor decoration — the page actually
      looks like an arcade cabinet now.
    • Live counter promotes ASI Pokédex progress (YOU vs total) as the
      primary social-proof number, because "X of 6 categories unlocked"
      is inherently curiosity-gap shaped.
    • The symbolic bounty number is prominent but framed as "current bounty
      pot: $X — doubles per claim" so it's a story, not a promise to pay.
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
  claimersSoFar = 0, // reserved for backend wiring
}) {
  const bountyNow = symbolicBountyAmount(claimersSoFar);

  return (
    <section className="stage scanlines relative safe-top">
      <div className="grid-floor" />
      <TopBar onToggleSound={onToggleSound} soundOn={soundOn} onAbout={onAbout} />

      <Ticker />

      <div className="relative mx-auto max-w-[1400px] px-5 sm:px-8 lg:px-12 pt-8 sm:pt-12 lg:pt-10 pb-0 z-10">
        <div className="grid grid-cols-1 lg:grid-cols-[1.15fr_1fr] gap-6 lg:gap-12 items-end min-h-[72vh] lg:min-h-[78vh]">

          {/* LEFT — Copy */}
          <div className="relative z-10 order-2 lg:order-1 pb-10 sm:pb-16 lg:pb-20">
            <div className="mb-5 sm:mb-7 rise-1 flex flex-wrap items-center gap-2">
              <span className="chip-yellow">
                <Trophy className="w-3 h-3" strokeWidth={2.5} />
                HALL OF FAME · UNCLAIMED
              </span>
              <span className="chip-cyan">
                OWASP ASI 2026
              </span>
              <span className="chip-ghost">
                {bountyClaimed ? "You're in" : "No login"}
              </span>
            </div>

            <div
              className="t-kicker mb-3 sm:mb-4 rise-2 glow-cyan neon-flicker"
              style={{ color: "var(--color-cyan)" }}
            >
              Red-Team Challenge · 7 Rounds · Content-Layer Agent Gate
            </div>

            <h1
              className="t-display text-[64px] xs:text-[76px] sm:text-[108px] md:text-[132px] lg:text-[124px] xl:text-[148px] leading-[0.86] text-white rise-3"
              style={{
                letterSpacing: "-0.02em",
                textShadow:
                  "0 0 18px rgba(95, 240, 255, 0.35), 0 0 48px rgba(255, 61, 122, 0.25), 0 2px 0 rgba(0,0,0,0.5)",
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
                      "linear-gradient(90deg, var(--color-pink) 0%, var(--color-cyan) 70%, transparent 100%)",
                    opacity: 0.85,
                    filter: "blur(2px)",
                  }}
                />
              </span>
            </h1>

            <p className="mt-5 sm:mt-7 max-w-[52ch] text-[15px] sm:text-[17px] leading-[1.55] text-[var(--color-ink-dim)] rise-4">
              Tex is a content gate for AI agents. Try to sneak a malicious
              message past him — every loss is mapped to{" "}
              <span className="text-[var(--color-ink)] font-semibold">
                OWASP ASI 2026
              </span>
              , the new standard for agent risk.{" "}
              <span className="text-[var(--color-ink)] font-semibold">
                Beat The Warden
              </span>{" "}
              and you get your name on the Hall of Fame, a signed Founding
              Bypass certificate, and API access.
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

            {/* Live counter — the Pokédex leads because curiosity-gap
                ("X of 6 you've seen") is the most click-through number */}
            <div className="mt-5 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[11px] font-mono uppercase tracking-[0.22em] rise-5">
              <span className="inline-flex items-center gap-1.5 text-[var(--color-ink-dim)]">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-[var(--color-permit)] streak-pulse" />
                Live
              </span>
              <span className="text-[var(--color-ink-faint)]">·</span>
              <span className="text-[var(--color-ink-dim)]">
                <span className="text-[var(--color-violet)] font-bold">
                  {asiCategoriesSeenCount || 0}
                </span>
                <span className="text-[var(--color-ink-faint)]">
                  /{ASI_COVERED_COUNT} categories you've unlocked
                </span>
              </span>
              <span className="text-[var(--color-ink-faint)]">·</span>
              <span className="text-[var(--color-ink-dim)]">
                {formatCount(totalAttempts)}{" "}
                <span className="text-[var(--color-ink-faint)]">attacks thrown</span>
              </span>
              <span className="text-[var(--color-ink-faint)]">·</span>
              <span className="text-[var(--color-ink-dim)]">
                {formatCount(asiFindingsCount)}{" "}
                <span className="text-[var(--color-ink-faint)]">
                  ASI findings
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
                label={`Beat Round 7 → Hall of Fame + API access`}
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
              and infrastructure layers. Current bounty pot: ${bountyNow}
              {" "}· doubles per confirmed bypass.
            </p>
          </div>

          {/* RIGHT — Tex on spotlight stage */}
          <div className="relative order-1 lg:order-2 h-[360px] sm:h-[500px] lg:h-auto lg:self-stretch flex items-end justify-center">
            <TexStage />
          </div>
        </div>
      </div>

      <div className="relative">
        <div className="h-px bg-gradient-to-r from-transparent via-[var(--color-cyan)] to-transparent opacity-50" />
      </div>
    </section>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function TopBar({ onToggleSound, soundOn, onAbout }) {
  return (
    <div className="relative z-20 mx-auto max-w-[1400px] px-5 sm:px-8 lg:px-12 pt-4 sm:pt-5 flex items-center justify-between">
      <div className="flex items-center gap-2">
        <span className="inline-block w-1.5 h-1.5 rounded-full bg-[var(--color-permit)] streak-pulse" />
        <span className="t-label text-[var(--color-ink-dim)]">
          Tex Arena{" "}
          <span className="text-[var(--color-ink-faint)]">· Live</span>
        </span>
      </div>
      <div className="flex items-center gap-2 sm:gap-3">
        <button
          onClick={onAbout}
          className="t-label text-[var(--color-ink-dim)] hover:text-[var(--color-cyan)] transition-colors"
        >
          What is Tex?
        </button>
        <button
          onClick={onToggleSound}
          className="p-1.5 border border-[var(--color-hairline-2)] text-[var(--color-ink-dim)] hover:text-[var(--color-cyan)] hover:border-[var(--color-cyan)] transition-colors rounded-sm"
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

/* ─────────────────────────────────────────────────────────────────── */
/*  Ticker — v5                                                        */
/*  Old version used ink-faint gray-brown at 12px. It was invisible.   */
/*  New version: bigger, high-contrast cyan text with a subtle flicker */
/*  accent on the diamonds. Copy alternates between challenge, social  */
/*  proof, and curiosity hooks — every segment works as a standalone   */
/*  piece of thumb-stopping attention bait.                            */
/* ─────────────────────────────────────────────────────────────────── */

const TICKER_SEGMENTS = [
  { text: "NOBODY HAS BEATEN TEX", tone: "pink" },
  { text: "HALL OF FAME · UNCLAIMED", tone: "yellow" },
  { text: "7 OPPONENTS · 1 BELT", tone: "cyan" },
  { text: "FREE · NO LOGIN · < 2MS VERDICTS", tone: "cyan" },
  { text: "OWASP ASI 2026 · CONTENT LAYER", tone: "violet" },
  { text: "EVERY LOSS = ONE REAL ASI FINDING", tone: "cyan" },
  { text: "BEAT THE WARDEN · UNLOCK THE API", tone: "pink" },
  { text: "POST YOUR GRID · CHALLENGE A FRIEND", tone: "violet" },
];

function Ticker() {
  const all = [...TICKER_SEGMENTS, ...TICKER_SEGMENTS, ...TICKER_SEGMENTS];
  return (
    <div
      className="relative overflow-hidden border-y border-[var(--color-hairline-2)] mt-4"
      style={{
        background:
          "linear-gradient(90deg, rgba(12,14,34,0.95) 0%, rgba(20,24,51,0.8) 50%, rgba(12,14,34,0.95) 100%)",
      }}
    >
      <div className="marquee-track py-2.5 text-[13px] sm:text-[15px] font-mono uppercase tracking-[0.28em] whitespace-nowrap">
        {all.map((seg, i) => (
          <span key={i} className="px-6 sm:px-10 flex-shrink-0 inline-flex items-center gap-4">
            <span style={{ color: toneColor(seg.tone) }}>
              {seg.text}
            </span>
            <span
              className="text-base"
              style={{
                color: "var(--color-yellow)",
                textShadow: "0 0 8px rgba(255, 225, 74, 0.6)",
              }}
            >
              ◆
            </span>
          </span>
        ))}
      </div>
    </div>
  );
}

function toneColor(tone) {
  switch (tone) {
    case "pink": return "var(--color-pink)";
    case "cyan": return "var(--color-cyan)";
    case "yellow": return "var(--color-yellow)";
    case "violet": return "var(--color-violet)";
    default: return "var(--color-ink-dim)";
  }
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
          color: highlight ? "var(--color-yellow)" : "var(--color-ink-faint)",
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
            "radial-gradient(ellipse 45% 40% at 55% 35%, rgba(95, 240, 255, 0.22) 0%, transparent 65%)",
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
            "radial-gradient(ellipse at center, rgba(255, 61, 122, 0.45) 0%, rgba(255, 61, 122, 0.15) 35%, transparent 70%)",
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
              "drop-shadow(0 20px 30px rgba(0, 0, 0, 0.6)) drop-shadow(0 0 60px rgba(95, 240, 255, 0.18))",
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
              "0 0 24px rgba(95, 240, 255, 0.55), 0 0 56px rgba(95, 240, 255, 0.28), 0 2px 0 rgba(0,0,0,0.6)",
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
