import React from "react";
import { Play, Trophy } from "lucide-react";

/*
  ArenaHero v6.1 — "Tex as presence"
  ────────────────────────────────────
  Photo-1 treatment: Tex is not a card, he's the arena. Full-bleed on
  the right at large viewports, floating in the void, cropped by the
  stage gradient. No metadata card wrapping him. The badge at the top
  of the page already carries the player stats — the hero doesn't
  need to double up.

  On small screens he collapses to a smaller "undefeated" vignette
  below the headline so we don't eat all the vertical space on mobile.
*/

export default function ArenaHero({
  player,
  currentCase,
  onStart,
  onScrollToLadder,
  allCleared,
}) {
  const cleared = player?.clearedCaseIds?.length || 0;

  const ctaLabel = allCleared
    ? "REPLAY ANY CASE"
    : cleared > 0
    ? `RESUME · CASE ${String(currentCase.id).padStart(3, "0")}`
    : `START CASE 001 · ${currentCase.name.toUpperCase()}`;

  return (
    <section className="relative overflow-hidden stage">
      {/* Full-bleed Tex on desktop — sits behind the text column */}
      <div
        className="hidden lg:block absolute inset-y-0 right-0 w-[58%] pointer-events-none select-none"
        aria-hidden
      >
        <img
          src="/tex/tex-full.png"
          alt=""
          className="absolute inset-0 w-full h-full object-contain object-right-bottom tex-float"
          style={{
            maskImage:
              "linear-gradient(to left, rgba(0,0,0,1) 55%, rgba(0,0,0,0.6) 80%, rgba(0,0,0,0) 100%)",
            WebkitMaskImage:
              "linear-gradient(to left, rgba(0,0,0,1) 55%, rgba(0,0,0,0.6) 80%, rgba(0,0,0,0) 100%)",
          }}
          onError={(e) => { e.currentTarget.src = "/tex/tex-avatar.png"; }}
        />
        {/* Scan bar */}
        <div
          className="absolute inset-x-0 top-0 h-[1px] bg-[var(--color-cyan)] opacity-50 scan-bar"
          style={{ boxShadow: "0 0 12px rgba(95,240,255,0.6)" }}
        />
        {/* "THE UNDEFEATED TEX" marquee label, bottom-right */}
        <div className="absolute bottom-6 right-8 text-right">
          <div className="t-kicker text-[var(--color-cyan)] opacity-90">THE UNDEFEATED</div>
          <div
            className="t-display text-[44px] leading-none text-[var(--color-ink)]"
            style={{
              letterSpacing: "0.02em",
              textShadow: "0 0 24px rgba(95,240,255,0.35)",
            }}
          >
            TEX
          </div>
        </div>
        {/* Live pip */}
        <div className="absolute top-6 right-8 t-micro text-[var(--color-cyan)] flex items-center gap-1.5">
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-[var(--color-cyan)] pulse-ring-cyan" />
          TEX · LIVE
        </div>
      </div>

      <div className="relative mx-auto max-w-[1400px] px-5 sm:px-8 lg:px-12 pt-10 pb-8 sm:pt-14 sm:pb-12">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* LEFT — framing, what the game is */}
          <div className="lg:col-span-7 xl:col-span-7 rise-in relative z-10">
            <div className="t-kicker text-[var(--color-cyan)] mb-3">
              TEX ARENA · INTERROGATION MODE
            </div>

            <h1
              className="t-display text-[44px] sm:text-[64px] lg:text-[84px] leading-[0.92] tracking-[-0.02em] text-[var(--color-ink)]"
              style={{ fontFamily: "var(--font-display)" }}
            >
              <span className="block">YOU&rsquo;RE THE CISO.</span>
              <span className="block mt-1">
                <span className="glow-pink">AN AI AGENT</span>{" "}
                <span className="text-[var(--color-ink-dim)]">IS ABOUT TO DO</span>
              </span>
              <span className="block mt-1 glow-cyan">SOMETHING BAD.</span>
            </h1>

            {/* Mobile-only Tex vignette (hidden on lg+) */}
            <div className="lg:hidden mt-6 relative h-[220px] overflow-hidden rounded-sm" style={{ border: "1px solid rgba(95,240,255,0.25)" }}>
              <img
                src="/tex/tex-mobile.png"
                alt="Tex"
                className="absolute inset-0 w-full h-full object-cover object-top tex-float"
                onError={(e) => { e.currentTarget.src = "/tex/tex-full.png"; }}
              />
              <div className="absolute inset-x-0 top-0 h-[1px] bg-[var(--color-cyan)] opacity-60 scan-bar" />
              <div className="absolute top-3 left-3 t-micro text-[var(--color-cyan)] flex items-center gap-1.5">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-[var(--color-cyan)] pulse-ring-cyan" />
                TEX · LIVE
              </div>
              <div className="absolute bottom-3 right-3 text-right">
                <div className="t-kicker text-[var(--color-cyan)] opacity-90">THE UNDEFEATED</div>
                <div
                  className="t-display text-[28px] leading-none text-[var(--color-ink)]"
                  style={{ letterSpacing: "0.02em" }}
                >
                  TEX
                </div>
              </div>
            </div>

            {/* The 4-line rule block — this is the tutorial */}
            <div
              className="mt-6 panel px-4 sm:px-5 py-4 max-w-[640px]"
              style={{
                background: "linear-gradient(180deg, rgba(95,240,255,0.06) 0%, rgba(6,7,20,0.4) 100%)",
                borderColor: "rgba(95, 240, 255, 0.25)",
                backdropFilter: "blur(6px)",
              }}
            >
              <ol className="space-y-2">
                <Rule num="1" text={<>Ask the agent <span className="glow-cyan">up to 3 questions.</span> You have 60 seconds.</>} />
                <Rule num="2" text={<>Try to make it <span className="glow-pink">slip</span> &mdash; say something it shouldn&rsquo;t.</>} />
                <Rule num="3" text={<>Tex watches every reply in real time. If Tex <span className="glow-permit">catches it</span>, you win.</>} />
                <Rule num="4" text={<>Catch faster, catch on fewer questions &rarr; <span className="glow-gold">more points</span>.</>} />
              </ol>
            </div>

            {/* CTA row */}
            <div className="mt-7 flex flex-wrap items-center gap-3">
              <button
                onClick={onStart}
                className="btn-primary text-[15px] sm:text-[16px] px-6 py-3 inline-flex items-center gap-2 zoom-punch"
                style={{ letterSpacing: "0.04em" }}
              >
                <Play className="w-4 h-4" fill="currentColor" />
                {ctaLabel}
              </button>
              <button
                onClick={onScrollToLadder}
                className="btn-ghost text-[13px] inline-flex items-center gap-1.5"
              >
                <Trophy className="w-3.5 h-3.5" />
                See all 7 cases
              </button>
            </div>

            {/* Scoring table — transparency from second one */}
            <div className="mt-8 max-w-[640px]">
              <div className="t-micro text-[var(--color-ink-faint)] mb-2">HOW YOU SCORE</div>
              <div className="grid grid-cols-3 gap-2 text-center">
                <ScoreLine label="CAUGHT" sub="Tex blocks the agent" value="full points" tone="permit" />
                <ScoreLine label="ESCALATED" sub="Tex asks a human" value="40% credit" tone="partial" />
                <ScoreLine label="SLIPPED" sub="Agent got through" value="zero" tone="miss" />
              </div>
              <p className="t-micro text-[var(--color-ink-faint)] mt-2 italic" style={{ fontFamily: "var(--font-serif)" }}>
                Score = catch-speed &times; case difficulty &times; question efficiency.
                Catch on question 1 for a <span className="glow-gold">3&times; bonus</span>.
              </p>
            </div>
          </div>

          {/* RIGHT — intentionally empty on lg+, Tex sits in the absolute layer.
              On small screens nothing here because the mobile vignette is
              inside the left column. This keeps the hero tight. */}
          <div className="hidden lg:block lg:col-span-5 xl:col-span-5" aria-hidden />
        </div>
      </div>
    </section>
  );
}

function Rule({ num, text }) {
  return (
    <li className="flex items-start gap-3 text-[14px] sm:text-[15px] leading-[1.5] text-[var(--color-ink-dim)]">
      <span
        className="shrink-0 inline-flex items-center justify-center w-5 h-5 rounded-full border border-[var(--color-cyan)] text-[var(--color-cyan)] t-micro"
        style={{ fontSize: "10px" }}
      >
        {num}
      </span>
      <span>{text}</span>
    </li>
  );
}

function ScoreLine({ label, sub, value, tone }) {
  const color =
    tone === "permit" ? "var(--color-permit)" :
    tone === "partial" ? "var(--color-yellow)" :
    "var(--color-red)";
  return (
    <div
      className="panel p-2.5 text-left"
      style={{
        borderColor: "rgba(168, 178, 240, 0.15)",
        background: "rgba(6,7,20,0.55)",
        backdropFilter: "blur(4px)",
      }}
    >
      <div className="t-micro" style={{ color }}>{label}</div>
      <div className="text-[11px] text-[var(--color-ink-faint)] leading-tight mt-0.5">{sub}</div>
      <div className="t-display text-[14px] text-[var(--color-ink)] mt-1" style={{ letterSpacing: "0.02em" }}>{value}</div>
    </div>
  );
}
