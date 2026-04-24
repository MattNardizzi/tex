import React from "react";
import { Play, RotateCw, Trophy } from "lucide-react";

/*
  ArenaHero v6 — "Interrogation"
  ────────────────────────────────
  Job: teach the game in under 10 seconds. No overlay. No modal. No
  tooltip. The first screen answers:
      WHAT AM I?      You're the CISO.
      WHAT DO I DO?   Interrogate the agent. 3 questions. 60 seconds.
      WHAT WINS?      Tex catching the agent. Faster = higher score.
      WHAT'S NEXT?    One button: START CASE 001.
*/

export default function ArenaHero({
  player,
  currentCase,
  onStart,
  onScrollToLadder,
  allCleared,
}) {
  const handle = player?.handle;
  const streak = player?.streakDays || 0;
  const cleared = player?.clearedCaseIds?.length || 0;

  const ctaLabel = allCleared
    ? "REPLAY ANY CASE"
    : cleared > 0
    ? `RESUME · CASE ${String(currentCase.id).padStart(3, "0")}`
    : `START CASE 001 · ${currentCase.name.toUpperCase()}`;

  return (
    <section className="relative overflow-hidden stage">
      <div className="mx-auto max-w-[1400px] px-5 sm:px-8 lg:px-12 pt-10 pb-8 sm:pt-14 sm:pb-12">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* LEFT — framing, what the game is */}
          <div className="lg:col-span-7 xl:col-span-8 rise-in">
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

            {/* The 4-line rule block. This is the entire tutorial. */}
            <div
              className="mt-6 panel px-4 sm:px-5 py-4 max-w-[640px]"
              style={{
                background: "linear-gradient(180deg, rgba(95,240,255,0.05) 0%, transparent 100%)",
                borderColor: "rgba(95, 240, 255, 0.25)",
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

          {/* RIGHT — Tex avatar + live player state */}
          <div className="lg:col-span-5 xl:col-span-4 rise-2">
            <div className="relative panel overflow-hidden" style={{ borderColor: "rgba(95,240,255,0.25)" }}>
              <div className="aspect-[4/5] relative bg-[var(--color-bg-2)]">
                <img
                  src="/tex/tex-full.png"
                  alt="Tex — your AI content gate"
                  className="absolute inset-0 w-full h-full object-cover object-top tex-float"
                  onError={(e) => { e.currentTarget.src = "/tex/tex-avatar.png"; }}
                />
                {/* scan bar overlay */}
                <div className="absolute inset-x-0 top-0 h-[1px] bg-[var(--color-cyan)] opacity-60 scan-bar" style={{ boxShadow: "0 0 12px rgba(95,240,255,0.6)" }} />
                <div className="absolute top-3 left-3 t-micro text-[var(--color-cyan)] flex items-center gap-1.5">
                  <span className="inline-block w-1.5 h-1.5 rounded-full bg-[var(--color-cyan)] pulse-ring-cyan" />
                  TEX &middot; LIVE
                </div>
                <div className="absolute bottom-3 left-3 right-3">
                  <div className="t-display text-[18px] leading-none text-[var(--color-ink)]">MEET TEX</div>
                  <div className="t-micro text-[var(--color-ink-dim)] mt-1">
                    Adjudicates agent content in &lt;200ms. Your partner, not your opponent.
                  </div>
                </div>
              </div>

              {/* Live player strip */}
              <div className="px-4 py-3 border-t border-[var(--color-hairline-2)] flex items-center justify-between gap-3">
                <div>
                  <div className="t-micro text-[var(--color-ink-faint)]">
                    {handle ? `@${handle}` : "no handle yet"}
                  </div>
                  <div className="t-display text-[16px] mt-0.5 text-[var(--color-ink)]">
                    {cleared}/7 cleared
                  </div>
                </div>
                {streak > 0 && (
                  <div className="text-right">
                    <div className="t-micro text-[var(--color-ink-faint)]">STREAK</div>
                    <div className="t-display text-[16px] mt-0.5 glow-gold flex items-center gap-1 justify-end">
                      <RotateCw className="w-3.5 h-3.5" />
                      {streak}d
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
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
    <div className="panel p-2.5 text-left" style={{ borderColor: "rgba(168, 178, 240, 0.15)" }}>
      <div className="t-micro" style={{ color }}>{label}</div>
      <div className="text-[11px] text-[var(--color-ink-faint)] leading-tight mt-0.5">{sub}</div>
      <div className="t-display text-[14px] text-[var(--color-ink)] mt-1" style={{ letterSpacing: "0.02em" }}>{value}</div>
    </div>
  );
}
