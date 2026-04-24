import React from "react";
import { rankForPoints, totalRecord } from "../lib/storage";
import { User, Pencil, Flame, Star, Lock } from "lucide-react";
import { ASI_DISPLAY, ASI_COVERED_COUNT } from "../lib/rounds";

/*
  FIGHTER CARD — v5 "POKÉDEX + COSMETIC RANK"
  ─────────────────────────────────────────────
  Two big additions in v5:

   1. ASI POKÉDEX. 6 slots — one per OWASP ASI category Tex covers.
      Greyed out until the player's own attack triggers that category.
      Collect all 6 → "ASI HUNTER" badge lights up. This is the
      curiosity-gap hook that makes people play rounds they've already
      lost: "I still haven't unlocked ASI06."

   2. RANK COSMETIC FRAME. The card's border + glow changes with rank
      tier (rank-frame-1 → rank-frame-6 in CSS). Pure vanity; zero
      backend cost. Tells you at a glance "this person has put work in."

  The score display now leads with STREAK (visible, pulses when ≥ 3)
  and the bypass/wins count (the only "W" number that matters —
  knockouts are Tex's wins, not yours).
*/

export default function FighterCard({ player, onEditHandle }) {
  const rank = rankForPoints(player.totalPoints);
  const rec = totalRecord(player);
  const handleDisplay = player.handle ? `@${player.handle}` : "@anonymous";
  const seen = new Set(player.asiCategoriesSeen || []);
  const collectedCount = seen.size;
  const isComplete = collectedCount >= ASI_COVERED_COUNT;

  return (
    <section
      className={`panel rank-frame-${rank.current.tier} overflow-hidden transition-all duration-500`}
    >
      <div className="grid grid-cols-1 md:grid-cols-[auto_1fr_auto] items-center gap-4 sm:gap-6 px-4 sm:px-5 py-4">
        {/* Avatar + identity */}
        <button
          onClick={onEditHandle}
          className="flex items-center gap-3 group"
          aria-label="Edit handle"
        >
          <div
            className="w-12 h-12 border flex items-center justify-center transition-colors"
            style={{
              borderColor: rank.current.color,
              background: "var(--color-bg-3)",
              color: rank.current.color,
              boxShadow: rank.current.tier >= 4
                ? `0 0 16px ${toRgba(rank.current.color, 0.35)}`
                : "none",
            }}
          >
            <User className="w-5 h-5" strokeWidth={1.5} />
          </div>
          <div className="text-left">
            <div className="flex items-center gap-1.5 t-micro text-[var(--color-ink-dim)]">
              {handleDisplay}
              <Pencil className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 transition-opacity" strokeWidth={2} />
            </div>
            <div
              className="t-display text-[22px] sm:text-[26px] leading-none mt-1"
              style={{
                color: rank.current.color,
                letterSpacing: "0.01em",
                textShadow:
                  rank.current.tier >= 3
                    ? `0 0 10px ${toRgba(rank.current.color, 0.5)}`
                    : "none",
              }}
            >
              {rank.current.name}
            </div>
          </div>
        </button>

        {/* Middle: Rank progress + Pokédex */}
        <div className="min-w-0 space-y-3">
          {/* Rank progress bar */}
          <div className="hidden md:block">
            <div className="flex items-baseline justify-between t-micro text-[var(--color-ink-faint)] mb-1.5">
              <span>{rank.current.name}</span>
              <span>{rank.next ? `→ ${rank.next.name} @ ${rank.next.min}pts` : "MAX TIER"}</span>
            </div>
            <div className="h-1 bg-[var(--color-hairline)] relative overflow-hidden rounded-full">
              <div
                className="absolute inset-y-0 left-0 transition-all duration-700 rounded-full"
                style={{
                  width: `${Math.round(rank.progress * 100)}%`,
                  background: `linear-gradient(90deg, ${rank.current.color}, var(--color-cyan))`,
                  boxShadow: `0 0 8px ${toRgba(rank.current.color, 0.6)}`,
                }}
              />
            </div>
          </div>

          {/* ASI Pokédex */}
          <PokedexRow
            seen={seen}
            collectedCount={collectedCount}
            isComplete={isComplete}
          />
        </div>

        {/* Right: compact arcade stats */}
        <div className="flex items-center gap-3 sm:gap-4 justify-end">
          <Stat
            label="Bypasses"
            value={rec.W}
            color="var(--color-permit)"
          />
          <div className="h-8 w-px bg-[var(--color-hairline-2)]" />
          <StreakStat streak={player.streak} best={player.bestStreak} />
          <div className="h-8 w-px bg-[var(--color-hairline-2)]" />
          <Stat
            label="Pts"
            value={player.totalPoints}
            color="var(--color-cyan)"
            wide
          />
        </div>
      </div>
    </section>
  );
}

/* ─────────────────────────────────────────────────────────────────── */
/*  PokedexRow — the 6-slot OWASP ASI collection strip                 */
/* ─────────────────────────────────────────────────────────────────── */

function PokedexRow({ seen, collectedCount, isComplete }) {
  // Use ASI_DISPLAY order for consistent layout
  const slots = Object.values(ASI_DISPLAY);

  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <span className="t-micro text-[var(--color-ink-faint)]">
          ASI Pokédex
        </span>
        <span className="t-micro" style={{
          color: isComplete ? "var(--color-yellow)" : "var(--color-ink-dim)",
        }}>
          {isComplete ? (
            <span className="inline-flex items-center gap-1">
              <Star className="w-3 h-3" fill="currentColor" /> ASI HUNTER COMPLETE
            </span>
          ) : (
            <>
              <span className="text-[var(--color-violet)] font-bold">
                {collectedCount}
              </span>
              <span> / {slots.length} UNLOCKED</span>
            </>
          )}
        </span>
      </div>
      <div className="grid grid-cols-6 gap-1.5">
        {slots.map((cat) => {
          const collected = seen.has(cat.short);
          return (
            <div
              key={cat.short}
              title={collected ? `${cat.title} — unlocked` : `${cat.title} — locked`}
              className="relative border px-1 py-1.5 flex flex-col items-center justify-center transition-all"
              style={{
                borderColor: collected
                  ? cat.color
                  : "var(--color-hairline-2)",
                background: collected
                  ? `linear-gradient(180deg, ${toRgba(cat.color, 0.12)} 0%, transparent 100%)`
                  : "var(--color-bg-3)",
                boxShadow: collected
                  ? `0 0 12px ${toRgba(cat.color, 0.25)}, inset 0 0 8px ${toRgba(cat.color, 0.08)}`
                  : "none",
                opacity: collected ? 1 : 0.55,
                borderRadius: "2px",
              }}
            >
              <span
                className="font-mono text-[9px] font-bold tracking-[0.1em]"
                style={{
                  color: collected ? cat.color : "var(--color-ink-faint)",
                }}
              >
                {cat.short.replace("ASI", "")}
              </span>
              {!collected && (
                <Lock
                  className="w-2.5 h-2.5 mt-0.5"
                  strokeWidth={2.5}
                  style={{ color: "var(--color-ink-faint)" }}
                />
              )}
              {collected && (
                <Star
                  className="w-2.5 h-2.5 mt-0.5"
                  fill={cat.color}
                  strokeWidth={0}
                />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────── */
/*  StreakStat — visually pulses when streak ≥ 3. Loss aversion hook.  */
/* ─────────────────────────────────────────────────────────────────── */

function StreakStat({ streak, best }) {
  const hot = streak >= 3;
  return (
    <div className="text-center">
      <div className="t-micro text-[var(--color-ink-faint)] inline-flex items-center gap-1 justify-center">
        {hot && <Flame className="w-3 h-3" fill="var(--color-pink)" stroke="var(--color-pink)" />}
        Streak
      </div>
      <div
        className={`t-display leading-none mt-0.5 text-[22px] ${hot ? "streak-pulse" : ""}`}
        style={{
          color: hot ? "var(--color-pink)" : "var(--color-ink)",
          fontWeight: 400,
          textShadow: hot ? "0 0 12px rgba(255, 61, 122, 0.5)" : "none",
        }}
      >
        {streak}
      </div>
      {best > streak && (
        <div className="t-micro text-[var(--color-ink-faint)] mt-0.5" style={{ fontSize: "8px" }}>
          best {best}
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, color, wide }) {
  return (
    <div className="text-center">
      <div className="t-micro text-[var(--color-ink-faint)]">{label}</div>
      <div
        className={`t-display leading-none mt-0.5 ${wide ? "text-[22px]" : "text-[20px]"}`}
        style={{ color, fontWeight: 400 }}
      >
        {value}
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────── */
/*  Helper: parse a CSS var to rgba — used for dynamic tints           */
/*  Since we can't read CSS vars at render time here, we use a small   */
/*  mapping table and fall back to a neutral for unknown strings.      */
/* ─────────────────────────────────────────────────────────────────── */

const VAR_RGB = {
  "var(--color-pink)": "255, 61, 122",
  "var(--color-pink-deep)": "196, 31, 87",
  "var(--color-cyan)": "95, 240, 255",
  "var(--color-cyan-deep)": "43, 184, 204",
  "var(--color-yellow)": "255, 225, 74",
  "var(--color-yellow-deep)": "212, 184, 32",
  "var(--color-violet)": "168, 85, 247",
  "var(--color-permit)": "59, 255, 158",
  "var(--color-red)": "255, 59, 59",
  "var(--color-ink)": "245, 247, 255",
  "var(--color-ink-dim)": "184, 188, 224",
};

function toRgba(cssVar, alpha) {
  // If it's already a hex, convert directly
  if (typeof cssVar === "string" && cssVar.startsWith("#")) {
    const hex = cssVar.slice(1);
    const bigint = parseInt(hex, 16);
    const r = (bigint >> 16) & 255;
    const g = (bigint >> 8) & 255;
    const b = bigint & 255;
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }
  const rgb = VAR_RGB[cssVar] || "184, 188, 224";
  return `rgba(${rgb}, ${alpha})`;
}
