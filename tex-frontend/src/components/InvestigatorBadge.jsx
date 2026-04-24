import React from "react";
import { Pencil, Flame, Target, Clock } from "lucide-react";
import { rankForPoints } from "../lib/storage.js";

/*
  InvestigatorBadge
  ─────────────────
  Player identity card. Replaces FighterCard. Shows the four numbers
  that matter in interrogation mode:
    1. handle + rank
    2. cases cleared (of 7)
    3. streak days
    4. total points

  Kept the rank-frame-N CSS classes from v5 so the visual upgrade on
  rank-up still works.
*/

export default function InvestigatorBadge({ player, onEditHandle }) {
  const rank = rankForPoints(player.totalPoints || 0);
  const handleDisplay = player.handle ? `@${player.handle}` : "@anonymous";
  const cleared = player.clearedCaseIds?.length || 0;
  const streak = player.streakDays || 0;
  const bestCatches = Object.values(player.perCase || {})
    .filter((r) => r.bestCatchMs != null)
    .map((r) => r.bestCatchMs);
  const fastestMs = bestCatches.length ? Math.min(...bestCatches) : null;

  const progressPct = Math.round((rank.progressToNext || 0) * 100);

  return (
    <section
      className={`panel rank-frame-${rank.current.tier} overflow-hidden transition-all duration-500`}
    >
      <div className="px-4 sm:px-5 py-4 flex items-center justify-between gap-4 flex-wrap">
        {/* Left: handle + rank */}
        <div className="flex items-center gap-3 min-w-0">
          <div
            className="shrink-0 w-12 h-12 rounded-sm flex items-center justify-center t-display"
            style={{
              background: rank.current.color,
              color: "#060714",
              fontSize: "18px",
              letterSpacing: "0.02em",
            }}
          >
            {(player.handle || "A").slice(0, 1).toUpperCase()}
          </div>
          <div className="min-w-0">
            <button
              onClick={onEditHandle}
              className="t-display text-[16px] text-[var(--color-ink)] hover:text-[var(--color-cyan)] transition-colors inline-flex items-center gap-1.5"
              style={{ letterSpacing: "0.02em" }}
            >
              {handleDisplay}
              <Pencil className="w-3 h-3 text-[var(--color-ink-faint)]" />
            </button>
            <div className="t-micro mt-0.5" style={{ color: rank.current.color }}>
              {rank.current.name}
              <span className="text-[var(--color-ink-faint)] ml-1">
                &middot; {(player.totalPoints || 0).toLocaleString()} pts
              </span>
            </div>
          </div>
        </div>

        {/* Right: stats grid */}
        <div className="flex items-center gap-4 sm:gap-6">
          <Stat icon={<Target className="w-3 h-3" />} label="CLEARED" value={`${cleared}/7`} color="var(--color-cyan)" />
          <Stat
            icon={<Flame className="w-3 h-3" />}
            label="STREAK"
            value={streak > 0 ? `${streak}d` : "—"}
            color="var(--color-yellow)"
            pulse={streak >= 3}
          />
          <Stat
            icon={<Clock className="w-3 h-3" />}
            label="FASTEST"
            value={fastestMs != null ? `${fastestMs}ms` : "—"}
            color="var(--color-permit)"
          />
        </div>
      </div>

      {/* Progress to next rank */}
      {rank.next && (
        <div className="px-4 sm:px-5 pb-3">
          <div className="flex items-center justify-between t-micro text-[var(--color-ink-faint)] mb-1">
            <span>NEXT: {rank.next.name}</span>
            <span>{progressPct}%</span>
          </div>
          <div className="h-1 bg-[var(--color-bg-3)] rounded-full overflow-hidden">
            <div
              className="h-full transition-all duration-700"
              style={{
                width: `${progressPct}%`,
                background: `linear-gradient(90deg, ${rank.current.color}, ${rank.next.color})`,
                boxShadow: `0 0 12px ${rank.next.color}`,
              }}
            />
          </div>
        </div>
      )}
    </section>
  );
}

function Stat({ icon, label, value, color, pulse }) {
  return (
    <div className={`text-center ${pulse ? "streak-pulse" : ""}`}>
      <div className="t-micro text-[var(--color-ink-faint)] flex items-center gap-1 justify-center" style={{ color }}>
        {icon} {label}
      </div>
      <div className="t-display text-[18px] sm:text-[22px] mt-0.5 text-[var(--color-ink)] tabular-nums" style={{ letterSpacing: "0.02em" }}>
        {value}
      </div>
    </div>
  );
}
