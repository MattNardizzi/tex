import React from "react";
import { rankForPoints, totalRecord } from "../lib/storage";
import { User, Pencil } from "lucide-react";

/*
  FIGHTER CARD — v3
  Terminal-style stat bar. Handle, rank, W-L-D-Streak, rank progress.
  One row. No decorative borders. Hairline divisions.
*/

export default function FighterCard({ player, onEditHandle }) {
  const rank = rankForPoints(player.totalPoints);
  const rec = totalRecord(player);
  const handleDisplay = player.handle ? `@${player.handle}` : "@anonymous";

  return (
    <section className="panel overflow-hidden">
      <div className="grid grid-cols-[auto_1fr_auto] items-center gap-4 sm:gap-6 px-4 sm:px-5 py-4">
        {/* Avatar + identity */}
        <button
          onClick={onEditHandle}
          className="flex items-center gap-3 group"
          aria-label="Edit handle"
        >
          <div className="w-11 h-11 border border-[var(--color-hairline-2)] bg-[var(--color-bg-3)] flex items-center justify-center text-[var(--color-pink)]">
            <User className="w-5 h-5" strokeWidth={1.5} />
          </div>
          <div className="text-left">
            <div className="flex items-center gap-1.5 t-micro text-[var(--color-ink-dim)]">
              {handleDisplay}
              <Pencil className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 transition-opacity" strokeWidth={2} />
            </div>
            <div
              className="t-display text-[22px] sm:text-[26px] leading-none mt-1 text-[var(--color-ink)]"
              style={{ letterSpacing: "0.01em" }}
            >
              {rank.current.name}
            </div>
          </div>
        </button>

        {/* Rank progress */}
        <div className="hidden sm:block min-w-0">
          <div className="flex items-baseline justify-between t-micro text-[var(--color-ink-faint)] mb-1.5">
            <span>{rank.current.name}</span>
            <span>{rank.next ? `→ ${rank.next.name}` : "MAX"}</span>
          </div>
          <div className="h-1 bg-[var(--color-hairline)] relative overflow-hidden">
            <div
              className="absolute inset-y-0 left-0 transition-all duration-700"
              style={{
                width: `${Math.round(rank.progress * 100)}%`,
                background: "linear-gradient(90deg, var(--color-cyan), var(--color-cyan-soft))",
                boxShadow: "0 0 6px rgba(95, 240, 255, 0.5)",
              }}
            />
          </div>
        </div>

        {/* Stats */}
        <div className="flex items-center gap-3 sm:gap-5">
          <Stat label="W" value={rec.W} color="var(--color-permit)" />
          <Stat label="L" value={rec.L} color="var(--color-red)" />
          <Stat label="D" value={rec.D} color="var(--color-gold)" />
          <div className="h-8 w-px bg-[var(--color-hairline-2)]" />
          <Stat label="Streak" value={player.streak} color="var(--color-ink)" wide />
          <div className="h-8 w-px bg-[var(--color-hairline-2)]" />
          <Stat label="Pts" value={player.totalPoints} color="var(--color-cyan)" wide />
        </div>
      </div>
    </section>
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
