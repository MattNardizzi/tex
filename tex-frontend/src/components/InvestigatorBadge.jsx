import React from "react";
import { Pencil, Flame, Clock, Target, Shield } from "lucide-react";
import { tierFor } from "../lib/scoring.js";
import { BOUNTY_CASE_ID } from "../lib/cases.js";

/*
  InvestigatorBadge v7 — "Your identity"
  ──────────────────────────────────────
  Tier-driven. This is the thing the player is building toward.
  It shows:
    • Handle (editable inline)
    • Current clearance tier (named, colored, glowing)
    • Cases cleared / 7
    • Best catch time
    • Streak

  Visual: a landscape card, rank-frame-N glow via CSS. The tier chip
  on the left reads as a real ID card.
*/

export default function InvestigatorBadge({ player, onEditHandle }) {
  const cleared = player.clearedCaseIds?.length || 0;
  const bountyCaught = player.clearedCaseIds?.includes(BOUNTY_CASE_ID);
  const tier = tierFor(cleared, bountyCaught);
  const handleDisplay = player.handle ? `@${player.handle}` : "@anonymous";
  const streak = player.streakDays || 0;
  const bestCatches = Object.values(player.perCase || {})
    .filter((r) => r.bestCatchMs != null)
    .map((r) => r.bestCatchMs);
  const fastestMs = bestCatches.length ? Math.min(...bestCatches) : null;

  return (
    <section
      className="panel overflow-hidden transition-all duration-500"
      style={{
        borderColor: tier.current.color,
        boxShadow: `0 0 32px ${tier.current.glowColor}`,
      }}
    >
      <div className="px-4 sm:px-5 py-4 grid grid-cols-1 md:grid-cols-[auto_1fr_auto] items-center gap-4">
        {/* LEFT — tier chip */}
        <div className="flex items-center gap-3 min-w-0">
          <div
            className="shrink-0 w-14 h-14 rounded-sm flex flex-col items-center justify-center t-display"
            style={{
              background: tier.current.color,
              color: "#060714",
              letterSpacing: "0.04em",
              boxShadow: `0 0 16px ${tier.current.glowColor}`,
            }}
          >
            <div style={{ fontSize: "10px", opacity: 0.8 }}>TIER</div>
            <div style={{ fontSize: "18px", marginTop: "-2px" }}>{tier.current.short}</div>
          </div>
          <div className="min-w-0">
            <button
              onClick={onEditHandle}
              className="t-display text-[17px] text-[var(--color-ink)] hover:text-[var(--color-cyan)] transition-colors inline-flex items-center gap-1.5"
              style={{ letterSpacing: "0.02em" }}
            >
              {handleDisplay}
              <Pencil className="w-3 h-3 text-[var(--color-ink-faint)]" />
            </button>
            <div
              className="t-display text-[13px] mt-0.5 inline-flex items-center gap-1.5"
              style={{ color: tier.current.color, letterSpacing: "0.03em" }}
            >
              <Shield className="w-3 h-3" />
              {tier.current.name}
            </div>
          </div>
        </div>

        {/* MIDDLE — progress toward next tier */}
        {tier.next ? (
          <div className="min-w-0 w-full">
            <div className="flex items-baseline justify-between t-micro text-[var(--color-ink-faint)] mb-1">
              <span>NEXT: {tier.next.name}</span>
              <span className="tabular-nums">{cleared}/{tier.next.min}</span>
            </div>
            <div className="h-1.5 bg-[var(--color-bg-3)] rounded-full overflow-hidden">
              <div
                className="h-full transition-all duration-700"
                style={{
                  width: `${Math.min(100, Math.round((cleared / tier.next.min) * 100))}%`,
                  background: `linear-gradient(90deg, ${tier.current.color}, ${tier.next.color})`,
                  boxShadow: `0 0 10px ${tier.next.glowColor}`,
                }}
              />
            </div>
            <div
              className="mt-1 text-[11px] text-[var(--color-ink-dim)] italic"
              style={{ fontFamily: "var(--font-serif)" }}
            >
              {tier.current.unlockCopy}
            </div>
          </div>
        ) : (
          <div className="min-w-0">
            <div className="t-display text-[14px] glow-gold">MAX TIER</div>
            <div
              className="text-[11px] text-[var(--color-ink-dim)] italic mt-1"
              style={{ fontFamily: "var(--font-serif)" }}
            >
              You've done it all. Legend status.
            </div>
          </div>
        )}

        {/* RIGHT — stats */}
        <div className="flex items-center gap-4 sm:gap-5">
          <Stat icon={<Target className="w-3 h-3" />} label="CASES" value={`${cleared}/7`} color="var(--color-cyan)" />
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
    </section>
  );
}

function Stat({ icon, label, value, color, pulse }) {
  return (
    <div className={`text-center ${pulse ? "streak-pulse" : ""}`}>
      <div className="t-micro flex items-center gap-1 justify-center" style={{ color }}>
        {icon} {label}
      </div>
      <div
        className="t-display text-[18px] mt-0.5 text-[var(--color-ink)] tabular-nums"
        style={{ letterSpacing: "0.02em" }}
      >
        {value}
      </div>
    </div>
  );
}
