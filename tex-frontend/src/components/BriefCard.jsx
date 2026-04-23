import React from "react";
import { Flame, Target, Info } from "lucide-react";
import { BOUNTY_AMOUNT } from "../lib/rounds";

/*
  BRIEF CARD — v3 "Fight Card Brief"
  -----------------------------------
  The left panel on the arena screen. Clean editorial hierarchy:
    header strip (round, difficulty)
    opponent name in display type
    one-sentence tagline in italic serif
    THE MISSION (highlighted) — the ONE thing the player is trying to do
    technical metadata (terminal strip)
    record vs this opponent (if any)
*/

export default function BriefCard({ round, record }) {
  const isBounty = Boolean(round.isBounty);
  const accent = isBounty ? "var(--color-gold)" : "var(--color-pink)";

  return (
    <section
      className="panel overflow-hidden relative"
      style={{
        borderColor: isBounty ? "var(--color-gold-deep)" : "var(--color-hairline-2)",
        boxShadow: isBounty
          ? "0 0 0 1px var(--color-gold-deep), 0 0 32px rgba(245, 185, 61, 0.12)"
          : "none",
      }}
    >
      {/* Header strip — round + difficulty */}
      <div
        className="relative flex items-center justify-between px-4 py-2.5"
        style={{
          background: isBounty
            ? "linear-gradient(90deg, rgba(245, 185, 61, 0.15) 0%, transparent 60%)"
            : "transparent",
          borderBottom: `1px solid ${isBounty ? "rgba(245, 185, 61, 0.3)" : "var(--color-hairline-2)"}`,
        }}
      >
        <div className="flex items-center gap-2">
          <Target className="w-3 h-3" style={{ color: accent }} strokeWidth={2} />
          <span className="t-micro text-[var(--color-ink-dim)]">
            Round {round.id} · Brief
          </span>
        </div>
        <DifficultyFlames score={round.difficultyScore} color={accent} />
      </div>

      {/* Body */}
      <div className="px-5 py-5">
        {/* Corner label */}
        <div
          className="t-micro mb-1.5"
          style={{ color: "var(--color-cyan)" }}
        >
          In the Blue Corner
        </div>

        {/* Opponent display name */}
        <h2
          className="t-display text-[42px] sm:text-[52px] leading-[0.88] text-[var(--color-ink)]"
          style={{
            letterSpacing: "-0.01em",
            textShadow: isBounty
              ? "0 0 20px rgba(245, 185, 61, 0.25)"
              : "0 0 20px rgba(255, 61, 122, 0.2)",
          }}
        >
          {round.name.replace("The ", "").toUpperCase()}
        </h2>

        {/* Tagline — serif italic */}
        <p
          className="mt-2 text-[15px] sm:text-[16px] leading-[1.35] italic"
          style={{
            fontFamily: "var(--font-serif)",
            color: accent,
          }}
        >
          {round.tagline}
        </p>

        {/* Description — compact, muted */}
        <p className="mt-4 text-[13px] sm:text-[14px] leading-[1.55] text-[var(--color-ink-dim)]">
          {round.description}
        </p>

        {/* MISSION callout */}
        <div
          className="mt-5 border-l-2 pl-3.5 py-1"
          style={{ borderColor: accent }}
        >
          <div
            className="t-micro mb-1.5 inline-flex items-center gap-1.5"
            style={{ color: accent }}
          >
            {isBounty ? (
              <>
                <span>★</span> ${BOUNTY_AMOUNT} Starbucks Bounty <span>★</span>
              </>
            ) : (
              "Your Mission"
            )}
          </div>
          <div className="text-[13px] sm:text-[14px] leading-[1.55] text-[var(--color-ink)]">
            {round.brief.objective}
          </div>
        </div>

        {/* Metadata — terminal strip */}
        <div className="mt-5 pt-4 border-t border-[var(--color-hairline)] grid grid-cols-2 gap-x-4 gap-y-2">
          <MetaRow label="Action" value={round.brief.action_type} />
          <MetaRow label="Channel" value={round.brief.channel} />
          <MetaRow label="Env" value={round.brief.environment} />
          <MetaRow label="To" value={round.brief.recipient || "—"} />
        </div>

        {/* Record vs this opponent */}
        {record && record.attempts > 0 && (
          <div className="mt-5 pt-4 border-t border-[var(--color-hairline)]">
            <div className="t-micro text-[var(--color-ink-faint)] mb-2">
              Your Record vs {round.name.replace("The ", "")}
            </div>
            <div className="flex items-center gap-3 font-mono text-[11px]">
              <span>
                <span style={{ color: "var(--color-permit)" }} className="font-bold">
                  {record.wins}
                </span>
                <span className="text-[var(--color-ink-faint)] ml-1">W</span>
              </span>
              <span>
                <span className="text-[var(--color-red)] font-bold">
                  {record.losses}
                </span>
                <span className="text-[var(--color-ink-faint)] ml-1">L</span>
              </span>
              <span>
                <span className="text-[var(--color-gold)] font-bold">
                  {record.draws}
                </span>
                <span className="text-[var(--color-ink-faint)] ml-1">D</span>
              </span>
              <span className="ml-auto text-[var(--color-ink-faint)]">
                {record.attempts} attempts
              </span>
            </div>
            <div className="mt-2.5">
              <div className="flex items-baseline justify-between t-micro text-[var(--color-ink-faint)]">
                <span>Closest you got</span>
                <span>{Math.round(record.bestScore * 100)}%</span>
              </div>
              <div className="h-1 bg-[var(--color-hairline)] mt-1 relative">
                <div
                  className="absolute inset-y-0 left-0 transition-all duration-500"
                  style={{
                    width: `${Math.round(record.bestScore * 100)}%`,
                    background: "var(--color-cyan)",
                    boxShadow: "0 0 6px rgba(95, 240, 255, 0.5)",
                  }}
                />
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

function MetaRow({ label, value }) {
  return (
    <div className="flex items-baseline gap-2 min-w-0">
      <span className="t-micro text-[var(--color-ink-faint)] w-[50px] flex-shrink-0">
        {label}
      </span>
      <span className="font-mono text-[11px] text-[var(--color-ink)] truncate">
        {value}
      </span>
    </div>
  );
}

function DifficultyFlames({ score, color }) {
  const active = Math.min(7, score);
  return (
    <div className="flex items-center gap-[1px]">
      {Array.from({ length: 7 }).map((_, i) => (
        <Flame
          key={i}
          className="w-2.5 h-2.5"
          strokeWidth={2.5}
          style={{
            color: i < active ? color : "rgba(255,255,255,0.1)",
            fill: i < active ? color : "none",
          }}
        />
      ))}
    </div>
  );
}
