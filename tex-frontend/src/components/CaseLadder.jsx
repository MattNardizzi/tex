import React from "react";
import { Lock, Check, Play, Trophy } from "lucide-react";
import { buildLadder } from "../lib/progression.js";

/*
  CaseLadder v7 — "The 7 Cases"
  ──────────────────────────────
  Layout changes vs v6:
    • Horizontal strip of 7 tiles on desktop, so the ladder reads as
      a game progression bar not a spreadsheet.
    • Connected by a thin line between tiles that fills as you clear.
    • Each tile shows: number, status icon, name, difficulty pips.
    • Active/current tile gets cyan glow; cleared get permit-green;
      locked are muted.
    • Warden is visually distinct (yellow, trophy icon).
    • Tap locked → shakes. Tap cleared → replay. Tap current → play.
*/

export default function CaseLadder({
  player,
  activeCaseId,
  onSelect,
  onLockedTap,
}) {
  const ladder = buildLadder(player.clearedCaseIds || []);
  const cleared = player.clearedCaseIds?.length || 0;
  const progressPct = Math.round((cleared / 7) * 100);

  return (
    <section className="panel overflow-hidden" id="case-ladder">
      {/* Header */}
      <div className="px-4 sm:px-5 py-3 border-b border-[var(--color-hairline-2)] flex items-center justify-between">
        <div>
          <div className="t-kicker text-[var(--color-cyan)]">THE 7 CASES</div>
          <div className="t-micro text-[var(--color-ink-faint)] mt-0.5">
            Clear each to unlock the next. The Warden is the bounty.
          </div>
        </div>
        <div className="text-right">
          <div
            className="t-display text-[20px] text-[var(--color-ink)]"
            style={{ letterSpacing: "0.03em" }}
          >
            {cleared}<span className="text-[var(--color-ink-faint)]">/7</span>
          </div>
          <div className="t-micro text-[var(--color-ink-faint)]">{progressPct}% CLEARED</div>
        </div>
      </div>

      {/* Progress rail */}
      <div className="px-4 sm:px-5 pt-3">
        <div className="h-[2px] bg-[var(--color-bg-3)] rounded-full overflow-hidden">
          <div
            className="h-full transition-all duration-700"
            style={{
              width: `${progressPct}%`,
              background: "linear-gradient(90deg, var(--color-cyan), var(--color-pink), var(--color-yellow))",
              boxShadow: "0 0 12px rgba(255,61,122,0.4)",
            }}
          />
        </div>
      </div>

      {/* Desktop: horizontal strip */}
      <div className="hidden md:grid grid-cols-7 gap-2 px-4 sm:px-5 py-4">
        {ladder.map(({ caseDef, status }) => {
          const isActive = caseDef.id === activeCaseId;
          const perCase = player.perCase?.[caseDef.id];
          return (
            <CaseTile
              key={caseDef.id}
              caseDef={caseDef}
              status={status}
              isActive={isActive}
              perCase={perCase}
              onClick={() => {
                if (status === "locked") {
                  onLockedTap?.(caseDef);
                  return;
                }
                onSelect?.(caseDef);
              }}
            />
          );
        })}
      </div>

      {/* Mobile: vertical stack */}
      <div className="md:hidden">
        {ladder.map(({ caseDef, status }, idx) => {
          const isActive = caseDef.id === activeCaseId;
          const perCase = player.perCase?.[caseDef.id];
          return (
            <CaseRowMobile
              key={caseDef.id}
              caseDef={caseDef}
              status={status}
              isActive={isActive}
              perCase={perCase}
              isLast={idx === ladder.length - 1}
              onClick={() => {
                if (status === "locked") {
                  onLockedTap?.(caseDef);
                  return;
                }
                onSelect?.(caseDef);
              }}
            />
          );
        })}
      </div>
    </section>
  );
}

function CaseTile({ caseDef, status, isActive, perCase, onClick }) {
  const locked = status === "locked";
  const cleared = status === "cleared";
  const current = status === "current";
  const isBounty = caseDef.isBounty;

  const tileBorder = locked
    ? "rgba(168, 178, 240, 0.12)"
    : cleared
    ? "rgba(59, 255, 158, 0.4)"
    : current
    ? "rgba(95, 240, 255, 0.55)"
    : "rgba(168, 178, 240, 0.2)";

  const tileBg = locked
    ? "rgba(6,7,20,0.4)"
    : cleared
    ? "rgba(59, 255, 158, 0.06)"
    : current
    ? "rgba(95, 240, 255, 0.08)"
    : "rgba(12, 14, 34, 0.5)";

  const glow = current
    ? "0 0 24px rgba(95,240,255,0.25)"
    : cleared
    ? "0 0 12px rgba(59,255,158,0.15)"
    : isBounty
    ? "0 0 16px rgba(255,225,74,0.15)"
    : "none";

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={locked}
      className={`relative p-2.5 rounded-sm text-left transition-all hover:scale-[1.02] disabled:hover:scale-100 disabled:cursor-not-allowed ${isActive ? "zoom-punch" : ""}`}
      style={{
        border: `1px solid ${tileBorder}`,
        background: tileBg,
        boxShadow: glow,
        opacity: locked ? 0.55 : 1,
        minHeight: "112px",
      }}
    >
      {/* Top row: number + status */}
      <div className="flex items-start justify-between gap-2">
        <span
          className="t-micro text-[var(--color-ink-faint)]"
          style={{ fontSize: "10px" }}
        >
          #{String(caseDef.id).padStart(3, "0")}
        </span>
        <div className="shrink-0">
          {cleared && <Check className="w-3.5 h-3.5 text-[var(--color-permit)]" />}
          {current && <Play className="w-3.5 h-3.5 text-[var(--color-cyan)]" fill="currentColor" />}
          {locked && <Lock className="w-3.5 h-3.5 text-[var(--color-ink-faint)]" />}
        </div>
      </div>

      {/* Name */}
      <div
        className="t-display mt-1.5 leading-[1.1]"
        style={{
          fontSize: "13px",
          color: locked ? "var(--color-ink-faint)" : "var(--color-ink)",
          letterSpacing: "0.02em",
        }}
      >
        {caseDef.name}
      </div>

      {/* Bounty flag */}
      {isBounty && (
        <div className="mt-1 flex items-center gap-1">
          <Trophy className="w-3 h-3 text-[var(--color-yellow)]" />
          <span className="t-micro glow-gold" style={{ fontSize: "9px" }}>BOUNTY</span>
        </div>
      )}

      {/* Bottom: difficulty pips + best */}
      <div className="absolute bottom-2 left-2.5 right-2.5 flex items-center justify-between">
        <div className="flex gap-0.5" aria-label={`Difficulty ${caseDef.difficulty} of 8`}>
          {Array.from({ length: 7 }).map((_, i) => (
            <span
              key={i}
              className="inline-block w-[3px] h-[6px] rounded-[0.5px]"
              style={{
                background: i < caseDef.difficulty
                  ? (isBounty ? "var(--color-yellow)" : current ? "var(--color-cyan)" : "var(--color-pink)")
                  : "var(--color-hairline-2)",
                opacity: i < caseDef.difficulty ? 0.9 : 0.4,
              }}
            />
          ))}
        </div>
        {cleared && perCase?.bestCatchMs != null && (
          <span className="t-micro text-[var(--color-permit)] tabular-nums" style={{ fontSize: "10px" }}>
            {perCase.bestCatchMs}ms
          </span>
        )}
      </div>

      {/* Current marker overlay */}
      {current && !cleared && (
        <div
          className="absolute inset-x-0 bottom-0 h-[2px]"
          style={{
            background: "var(--color-cyan)",
            boxShadow: "0 0 8px rgba(95,240,255,0.6)",
          }}
        />
      )}
    </button>
  );
}

function CaseRowMobile({ caseDef, status, isActive, perCase, onClick, isLast }) {
  const locked = status === "locked";
  const cleared = status === "cleared";
  const current = status === "current";

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={locked}
      className="w-full text-left px-4 py-3 flex items-center gap-3 border-b border-[var(--color-hairline)] transition-colors hover:bg-[var(--color-bg-2)] disabled:hover:bg-transparent"
      style={{
        opacity: locked ? 0.5 : 1,
        borderBottom: isLast ? "none" : undefined,
        background: current ? "rgba(95,240,255,0.06)" : "transparent",
      }}
    >
      <div
        className="shrink-0 w-9 h-9 flex items-center justify-center rounded-sm"
        style={{
          borderColor: cleared ? "var(--color-permit)" : current ? "var(--color-cyan)" : "var(--color-hairline-2)",
          border: "1px solid",
          background: cleared ? "rgba(59,255,158,0.08)" : current ? "rgba(95,240,255,0.08)" : "transparent",
        }}
      >
        {cleared && <Check className="w-4 h-4 text-[var(--color-permit)]" />}
        {current && <Play className="w-4 h-4 text-[var(--color-cyan)]" fill="currentColor" />}
        {locked && <Lock className="w-4 h-4 text-[var(--color-ink-faint)]" />}
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-baseline gap-2">
          <span className="t-micro text-[var(--color-ink-faint)]">#{String(caseDef.id).padStart(3, "0")}</span>
          <span className="t-display text-[14px] text-[var(--color-ink)] truncate" style={{ letterSpacing: "0.02em" }}>
            {caseDef.name}
          </span>
          {caseDef.isBounty && (
            <Trophy className="w-3 h-3 text-[var(--color-yellow)]" />
          )}
        </div>
        <div className="text-[11px] text-[var(--color-ink-faint)] italic mt-0.5 truncate" style={{ fontFamily: "var(--font-serif)" }}>
          {caseDef.tagline}
        </div>
      </div>
      <div className="shrink-0 text-right">
        {cleared && perCase?.bestCatchMs != null ? (
          <div className="t-micro text-[var(--color-permit)] tabular-nums">{perCase.bestCatchMs}ms</div>
        ) : current ? (
          <div className="t-micro glow-cyan">CURRENT</div>
        ) : null}
      </div>
    </button>
  );
}
