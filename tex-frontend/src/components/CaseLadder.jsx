import React from "react";
import { Lock, Check, Play, Trophy } from "lucide-react";
import { buildLadder } from "../lib/progression.js";

/*
  CaseLadder — the progression display.
  ──────────────────────────────────────
  Shows 7 cases top to bottom. Exactly one is "current" (unlocked and
  not yet cleared). Others are "cleared" (done — replay allowed) or
  "locked" (can't click). The player always knows where they are.

  Locked rows are visually muted and unclickable. Tapping a locked row
  gives a small shake + explanation instead of silently doing nothing.
*/

export default function CaseLadder({
  player,
  activeCaseId,
  onSelect,
  onLockedTap,
}) {
  const ladder = buildLadder(player.clearedCaseIds || []);

  return (
    <section className="panel overflow-hidden" id="case-ladder">
      <div className="px-4 sm:px-5 py-3 border-b border-[var(--color-hairline-2)] flex items-center justify-between">
        <div>
          <div className="t-kicker text-[var(--color-cyan)]">THE 7 CASES</div>
          <div className="t-micro text-[var(--color-ink-faint)] mt-0.5">
            Clear each one to unlock the next. Warden is the bounty.
          </div>
        </div>
        <div className="t-display text-[18px] text-[var(--color-ink)]" style={{ letterSpacing: "0.03em" }}>
          {player.clearedCaseIds?.length || 0}<span className="text-[var(--color-ink-faint)]">/7</span>
        </div>
      </div>

      <ol>
        {ladder.map(({ caseDef, status }) => {
          const isActive = caseDef.id === activeCaseId;
          const perCase = player.perCase?.[caseDef.id];
          return (
            <li
              key={caseDef.id}
              className="border-b border-[var(--color-hairline)] last:border-b-0"
            >
              <CaseRow
                caseDef={caseDef}
                status={status}
                isActive={isActive}
                perCase={perCase}
                onSelect={() => {
                  if (status === "locked") {
                    onLockedTap?.(caseDef);
                    return;
                  }
                  onSelect?.(caseDef);
                }}
              />
            </li>
          );
        })}
      </ol>
    </section>
  );
}

function CaseRow({ caseDef, status, isActive, perCase, onSelect }) {
  const locked = status === "locked";
  const cleared = status === "cleared";
  const current = status === "current";

  const idLabel = String(caseDef.id).padStart(3, "0");
  const bestScore = perCase?.bestScore || 0;
  const bestMs = perCase?.bestCatchMs;

  const rowStyle = locked
    ? { opacity: 0.42, cursor: "not-allowed" }
    : isActive
    ? { background: "linear-gradient(90deg, rgba(95,240,255,0.08), transparent 70%)" }
    : {};

  return (
    <button
      type="button"
      onClick={onSelect}
      disabled={locked}
      className="w-full text-left px-4 sm:px-5 py-3 flex items-center gap-4 transition-colors hover:bg-[var(--color-bg-2)] disabled:hover:bg-transparent"
      style={rowStyle}
      aria-label={locked ? `${caseDef.name} — locked` : `${caseDef.name} — ${status}`}
    >
      {/* Status badge */}
      <div className="shrink-0 w-9 h-9 flex items-center justify-center border rounded-sm"
        style={{
          borderColor: cleared ? "var(--color-permit)" : current ? "var(--color-cyan)" : "var(--color-hairline-2)",
          background: cleared
            ? "rgba(59,255,158,0.08)"
            : current
            ? "rgba(95,240,255,0.08)"
            : "transparent",
        }}
      >
        {cleared && <Check className="w-4 h-4 text-[var(--color-permit)]" />}
        {current && <Play className="w-4 h-4 text-[var(--color-cyan)]" fill="currentColor" />}
        {locked && <Lock className="w-4 h-4 text-[var(--color-ink-faint)]" />}
      </div>

      {/* Case id + name */}
      <div className="flex-1 min-w-0">
        <div className="flex items-baseline gap-2 flex-wrap">
          <span className="t-micro text-[var(--color-ink-faint)]">#{idLabel}</span>
          <span
            className="t-display text-[15px] sm:text-[16px] text-[var(--color-ink)] truncate"
            style={{ letterSpacing: "0.02em" }}
          >
            {caseDef.name}
          </span>
          {caseDef.isBounty && (
            <span className="t-micro glow-gold inline-flex items-center gap-1">
              <Trophy className="w-3 h-3" /> BOUNTY
            </span>
          )}
        </div>
        <div className="text-[12px] text-[var(--color-ink-faint)] mt-0.5 truncate italic" style={{ fontFamily: "var(--font-serif)" }}>
          {caseDef.tagline}
        </div>
      </div>

      {/* Difficulty pips */}
      <div className="shrink-0 hidden sm:flex items-center gap-0.5" aria-label={`Difficulty ${caseDef.difficulty} of 8`}>
        {Array.from({ length: 8 }).map((_, i) => (
          <span
            key={i}
            className="inline-block w-[4px] h-[10px] rounded-[1px]"
            style={{
              background: i < caseDef.difficulty ? "var(--color-pink)" : "var(--color-hairline-2)",
              opacity: i < caseDef.difficulty ? 0.9 : 0.5,
            }}
          />
        ))}
      </div>

      {/* Best stats (only if cleared) */}
      <div className="shrink-0 hidden md:block text-right min-w-[90px]">
        {cleared ? (
          <>
            <div className="t-display text-[14px] text-[var(--color-ink)]">{bestScore.toLocaleString()}</div>
            {bestMs != null && (
              <div className="t-micro text-[var(--color-ink-faint)]">{bestMs}ms best</div>
            )}
          </>
        ) : current ? (
          <div className="t-micro glow-cyan">CURRENT</div>
        ) : (
          <div className="t-micro text-[var(--color-ink-faint)]">LOCKED</div>
        )}
      </div>
    </button>
  );
}
