import React from "react";
import { ChevronRight, Share2, RotateCcw, BookOpen, Trophy } from "lucide-react";
import { ASI_DISPLAY, ASI_INFLUENCE_STYLE, VERDICT_META } from "../lib/cases.js";

/*
  VerdictMoment
  ─────────────
  The payoff screen. Shows up after the session ends (catch or miss).
  Three variants:
    • CAUGHT (FORBID)  — full celebration, score breakdown, share CTA
    • PARTIAL (ABSTAIN) — softer win, 40% credit, same CTAs
    • MISSED (PERMIT / timeout / 3-strikes) — the agent slipped; retry CTA
*/

export default function VerdictMoment({
  caseDef,
  outcome,         // { verdict, decision, catchMs, questionsUsed } OR { verdict: "PERMIT" }
  scoreResult,     // from computeCaseScore
  priorBest,
  onNextCase,
  onReplay,
  onOpenDojo,
  onShareDuel,
  onClaimBounty,
  isLastCase,
  isBountyWin,
}) {
  const verdict = outcome?.verdict || "PERMIT";
  const meta = VERDICT_META[verdict];
  const tone = meta.tone;

  const toneColor =
    tone === "caught" ? "var(--color-permit)" :
    tone === "partial" ? "var(--color-yellow)" :
    "var(--color-red)";

  const isWin = verdict === "FORBID" || verdict === "ABSTAIN";
  const score = scoreResult?.total || 0;
  const isNewBest = priorBest != null && score > priorBest && score > 0;

  return (
    <section className="relative panel overflow-hidden zoom-punch"
      style={{
        background:
          tone === "caught"
            ? "radial-gradient(ellipse 90% 60% at 50% 0%, rgba(59,255,158,0.10) 0%, transparent 60%)"
            : tone === "partial"
            ? "radial-gradient(ellipse 90% 60% at 50% 0%, rgba(255,225,74,0.10) 0%, transparent 60%)"
            : "radial-gradient(ellipse 90% 60% at 50% 0%, rgba(255,59,59,0.08) 0%, transparent 60%)",
        borderColor: toneColor,
      }}
    >
      {/* Verdict bar */}
      <div
        className="px-4 sm:px-5 py-3 border-b flex items-center justify-between"
        style={{ borderColor: toneColor }}
      >
        <div>
          <div className="t-kicker" style={{ color: toneColor }}>{meta.outcome}</div>
          <div
            className="t-display text-[22px] sm:text-[26px] text-[var(--color-ink)] leading-none mt-1"
            style={{ letterSpacing: "0.02em" }}
          >
            {meta.label}
          </div>
        </div>
        <div className="text-right">
          <div className="t-micro text-[var(--color-ink-faint)]">CASE #{String(caseDef.id).padStart(3, "0")}</div>
          <div className="t-display text-[14px] text-[var(--color-ink)] mt-0.5 truncate max-w-[180px]">
            {caseDef.name.toUpperCase()}
          </div>
        </div>
      </div>

      {/* Blurb */}
      <div className="px-4 sm:px-5 pt-4">
        <p
          className="text-[14px] sm:text-[15px] leading-[1.55] italic text-[var(--color-ink-dim)]"
          style={{ fontFamily: "var(--font-serif)" }}
        >
          {meta.blurb}
        </p>
      </div>

      {/* Score block */}
      {isWin && (
        <div className="px-4 sm:px-5 pt-4">
          <div className="flex items-baseline gap-3 flex-wrap">
            <div
              className={`t-display text-[52px] sm:text-[64px] leading-none ${isNewBest ? "new-best-pop" : ""}`}
              style={{ color: toneColor, letterSpacing: "0.02em" }}
            >
              +{score.toLocaleString()}
            </div>
            {isNewBest && (
              <span className="t-micro glow-gold">NEW PERSONAL BEST</span>
            )}
          </div>
          {scoreResult && (
            <div className="mt-2 text-[12px] text-[var(--color-ink-faint)] tabular-nums">
              {scoreResult.breakdown.base} base
              {" × "}{scoreResult.breakdown.difficulty} difficulty
              {" × "}{scoreResult.breakdown.efficiency} efficiency
              {scoreResult.breakdown.streak > 1 ? ` × ${scoreResult.breakdown.streak} streak` : ""}
              {scoreResult.breakdown.credit < 1 ? ` × ${scoreResult.breakdown.credit} (abstain)` : ""}
            </div>
          )}
          <div className="mt-2 t-micro text-[var(--color-ink-faint)]">
            Caught in {outcome.catchMs}ms · Used {outcome.questionsUsed} question{outcome.questionsUsed !== 1 ? "s" : ""}
          </div>
        </div>
      )}

      {/* ASI chips — only on actual catches */}
      {isWin && outcome.decision?.asi_findings?.length > 0 && (
        <div className="px-4 sm:px-5 pt-4">
          <div className="t-micro text-[var(--color-ink-faint)] mb-2">WHY TEX CAUGHT IT</div>
          <div className="flex flex-wrap gap-1.5">
            {outcome.decision.asi_findings.slice(0, 6).map((f, i) => {
              const meta = ASI_DISPLAY[f.short_code] || { short: f.short_code, title: f.title, color: "#a8b2f0" };
              const inf = ASI_INFLUENCE_STYLE[f.verdict_influence] || ASI_INFLUENCE_STYLE.informational;
              return (
                <div
                  key={i}
                  className="inline-flex items-center gap-1.5 px-2 py-1 rounded-sm border t-micro"
                  style={{ background: inf.bg, borderColor: inf.border, color: inf.color }}
                  title={meta.blurb}
                >
                  <span style={{ color: meta.color }}>●</span>
                  <span className="text-[var(--color-ink)]">{meta.short}</span>
                  <span className="text-[var(--color-ink-faint)]">·</span>
                  <span>{meta.title}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* CTAs */}
      <div className="px-4 sm:px-5 py-4 mt-4 border-t border-[var(--color-hairline-2)] flex flex-wrap items-center gap-2">
        {isBountyWin && onClaimBounty && (
          <button
            onClick={onClaimBounty}
            className="btn-primary text-[13px] px-4 py-2 inline-flex items-center gap-1.5"
            style={{ background: "var(--color-yellow)", color: "#1a1410", borderColor: "var(--color-yellow-deep)" }}
          >
            <Trophy className="w-3.5 h-3.5" />
            CLAIM BOUNTY
          </button>
        )}
        {isWin && !isLastCase && (
          <button
            onClick={onNextCase}
            className="btn-primary text-[13px] px-4 py-2 inline-flex items-center gap-1.5"
          >
            NEXT CASE
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        )}
        {!isWin && (
          <button
            onClick={onReplay}
            className="btn-primary text-[13px] px-4 py-2 inline-flex items-center gap-1.5"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            TRY AGAIN
          </button>
        )}
        {isWin && (
          <button
            onClick={onReplay}
            className="btn-ghost text-[13px] inline-flex items-center gap-1.5"
          >
            <RotateCcw className="w-3 h-3" />
            Replay for a better time
          </button>
        )}
        {isWin && onShareDuel && (
          <button
            onClick={onShareDuel}
            className="btn-ghost text-[13px] inline-flex items-center gap-1.5"
            style={{ color: "var(--color-pink)", borderColor: "var(--color-pink)" }}
          >
            <Share2 className="w-3 h-3" />
            Dare a friend
          </button>
        )}
        {isWin && onOpenDojo && (
          <button
            onClick={onOpenDojo}
            className="btn-ghost text-[13px] inline-flex items-center gap-1.5"
          >
            <BookOpen className="w-3 h-3" />
            See Tex's evidence
          </button>
        )}
      </div>
    </section>
  );
}
