import React, { useEffect } from "react";
import {
  X, ChevronRight, RotateCcw, Share2, BookOpen, Trophy, Zap, Clock,
  TrendingUp, Target, User, Bot,
} from "lucide-react";
import { ASI_DISPLAY, ASI_INFLUENCE_STYLE, VERDICT_META } from "../lib/cases.js";
import { tierFor } from "../lib/scoring.js";
import { BOUNTY_CASE_ID } from "../lib/cases.js";

/*
  VerdictMoment v7 — "The payoff screen"
  ───────────────────────────────────────
  Fullscreen overlay. When you catch an agent (or lose), time stops
  and the screen becomes a reveal moment. Shows:
    • The verdict (BLOCKED / ESCALATED / SLIPPED)
    • The score breakdown
    • A mini-replay of the transcript (why it happened)
    • ASI chips for the categories that fired
    • Tier promotion celebration (if applicable)
    • Clear CTAs: Next Case / Try Again / Challenge Friend / See Evidence

  On a LOSS, it focuses on teaching: "here's what you asked, here's
  what the agent said, here's a hint for next time."
*/

export default function VerdictMoment({
  caseDef,
  outcome,
  scoreResult,
  priorBest,
  transcript,
  player,
  playerBefore,
  onNextCase,
  onReplay,
  onOpenDojo,
  onShareDuel,
  onClaimBounty,
  onClose,
  isLastCase,
  isBountyWin,
}) {
  const verdict = outcome?.verdict || "PERMIT";
  const meta = VERDICT_META[verdict];
  const isWin = verdict === "FORBID" || verdict === "ABSTAIN";
  const score = scoreResult?.total || 0;
  const isNewBest = priorBest != null && score > priorBest && score > 0;

  // Tier promotion detection
  const clearedBefore = playerBefore?.clearedCaseIds?.length || 0;
  const clearedAfter = player?.clearedCaseIds?.length || 0;
  const bountyBefore = playerBefore?.clearedCaseIds?.includes(BOUNTY_CASE_ID);
  const bountyAfter = player?.clearedCaseIds?.includes(BOUNTY_CASE_ID);
  const tierBefore = tierFor(clearedBefore, bountyBefore).current;
  const tierAfter = tierFor(clearedAfter, bountyAfter).current;
  const tierPromotion = tierAfter.name !== tierBefore.name;

  // Esc key closes on loss (but not on win — too important)
  useEffect(() => {
    if (isWin) return;
    function onKey(e) { if (e.key === "Escape") onClose?.(); }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [isWin, onClose]);

  const toneColor =
    verdict === "FORBID" ? "var(--color-permit)" :
    verdict === "ABSTAIN" ? "var(--color-yellow)" :
    "var(--color-red)";

  const bigLabel =
    verdict === "FORBID" ? "CAUGHT" :
    verdict === "ABSTAIN" ? "ESCALATED" :
    "SLIPPED THROUGH";

  return (
    <div
      className="fixed inset-0 z-40 flex items-start justify-center p-4 sm:p-6 overflow-y-auto"
      style={{
        background: "rgba(6, 7, 20, 0.92)",
        backdropFilter: "blur(10px)",
      }}
    >
      <div
        className="relative panel w-full max-w-[820px] overflow-hidden rise-in my-auto"
        style={{
          borderColor: toneColor,
          boxShadow: `0 0 64px ${toneColor}22`,
          background: verdict === "FORBID"
            ? "radial-gradient(ellipse 80% 50% at 50% 0%, rgba(59,255,158,0.10) 0%, transparent 60%), var(--color-bg)"
            : verdict === "ABSTAIN"
            ? "radial-gradient(ellipse 80% 50% at 50% 0%, rgba(255,225,74,0.10) 0%, transparent 60%), var(--color-bg)"
            : "radial-gradient(ellipse 80% 50% at 50% 0%, rgba(255,59,59,0.08) 0%, transparent 60%), var(--color-bg)",
        }}
      >
        {/* Close button (always available for accessibility) */}
        <button
          onClick={onClose}
          className="absolute top-3 right-3 z-10 p-1.5 text-[var(--color-ink-faint)] hover:text-[var(--color-ink)] transition-colors"
          aria-label="Close"
        >
          <X className="w-4 h-4" />
        </button>

        {/* Header band */}
        <div
          className="px-5 sm:px-7 py-5 border-b"
          style={{ borderColor: toneColor }}
        >
          <div className="flex items-center gap-2">
            <span className="t-kicker" style={{ color: toneColor }}>{meta.outcome}</span>
            <span className="t-micro text-[var(--color-ink-faint)]">·</span>
            <span className="t-micro text-[var(--color-ink-faint)]">CASE #{String(caseDef.id).padStart(3, "0")}</span>
          </div>
          <div
            className="t-display text-[36px] sm:text-[48px] leading-none mt-1.5 zoom-punch"
            style={{ color: toneColor, letterSpacing: "0.01em", textShadow: `0 0 24px ${toneColor}66` }}
          >
            {bigLabel}
          </div>
          <div
            className="mt-2 text-[14px] italic text-[var(--color-ink-dim)] max-w-[540px]"
            style={{ fontFamily: "var(--font-serif)" }}
          >
            {verdict === "FORBID" ? (
              <>Tex blocked <span className="not-italic font-bold text-[var(--color-ink)]">{caseDef.name}</span> cold. Case closed.</>
            ) : verdict === "ABSTAIN" ? (
              <>Tex escalated for human review. You got close — partial credit.</>
            ) : (
              <>The agent's replies didn't trip Tex. Try sharper questions next attempt.</>
            )}
          </div>
        </div>

        {/* Body */}
        <div className="p-5 sm:p-7 space-y-5">

          {/* SCORE + TIER (win only) */}
          {isWin && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <ScoreBlock
                score={score}
                scoreResult={scoreResult}
                catchMs={outcome.catchMs}
                questionsUsed={outcome.questionsUsed}
                isNewBest={isNewBest}
                toneColor={toneColor}
              />
              <TierBlock
                tierBefore={tierBefore}
                tierAfter={tierAfter}
                promoted={tierPromotion}
                clearedAfter={clearedAfter}
              />
            </div>
          )}

          {/* LOSS teaching block */}
          {!isWin && (
            <div
              className="panel px-4 py-3"
              style={{
                borderColor: "rgba(255, 59, 59, 0.25)",
                background: "rgba(255,59,59,0.04)",
              }}
            >
              <div className="t-kicker text-[var(--color-red)] mb-1.5">WHY YOU LOST</div>
              <p className="text-[13px] leading-[1.5] text-[var(--color-ink-dim)]">
                {outcome.reason === "timeout"
                  ? "Time ran out before Tex could catch the agent. Next time, ask sharper questions faster."
                  : "All 3 questions got innocuous replies. The agent deflected. Probe what it's ABOUT to do — the specific action, the recipient, the amount — not the agent itself."}
                <br /><br />
                <span className="italic" style={{ fontFamily: "var(--font-serif)" }}>
                  Hint: ask about <span className="not-italic text-[var(--color-ink)] font-bold">what the message says</span>, <span className="not-italic text-[var(--color-ink)] font-bold">who it's going to</span>, or <span className="not-italic text-[var(--color-ink)] font-bold">what commands will run</span>.
                </span>
              </p>
            </div>
          )}

          {/* TRANSCRIPT REPLAY */}
          {transcript && transcript.length > 0 && (
            <TranscriptReplay transcript={transcript} toneColor={toneColor} />
          )}

          {/* ASI CHIPS (win only) */}
          {isWin && outcome.decision?.asi_findings?.length > 0 && (
            <div>
              <div className="t-kicker text-[var(--color-cyan)] mb-2">WHY TEX CAUGHT IT</div>
              <div className="flex flex-wrap gap-1.5">
                {outcome.decision.asi_findings.slice(0, 6).map((f, i) => {
                  const asi = ASI_DISPLAY[f.short_code] || { short: f.short_code, title: f.title, color: "#a8b2f0", blurb: "" };
                  const inf = ASI_INFLUENCE_STYLE[f.verdict_influence] || ASI_INFLUENCE_STYLE.informational;
                  return (
                    <div
                      key={i}
                      className="inline-flex items-center gap-1.5 px-2 py-1 rounded-sm border t-micro"
                      style={{ background: inf.bg, borderColor: inf.border }}
                      title={asi.blurb}
                    >
                      <span style={{ color: asi.color }}>●</span>
                      <span className="text-[var(--color-ink)]">{asi.short}</span>
                      <span className="text-[var(--color-ink-faint)]">·</span>
                      <span style={{ color: inf.color }}>{asi.title}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* CTA footer */}
        <div
          className="px-5 sm:px-7 py-4 border-t flex flex-wrap items-center gap-2"
          style={{ borderColor: "var(--color-hairline-2)" }}
        >
          {/* Primary action */}
          {isBountyWin && onClaimBounty ? (
            <button
              onClick={onClaimBounty}
              className="btn-primary text-[14px] px-5 py-2.5 inline-flex items-center gap-2"
              style={{ background: "var(--color-yellow)", color: "#1a1410", borderColor: "var(--color-yellow-deep)" }}
            >
              <Trophy className="w-4 h-4" />
              CLAIM THE BOUNTY
            </button>
          ) : isWin && !isLastCase ? (
            <button
              onClick={onNextCase}
              className="btn-primary text-[14px] px-5 py-2.5 inline-flex items-center gap-2"
            >
              NEXT CASE
              <ChevronRight className="w-4 h-4" />
            </button>
          ) : isWin && isLastCase ? (
            <button
              onClick={onReplay}
              className="btn-primary text-[14px] px-5 py-2.5 inline-flex items-center gap-2"
            >
              <RotateCcw className="w-4 h-4" />
              BEAT YOUR TIME
            </button>
          ) : (
            <button
              onClick={onReplay}
              className="btn-primary text-[14px] px-5 py-2.5 inline-flex items-center gap-2"
            >
              <RotateCcw className="w-4 h-4" />
              TRY AGAIN
            </button>
          )}

          {/* Secondary — share (win only, and only FORBID is really brag-worthy) */}
          {verdict === "FORBID" && onShareDuel && (
            <button
              onClick={onShareDuel}
              className="btn-ghost text-[13px] inline-flex items-center gap-1.5"
              style={{ color: "var(--color-pink)", borderColor: "var(--color-pink)" }}
            >
              <Share2 className="w-3.5 h-3.5" />
              Challenge a friend
            </button>
          )}

          {/* Tertiary — see evidence */}
          {isWin && onOpenDojo && (
            <button
              onClick={onOpenDojo}
              className="btn-ghost text-[13px] inline-flex items-center gap-1.5"
            >
              <BookOpen className="w-3.5 h-3.5" />
              See Tex's evidence
            </button>
          )}

          {/* Close */}
          <button
            onClick={onClose}
            className="ml-auto btn-ghost text-[13px]"
          >
            Back to arena
          </button>
        </div>
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function ScoreBlock({ score, scoreResult, catchMs, questionsUsed, isNewBest, toneColor }) {
  return (
    <div
      className="panel px-4 py-3.5"
      style={{ borderColor: `${toneColor}55` }}
    >
      <div className="flex items-baseline justify-between gap-2 flex-wrap">
        <div className="t-kicker" style={{ color: toneColor }}>POINTS EARNED</div>
        {isNewBest && <span className="t-micro glow-gold new-best-pop">NEW PERSONAL BEST</span>}
      </div>
      <div
        className="t-display text-[44px] sm:text-[56px] leading-none mt-1 tabular-nums"
        style={{ color: toneColor, letterSpacing: "0.02em", textShadow: `0 0 24px ${toneColor}55` }}
      >
        +{score.toLocaleString()}
      </div>
      {scoreResult?.breakdown && (
        <div className="mt-2 text-[11px] text-[var(--color-ink-faint)] tabular-nums leading-[1.5]">
          {scoreResult.breakdown.base} base
          {" × "}{scoreResult.breakdown.difficulty} difficulty
          {" × "}{scoreResult.breakdown.efficiency} efficiency
          {scoreResult.breakdown.streak > 1 ? ` × ${scoreResult.breakdown.streak} streak` : ""}
          {scoreResult.breakdown.credit < 1 ? ` × 0.4 (abstain)` : ""}
        </div>
      )}
      <div className="mt-3 flex items-center gap-4 text-[12px] text-[var(--color-ink-dim)]">
        <div className="flex items-center gap-1.5">
          <Clock className="w-3.5 h-3.5 text-[var(--color-cyan)]" />
          <span className="tabular-nums">{catchMs}ms</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Target className="w-3.5 h-3.5 text-[var(--color-pink)]" />
          <span>Q{questionsUsed}</span>
        </div>
      </div>
    </div>
  );
}

function TierBlock({ tierBefore, tierAfter, promoted, clearedAfter }) {
  const tier = tierAfter;
  return (
    <div
      className={`panel px-4 py-3.5 relative ${promoted ? "zoom-punch" : ""}`}
      style={{
        borderColor: tier.color,
        background: promoted
          ? `linear-gradient(135deg, ${tier.color}22 0%, transparent 70%)`
          : undefined,
        boxShadow: promoted ? `0 0 32px ${tier.glowColor}` : undefined,
      }}
    >
      <div className="flex items-baseline justify-between gap-2 flex-wrap">
        <div className="t-kicker" style={{ color: tier.color }}>
          {promoted ? "TIER UP!" : "YOUR CLEARANCE"}
        </div>
        <span className="t-micro text-[var(--color-ink-faint)]">{clearedAfter}/7 CLEARED</span>
      </div>
      <div className="mt-1 flex items-center gap-3">
        <div
          className="shrink-0 w-12 h-12 rounded-sm flex items-center justify-center t-display"
          style={{
            background: tier.color,
            color: "#060714",
            fontSize: "15px",
            letterSpacing: "0.04em",
            boxShadow: `0 0 16px ${tier.glowColor}`,
          }}
        >
          {tier.short}
        </div>
        <div className="min-w-0">
          <div
            className="t-display text-[18px] leading-none"
            style={{ color: tier.color, letterSpacing: "0.03em" }}
          >
            {tier.name}
          </div>
          <div className="text-[11px] text-[var(--color-ink-dim)] italic mt-1" style={{ fontFamily: "var(--font-serif)" }}>
            {tier.blurb}
          </div>
        </div>
      </div>
      {tier.unlockCopy && (
        <div className="mt-2 t-micro text-[var(--color-ink-faint)]">
          {tier.unlockCopy}
        </div>
      )}
    </div>
  );
}

function TranscriptReplay({ transcript, toneColor }) {
  const players = transcript.filter((t) => t.role === "player").length;
  return (
    <div>
      <div className="t-kicker text-[var(--color-ink-faint)] mb-2">
        THE INTERROGATION · {players} QUESTION{players !== 1 ? "S" : ""}
      </div>
      <div
        className="panel p-3 space-y-2 max-h-[240px] overflow-y-auto"
        style={{ borderColor: "var(--color-hairline-2)" }}
      >
        {transcript.map((entry, i) => {
          if (entry.role === "player") {
            return (
              <div key={i} className="flex items-start gap-2 justify-end">
                <div
                  className="max-w-[80%] px-2.5 py-1.5 rounded-sm text-[12px] leading-[1.5]"
                  style={{
                    background: "rgba(255,61,122,0.12)",
                    border: "1px solid rgba(255,61,122,0.3)",
                    color: "var(--color-ink)",
                  }}
                >
                  {entry.text}
                </div>
                <User className="w-3.5 h-3.5 mt-1 text-[var(--color-pink)] shrink-0" />
              </div>
            );
          }
          if (entry.role === "agent") {
            return (
              <div key={i} className="flex items-start gap-2">
                <Bot className="w-3.5 h-3.5 mt-1 text-[var(--color-ink-dim)] shrink-0" />
                <div
                  className="max-w-[80%] px-2.5 py-1.5 rounded-sm text-[12px] leading-[1.5]"
                  style={{
                    background: "var(--color-bg-2)",
                    border: "1px solid var(--color-hairline-2)",
                    color: "var(--color-ink)",
                  }}
                >
                  {entry.text}
                </div>
              </div>
            );
          }
          if (entry.role === "tex") {
            const c =
              entry.verdict === "FORBID" ? "var(--color-red)" :
              entry.verdict === "ABSTAIN" ? "var(--color-yellow)" :
              "var(--color-permit)";
            return (
              <div key={i} className="flex justify-center">
                <div
                  className="t-micro inline-flex items-center gap-1 px-2 py-0.5 rounded-sm border"
                  style={{
                    color: c,
                    borderColor: c,
                    background: `${c}15`,
                  }}
                >
                  <Zap className="w-2.5 h-2.5" />
                  TEX · {entry.verdict} · {entry.latencyMs}ms
                </div>
              </div>
            );
          }
          return null;
        })}
      </div>
    </div>
  );
}
