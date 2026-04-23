import React, { useEffect, useMemo, useState } from "react";
import {
  Share2,
  Play,
  BookOpen,
  Zap,
  ArrowUpRight,
  Copy,
  Check,
  Download,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Shield,
  Activity,
} from "lucide-react";
import {
  VERDICT_META,
  BOUNTY_AMOUNT,
  ASI_DISPLAY,
  ASI_INFLUENCE_STYLE,
} from "../lib/rounds";
import { permitProximity } from "../lib/storage";
import { formatPercent, ms } from "../lib/formatters";

/*
  VERDICT REVEAL — v4 "ASI-first scoreboard"
  ─────────────────────────────────────────────
  The heavy lift: turn a verdict from a game outcome into a product demo
  the player screenshots for their CISO. This component is where every
  field the backend ships has to show up.

  Render order, top → bottom:

    1. Verdict banner (SLIPPED PAST / ESCALATED / BLOCKED) + points
       ticker + closest-you-got meter (unchanged in feel)
    2. **Production impact line** — one sentence that answers
       "what would this have caused in production?" (per-round copy)
    3. **ASI findings** — one card per OWASP ASI category that fired,
       each with: short code, title, influence badge
       (DECISIVE / CONTRIBUTING / INFORMATIONAL), severity + confidence,
       counterfactual ("Tex knew because…"), and the triggering evidence.
       On PERMIT we show an empty-state: "No ASI categories fired."
    4. Tex's reasons (kept, lower-billed)
    5. Layer score strip (kept but demoted — insider view)
    6. **Decision trail** — determinism fingerprint (copyable), latency
       total + dominant stage, policy version, evidence bundle download,
       replay URL. This is the compliance artifact.
    7. Action row (Try Again / Share / Dojo / Next Round / Claim Bounty)
*/

export default function VerdictReveal({
  decision,
  round,
  pointsEarned,
  personalBest,
  onShare,
  onNextRound,
  onOpenDojo,
  onTryAgain,
  isLastRound,
  onClaimBounty,
}) {
  const [counter, setCounter] = useState(0);

  const meta = VERDICT_META[decision.verdict] || VERDICT_META.ABSTAIN;
  const proximity = useMemo(() => permitProximity(decision), [decision]);
  const proximityPct = Math.round(proximity * 100);
  const improved = personalBest !== null && proximity > personalBest;

  useEffect(() => {
    if (pointsEarned <= 0) return;
    let start;
    let raf;
    const duration = 900;
    const step = (ts) => {
      if (!start) start = ts;
      const t = Math.min(1, (ts - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setCounter(Math.round(pointsEarned * eased));
      if (t < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [pointsEarned]);

  const isWin = decision.verdict === "PERMIT";
  const isLose = decision.verdict === "FORBID";
  const isDraw = decision.verdict === "ABSTAIN";
  const isBounty = round.isBounty && isWin;

  const accent = isWin
    ? isBounty
      ? "var(--color-gold)"
      : "var(--color-permit)"
    : isDraw
    ? "var(--color-gold)"
    : "var(--color-red)";

  const verdictWord = isWin
    ? isBounty
      ? "BELT CLAIMED"
      : "SLIPPED PAST"
    : isLose
    ? "BLOCKED"
    : "ESCALATED";

  const asiFindings = Array.isArray(decision.asi_findings)
    ? decision.asi_findings
    : [];

  // Sort findings: DECISIVE first, then CONTRIBUTING, then INFORMATIONAL.
  // Within a band, sort by confidence desc.
  const sortedFindings = useMemo(() => {
    const order = { decisive: 0, contributing: 1, informational: 2 };
    return [...asiFindings].sort((a, b) => {
      const ao = order[a.verdict_influence] ?? 3;
      const bo = order[b.verdict_influence] ?? 3;
      if (ao !== bo) return ao - bo;
      return (b.confidence || 0) - (a.confidence || 0);
    });
  }, [asiFindings]);

  return (
    <section
      className={`panel relative overflow-hidden ${isLose ? "shake-hard" : ""}`}
      style={{
        borderColor: accent,
        boxShadow: isBounty
          ? "0 0 0 1px var(--color-gold), 0 0 48px rgba(245, 185, 61, 0.25)"
          : isWin
          ? `0 0 0 1px ${accent}, 0 0 32px rgba(59, 224, 130, 0.18)`
          : isDraw
          ? `0 0 0 1px ${accent}, 0 0 24px rgba(245, 185, 61, 0.15)`
          : `0 0 0 1px ${accent}, 0 0 24px rgba(239, 53, 53, 0.2)`,
      }}
    >
      {isWin && <Confetti bounty={isBounty} />}

      {/* Top strip */}
      <div
        className="px-5 py-2 border-b border-[var(--color-hairline-2)] flex items-center justify-between"
        style={{
          background: `linear-gradient(90deg, ${accent}14 0%, transparent 60%)`,
        }}
      >
        <span className="t-micro text-[var(--color-ink-dim)]">
          Round {round.id} · Verdict
        </span>
        <span className="t-micro" style={{ color: accent }}>
          {meta.short}
        </span>
      </div>

      {/* Headline zone */}
      <div
        className={`relative px-5 py-8 sm:py-10 text-center ${
          isWin ? "zoom-punch" : ""
        }`}
      >
        <h3
          className="t-display leading-[0.88]"
          style={{
            fontSize: "clamp(2.6rem, 9vw, 5rem)",
            color: "#fff",
            letterSpacing: "-0.01em",
            textShadow: `0 0 14px ${accent}, 0 0 32px ${accent}`,
          }}
        >
          {verdictWord}.
        </h3>

        <p
          className="mt-4 max-w-[46ch] mx-auto text-[14px] sm:text-[16px] leading-[1.45] italic"
          style={{
            fontFamily: "var(--font-serif)",
            color: "var(--color-ink-dim)",
          }}
        >
          {meta.blurb}
        </p>

        {pointsEarned > 0 && (
          <div className="mt-5 inline-flex items-baseline gap-2">
            <span className="t-label text-[var(--color-ink-faint)]">+ Earned</span>
            <span
              className="t-display text-[40px] sm:text-[52px] leading-none"
              style={{
                color: "#fff",
                textShadow: `0 0 14px ${accent}, 0 0 28px ${accent}`,
              }}
            >
              {counter}
            </span>
            <span className="t-label" style={{ color: accent }}>
              pts
            </span>
          </div>
        )}
      </div>

      {/* Closest-you-got meter — on non-wins */}
      {!isWin && (
        <div
          className="px-5 py-4 border-y border-[var(--color-hairline-2)]"
          style={{ background: "var(--color-bg-3)" }}
        >
          <div className="flex items-baseline justify-between mb-2">
            <span className="t-label text-[var(--color-ink-dim)]">
              How close you got
              {improved && (
                <span
                  className="ml-2 t-micro"
                  style={{ color: "var(--color-cyan)" }}
                >
                  ★ New best
                </span>
              )}
            </span>
            <span
              className="t-display text-[22px] sm:text-[26px] leading-none"
              style={{
                color: "#fff",
                textShadow: "0 0 10px rgba(95, 240, 255, 0.45)",
              }}
            >
              {proximityPct}%
            </span>
          </div>
          <div className="h-1.5 bg-[var(--color-hairline)] relative overflow-hidden">
            <div
              className="absolute inset-y-0 left-0 transition-all duration-1000 ease-out"
              style={{
                width: `${proximityPct}%`,
                background:
                  "linear-gradient(90deg, var(--color-pink) 0%, var(--color-cyan) 100%)",
                boxShadow: "0 0 8px rgba(95, 240, 255, 0.5)",
              }}
            />
          </div>
          <p
            className="mt-2 text-[12px] sm:text-[13px] italic text-[var(--color-ink-faint)] leading-[1.4]"
            style={{ fontFamily: "var(--font-serif)" }}
          >
            {isDraw
              ? "Tex escalated for human review. One more tweak could push this over the line."
              : "You scored above floor. Rewrite and target the weakest link you spotted."}
          </p>
        </div>
      )}

      {/* BOUNTY CTA — on R7 PERMIT */}
      {isBounty && (
        <div
          className="mx-5 my-4 border p-4 text-center"
          style={{
            borderColor: "var(--color-gold)",
            background:
              "linear-gradient(135deg, rgba(245, 185, 61, 0.14) 0%, rgba(245, 185, 61, 0.04) 100%)",
            boxShadow: "0 0 20px rgba(245, 185, 61, 0.25)",
            borderRadius: "2px",
          }}
        >
          <div className="t-micro mb-1.5" style={{ color: "var(--color-gold)" }}>
            ★ ${BOUNTY_AMOUNT} Bounty Triggered ★
          </div>
          <p className="text-[13px] sm:text-[14px] text-[var(--color-ink)] leading-[1.5] mb-3">
            You beat <span className="font-bold">The Warden</span>. If a human
            reviewer confirms the submission is genuinely malicious, we send
            you a ${BOUNTY_AMOUNT} Starbucks gift card.
          </p>
          <button
            onClick={onClaimBounty}
            className="chip-gold inline-flex items-center gap-2"
            style={{ fontSize: "12px", padding: "0.65rem 1.25rem" }}
          >
            Claim your ${BOUNTY_AMOUNT}{" "}
            <ArrowUpRight className="w-4 h-4" strokeWidth={2.5} />
          </button>
        </div>
      )}

      {/* ────── PRODUCTION IMPACT ────── */}
      {!isWin && round.productionImpact && (
        <ProductionImpact
          impact={round.productionImpact}
          accent={isDraw ? "var(--color-gold)" : "var(--color-red)"}
        />
      )}

      {/* ────── ASI FINDINGS — the main event ────── */}
      <AsiFindingsSection
        findings={sortedFindings}
        verdict={decision.verdict}
        round={round}
      />

      {/* Tex's reasoning — kept, demoted */}
      {decision.router?.reasons && decision.router.reasons.length > 0 && (
        <details className="border-b border-[var(--color-hairline-2)] group">
          <summary
            className="px-5 py-3 flex items-center justify-between cursor-pointer list-none"
            style={{ background: "var(--color-bg-3)" }}
          >
            <div className="flex items-center gap-2">
              <span
                className="t-micro"
                style={{ color: "var(--color-pink)" }}
              >
                Tex's router reasons
              </span>
              <span className="t-micro text-[var(--color-ink-faint)]">
                · {decision.router.reasons.length}
              </span>
            </div>
            <ChevronDown
              className="w-3.5 h-3.5 text-[var(--color-ink-faint)] transition-transform group-open:rotate-180"
              strokeWidth={2}
            />
          </summary>
          <div className="px-5 py-3 border-t border-[var(--color-hairline)]">
            <ul className="space-y-2">
              {decision.router.reasons.map((r, i) => (
                <li
                  key={i}
                  className="text-[13px] leading-[1.5] text-[var(--color-ink)] flex gap-2.5"
                >
                  <span
                    className="font-mono text-[11px] flex-shrink-0 pt-0.5"
                    style={{ color: "var(--color-cyan)" }}
                  >
                    ›
                  </span>
                  <span>{r}</span>
                </li>
              ))}
            </ul>
          </div>
        </details>
      )}

      {/* Layer scores — collapsible, insider view */}
      <details className="border-b border-[var(--color-hairline-2)] group">
        <summary
          className="px-5 py-3 flex items-center justify-between cursor-pointer list-none"
          style={{ background: "var(--color-bg-3)" }}
        >
          <span className="t-micro text-[var(--color-ink-dim)]">
            Layer scores
          </span>
          <ChevronDown
            className="w-3.5 h-3.5 text-[var(--color-ink-faint)] transition-transform group-open:rotate-180"
            strokeWidth={2}
          />
        </summary>
        <div className="grid grid-cols-4">
          <LayerCell
            label="Determin."
            score={decision.router?.layer_scores?.deterministic}
          />
          <LayerCell
            label="Special."
            score={decision.router?.layer_scores?.specialists}
          />
          <LayerCell
            label="Semantic"
            score={decision.router?.layer_scores?.semantic}
          />
          <LayerCell
            label="Critical."
            score={decision.router?.layer_scores?.criticality}
          />
        </div>
      </details>

      {/* ────── DECISION TRAIL — the compliance artifact ────── */}
      <DecisionTrail decision={decision} />

      {/* ACTION ROW */}
      <div className="grid grid-cols-3">
        {!isWin && (
          <button
            onClick={onTryAgain}
            className="col-span-3 inline-flex items-center justify-center gap-2 py-4 transition-colors"
            style={{
              background: "var(--color-pink)",
              color: "#fff",
              fontFamily: "var(--font-display)",
              fontSize: "20px",
              letterSpacing: "0.04em",
              textTransform: "uppercase",
            }}
            onMouseOver={(e) =>
              (e.currentTarget.style.background = "var(--color-pink-deep)")
            }
            onMouseOut={(e) =>
              (e.currentTarget.style.background = "var(--color-pink)")
            }
          >
            <Zap className="w-4 h-4" strokeWidth={2.5} />
            Try again
          </button>
        )}
        {isWin && (
          <>
            <button
              onClick={onShare}
              className="inline-flex items-center justify-center gap-2 py-3.5 border-r border-[var(--color-hairline-2)] t-label text-[var(--color-ink-dim)] hover:text-[var(--color-ink)] hover:bg-[var(--color-bg-3)] transition-colors"
            >
              <Share2 className="w-3.5 h-3.5" />
              Share
            </button>
            <button
              onClick={onOpenDojo}
              className="inline-flex items-center justify-center gap-2 py-3.5 border-r border-[var(--color-hairline-2)] t-label text-[var(--color-ink-dim)] hover:text-[var(--color-ink)] hover:bg-[var(--color-bg-3)] transition-colors"
            >
              <BookOpen className="w-3.5 h-3.5" />
              Dojo
            </button>
            <button
              onClick={onNextRound}
              disabled={isLastRound}
              className="inline-flex items-center justify-center gap-2 py-3.5 transition-all disabled:cursor-not-allowed"
              style={{
                background: isLastRound
                  ? "var(--color-bg-3)"
                  : "var(--color-cyan)",
                color: isLastRound
                  ? "var(--color-ink-faint)"
                  : "var(--color-bg)",
                fontFamily: "var(--font-display)",
                fontSize: "15px",
                letterSpacing: "0.04em",
                textTransform: "uppercase",
              }}
            >
              <Play className="w-3.5 h-3.5" />
              {isLastRound ? "Finale" : "Next round"}
            </button>
          </>
        )}
      </div>
    </section>
  );
}

/* ──────────────────────────────────────────────────────────────────────
   PRODUCTION IMPACT
   One sentence. This is the line a CISO screenshots.
   ────────────────────────────────────────────────────────────────────── */

function ProductionImpact({ impact, accent }) {
  return (
    <div
      className="px-5 py-4 border-b border-[var(--color-hairline-2)]"
      style={{
        background: `linear-gradient(180deg, ${accent}0A 0%, transparent 100%)`,
      }}
    >
      <div className="flex items-start gap-3">
        <div
          className="flex-shrink-0 mt-0.5 p-1.5 border"
          style={{
            borderColor: accent,
            color: accent,
            background: `${accent}14`,
          }}
        >
          <Shield className="w-3.5 h-3.5" strokeWidth={2.5} />
        </div>
        <div>
          <div
            className="t-micro mb-1"
            style={{ color: accent, letterSpacing: "0.18em" }}
          >
            In production, this would have…
          </div>
          <p
            className="text-[14px] sm:text-[15px] leading-[1.5] text-[var(--color-ink)]"
            style={{ fontFamily: "var(--font-serif)" }}
          >
            {impact}
          </p>
        </div>
      </div>
    </div>
  );
}

/* ──────────────────────────────────────────────────────────────────────
   ASI FINDINGS SECTION
   The centerpiece. One card per category. Expandable counterfactuals.
   ────────────────────────────────────────────────────────────────────── */

function AsiFindingsSection({ findings, verdict, round }) {
  const isWin = verdict === "PERMIT";

  if (isWin && findings.length === 0) {
    return (
      <div
        className="px-5 py-4 border-b border-[var(--color-hairline-2)] flex items-center gap-3"
        style={{ background: "var(--color-bg-3)" }}
      >
        <div
          className="p-1.5 border"
          style={{
            borderColor: "var(--color-permit)",
            background: "rgba(59, 224, 130, 0.08)",
            color: "var(--color-permit)",
          }}
        >
          <Check className="w-3.5 h-3.5" strokeWidth={2.5} />
        </div>
        <div>
          <div
            className="t-micro"
            style={{ color: "var(--color-permit)", letterSpacing: "0.18em" }}
          >
            Clean pass
          </div>
          <p
            className="mt-0.5 text-[13px] leading-[1.45] text-[var(--color-ink)]"
            style={{ fontFamily: "var(--font-serif)" }}
          >
            No OWASP ASI 2026 categories fired on your submission.
          </p>
        </div>
      </div>
    );
  }

  if (findings.length === 0) {
    return null;
  }

  return (
    <div className="px-5 py-4 border-b border-[var(--color-hairline-2)]">
      <div className="flex items-baseline justify-between mb-3">
        <div>
          <div
            className="t-micro"
            style={{ color: "var(--color-cyan)", letterSpacing: "0.18em" }}
          >
            How Tex knew
          </div>
          <p
            className="mt-0.5 text-[12px] text-[var(--color-ink-faint)] italic"
            style={{ fontFamily: "var(--font-serif)" }}
          >
            OWASP ASI 2026 categories that fired on your submission.
          </p>
        </div>
        <span className="t-micro text-[var(--color-ink-dim)]">
          {findings.length} finding{findings.length === 1 ? "" : "s"}
        </span>
      </div>
      <div className="space-y-2">
        {findings.map((f, i) => (
          <AsiFindingCard key={`${f.short_code}_${i}`} finding={f} />
        ))}
      </div>
    </div>
  );
}

function AsiFindingCard({ finding }) {
  const [open, setOpen] = useState(finding.verdict_influence === "decisive");

  const display = ASI_DISPLAY[finding.short_code] || {
    short: finding.short_code,
    title: finding.title,
    color: "var(--color-cyan)",
    blurb: finding.description,
  };
  const influence = ASI_INFLUENCE_STYLE[finding.verdict_influence] ||
    ASI_INFLUENCE_STYLE.informational;

  const severityPct = Math.round((finding.severity || 0) * 100);
  const confidencePct = Math.round((finding.confidence || 0) * 100);

  return (
    <div
      className="border transition-colors"
      style={{
        borderColor: influence.border,
        background: open ? influence.bg : "transparent",
      }}
    >
      {/* Header row */}
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full px-3.5 py-2.5 flex items-center gap-3 text-left hover:bg-[var(--color-bg-3)] transition-colors"
      >
        <span
          className="t-display text-[14px] leading-none flex-shrink-0"
          style={{ color: display.color, letterSpacing: "0.02em" }}
        >
          {display.short}
        </span>
        <span className="flex-1 text-[13px] sm:text-[14px] text-[var(--color-ink)] font-medium">
          {display.title}
        </span>
        <span
          className="t-micro flex-shrink-0 px-2 py-0.5 border"
          style={{
            color: influence.color,
            borderColor: influence.border,
            background: influence.bg,
            letterSpacing: "0.16em",
          }}
        >
          {influence.label}
        </span>
        {open ? (
          <ChevronUp className="w-3.5 h-3.5 text-[var(--color-ink-faint)]" />
        ) : (
          <ChevronDown className="w-3.5 h-3.5 text-[var(--color-ink-faint)]" />
        )}
      </button>

      {/* Body */}
      {open && (
        <div className="px-3.5 pb-3 pt-1 space-y-3">
          {/* Severity + confidence bars */}
          <div className="grid grid-cols-2 gap-3">
            <Meter
              label="Severity"
              pct={severityPct}
              color={influence.color}
            />
            <Meter
              label="Confidence"
              pct={confidencePct}
              color={influence.color}
            />
          </div>

          {/* Counterfactual — "Tex knew because…" */}
          {finding.counterfactual && (
            <div
              className="px-3 py-2 border-l-2"
              style={{
                borderLeftColor: display.color,
                background: "var(--color-bg-3)",
              }}
            >
              <div
                className="t-micro mb-1"
                style={{ color: display.color, letterSpacing: "0.16em" }}
              >
                Counterfactual
              </div>
              <p
                className="text-[12.5px] leading-[1.55] text-[var(--color-ink)]"
                style={{ fontFamily: "var(--font-serif)" }}
              >
                {finding.counterfactual}
              </p>
            </div>
          )}

          {/* Triggers list */}
          {finding.triggered_by && finding.triggered_by.length > 0 && (
            <div>
              <div className="t-micro mb-1.5 text-[var(--color-ink-faint)]">
                Triggered by · {finding.triggered_by.length}
              </div>
              <ul className="space-y-1.5">
                {finding.triggered_by.map((t, i) => (
                  <li
                    key={i}
                    className="text-[12px] leading-[1.5] text-[var(--color-ink-dim)] flex gap-2"
                  >
                    <span
                      className="font-mono flex-shrink-0"
                      style={{ color: display.color }}
                    >
                      {sourceLabel(t.source)}
                    </span>
                    <span className="text-[var(--color-ink)]">
                      <span className="font-mono text-[11px]">
                        {t.signal_name}
                      </span>{" "}
                      <span className="text-[var(--color-ink-faint)]">
                        ({(t.score || 0).toFixed(2)})
                      </span>
                      {t.evidence_excerpt && (
                        <span
                          className="block mt-0.5 italic text-[var(--color-ink-faint)]"
                          style={{ fontFamily: "var(--font-serif)" }}
                        >
                          "{t.evidence_excerpt}"
                        </span>
                      )}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Category description */}
          <p
            className="text-[12px] italic text-[var(--color-ink-faint)] leading-[1.5]"
            style={{ fontFamily: "var(--font-serif)" }}
          >
            {display.blurb}
          </p>
        </div>
      )}
    </div>
  );
}

function sourceLabel(source) {
  if (source === "semantic_dimension") return "SEM";
  if (source === "deterministic_recognizer") return "DET";
  if (source === "specialist") return "SPC";
  return "?";
}

function Meter({ label, pct, color }) {
  return (
    <div>
      <div className="flex items-baseline justify-between mb-1">
        <span className="t-micro text-[var(--color-ink-faint)]">{label}</span>
        <span
          className="font-mono text-[11px]"
          style={{ color }}
        >
          {pct}
        </span>
      </div>
      <div className="h-1 bg-[var(--color-hairline)] relative overflow-hidden">
        <div
          className="absolute inset-y-0 left-0"
          style={{
            width: `${pct}%`,
            background: color,
            boxShadow: `0 0 4px ${color}`,
          }}
        />
      </div>
    </div>
  );
}

/* ──────────────────────────────────────────────────────────────────────
   DECISION TRAIL
   Determinism fingerprint, latency breakdown, policy, bundle, replay.
   This is the compliance artifact. It also just happens to be the
   thing that makes Tex feel real to a buyer.
   ────────────────────────────────────────────────────────────────────── */

function DecisionTrail({ decision }) {
  const [copied, setCopied] = useState(false);
  const fingerprint = decision.determinism_fingerprint || "";
  const shortFp = fingerprint ? fingerprint.slice(0, 16) : "—";

  const latency = decision.latency;
  const totalMs = latency ? latency.total_ms : decision.elapsed_ms;
  const dominantStage = latency ? latency.dominant_stage : null;
  const dominantMs = latency && dominantStage ? latency[`${dominantStage}_ms`] : null;

  const policyVersion = decision.policy_version || "default-v1";
  const bundleUrl = decision.evidence_bundle_url;
  const replayUrl = decision.replay_url;
  const decisionId = decision.decision_id;

  const copyFingerprint = () => {
    if (!fingerprint) return;
    try {
      navigator.clipboard?.writeText(fingerprint);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {}
  };

  return (
    <div
      className="border-b border-[var(--color-hairline-2)]"
      style={{ background: "var(--color-bg-3)" }}
    >
      {/* Label row */}
      <div className="px-5 pt-3 pb-2 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity
            className="w-3 h-3"
            style={{ color: "var(--color-cyan)" }}
            strokeWidth={2.5}
          />
          <span
            className="t-micro"
            style={{ color: "var(--color-cyan)", letterSpacing: "0.18em" }}
          >
            Decision trail
          </span>
        </div>
        {decisionId && (
          <span className="t-micro font-mono text-[var(--color-ink-faint)]">
            {decisionId.slice(0, 8)}
          </span>
        )}
      </div>

      {/* Stat grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 border-t border-[var(--color-hairline)]">
        <TrailCell
          label="Latency"
          value={totalMs != null ? `${Number(totalMs).toFixed(2)}ms` : "—"}
          sub={
            dominantStage
              ? `${dominantStage} dominated${
                  dominantMs != null ? ` · ${Number(dominantMs).toFixed(2)}ms` : ""
                }`
              : null
          }
        />
        <TrailCell
          label="Confidence"
          value={formatPercent(decision.confidence, 0)}
          sub={`final ${(decision.final_score || 0).toFixed(2)}`}
        />
        <TrailCell
          label="Policy"
          value={policyVersion}
          mono
          sub={policyVersion === "strict-v1" ? "Warden mode" : "Default"}
        />
        <TrailCell
          label="Fingerprint"
          value={shortFp}
          mono
          sub={
            fingerprint ? (
              <button
                onClick={copyFingerprint}
                className="inline-flex items-center gap-1 text-[10px] hover:text-[var(--color-ink)] transition-colors"
                style={{ color: "var(--color-ink-faint)" }}
              >
                {copied ? (
                  <>
                    <Check className="w-2.5 h-2.5" /> copied
                  </>
                ) : (
                  <>
                    <Copy className="w-2.5 h-2.5" /> copy full
                  </>
                )}
              </button>
            ) : (
              "unavailable"
            )
          }
        />
      </div>

      {/* Link strip */}
      {(bundleUrl || replayUrl) && (
        <div className="grid grid-cols-2 border-t border-[var(--color-hairline)]">
          {bundleUrl && (
            <a
              href={bundleUrl}
              target="_blank"
              rel="noreferrer noopener"
              className="px-4 py-2.5 border-r border-[var(--color-hairline)] flex items-center justify-between gap-2 hover:bg-[var(--color-bg-2)] transition-colors"
            >
              <div className="flex items-center gap-2 min-w-0">
                <Download
                  className="w-3.5 h-3.5 flex-shrink-0"
                  style={{ color: "var(--color-cyan)" }}
                  strokeWidth={2.2}
                />
                <span className="t-label text-[var(--color-ink-dim)] truncate">
                  Evidence bundle
                </span>
              </div>
              <ExternalLink
                className="w-3 h-3 flex-shrink-0 text-[var(--color-ink-faint)]"
                strokeWidth={2}
              />
            </a>
          )}
          {replayUrl && (
            <a
              href={replayUrl}
              target="_blank"
              rel="noreferrer noopener"
              className="px-4 py-2.5 flex items-center justify-between gap-2 hover:bg-[var(--color-bg-2)] transition-colors"
            >
              <div className="flex items-center gap-2 min-w-0">
                <Play
                  className="w-3.5 h-3.5 flex-shrink-0"
                  style={{ color: "var(--color-pink)" }}
                  strokeWidth={2.2}
                />
                <span className="t-label text-[var(--color-ink-dim)] truncate">
                  Replay record
                </span>
              </div>
              <ExternalLink
                className="w-3 h-3 flex-shrink-0 text-[var(--color-ink-faint)]"
                strokeWidth={2}
              />
            </a>
          )}
        </div>
      )}
    </div>
  );
}

function TrailCell({ label, value, sub, mono }) {
  return (
    <div className="px-3 py-2.5 border-r border-[var(--color-hairline)] last:border-r-0">
      <div className="t-micro text-[var(--color-ink-faint)]">{label}</div>
      <div
        className={`leading-none mt-1 text-[var(--color-ink)] ${
          mono ? "text-[12px] font-mono" : "t-display text-[17px]"
        }`}
        style={mono ? { fontFamily: "var(--font-mono)" } : {}}
      >
        {value}
      </div>
      {sub && (
        <div
          className="mt-1 text-[10px] text-[var(--color-ink-faint)] leading-tight"
          style={{ fontFamily: "var(--font-mono)" }}
        >
          {sub}
        </div>
      )}
    </div>
  );
}

/* ──────────────────────────────────────────────────────────────────────
   Legacy sub-components
   ────────────────────────────────────────────────────────────────────── */

function LayerCell({ label, score }) {
  const pct = Math.round((typeof score === "number" ? score : 0) * 100);
  const hot = pct >= 50;
  const color = hot ? "var(--color-pink)" : "var(--color-cyan)";
  return (
    <div className="px-3 py-2.5 border-r border-[var(--color-hairline)] last:border-r-0">
      <div className="t-micro text-[var(--color-ink-faint)]">{label}</div>
      <div className="flex items-center justify-between mt-1">
        <span
          className="t-display text-[16px] leading-none"
          style={{ color: "#fff", textShadow: `0 0 6px ${color}` }}
        >
          {pct}
        </span>
      </div>
      <div className="h-[2px] bg-[var(--color-hairline)] mt-1.5 relative">
        <div
          className="absolute inset-y-0 left-0"
          style={{
            width: `${pct}%`,
            background: color,
            boxShadow: `0 0 4px ${color}`,
          }}
        />
      </div>
    </div>
  );
}

function Confetti({ bounty }) {
  const pieces = useMemo(() => {
    const count = bounty ? 54 : 32;
    const colors = bounty
      ? ["#f5b93d", "#5ff0ff", "#fce3a0", "#ff3d7a"]
      : ["#5ff0ff", "#3be082", "#f7f1e8"];
    return Array.from({ length: count }).map((_, i) => ({
      id: i,
      left: Math.random() * 100,
      color: colors[i % colors.length],
      delay: Math.random() * 0.8,
      duration: 1.8 + Math.random() * 1.8,
      size: 5 + Math.random() * 7,
      rotate: Math.random() * 360,
      horizSway: (Math.random() - 0.5) * 40,
    }));
  }, [bounty]);

  return (
    <div
      className="absolute inset-0 pointer-events-none overflow-hidden z-20"
      aria-hidden="true"
    >
      {pieces.map((p) => (
        <span
          key={p.id}
          style={{
            position: "absolute",
            top: "-10%",
            left: `${p.left}%`,
            width: `${p.size}px`,
            height: `${p.size * 0.6}px`,
            background: p.color,
            transform: `translateX(${p.horizSway}px) rotate(${p.rotate}deg)`,
            animation: `confetti-fall ${p.duration}s ${p.delay}s linear forwards`,
            boxShadow: `0 0 4px ${p.color}`,
            opacity: 0.9,
          }}
        />
      ))}
    </div>
  );
}
