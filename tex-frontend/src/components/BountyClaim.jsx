import React, { useState } from "react";
import { X, Trophy, Mail, Copy, Check, Award, Code } from "lucide-react";
import { symbolicBountyAmount } from "../lib/rounds";

/*
  BOUNTY CLAIM — v5 "THREE-TIER UNLOCK"
  ------------------------------------
  Shown when the player PERMITs Round 7. The old modal offered a $10
  Starbucks gift card. That attracted the wrong audience and was a
  financial liability.

  v5 structure:
   TIER 1 · HALL OF FAME     Permanent entry on texaegis.com
   TIER 2 · FOUNDING BYPASS  Signed PDF certificate
   TIER 3 · FOUNDERS' TIER   10K free API requests + direct Slack with
                              the founder

  The email template the modal generates is pre-filled so the winner
  auto-describes what they're building, which makes every Warden-beater
  a qualified inbound lead.
*/

export default function BountyClaim({
  decision,
  submittedContent,
  onClose,
  claimersSoFar = 0,
}) {
  const [copied, setCopied] = useState(false);

  const bountyNow = symbolicBountyAmount(claimersSoFar);
  const body = buildEmailBody({ decision, submittedContent, bountyNow });
  const subject = `TEX ARENA — WARDEN BYPASS · req ${decision?.request_id?.slice(0, 8) || "unknown"}`;
  const to = "matthew@vortexblack.ai";
  const mailto = `mailto:${to}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(`To: ${to}\nSubject: ${subject}\n\n${body}`);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {}
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 safe-top safe-bottom"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      style={{
        background: "radial-gradient(ellipse at center, rgba(6, 7, 20, 0.94) 0%, rgba(6, 7, 20, 0.98) 80%)",
        backdropFilter: "blur(16px)",
      }}
    >
      <div
        className="panel relative w-full max-w-[680px] max-h-[92vh] overflow-y-auto rise-in"
        onClick={(e) => e.stopPropagation()}
        style={{
          borderColor: "var(--color-yellow)",
          boxShadow:
            "0 24px 80px rgba(0, 0, 0, 0.6), 0 0 0 1px var(--color-yellow), 0 0 64px rgba(255, 225, 74, 0.35), 0 0 120px rgba(255, 61, 122, 0.15)",
        }}
      >
        <button
          onClick={onClose}
          className="absolute top-3 right-3 z-20 p-1.5 text-[var(--color-ink-dim)] hover:text-[var(--color-ink)] transition-colors"
          aria-label="Close"
        >
          <X className="w-4 h-4" />
        </button>

        {/* Header */}
        <div className="px-6 sm:px-8 pt-8 pb-5 text-center border-b border-[var(--color-hairline)]">
          <Trophy
            className="w-10 h-10 sm:w-12 sm:h-12 mx-auto mb-3 text-[var(--color-yellow)]"
            style={{ filter: "drop-shadow(0 0 20px rgba(255, 225, 74, 0.6))" }}
            strokeWidth={1.5}
          />
          <div className="t-kicker text-[var(--color-cyan)] mb-2">
            First challenger in history
          </div>
          <h2
            className="t-display text-[40px] sm:text-[56px] leading-[0.88] text-[var(--color-ink)] mb-3 neon-flicker"
            style={{
              letterSpacing: "-0.01em",
              textShadow: "0 0 20px rgba(255, 225, 74, 0.5), 0 0 44px rgba(255, 225, 74, 0.25)",
            }}
          >
            You beat Tex.
          </h2>
          <p
            className="text-[14px] sm:text-[16px] italic text-[var(--color-ink-dim)] max-w-[48ch] mx-auto leading-[1.45]"
            style={{ fontFamily: "var(--font-serif)" }}
          >
            You got malicious content past The Warden running the strictest policy.
            Claim your three-part unlock below.
          </p>
        </div>

        {/* THREE-TIER REWARD GRID */}
        <div className="px-5 sm:px-8 py-5 border-b border-[var(--color-hairline)]">
          <div className="t-micro text-[var(--color-yellow)] mb-3">Your Unlock</div>
          <div className="grid grid-cols-1 gap-2.5">
            <RewardTier
              icon={<Trophy className="w-4 h-4" strokeWidth={2.2} />}
              color="var(--color-yellow)"
              rgb="255, 225, 74"
              title="HALL OF FAME"
              subtitle="Permanent public entry at texaegis.com"
              body="Your handle, attack excerpt, timestamp, and request ID go on the public wall. Permanent. LinkedIn-ready."
            />
            <RewardTier
              icon={<Award className="w-4 h-4" strokeWidth={2.2} />}
              color="var(--color-pink)"
              rgb="255, 61, 122"
              title="FOUNDING BYPASS CERT"
              subtitle="Signed PDF — evidence hash + date"
              body="A formal certificate I personally sign. Frame it, post it, or just keep it. Numbered and dated."
            />
            <RewardTier
              icon={<Code className="w-4 h-4" strokeWidth={2.2} />}
              color="var(--color-cyan)"
              rgb="95, 240, 255"
              title="FOUNDERS' TIER ACCESS"
              subtitle="10,000 free Tex API requests + direct Slack"
              body="Integrate Tex into your own stack. I onboard you personally. The winner's bypass becomes a test case in our eval suite."
            />
          </div>
          <p
            className="mt-4 text-[12px] italic text-[var(--color-ink-faint)] text-center"
            style={{ fontFamily: "var(--font-serif)" }}
          >
            Current symbolic bounty pot: <span style={{ color: "var(--color-yellow)" }}>${bountyNow}</span> · doubles per confirmed bypass.
          </p>
        </div>

        {/* Instructions */}
        <div className="px-6 sm:px-8 py-5 border-b border-[var(--color-hairline)]">
          <div className="t-micro text-[var(--color-cyan)] mb-3">How to claim</div>
          <ol className="space-y-2.5">
            <ClaimStep n="1">
              Email the details to <span className="font-mono text-[var(--color-cyan)]">{to}</span>.
              The template below is pre-filled with the evidence we need.
            </ClaimStep>
            <ClaimStep n="2">
              I personally review within 24 hours. If it's a genuine bypass, you get
              all three unlocks.
            </ClaimStep>
            <ClaimStep n="3">
              If you're OK with it, I'll also post your bypass as a case study so
              the community learns from it. Totally optional.
            </ClaimStep>
          </ol>
        </div>

        {/* Email preview */}
        <div className="mx-5 sm:mx-8 my-5 border border-[var(--color-yellow-deep)] bg-[var(--color-bg)]">
          <div
            className="flex items-center justify-between px-3 py-2 border-b border-[var(--color-yellow-deep)]"
            style={{ background: "rgba(255, 225, 74, 0.08)" }}
          >
            <span className="t-micro text-[var(--color-yellow)]">
              Email template · pre-filled
            </span>
            <button
              onClick={copy}
              className="inline-flex items-center gap-1.5 t-micro text-[var(--color-ink-dim)] hover:text-[var(--color-cyan)] transition-colors"
            >
              {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
          <pre
            className="p-3 font-mono text-[11px] leading-[1.55] text-[var(--color-ink-dim)] whitespace-pre-wrap break-words max-h-[220px] overflow-y-auto"
            style={{ fontFamily: "var(--font-mono)" }}
          >
            <span className="text-[var(--color-cyan)]">To:</span> {to}{"\n"}
            <span className="text-[var(--color-cyan)]">Subject:</span> {subject}{"\n\n"}
            {body}
          </pre>
        </div>

        {/* CTAs */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 px-5 sm:px-8 pb-6">
          <a
            href={mailto}
            className="chip-yellow inline-flex items-center justify-center gap-2 py-3"
            style={{ fontSize: "13px", padding: "0.75rem 1rem" }}
          >
            <Mail className="w-4 h-4" strokeWidth={2} />
            Open in email
          </a>
          <button
            onClick={copy}
            className="inline-flex items-center justify-center gap-2 py-3 transition-all"
            style={{
              background: "var(--color-cyan)",
              color: "var(--color-bg)",
              fontFamily: "var(--font-mono)",
              fontSize: "11px",
              fontWeight: 700,
              letterSpacing: "0.2em",
              textTransform: "uppercase",
              borderRadius: "2px",
              boxShadow: "0 0 24px rgba(95, 240, 255, 0.35)",
            }}
          >
            {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            {copied ? "Copied" : "Copy template"}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function RewardTier({ icon, color, rgb, title, subtitle, body }) {
  return (
    <div
      className="flex gap-3 p-3 border transition-colors"
      style={{
        borderColor: `rgba(${rgb}, 0.4)`,
        background: `linear-gradient(90deg, rgba(${rgb}, 0.08) 0%, transparent 70%)`,
        borderRadius: "2px",
      }}
    >
      <div
        className="flex-shrink-0 mt-0.5 p-1.5 border"
        style={{
          borderColor: color,
          color,
          background: `rgba(${rgb}, 0.12)`,
        }}
      >
        {icon}
      </div>
      <div>
        <div
          className="t-micro font-bold"
          style={{ color, letterSpacing: "0.18em" }}
        >
          {title}
        </div>
        <div className="text-[12px] text-[var(--color-ink-dim)] mt-0.5 mb-1">
          {subtitle}
        </div>
        <p
          className="text-[12.5px] leading-[1.45] text-[var(--color-ink-dim)]"
          style={{ fontFamily: "var(--font-serif)" }}
        >
          {body}
        </p>
      </div>
    </div>
  );
}

function ClaimStep({ n, children }) {
  return (
    <li className="flex gap-3 text-[13px] leading-[1.55] text-[var(--color-ink-dim)]">
      <span
        className="flex-shrink-0 w-5 h-5 flex items-center justify-center t-display text-[13px]"
        style={{
          border: "1px solid var(--color-cyan)",
          color: "var(--color-cyan)",
          borderRadius: "2px",
        }}
      >
        {n}
      </span>
      <span>{children}</span>
    </li>
  );
}

function buildEmailBody({ decision, submittedContent, bountyNow }) {
  const rid = decision?.request_id || "—";
  const hash = decision?.evidence?.evidence_hash || "—";
  const conf = decision?.confidence ? Math.round(decision.confidence * 100) + "%" : "—";

  return `Matthew —

I beat The Warden. Here are the details:

REQUEST ID: ${rid}
EVIDENCE HASH: ${hash}
CONFIDENCE: ${conf}
POLICY: ${decision?.policy_version || "—"}

MY SUBMISSION:
---
${submittedContent}
---

HANDLE / NAME: <your handle or full name>
EMAIL FOR HALL OF FAME: <where to send the certificate>
WHAT I'M BUILDING (so you know what to provision for the API trial):
<1-2 sentences about your agent or use case>

OK TO POST PUBLICLY AS A CASE STUDY? <yes / no>

Current symbolic bounty pot: $${bountyNow}.

— [your name/handle]
`;
}
