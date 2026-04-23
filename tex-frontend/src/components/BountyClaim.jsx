import React, { useState } from "react";
import { X, Trophy, Mail, Copy, Check } from "lucide-react";
import { BOUNTY_AMOUNT } from "../lib/rounds";

/*
  BOUNTY CLAIM — v3 "First Challenger"
  ------------------------------------
  Shown when the player PERMITs Round 7 (The Warden). Gold-accented
  editorial modal with the email template pre-filled + mailto: link.
*/

export default function BountyClaim({ decision, submittedContent, onClose }) {
  const [copied, setCopied] = useState(false);

  const body = buildEmailBody({ decision, submittedContent });
  const subject = `TEX ARENA — $${BOUNTY_AMOUNT} BOUNTY CLAIM (req ${decision?.request_id?.slice(0, 8) || "unknown"})`;
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
        background: "radial-gradient(ellipse at center, rgba(10, 5, 7, 0.94) 0%, rgba(10, 5, 7, 0.98) 80%)",
        backdropFilter: "blur(16px)",
      }}
    >
      <div
        className="panel relative w-full max-w-[640px] max-h-[92vh] overflow-y-auto rise-in"
        onClick={(e) => e.stopPropagation()}
        style={{
          borderColor: "var(--color-gold)",
          boxShadow: "0 24px 80px rgba(0, 0, 0, 0.6), 0 0 0 1px var(--color-gold), 0 0 48px rgba(245, 185, 61, 0.3)",
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
            className="w-10 h-10 sm:w-12 sm:h-12 mx-auto mb-3 text-[var(--color-gold)]"
            style={{ filter: "drop-shadow(0 0 16px rgba(245, 185, 61, 0.5))" }}
            strokeWidth={1.5}
          />
          <div className="t-kicker text-[var(--color-cyan)] mb-2">
            First challenger in history
          </div>
          <h2
            className="t-display text-[40px] sm:text-[52px] leading-[0.88] text-[var(--color-ink)] mb-3"
            style={{
              letterSpacing: "-0.01em",
              textShadow: "0 0 16px rgba(245, 185, 61, 0.4), 0 0 36px rgba(245, 185, 61, 0.2)",
            }}
          >
            You beat Tex.
          </h2>
          <p
            className="text-[14px] sm:text-[16px] italic text-[var(--color-ink-dim)] max-w-[44ch] mx-auto leading-[1.4]"
            style={{ fontFamily: "var(--font-serif)" }}
          >
            You got malicious content past The Warden. Claim your ${BOUNTY_AMOUNT} Starbucks gift card below.
          </p>

          <div className="mt-4">
            <span className="chip-gold" style={{ fontSize: "12px" }}>
              ★ ${BOUNTY_AMOUNT} STARBUCKS · UNLOCKED ★
            </span>
          </div>
        </div>

        {/* Instructions */}
        <div className="px-6 sm:px-8 py-5 border-b border-[var(--color-hairline)]">
          <div className="t-micro text-[var(--color-gold)] mb-3">How to claim</div>
          <ol className="space-y-2.5">
            <ClaimStep n="1">
              Email your bypass to <span className="font-mono text-[var(--color-cyan)]">{to}</span>. The template below has the details we need.
            </ClaimStep>
            <ClaimStep n="2">
              I review it personally — usually within 24 hours. If it's a legit bypass (content a reasonable person would call malicious), I send a ${BOUNTY_AMOUNT} Starbucks e-gift.
            </ClaimStep>
            <ClaimStep n="3">
              If you're cool with it, I'll also post about the bypass so the community can learn from it. Totally optional.
            </ClaimStep>
          </ol>
        </div>

        {/* Email preview */}
        <div className="mx-5 sm:mx-8 my-5 border border-[var(--color-gold-deep)] bg-[var(--color-bg)]">
          <div className="flex items-center justify-between px-3 py-2 border-b border-[var(--color-gold-deep)]"
               style={{ background: "rgba(245, 185, 61, 0.08)" }}>
            <span className="t-micro text-[var(--color-gold)]">
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
          <pre className="p-3 font-mono text-[11px] leading-[1.55] text-[var(--color-ink-dim)] whitespace-pre-wrap break-words max-h-[200px] overflow-y-auto"
               style={{ fontFamily: "var(--font-mono)" }}>
            <span className="text-[var(--color-cyan)]">To:</span> {to}{"\n"}
            <span className="text-[var(--color-cyan)]">Subject:</span> {subject}{"\n\n"}
            {body}
          </pre>
        </div>

        {/* CTAs */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 px-5 sm:px-8 pb-6">
          <a
            href={mailto}
            className="chip-gold inline-flex items-center justify-center gap-2 py-3"
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

function ClaimStep({ n, children }) {
  return (
    <li className="flex gap-3 text-[13px] leading-[1.55] text-[var(--color-ink-dim)]">
      <span
        className="flex-shrink-0 w-5 h-5 flex items-center justify-center t-display text-[13px]"
        style={{
          border: "1px solid var(--color-gold)",
          color: "var(--color-gold)",
          borderRadius: "2px",
        }}
      >
        {n}
      </span>
      <span>{children}</span>
    </li>
  );
}

function buildEmailBody({ decision, submittedContent }) {
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

Starbucks email: <your_email_here>
Can I post about this publicly? <yes / no>

— [your name/handle]
`;
}
