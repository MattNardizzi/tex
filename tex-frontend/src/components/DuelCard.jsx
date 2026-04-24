import React, { useEffect, useRef, useState } from "react";
import { X, Copy, Download, Share2, Check, Zap } from "lucide-react";
import { tierFor } from "../lib/scoring.js";
import { BOUNTY_CASE_ID } from "../lib/cases.js";

/*
  DuelCard v7 — "Case-file poster"
  ────────────────────────────────
  The share artifact. Renders as a 1200x630 PNG that looks like an
  intercepted case-file / wanted poster with:
    • The agent name (big)
    • "CAUGHT BY @handle IN XXms"
    • Tier badge
    • Dare line at bottom

  When a friend clicks the duel link, they land on that exact case
  with a banner showing your time. If they beat it, they can send a
  counter-dare back.

  Design: heavy grunge case-file aesthetic — pink accent, mono font
  for meta, display font for big numbers. Feels like something you'd
  actually want to screenshot and share.
*/

export default function DuelCard({ caseDef, outcome, player, onClose }) {
  const canvasRef = useRef(null);
  const [copiedLink, setCopiedLink] = useState(false);
  const [copiedImg, setCopiedImg] = useState(false);

  const handle = (player?.handle || "anonymous").replace(/^@/, "");
  const ms = outcome?.catchMs ?? 0;
  const qUsed = outcome?.questionsUsed ?? 3;
  const verdict = outcome?.verdict || "FORBID";
  const cleared = player?.clearedCaseIds?.length || 0;
  const bountyCaught = player?.clearedCaseIds?.includes(BOUNTY_CASE_ID);
  const tier = tierFor(cleared, bountyCaught).current;

  const duelUrl = buildDuelUrl({ caseId: caseDef.id, handle, ms });
  const shareText = buildShareText({ caseName: caseDef.name, ms, qUsed, handle, duelUrl, tier });

  useEffect(() => {
    drawPoster(canvasRef.current, { caseDef, handle, ms, qUsed, verdict, tier });
  }, [caseDef, handle, ms, qUsed, verdict, tier]);

  async function copyLink() {
    try {
      await navigator.clipboard.writeText(shareText);
      setCopiedLink(true);
      setTimeout(() => setCopiedLink(false), 2000);
    } catch {}
  }

  async function copyImage() {
    try {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const blob = await new Promise((r) => canvas.toBlob(r, "image/png"));
      if (!blob) return;
      await navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]);
      setCopiedImg(true);
      setTimeout(() => setCopiedImg(false), 2000);
    } catch {
      downloadImage();
    }
  }

  function downloadImage() {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const link = document.createElement("a");
    link.download = `tex-duel-${caseDef.id}-${handle}.png`;
    link.href = canvas.toDataURL("image/png");
    link.click();
  }

  async function nativeShare() {
    if (!navigator.share) { copyLink(); return; }
    try {
      await navigator.share({
        title: "Tex Arena — Duel",
        text: shareText,
        url: duelUrl,
      });
    } catch {}
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 overflow-y-auto"
      style={{ background: "rgba(6, 7, 20, 0.90)", backdropFilter: "blur(8px)" }}
      onClick={onClose}
    >
      <div
        className="relative panel w-full max-w-[620px] overflow-hidden rise-in my-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-4 sm:px-5 py-3 border-b border-[var(--color-hairline-2)] flex items-center justify-between">
          <div>
            <div className="t-kicker text-[var(--color-pink)]">CHALLENGE A FRIEND</div>
            <div className="t-micro text-[var(--color-ink-faint)] mt-0.5 italic" style={{ fontFamily: "var(--font-serif)" }}>
              Not a score brag — a dare they can accept.
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 text-[var(--color-ink-faint)] hover:text-[var(--color-ink)]" aria-label="Close">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-4 sm:p-5">
          <div className="rounded-sm overflow-hidden" style={{ border: "1px solid var(--color-hairline-2)" }}>
            <canvas
              ref={canvasRef}
              width={1200}
              height={630}
              style={{ width: "100%", height: "auto", display: "block" }}
            />
          </div>

          <div className="mt-3 panel px-3 py-2.5" style={{ background: "rgba(6,7,20,0.6)" }}>
            <div className="t-micro text-[var(--color-ink-faint)] mb-1">WHAT THEY'LL SEE</div>
            <pre
              className="text-[11px] sm:text-[12px] leading-[1.5] text-[var(--color-ink)] whitespace-pre-wrap break-words"
              style={{ fontFamily: "var(--font-mono)" }}
            >
              {shareText}
            </pre>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-2">
            <button onClick={copyLink} className="btn-primary text-[13px] px-4 py-2 inline-flex items-center gap-1.5">
              {copiedLink ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              {copiedLink ? "COPIED" : "COPY DARE TEXT"}
            </button>
            <button onClick={copyImage} className="btn-ghost text-[13px] inline-flex items-center gap-1.5">
              {copiedImg ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
              {copiedImg ? "Image copied" : "Copy image"}
            </button>
            <button onClick={downloadImage} className="btn-ghost text-[13px] inline-flex items-center gap-1.5">
              <Download className="w-3 h-3" />
              Download
            </button>
            {typeof navigator !== "undefined" && navigator.share && (
              <button
                onClick={nativeShare}
                className="btn-ghost text-[13px] inline-flex items-center gap-1.5"
                style={{ color: "var(--color-pink)", borderColor: "var(--color-pink)" }}
              >
                <Share2 className="w-3 h-3" />
                Share
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

function buildDuelUrl({ caseId, handle, ms }) {
  if (typeof window === "undefined") return "";
  const base = `${window.location.origin}${window.location.pathname.replace(/\/$/, "")}`;
  const params = new URLSearchParams({ duel: String(caseId), from: handle, ms: String(ms) });
  return `${base}?${params.toString()}`;
}

function buildShareText({ caseName, ms, qUsed, handle, duelUrl, tier }) {
  return `I caught ${caseName} in ${ms}ms on Q${qUsed}.

Tex Arena · ${tier.name}
@${handle}

Your turn → ${duelUrl}`;
}

// ────────────────────────────────────────────────────────────────────
// Canvas — 1200x630 case-file poster
// ────────────────────────────────────────────────────────────────────

function drawPoster(canvas, { caseDef, handle, ms, qUsed, verdict, tier }) {
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  const W = canvas.width, H = canvas.height;

  // Deep bg
  ctx.fillStyle = "#060714";
  ctx.fillRect(0, 0, W, H);

  // Top-right cyan glow
  const g1 = ctx.createRadialGradient(W - 150, 150, 40, W - 150, 150, 500);
  g1.addColorStop(0, "rgba(95,240,255,0.22)");
  g1.addColorStop(1, "rgba(95,240,255,0)");
  ctx.fillStyle = g1;
  ctx.fillRect(0, 0, W, H);

  // Bottom-left pink glow
  const g2 = ctx.createRadialGradient(150, H - 100, 40, 150, H - 100, 520);
  g2.addColorStop(0, "rgba(255,61,122,0.2)");
  g2.addColorStop(1, "rgba(255,61,122,0)");
  ctx.fillStyle = g2;
  ctx.fillRect(0, 0, W, H);

  // Grid floor
  ctx.strokeStyle = "rgba(168,178,240,0.05)";
  ctx.lineWidth = 1;
  for (let y = 60; y < H; y += 36) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
  }

  // Top pink band, bottom cyan band
  ctx.fillStyle = "#ff3d7a"; ctx.fillRect(0, 0, W, 6);
  ctx.fillStyle = "#5ff0ff"; ctx.fillRect(0, H - 6, W, 6);

  // Corner label — CASE FILE
  ctx.fillStyle = "#ff3d7a";
  ctx.font = 'bold 22px "Anton", "Impact", sans-serif';
  ctx.textBaseline = "top";
  ctx.fillText(`CASE FILE · #${String(caseDef.id).padStart(3, "0")}`, 60, 44);

  // Top-right: TEX ARENA
  ctx.fillStyle = "#5ff0ff";
  ctx.font = 'bold 20px "Anton", "Impact", sans-serif';
  ctx.textAlign = "right";
  ctx.fillText("TEX ARENA", W - 60, 48);
  ctx.textAlign = "left";

  // Big label: CAUGHT
  ctx.fillStyle = "#f5f7ff";
  ctx.font = 'bold 58px "Anton", "Impact", sans-serif';
  ctx.fillText("CAUGHT", 60, 110);

  // Big: case name
  ctx.fillStyle = "#ff3d7a";
  ctx.font = 'bold 72px "Anton", "Impact", sans-serif';
  const caseName = caseDef.name.toUpperCase();
  wrapText(ctx, caseName, 60, 180, W - 120, 80);

  // Time block
  const timeY = 360;
  ctx.fillStyle = "#b8bce0";
  ctx.font = '22px "Inter Tight", sans-serif';
  ctx.fillText("IN", 60, timeY);

  const verdictColor = verdict === "FORBID" ? "#3bff9e" : "#ffe14a";
  ctx.fillStyle = verdictColor;
  ctx.font = 'bold 92px "Anton", "Impact", sans-serif';
  const msText = `${ms}ms`;
  ctx.fillText(msText, 110, timeY - 22);
  const msW = ctx.measureText(msText).width;

  ctx.fillStyle = "#8088b8";
  ctx.font = '20px "Inter Tight", sans-serif';
  ctx.fillText(`ON QUESTION ${qUsed}`, 120 + msW, timeY);

  // Dare line
  const dareY = 470;
  ctx.fillStyle = "#5ff0ff";
  ctx.font = 'bold 36px "Anton", "Impact", sans-serif';
  ctx.fillText("YOUR TURN.", 60, dareY);

  ctx.fillStyle = "#f5f7ff";
  ctx.font = 'italic 26px "Fraunces", "Georgia", serif';
  ctx.fillText("Beat my time.", 60, dareY + 52);

  // Bottom-left: handle + tier
  ctx.fillStyle = "#ff3d7a";
  ctx.font = 'bold 24px "Anton", "Impact", sans-serif';
  ctx.fillText(`@${handle}`, 60, H - 86);

  ctx.fillStyle = tier.color === "var(--color-yellow)" ? "#ffe14a"
    : tier.color === "var(--color-pink)" ? "#ff3d7a"
    : tier.color === "var(--color-violet)" ? "#a855f7"
    : tier.color === "var(--color-cyan)" ? "#5ff0ff"
    : "#b8bce0";
  ctx.font = '16px "Inter Tight", sans-serif';
  ctx.fillText(`${tier.name} · CLEARANCE ${tier.short}`, 60, H - 56);

  // Bottom-right: url
  ctx.fillStyle = "#8088b8";
  ctx.font = '18px "Inter Tight", sans-serif';
  ctx.textAlign = "right";
  ctx.fillText("texaegis.com · tex arena", W - 60, H - 56);
  ctx.textAlign = "left";

  // Verdict chip top-right
  const chipW = 180, chipH = 52, chipX = W - chipW - 60, chipY = 92;
  ctx.strokeStyle = verdictColor;
  ctx.lineWidth = 2;
  ctx.strokeRect(chipX, chipY, chipW, chipH);
  ctx.fillStyle = verdict === "FORBID" ? "rgba(59,255,158,0.14)" : "rgba(255,225,74,0.14)";
  ctx.fillRect(chipX, chipY, chipW, chipH);
  ctx.fillStyle = verdictColor;
  ctx.font = 'bold 24px "Anton", "Impact", sans-serif';
  ctx.textAlign = "center";
  ctx.fillText(verdict === "FORBID" ? "BLOCKED" : "ESCALATED", chipX + chipW / 2, chipY + 14);
  ctx.textAlign = "left";
}

function wrapText(ctx, text, x, y, maxWidth, lineHeight) {
  const words = text.split(" ");
  let line = "";
  let yy = y;
  for (let i = 0; i < words.length; i++) {
    const test = line + words[i] + " ";
    if (ctx.measureText(test).width > maxWidth && i > 0) {
      ctx.fillText(line.trim(), x, yy);
      line = words[i] + " ";
      yy += lineHeight;
    } else {
      line = test;
    }
  }
  ctx.fillText(line.trim(), x, yy);
}
