import React, { useEffect, useRef, useState } from "react";
import { X, Copy, Download, Share2, Check } from "lucide-react";

/*
  DuelCard — replaces ShareCard
  ─────────────────────────────
  Post-catch share artifact. Not a "score brag" — a dare.

  Renders a canvas PNG the player can download or copy, plus a shareable
  URL with ?duel=<caseId>&from=<handle>&ms=<catchMs>. When a friend
  opens that URL, the arena lands them on that case with a banner:
  "@matt caught Lena in 11ms. Beat that time."

  Design philosophy — the ask is specific, personal, and beatable:
    "I caught The Compliance Officer in 143ms. Your turn, @chris."
*/

export default function DuelCard({ caseDef, outcome, player, onClose }) {
  const canvasRef = useRef(null);
  const [copied, setCopied] = useState(false);
  const [copiedCard, setCopiedCard] = useState(false);

  const handle = (player?.handle || "anonymous").replace(/^@/, "");
  const ms = outcome?.catchMs ?? 0;
  const qUsed = outcome?.questionsUsed ?? 3;
  const verdict = outcome?.verdict || "FORBID";

  const duelUrl = buildDuelUrl({ caseId: caseDef.id, handle, ms });
  const shareText = buildShareText({ caseName: caseDef.name, ms, qUsed, handle, duelUrl });

  useEffect(() => {
    drawDuelCard(canvasRef.current, { caseDef, handle, ms, qUsed, verdict });
  }, [caseDef, handle, ms, qUsed, verdict]);

  async function copyLink() {
    try {
      await navigator.clipboard.writeText(shareText);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch { /* no-op */ }
  }

  async function copyCard() {
    try {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const blob = await new Promise((r) => canvas.toBlob(r, "image/png"));
      if (!blob) return;
      await navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]);
      setCopiedCard(true);
      setTimeout(() => setCopiedCard(false), 2000);
    } catch {
      // Fallback: download instead
      downloadCard();
    }
  }

  function downloadCard() {
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
        title: "Tex Arena Duel",
        text: shareText,
        url: duelUrl,
      });
    } catch { /* user cancelled */ }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "rgba(6, 7, 20, 0.85)", backdropFilter: "blur(6px)" }}
      onClick={onClose}
    >
      <div
        className="relative panel w-full max-w-[560px] overflow-hidden rise-in"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-4 sm:px-5 py-3 border-b border-[var(--color-hairline-2)] flex items-center justify-between">
          <div>
            <div className="t-kicker text-[var(--color-pink)]">DARE A FRIEND</div>
            <div className="t-micro text-[var(--color-ink-faint)] mt-0.5">
              Not a score brag. A time to beat.
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-[var(--color-ink-faint)] hover:text-[var(--color-ink)]"
            aria-label="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-4 sm:p-5">
          {/* Canvas preview */}
          <div
            className="rounded-sm overflow-hidden"
            style={{ border: "1px solid var(--color-hairline-2)" }}
          >
            <canvas
              ref={canvasRef}
              width={1200}
              height={630}
              style={{ width: "100%", height: "auto", display: "block" }}
            />
          </div>

          {/* Share text preview */}
          <div className="mt-3 panel px-3 py-2.5">
            <div className="t-micro text-[var(--color-ink-faint)] mb-1">SHARE MESSAGE</div>
            <pre
              className="text-[12px] leading-[1.5] text-[var(--color-ink)] whitespace-pre-wrap break-words"
              style={{ fontFamily: "var(--font-mono)" }}
            >
              {shareText}
            </pre>
          </div>

          {/* Actions */}
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <button
              onClick={copyLink}
              className="btn-primary text-[13px] px-4 py-2 inline-flex items-center gap-1.5"
            >
              {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? "COPIED" : "COPY DARE"}
            </button>
            <button
              onClick={copyCard}
              className="btn-ghost text-[13px] inline-flex items-center gap-1.5"
            >
              {copiedCard ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
              {copiedCard ? "Image copied" : "Copy image"}
            </button>
            <button
              onClick={downloadCard}
              className="btn-ghost text-[13px] inline-flex items-center gap-1.5"
            >
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

// ────────────────────────────────────────────────────────────────────────
//  URL + text builders
// ────────────────────────────────────────────────────────────────────────

function buildDuelUrl({ caseId, handle, ms }) {
  if (typeof window === "undefined") return "";
  const base = `${window.location.origin}${window.location.pathname.replace(/\/$/, "")}`;
  const params = new URLSearchParams({
    duel: String(caseId),
    from: handle,
    ms: String(ms),
  });
  return `${base}?${params.toString()}`;
}

function buildShareText({ caseName, ms, qUsed, handle, duelUrl }) {
  return `I used Tex to catch ${caseName} in ${ms}ms on Q${qUsed}.

Your turn. Beat my time: ${duelUrl}

@${handle} · Tex Arena · texaegis.com`;
}

// ────────────────────────────────────────────────────────────────────────
//  Canvas renderer — 1200x630 social share card
// ────────────────────────────────────────────────────────────────────────

function drawDuelCard(canvas, { caseDef, handle, ms, qUsed, verdict }) {
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const W = canvas.width;
  const H = canvas.height;

  // Background — deep indigo void
  ctx.fillStyle = "#060714";
  ctx.fillRect(0, 0, W, H);

  // Radial glow top-right (cyan Tex presence)
  const g1 = ctx.createRadialGradient(W - 200, 160, 40, W - 200, 160, 480);
  g1.addColorStop(0, "rgba(95, 240, 255, 0.22)");
  g1.addColorStop(1, "rgba(95, 240, 255, 0)");
  ctx.fillStyle = g1;
  ctx.fillRect(0, 0, W, H);

  // Radial glow bottom-left (pink player)
  const g2 = ctx.createRadialGradient(180, H - 100, 40, 180, H - 100, 500);
  g2.addColorStop(0, "rgba(255, 61, 122, 0.18)");
  g2.addColorStop(1, "rgba(255, 61, 122, 0)");
  ctx.fillStyle = g2;
  ctx.fillRect(0, 0, W, H);

  // Subtle grid floor
  ctx.strokeStyle = "rgba(168, 178, 240, 0.06)";
  ctx.lineWidth = 1;
  for (let y = 60; y < H; y += 40) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
  }
  for (let x = 60; x < W; x += 40) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
  }

  // Border — thin pink on top and bottom for the "marquee" feel
  ctx.fillStyle = "#ff3d7a"; ctx.fillRect(0, 0, W, 6);
  ctx.fillStyle = "#5ff0ff"; ctx.fillRect(0, H - 6, W, 6);

  // ─── Top row: TEX ARENA · DUEL ──────────────────────────────────────
  ctx.fillStyle = "#5ff0ff";
  ctx.font = 'bold 22px "Anton", "Impact", sans-serif';
  ctx.textBaseline = "top";
  ctx.letterSpacing = "4px";
  ctx.fillText("TEX ARENA · DUEL", 60, 44);

  // Case label
  ctx.fillStyle = "#8088b8";
  ctx.font = '20px "Inter Tight", sans-serif';
  ctx.fillText(`CASE #${String(caseDef.id).padStart(3, "0")}`, W - 280, 48);

  // ─── Big headline: the dare ─────────────────────────────────────────
  ctx.fillStyle = "#f5f7ff";
  ctx.font = 'bold 72px "Anton", "Impact", sans-serif';
  wrapText(ctx, "I CAUGHT", 60, 130, W - 120, 78);

  ctx.fillStyle = "#ff3d7a";
  ctx.font = 'bold 76px "Anton", "Impact", sans-serif';
  wrapText(ctx, caseDef.name.toUpperCase(), 60, 218, W - 120, 82);

  // ─── Time row ───────────────────────────────────────────────────────
  const timeY = 360;
  ctx.fillStyle = "#b8bce0";
  ctx.font = '22px "Inter Tight", sans-serif';
  ctx.fillText("IN", 60, timeY);

  const verdictColor = verdict === "FORBID" ? "#3bff9e" : "#ffe14a";
  ctx.fillStyle = verdictColor;
  ctx.font = 'bold 96px "Anton", "Impact", sans-serif';
  const msText = `${ms}ms`;
  ctx.fillText(msText, 110, timeY - 26);
  const msWidth = ctx.measureText(msText).width;

  ctx.fillStyle = "#b8bce0";
  ctx.font = '22px "Inter Tight", sans-serif';
  ctx.fillText(`on question ${qUsed}`, 120 + msWidth, timeY);

  // ─── The dare line ──────────────────────────────────────────────────
  const dareY = 470;
  ctx.fillStyle = "#5ff0ff";
  ctx.font = 'bold 34px "Anton", "Impact", sans-serif';
  ctx.fillText("YOUR TURN.", 60, dareY);

  ctx.fillStyle = "#f5f7ff";
  ctx.font = 'italic 28px "Fraunces", "Georgia", serif';
  ctx.fillText("Beat my time.", 60, dareY + 50);

  // ─── Bottom: handle + url ───────────────────────────────────────────
  ctx.fillStyle = "#ff3d7a";
  ctx.font = 'bold 22px "Anton", "Impact", sans-serif';
  ctx.fillText(`@${handle}`, 60, H - 70);

  ctx.fillStyle = "#8088b8";
  ctx.font = '20px "Inter Tight", sans-serif';
  const urlLabel = "texaegis.com · tex arena";
  const urlWidth = ctx.measureText(urlLabel).width;
  ctx.fillText(urlLabel, W - urlWidth - 60, H - 68);

  // ─── Verdict chip (top right) ───────────────────────────────────────
  const chipX = W - 240;
  const chipY = 88;
  const chipW = 180;
  const chipH = 48;
  ctx.strokeStyle = verdictColor;
  ctx.lineWidth = 2;
  ctx.strokeRect(chipX, chipY, chipW, chipH);
  ctx.fillStyle = verdict === "FORBID" ? "rgba(59,255,158,0.12)" : "rgba(255,225,74,0.12)";
  ctx.fillRect(chipX, chipY, chipW, chipH);
  ctx.fillStyle = verdictColor;
  ctx.font = 'bold 22px "Anton", "Impact", sans-serif';
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
