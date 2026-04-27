// ────────────────────────────────────────────────────────────────────
//  Share-Near-Miss Image Generator
//
//  This is the entire growth engine for the marketing surface.
//  Wordle's green/yellow/gray grid is the reference — distinct,
//  instantly readable, screenshot-ready.
//
//  Output: 1200×630 PNG (Twitter card / OG dimensions)
//  - Six layer tiles (filled red if fired, dark if dark)
//  - Stealth score as massive numeric headline
//  - Incident name + ASI tag
//  - Tex verdict
//  - texaegis.com URL
//
//  Returns a Blob you can download or copy to clipboard.
// ────────────────────────────────────────────────────────────────────

import { LAYER_LABELS } from "./stealthScore.js";

const W = 1200;
const H = 630;

const C = {
  bg0: "#06070E",
  bg1: "#0B0D1C",
  ink: "#E8E9F5",
  inkDim: "#A8AEC9",
  inkFaint: "#6B6F8F",
  cyan: "#5FF0FF",
  pink: "#FF3D7A",
  yellow: "#FFE14A",
  green: "#5FFA9F",
  red: "#FF4B4B",
  hairline: "rgba(168, 174, 201, 0.18)",
};

/**
 * Generate the share image.
 *
 * @param {object} args
 * @param {object} args.incident
 * @param {object} args.score   — output of computeRoundScore
 * @param {string} args.handle  — player handle, optional
 */
export async function generateShareImage({ incident, score, handle }) {
  const canvas = document.createElement("canvas");
  canvas.width = W;
  canvas.height = H;
  const ctx = canvas.getContext("2d");

  // Background
  ctx.fillStyle = C.bg0;
  ctx.fillRect(0, 0, W, H);

  // Pink corner glow
  const grad = ctx.createRadialGradient(W * 0.85, H * 1.1, 50, W * 0.85, H * 1.1, 600);
  grad.addColorStop(0, "rgba(255, 61, 122, 0.18)");
  grad.addColorStop(1, "rgba(255, 61, 122, 0)");
  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, W, H);

  // Cyan top-left glow
  const grad2 = ctx.createRadialGradient(120, -60, 30, 120, -60, 500);
  grad2.addColorStop(0, "rgba(95, 240, 255, 0.16)");
  grad2.addColorStop(1, "rgba(95, 240, 255, 0)");
  ctx.fillStyle = grad2;
  ctx.fillRect(0, 0, W, H);

  // Frame
  ctx.strokeStyle = C.hairline;
  ctx.lineWidth = 1;
  ctx.strokeRect(40, 40, W - 80, H - 80);

  // ── Header ───────────────────────────────────────────────────────
  ctx.font = "500 18px 'JetBrains Mono', monospace";
  ctx.fillStyle = C.cyan;
  ctx.textBaseline = "top";
  ctx.fillText("● TEX ARENA", 72, 72);

  ctx.fillStyle = C.inkFaint;
  ctx.font = "500 14px 'JetBrains Mono', monospace";
  ctx.fillText("OWASP ASI 2026", 72, 100);

  // Top-right: handle / texaegis.com
  ctx.textAlign = "right";
  ctx.font = "500 14px 'JetBrains Mono', monospace";
  ctx.fillStyle = C.inkDim;
  ctx.fillText("TEXAEGIS.COM", W - 72, 100);
  if (handle) {
    ctx.fillStyle = C.pink;
    ctx.font = "600 16px 'JetBrains Mono', monospace";
    ctx.fillText(`@${handle}`, W - 72, 72);
  }
  ctx.textAlign = "left";

  // ── Stealth Score (massive headline) ─────────────────────────────
  const scoreText = score.forfeit ? "FORFEIT" : String(score.total);
  ctx.font = "800 220px 'Anton', sans-serif";
  ctx.fillStyle = score.forfeit
    ? C.inkDim
    : score.verdict === "PERMIT"
    ? C.green
    : score.verdict === "ABSTAIN"
    ? C.yellow
    : C.pink;
  ctx.textBaseline = "alphabetic";
  ctx.fillText(scoreText, 72, 360);

  // Score subtitle
  ctx.font = "500 18px 'JetBrains Mono', monospace";
  ctx.fillStyle = C.inkFaint;
  ctx.fillText("STEALTH SCORE", 72, 392);

  // Stealth fraction (e.g. "0.84 stealth")
  if (!score.forfeit) {
    ctx.font = "600 22px 'JetBrains Mono', monospace";
    ctx.fillStyle = C.ink;
    const stealthLabel = `${(score.stealth * 100).toFixed(0)}% STEALTH · ${score.verdict}`;
    ctx.fillText(stealthLabel, 72, 425);
  }

  // ── Incident name ────────────────────────────────────────────────
  ctx.font = "800 56px 'Anton', sans-serif";
  ctx.fillStyle = C.ink;
  ctx.fillText(incident.name.toUpperCase(), 72, 500);

  // ASI codes + tier
  ctx.font = "500 16px 'JetBrains Mono', monospace";
  ctx.fillStyle = C.cyan;
  const tagLine =
    `TIER ${"I".repeat(incident.tier)} · ` +
    (incident.asi || []).join(" · ");
  ctx.fillText(tagLine, 72, 528);

  // ── Layer tiles (right side) ─────────────────────────────────────
  drawLayerGrid(ctx, score.profile || {}, score.forfeit);

  // ── Footer ───────────────────────────────────────────────────────
  ctx.font = "500 13px 'JetBrains Mono', monospace";
  ctx.fillStyle = C.inkFaint;
  ctx.textAlign = "left";
  ctx.fillText(
    "OWASP ASI 2026 ADJUDICATION BENCHMARK · LIVE PRODUCTION GATE",
    72,
    H - 60
  );

  return new Promise((resolve) => {
    canvas.toBlob((blob) => resolve(blob), "image/png", 0.95);
  });
}

function drawLayerGrid(ctx, profile, forfeit) {
  const layers = ["deterministic", "retrieval", "specialists", "semantic", "router"];
  const startX = 720;
  const startY = 200;
  const tileW = 200;
  const tileH = 56;
  const gap = 12;

  // Header
  ctx.font = "500 14px 'JetBrains Mono', monospace";
  ctx.fillStyle = C.inkFaint;
  ctx.textAlign = "left";
  ctx.fillText("TEX PIPELINE", startX, startY - 20);

  layers.forEach((layer, i) => {
    const y = startY + i * (tileH + gap);
    const fired = !forfeit && profile[layer];

    // Tile background
    if (fired) {
      ctx.fillStyle = "rgba(255, 75, 75, 0.18)";
      ctx.fillRect(startX, y, tileW, tileH);
      ctx.strokeStyle = C.red;
      ctx.lineWidth = 1.5;
      ctx.strokeRect(startX, y, tileW, tileH);
    } else {
      ctx.fillStyle = C.bg1;
      ctx.fillRect(startX, y, tileW, tileH);
      ctx.strokeStyle = C.hairline;
      ctx.lineWidth = 1;
      ctx.strokeRect(startX, y, tileW, tileH);
    }

    // Indicator dot
    ctx.beginPath();
    ctx.arc(startX + 18, y + tileH / 2, 5, 0, Math.PI * 2);
    ctx.fillStyle = fired ? C.red : C.inkFaint;
    ctx.fill();

    // Label
    ctx.font = "600 14px 'JetBrains Mono', monospace";
    ctx.fillStyle = fired ? C.red : C.ink;
    ctx.fillText(LAYER_LABELS[layer] || layer.toUpperCase(), startX + 36, y + 24);

    // Status
    ctx.font = "500 11px 'JetBrains Mono', monospace";
    ctx.fillStyle = fired ? C.red : C.inkFaint;
    ctx.fillText(fired ? "FIRED" : "DARK", startX + 36, y + 42);
  });
}

/** Trigger a download of the share image */
export async function downloadShareImage(args) {
  const blob = await generateShareImage(args);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `tex-arena-${args.incident.id}-${Date.now()}.png`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
