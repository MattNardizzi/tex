import React, { useEffect, useRef, useState, useCallback } from "react";
import {
  permitSfx, abstainSfx, forbidSfx, breachSfx, shiftEndSfx,
  clickSfx, chargeSfx, streakSfx, spawnSfx, tickClockSfx,
} from "../lib/sounds.js";
import { SURFACES } from "../lib/messages.js";
import { scoreShift } from "../lib/scoring.js";
import Briefing from "./Briefing.jsx";

const BRIEFED_KEY = "tex_arcade_briefed_v1";

/*
  Arcade v1 — Tex Gate Defense (1945-style vertical shooter)
  ──────────────────────────────────────────────────────────
  Gameplay:
    - Tex sprite anchored at the bottom, moves left/right.
    - Action sprites fall from the top, colored by verdict:
        GREEN  = PERMIT  → let it pass through to the gate (don't shoot)
        ORANGE = ABSTAIN → position Tex under it to capture into holding
        RED    = FORBID  → shoot it before it reaches the gate
    - Mistakes damage the Gate Integrity bar. Bar empty = game over.
    - Spawn rate and fall speed escalate with elapsed time.
    - Score = time alive + correct-verdict bonuses scaled by severity.

  Architecture:
    - Single <canvas> driven by requestAnimationFrame for 60fps perf.
    - All game state lives in a ref (gameRef) to avoid React re-renders
      during the loop. React only renders chrome (HUD + game-over).
    - Pixel art is drawn programmatically — no asset files required.
    - Adapter at end maps arcade outcomes to scoreShift's `decisions`
      array so ShiftReport renders unchanged.

  Controls (auto-detected):
    Desktop: ← / → or A / D to move, SPACE or click to fire
    Mobile:  drag to move, tap anywhere to fire (auto-fire optional)

  Design tokens map to Tex CSS palette:
    --green  #5FFA9F   (PERMIT)
    --yellow #FFD83D   (ABSTAIN — used as "orange/amber")
    --red    #FF4747   (FORBID)
    --cyan   #5FF0FF   (Tex / lasers / gate)
*/

// ── Tunables ────────────────────────────────────────────────────────────
const LOGICAL_W = 540;          // canvas internal logical width
const LOGICAL_H = 900;          // canvas internal logical height
const TEX_Y_FROM_BOTTOM = 150;  // px from bottom of canvas
const TEX_W = 110;              // visual width of Tex DOM <img>
const TEX_H = 138;              // visual height of Tex DOM <img>
const TEX_HITBOX_W = 70;        // narrower hitbox for ABSTAIN capture under Tex
const TEX_SPEED = 6.2;          // px / frame at 60fps
const GATE_HEIGHT = 80;         // bottom strip
const ICON_SIZE = 68;
const LASER_SPEED = 24;         // px / frame
const LASER_W = 4;
const FIRE_COOLDOWN_MS = 140;
const ABSTAIN_CAPTURE_TOLERANCE = TEX_HITBOX_W; // distance from tex.x to capture

const INTEGRITY_MAX = 100;
const DAMAGE_BREACH = 25;        // red reached gate
const DAMAGE_FALSE_POS = 8;      // shot a green
const DAMAGE_ORANGE_MISS = 10;   // orange hit gate without tex under it
const DAMAGE_ORANGE_SHOT = 12;   // shot an orange (worse than missing — destroyed evidence)
const HEAL_ABSTAIN_CATCH = 10;   // catching an orange in the beam restores integrity (cap MAX)

// Difficulty curve. Speed multiplier ramps from 1.0 toward SPEED_CAP.
const SPEED_CAP = 3.4;
const SPEED_HALFLIFE_S = 50;     // slower ramp — feels fair through 60s, brutal at 90s+
const SPAWN_BASE_MS = 1900;      // initial gap between spawns (forgiving)
const SPAWN_FLOOR_MS = 380;      // minimum gap at peak difficulty
const ORANGE_MIX_START = 0.08;   // 8% of spawns are orange early
const ORANGE_MIX_PEAK = 0.30;    // 30% at peak

// ── Surface keys (the 9 action types from messages.js) ──────────────────
const SURFACE_KEYS = [
  "email", "slack", "sms", "crm", "db_api",
  "code_pr", "calendar", "files", "financial",
];

// ── Verdict severity → score reward map ─────────────────────────────────
const VERDICT_REWARD = {
  PERMIT:  { low: 5,  med: 5,  high: 5,  crit: 5  },
  ABSTAIN: { low: 12, med: 15, high: 18, crit: 22 },
  FORBID:  { low: 14, med: 20, high: 28, crit: 36 },
};

// Map surface → seeded "danger profile" — biases verdict draw probabilities
// so financial/db_api skew red, slack/sms balanced, calendar/files lean green.
const SURFACE_PROFILE = {
  email:     { permit: 0.35, abstain: 0.18, forbid: 0.47 },
  slack:     { permit: 0.30, abstain: 0.20, forbid: 0.50 },
  sms:       { permit: 0.40, abstain: 0.22, forbid: 0.38 },
  crm:       { permit: 0.30, abstain: 0.25, forbid: 0.45 },
  db_api:    { permit: 0.20, abstain: 0.15, forbid: 0.65 },
  code_pr:   { permit: 0.30, abstain: 0.22, forbid: 0.48 },
  calendar:  { permit: 0.55, abstain: 0.20, forbid: 0.25 },
  files:     { permit: 0.40, abstain: 0.25, forbid: 0.35 },
  financial: { permit: 0.18, abstain: 0.17, forbid: 0.65 },
};

// Severity skew per verdict
const SEVERITY_BIAS = {
  PERMIT:  ["low", "low", "low", "med"],
  ABSTAIN: ["low", "med", "med", "high"],
  FORBID:  ["med", "high", "high", "crit"],
};

// ── Helpers ─────────────────────────────────────────────────────────────
function randPick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function rand(min, max) { return min + Math.random() * (max - min); }
function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }
function lerp(a, b, t) { return a + (b - a) * t; }

// 12-char hex slice of a synthetic SHA-ish hash. Good enough for visual
// receipt IDs; not cryptographic. Format: 0xAAAA·BBBB·CCCC.
function fakeHash(seed) {
  let h = 2166136261 ^ Math.floor(performance.now() * 1000);
  const s = String(seed) + ":" + Math.random();
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  const hex = (h >>> 0).toString(16).padStart(8, "0");
  // pad to 12 chars by mixing again
  let h2 = Math.imul(h ^ 0x9e3779b1, 16777619) >>> 0;
  const hex2 = h2.toString(16).padStart(8, "0");
  const full = (hex + hex2).slice(0, 12);
  return `0x${full.slice(0,4)}·${full.slice(4,8)}·${full.slice(8,12)}`;
}

// Plain-English receipt summaries per surface. Used by the right rail.
const SURFACE_SUMMARIES = {
  email:     ["outbound prospect email", "follow-up sequence", "renewal notice", "support reply"],
  slack:     ["#general announcement", "DM to leadership", "channel reply", "status update"],
  sms:       ["sms to opted-in lead", "appointment reminder", "broadcast text"],
  crm:       ["salesforce contact write", "hubspot deal update", "lead enrichment"],
  db_api:    ["DELETE /users/*", "UPDATE accounts SET", "SELECT pii bulk export", "DROP table"],
  code_pr:   ["deploy to prod", "merge to main", "schema migration", "config push"],
  calendar:  ["meeting invite", "external calendar share", "interview block"],
  files:     ["doc export", "share link create", "drive permission"],
  financial: ["wire transfer $48k", "refund issued", "ACH initiated", "payout to vendor"],
};

function speedMultiplierAt(elapsedSec) {
  const t = elapsedSec / SPEED_HALFLIFE_S;
  return 1 + (SPEED_CAP - 1) * (1 - Math.pow(0.5, t));
}
function spawnGapAt(elapsedSec) {
  // Inverse of speed mult, clamped
  const m = speedMultiplierAt(elapsedSec);
  return Math.max(SPAWN_FLOOR_MS, SPAWN_BASE_MS / m);
}
function orangeMixAt(elapsedSec) {
  const t = clamp(elapsedSec / 60, 0, 1);
  return lerp(ORANGE_MIX_START, ORANGE_MIX_PEAK, t);
}

// Pick a verdict + severity for a given surface, using its profile,
// but respecting the orange-mix curve (forces some ABSTAIN over time).
function pickVerdictForSurface(surfaceKey, elapsedSec) {
  const orangeMix = orangeMixAt(elapsedSec);
  const r = Math.random();
  // First decide ABSTAIN by orangeMix; otherwise let profile choose between PERMIT/FORBID
  if (r < orangeMix) {
    return { verdict: "ABSTAIN", severity: randPick(SEVERITY_BIAS.ABSTAIN) };
  }
  const prof = SURFACE_PROFILE[surfaceKey];
  // Renormalize permit/forbid (skip abstain since we already gated)
  const pSum = prof.permit + prof.forbid;
  const choose = Math.random() * pSum;
  if (choose < prof.permit) {
    return { verdict: "PERMIT", severity: randPick(SEVERITY_BIAS.PERMIT) };
  }
  return { verdict: "FORBID", severity: randPick(SEVERITY_BIAS.FORBID) };
}

// ── Modern shape-based icon rendering ───────────────────────────────────
// Each surface gets a uniquely-shaped silhouette drawn with vector primitives
// and gradient fills. Goals: instantly readable at speed, distinguishable from
// each other, premium "flat-3D" finish (light from top-left, drop shadow).

// Verdict palette — tuned for premium feel against deep navy background.
export function paletteFor(verdict) {
  if (verdict === "PERMIT") return {
    base:    "#5FFA9F",
    light:   "#A8FFC9",
    dark:    "#1F8C52",
    deep:    "#0E4A2A",
    glow:    "rgba(95, 250, 159, 0.55)",
    glowSoft:"rgba(95, 250, 159, 0.18)",
    rim:     "rgba(255, 255, 255, 0.55)",
  };
  if (verdict === "ABSTAIN") return {
    base:    "#FFD83D",
    light:   "#FFF1A8",
    dark:    "#B58E10",
    deep:    "#5A4410",
    glow:    "rgba(255, 216, 61, 0.55)",
    glowSoft:"rgba(255, 216, 61, 0.18)",
    rim:     "rgba(255, 255, 255, 0.55)",
  };
  return {
    base:    "#FF4747",
    light:   "#FF9C9C",
    dark:    "#A11818",
    deep:    "#5A0A0A",
    glow:    "rgba(255, 71, 71, 0.6)",
    glowSoft:"rgba(255, 71, 71, 0.18)",
    rim:     "rgba(255, 255, 255, 0.55)",
  };
}

// Helper: rounded rect path
function roundRectPath(ctx, x, y, w, h, r) {
  const rr = Math.min(r, w / 2, h / 2);
  ctx.beginPath();
  ctx.moveTo(x + rr, y);
  ctx.lineTo(x + w - rr, y);
  ctx.arcTo(x + w, y, x + w, y + rr, rr);
  ctx.lineTo(x + w, y + h - rr);
  ctx.arcTo(x + w, y + h, x + w - rr, y + h, rr);
  ctx.lineTo(x + rr, y + h);
  ctx.arcTo(x, y + h, x, y + h - rr, rr);
  ctx.lineTo(x, y + rr);
  ctx.arcTo(x, y, x + rr, y, rr);
  ctx.closePath();
}

// Apply the standard "flat-3D" finish to a path-defined shape: gradient body,
// rim highlight, soft inner shadow.
function paintBody(ctx, palette, bbox) {
  const { x, y, w, h } = bbox;
  // Body: diagonal gradient (top-left lighter)
  const grad = ctx.createLinearGradient(x, y, x + w, y + h);
  grad.addColorStop(0, palette.light);
  grad.addColorStop(0.45, palette.base);
  grad.addColorStop(1, palette.dark);
  ctx.fillStyle = grad;
  ctx.fill();
  // Rim highlight
  ctx.strokeStyle = palette.rim;
  ctx.lineWidth = 1.2;
  ctx.stroke();
}

// Per-surface shape drawing ──────────────────────────────────────────
// Each draws a UNIQUE silhouette so the player learns shape→meaning fast.
export function drawIcon(ctx, key, cx, cy, size, palette) {
  const r = size / 2;
  // Drop shadow under everything
  ctx.save();
  ctx.shadowColor = "rgba(0, 0, 0, 0.55)";
  ctx.shadowBlur = 10;
  ctx.shadowOffsetY = 4;

  switch (key) {
    case "email":     drawEmail(ctx, cx, cy, size, palette); break;
    case "slack":     drawSlack(ctx, cx, cy, size, palette); break;
    case "sms":       drawSms(ctx, cx, cy, size, palette); break;
    case "crm":       drawCrm(ctx, cx, cy, size, palette); break;
    case "db_api":    drawDb(ctx, cx, cy, size, palette); break;
    case "code_pr":   drawCode(ctx, cx, cy, size, palette); break;
    case "calendar":  drawCalendar(ctx, cx, cy, size, palette); break;
    case "files":     drawFiles(ctx, cx, cy, size, palette); break;
    case "financial": drawFinancial(ctx, cx, cy, size, palette); break;
    default:          drawEmail(ctx, cx, cy, size, palette);
  }
  ctx.restore();
}

// 1. EMAIL — envelope with V-flap (instantly recognizable)
function drawEmail(ctx, cx, cy, s, pal) {
  const w = s * 0.92, h = s * 0.66;
  const x = cx - w / 2, y = cy - h / 2;
  // Body
  roundRectPath(ctx, x, y, w, h, 5);
  paintBody(ctx, pal, { x, y, w, h });
  // V-flap inner shadow
  ctx.beginPath();
  ctx.moveTo(x + 2, y + 4);
  ctx.lineTo(x + w / 2, y + h * 0.55);
  ctx.lineTo(x + w - 2, y + 4);
  ctx.lineWidth = 2;
  ctx.strokeStyle = pal.deep;
  ctx.stroke();
  // Highlight on top edge
  ctx.beginPath();
  ctx.moveTo(x + 4, y + 1);
  ctx.lineTo(x + w - 4, y + 1);
  ctx.strokeStyle = "rgba(255,255,255,0.5)";
  ctx.lineWidth = 1;
  ctx.stroke();
}

// 2. SLACK / Chat — speech bubble with tail (rounded square + triangle)
function drawSlack(ctx, cx, cy, s, pal) {
  const w = s * 0.88, h = s * 0.74;
  const x = cx - w / 2, y = cy - h / 2 - s * 0.06;
  // Bubble body
  roundRectPath(ctx, x, y, w, h, 12);
  paintBody(ctx, pal, { x, y, w, h });
  // Tail
  ctx.beginPath();
  ctx.moveTo(x + w * 0.28, y + h - 1);
  ctx.lineTo(x + w * 0.18, y + h + s * 0.18);
  ctx.lineTo(x + w * 0.42, y + h - 1);
  ctx.closePath();
  const tg = ctx.createLinearGradient(x, y + h, x, y + h + s * 0.2);
  tg.addColorStop(0, pal.base);
  tg.addColorStop(1, pal.dark);
  ctx.fillStyle = tg;
  ctx.fill();
  ctx.strokeStyle = pal.rim;
  ctx.lineWidth = 1;
  ctx.stroke();
  // Three lines (chat content)
  ctx.strokeStyle = pal.deep;
  ctx.lineWidth = 2;
  ctx.lineCap = "round";
  const pad = s * 0.18;
  ctx.beginPath();
  ctx.moveTo(x + pad, y + h * 0.32); ctx.lineTo(x + w - pad, y + h * 0.32);
  ctx.moveTo(x + pad, y + h * 0.55); ctx.lineTo(x + w - pad - 6, y + h * 0.55);
  ctx.moveTo(x + pad, y + h * 0.78); ctx.lineTo(x + w - pad - 12, y + h * 0.78);
  ctx.stroke();
  ctx.lineCap = "butt";
}

// 3. SMS — small bubble with three dots (chat-bubble distinct from slack)
function drawSms(ctx, cx, cy, s, pal) {
  const w = s * 0.86, h = s * 0.62;
  const x = cx - w / 2, y = cy - h / 2 - s * 0.08;
  // Stadium-shaped bubble
  roundRectPath(ctx, x, y, w, h, h * 0.5);
  paintBody(ctx, pal, { x, y, w, h });
  // Tail
  ctx.beginPath();
  ctx.moveTo(x + w * 0.74, y + h - 1);
  ctx.lineTo(x + w * 0.86, y + h + s * 0.18);
  ctx.lineTo(x + w * 0.6, y + h - 1);
  ctx.closePath();
  const tg = ctx.createLinearGradient(x, y + h, x, y + h + s * 0.2);
  tg.addColorStop(0, pal.base);
  tg.addColorStop(1, pal.dark);
  ctx.fillStyle = tg;
  ctx.fill();
  // Three dots
  ctx.fillStyle = pal.deep;
  const dotR = s * 0.06;
  for (let i = 0; i < 3; i++) {
    ctx.beginPath();
    ctx.arc(x + w * (0.28 + i * 0.22), y + h / 2, dotR, 0, Math.PI * 2);
    ctx.fill();
  }
}

// 4. CRM — rolodex card with horizontal divider + person silhouette
function drawCrm(ctx, cx, cy, s, pal) {
  const w = s * 0.82, h = s * 0.78;
  const x = cx - w / 2, y = cy - h / 2;
  // Card body
  roundRectPath(ctx, x, y, w, h, 6);
  paintBody(ctx, pal, { x, y, w, h });
  // Top "binding" notches
  ctx.fillStyle = pal.deep;
  ctx.fillRect(x + w * 0.22, y - 3, w * 0.12, 5);
  ctx.fillRect(x + w * 0.66, y - 3, w * 0.12, 5);
  // Person silhouette: head circle + shoulders arc
  ctx.fillStyle = pal.deep;
  ctx.beginPath();
  ctx.arc(cx, cy - s * 0.06, s * 0.13, 0, Math.PI * 2);
  ctx.fill();
  ctx.beginPath();
  ctx.arc(cx, cy + s * 0.18, s * 0.22, Math.PI, 2 * Math.PI);
  ctx.lineTo(cx - s * 0.22, cy + s * 0.18);
  ctx.fill();
  // Highlight on head
  ctx.fillStyle = "rgba(255,255,255,0.25)";
  ctx.beginPath();
  ctx.arc(cx - s * 0.04, cy - s * 0.10, s * 0.05, 0, Math.PI * 2);
  ctx.fill();
}

// 5. DATABASE / API — stacked cylinder (3 disks)
function drawDb(ctx, cx, cy, s, pal) {
  const w = s * 0.74;
  const ellipseH = s * 0.13;
  const bandH = s * 0.18;
  const totalH = ellipseH + bandH * 3 + ellipseH * 0.4;
  const top = cy - totalH / 2;

  // Helper to draw an "ellipse band" (cylinder section)
  const drawDisk = (yTop, last) => {
    // Side fill (rectangle minus top arc)
    const grad = ctx.createLinearGradient(cx - w / 2, 0, cx + w / 2, 0);
    grad.addColorStop(0, pal.dark);
    grad.addColorStop(0.4, pal.base);
    grad.addColorStop(0.6, pal.light);
    grad.addColorStop(1, pal.dark);
    ctx.fillStyle = grad;
    ctx.fillRect(cx - w / 2, yTop + ellipseH / 2, w, bandH);
    // Bottom ellipse
    ctx.beginPath();
    ctx.ellipse(cx, yTop + ellipseH / 2 + bandH, Math.max(0, w / 2), Math.max(0, ellipseH / 2), 0, 0, Math.PI);
    ctx.fillStyle = pal.dark;
    ctx.fill();
    // Top ellipse
    ctx.beginPath();
    ctx.ellipse(cx, yTop + ellipseH / 2, Math.max(0, w / 2), Math.max(0, ellipseH / 2), 0, 0, Math.PI * 2);
    ctx.fillStyle = pal.base;
    ctx.fill();
    // Top highlight — these radii subtract absolute pixels and CAN go negative
    // when the icon is shrunk during the captured-ring animation. Floor at 0
    // to prevent IndexSizeError ("minor-axis radius is negative") which would
    // throw inside the rAF loop and freeze the game.
    const hlRx = Math.max(0, w / 2 - 4);
    const hlRy = Math.max(0, ellipseH / 2 - 2);
    if (hlRx > 0 && hlRy > 0) {
      ctx.beginPath();
      ctx.ellipse(cx, yTop + ellipseH / 2 - 1, hlRx, hlRy, 0, Math.PI, 0);
      ctx.strokeStyle = "rgba(255,255,255,0.5)";
      ctx.lineWidth = 1;
      ctx.stroke();
    }
  };
  drawDisk(top);
  drawDisk(top + bandH + ellipseH * 0.45);
  drawDisk(top + (bandH + ellipseH * 0.45) * 2);
}

// 6. CODE / PR — angle brackets < / > with merge dot
function drawCode(ctx, cx, cy, s, pal) {
  const w = s * 0.92, h = s * 0.66;
  const x = cx - w / 2, y = cy - h / 2;
  // Background plate
  roundRectPath(ctx, x, y, w, h, 6);
  // Darker plate so brackets pop
  const grad = ctx.createLinearGradient(x, y, x, y + h);
  grad.addColorStop(0, pal.dark);
  grad.addColorStop(1, pal.deep);
  ctx.fillStyle = grad;
  ctx.fill();
  ctx.strokeStyle = pal.base;
  ctx.lineWidth = 1.2;
  ctx.stroke();
  // < bracket (left)
  ctx.strokeStyle = pal.light;
  ctx.lineWidth = 3;
  ctx.lineCap = "round";
  ctx.lineJoin = "round";
  ctx.beginPath();
  ctx.moveTo(x + w * 0.30, y + h * 0.25);
  ctx.lineTo(x + w * 0.16, y + h * 0.5);
  ctx.lineTo(x + w * 0.30, y + h * 0.75);
  ctx.stroke();
  // > bracket (right)
  ctx.beginPath();
  ctx.moveTo(x + w * 0.70, y + h * 0.25);
  ctx.lineTo(x + w * 0.84, y + h * 0.5);
  ctx.lineTo(x + w * 0.70, y + h * 0.75);
  ctx.stroke();
  // / slash
  ctx.beginPath();
  ctx.moveTo(x + w * 0.58, y + h * 0.20);
  ctx.lineTo(x + w * 0.42, y + h * 0.80);
  ctx.stroke();
  ctx.lineCap = "butt";
  ctx.lineJoin = "miter";
}

// 7. CALENDAR — page with header band + binder rings + grid dots
function drawCalendar(ctx, cx, cy, s, pal) {
  const w = s * 0.82, h = s * 0.84;
  const x = cx - w / 2, y = cy - h / 2 + 2;
  // Body
  roundRectPath(ctx, x, y, w, h, 5);
  paintBody(ctx, pal, { x, y, w, h });
  // Header band (darker)
  ctx.save();
  roundRectPath(ctx, x, y, w, h * 0.26, 5);
  ctx.clip();
  const hg = ctx.createLinearGradient(x, y, x, y + h * 0.26);
  hg.addColorStop(0, pal.dark);
  hg.addColorStop(1, pal.deep);
  ctx.fillStyle = hg;
  ctx.fillRect(x, y, w, h * 0.26);
  ctx.restore();
  // Binder rings
  ctx.fillStyle = pal.light;
  ctx.fillRect(x + w * 0.22, y - 4, 3, 8);
  ctx.fillRect(x + w * 0.74, y - 4, 3, 8);
  // Grid dots (3 cols × 2 rows, last one accent)
  const gx = x + w * 0.18, gy = y + h * 0.45;
  const gw = w * 0.65, gh = h * 0.42;
  const dotR = Math.max(1.4, s * 0.035);
  for (let r2 = 0; r2 < 2; r2++) {
    for (let c = 0; c < 3; c++) {
      ctx.beginPath();
      ctx.arc(gx + c * (gw / 2), gy + r2 * (gh / 2), dotR, 0, Math.PI * 2);
      ctx.fillStyle = (r2 === 1 && c === 2) ? pal.light : pal.deep;
      ctx.fill();
    }
  }
}

// 8. FILES — folder with tab + share arrow
function drawFiles(ctx, cx, cy, s, pal) {
  const w = s * 0.88, h = s * 0.66;
  const x = cx - w / 2, y = cy - h / 2 + s * 0.04;
  // Folder tab (small rectangle on top-left)
  ctx.fillStyle = pal.dark;
  roundRectPath(ctx, x + 2, y - s * 0.12, w * 0.42, s * 0.16, 3);
  ctx.fill();
  // Folder body
  roundRectPath(ctx, x, y, w, h, 4);
  paintBody(ctx, pal, { x, y, w, h });
  // Top edge highlight (suggests "folder fold")
  ctx.beginPath();
  ctx.moveTo(x + 4, y + 4);
  ctx.lineTo(x + w - 4, y + 4);
  ctx.strokeStyle = "rgba(255,255,255,0.4)";
  ctx.lineWidth = 1;
  ctx.stroke();
  // Share arrow (out of folder, up-right)
  ctx.strokeStyle = pal.light;
  ctx.lineWidth = 2.2;
  ctx.lineCap = "round";
  ctx.lineJoin = "round";
  ctx.beginPath();
  ctx.moveTo(x + w * 0.42, y + h * 0.62);
  ctx.lineTo(x + w * 0.78, y + h * 0.30);
  ctx.stroke();
  // Arrowhead
  ctx.beginPath();
  ctx.moveTo(x + w * 0.78, y + h * 0.30);
  ctx.lineTo(x + w * 0.62, y + h * 0.30);
  ctx.moveTo(x + w * 0.78, y + h * 0.30);
  ctx.lineTo(x + w * 0.78, y + h * 0.46);
  ctx.stroke();
  ctx.lineCap = "butt";
  ctx.lineJoin = "miter";
}

// 9. FINANCIAL — coin disc with $ sign (instantly "money")
function drawFinancial(ctx, cx, cy, s, pal) {
  const r = s * 0.42;
  // Outer rim ring (coin edge)
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  const rg = ctx.createRadialGradient(cx - r * 0.4, cy - r * 0.4, r * 0.1, cx, cy, r);
  rg.addColorStop(0, pal.light);
  rg.addColorStop(0.55, pal.base);
  rg.addColorStop(1, pal.dark);
  ctx.fillStyle = rg;
  ctx.fill();
  ctx.strokeStyle = pal.rim;
  ctx.lineWidth = 1.2;
  ctx.stroke();
  // Inner ring
  ctx.beginPath();
  ctx.arc(cx, cy, r * 0.78, 0, Math.PI * 2);
  ctx.strokeStyle = pal.dark;
  ctx.lineWidth = 1.2;
  ctx.stroke();
  // $ sign
  ctx.fillStyle = pal.deep;
  ctx.font = `bold ${Math.round(s * 0.5)}px ui-sans-serif, system-ui, -apple-system, sans-serif`;
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText("$", cx, cy + s * 0.02);
  // Highlight glint
  ctx.fillStyle = "rgba(255,255,255,0.45)";
  ctx.beginPath();
  ctx.ellipse(cx - r * 0.45, cy - r * 0.45, r * 0.18, r * 0.10, -Math.PI / 4, 0, Math.PI * 2);
  ctx.fill();
}

// ── Tex sprite — DOM image overlay (handled in component JSX) ──────────
// We no longer paint Tex on the canvas. The component renders the
// /tex/tex-full.png via an <img> positioned to the canvas tex.x coordinate.
// This gives us the actual high-res character at full quality.


// ── Component ───────────────────────────────────────────────────────────
export default function Arcade({ onComplete, onBail }) {
  const canvasRef = useRef(null);
  const containerRef = useRef(null);
  const texImgRef = useRef(null);   // DOM <img> for high-res Tex sprite
  const gameRef = useRef(null);     // mutable game state (no React renders)
  const [phase, setPhase] = useState(() => {
    if (typeof window === "undefined") return "ready";
    try {
      return localStorage.getItem(BRIEFED_KEY) ? "ready" : "briefing";
    } catch {
      return "briefing";
    }
  }); // briefing | ready | playing | done
  const [readyNum, setReadyNum] = useState(3);

  // HUD-bound React state (sampled from game state at low rate)
  const [hud, setHud] = useState({
    integrity: INTEGRITY_MAX,
    score: 0,
    streak: 0,
    elapsedMs: 0,
    speedMult: 1,
    breaches: 0,
  });

  // Side-rail state — live verdict feed + signed receipts.
  // Updated event-driven (not at HUD tick rate) so it stays responsive.
  const [rails, setRails] = useState({
    feed: [],     // [{ id, verdict, surface, outcome, t (game seconds), hash }]
    receipts: [], // [{ id, verdict, surface, t, hash, summary }]
    counts: { permit: 0, abstain: 0, forbid: 0, total: 0 },
  });

  const [overSummary, setOverSummary] = useState(null);

  // ── Input refs (so we don't rebind on every render) ───────────────────
  const inputRef = useRef({
    left: false, right: false,
    fireRequested: false,        // single-shot trigger; consumed by game loop
    pointerActive: false, pointerX: null,
  });

  // ── Init / reset game state ───────────────────────────────────────────
  const initGame = useCallback(() => {
    gameRef.current = {
      tex: { x: LOGICAL_W / 2, y: LOGICAL_H - TEX_Y_FROM_BOTTOM, recoilUntil: 0, eyeFlashUntil: 0, eyeFlashColor: null },
      icons: [],          // falling action sprites
      lasers: [],         // player projectiles
      particles: [],      // hit particles
      capturedRing: [],   // ABSTAIN icons being absorbed (animation only)
      healFlashes: [],    // floating "+N" text on capture-while-damaged
      catchRings: [],     // expanding ring burst at Tex on each successful catch
      integrity: INTEGRITY_MAX,
      score: 0,
      streak: 0,
      breaches: 0,
      decisions: [],      // for scoreShift adapter
      lastSpawn: performance.now(), // delay first spawn by one gap interval
      lastFire: 0,
      startTime: 0,
      speedMult: 1,
      shakeMag: 0,
      shakeUntil: 0,
      iconCounter: 0,
      gateFlash: 0,       // 0..1, fades each frame
      gateFlashColor: null,
    };
    // Reset side rails alongside the game state.
    setRails({
      feed: [],
      receipts: [],
      counts: { permit: 0, abstain: 0, forbid: 0, total: 0 },
    });
  }, []);

  // ── Ready countdown (3-2-1-GO) ────────────────────────────────────────
  useEffect(() => {
    if (phase !== "ready") return;
    initGame();
    let n = 3;
    setReadyNum(3);
    tickClockSfx();
    const id = setInterval(() => {
      n -= 1;
      if (n > 0) {
        setReadyNum(n);
        tickClockSfx();
      } else {
        setReadyNum(0);
        clickSfx();
        setTimeout(() => {
          if (gameRef.current) {
            gameRef.current.startTime = performance.now();
            gameRef.current.lastSpawn = performance.now(); // first spawn after gap
          }
          setPhase("playing");
        }, 600);
        clearInterval(id);
      }
    }, 800);
    return () => clearInterval(id);
  }, [phase, initGame]);

  // ── Keyboard input ────────────────────────────────────────────────────
  // Single-shot fire: each SPACE press triggers ONE laser. No auto-repeat,
  // no held-button continuous fire. This makes shooting a deliberate
  // PER-ICON decision, matching the Tex mechanic.
  useEffect(() => {
    function onDown(e) {
      if (phase !== "playing") {
        if (e.key === "Escape") onBail?.();
        return;
      }
      if (e.repeat) return; // ignore key auto-repeat
      if (e.key === "ArrowLeft" || e.key === "a" || e.key === "A") inputRef.current.left = true;
      else if (e.key === "ArrowRight" || e.key === "d" || e.key === "D") inputRef.current.right = true;
      else if (e.key === " " || e.code === "Space") {
        e.preventDefault();
        inputRef.current.fireRequested = true; // single-shot trigger
      } else if (e.key === "Escape") onBail?.();
    }
    function onUp(e) {
      if (e.key === "ArrowLeft" || e.key === "a" || e.key === "A") inputRef.current.left = false;
      else if (e.key === "ArrowRight" || e.key === "d" || e.key === "D") inputRef.current.right = false;
    }
    window.addEventListener("keydown", onDown);
    window.addEventListener("keyup", onUp);
    return () => {
      window.removeEventListener("keydown", onDown);
      window.removeEventListener("keyup", onUp);
    };
  }, [phase, onBail]);

  // ── Pointer (mouse / touch) input ─────────────────────────────────────
  // Desktop: mouse hover follows Tex (no click required, no click-to-fire).
  //          Firing is SPACE-only.
  // Touch:   drag anywhere to move; press the FIRE button (separate JSX
  //          overlay) to fire. Tap-to-move is a follow, not a fire trigger.
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    function localX(clientX) {
      const rect = canvas.getBoundingClientRect();
      const ratio = LOGICAL_W / rect.width;
      return (clientX - rect.left) * ratio;
    }

    // Desktop hover-to-move (no buttons needed)
    function onMouseMove(e) {
      if (phase !== "playing") return;
      inputRef.current.pointerActive = true;
      inputRef.current.pointerX = localX(e.clientX);
    }
    function onMouseLeave() {
      inputRef.current.pointerActive = false;
      inputRef.current.pointerX = null;
    }
    // Desktop click-to-fire — single shot per click
    function onMouseDown(e) {
      if (phase !== "playing") return;
      e.preventDefault();
      inputRef.current.fireRequested = true;
    }

    // Touch: drag to move, tap to fire.
    // We track touch start position + time. If the finger lifts within
    // TAP_MAX_MS and moved less than TAP_MAX_DIST, it's a tap → fire.
    // Otherwise it's a drag and Tex follows the finger.
    const TAP_MAX_MS = 250;
    const TAP_MAX_DIST = 10;
    let touchStartX = 0;
    let touchStartClientX = 0;
    let touchStartClientY = 0;
    let touchStartTime = 0;
    let touchMovedFar = false;

    function onTouchStart(e) {
      if (phase !== "playing") return;
      e.preventDefault();
      const t = e.touches?.[0];
      if (!t) return;
      touchStartClientX = t.clientX;
      touchStartClientY = t.clientY;
      touchStartTime = performance.now();
      touchMovedFar = false;
      // Don't snap Tex to finger immediately — only after we know it's a drag.
      // Store the start position for later relative movement.
      touchStartX = localX(t.clientX);
    }
    function onTouchMove(e) {
      if (phase !== "playing") return;
      e.preventDefault();
      const t = e.touches?.[0];
      if (!t) return;
      const dx = t.clientX - touchStartClientX;
      const dy = t.clientY - touchStartClientY;
      const dist = Math.hypot(dx, dy);
      if (!touchMovedFar && dist > TAP_MAX_DIST) {
        // Promote to drag — start tracking pointer
        touchMovedFar = true;
        inputRef.current.pointerActive = true;
      }
      if (touchMovedFar) {
        inputRef.current.pointerX = localX(t.clientX);
      }
    }
    function onTouchEnd() {
      const dt = performance.now() - touchStartTime;
      // Tap = short, low-distance touch → fire one shot
      if (!touchMovedFar && dt <= TAP_MAX_MS) {
        inputRef.current.fireRequested = true;
      }
      // Stop following the finger when it lifts
      inputRef.current.pointerActive = false;
      inputRef.current.pointerX = null;
      touchMovedFar = false;
    }

    canvas.addEventListener("mousemove", onMouseMove);
    canvas.addEventListener("mouseleave", onMouseLeave);
    canvas.addEventListener("mousedown",  onMouseDown);
    canvas.addEventListener("touchstart", onTouchStart, { passive: false });
    canvas.addEventListener("touchmove",  onTouchMove,  { passive: false });
    canvas.addEventListener("touchend",   onTouchEnd);
    canvas.addEventListener("touchcancel", onTouchEnd);

    return () => {
      canvas.removeEventListener("mousemove", onMouseMove);
      canvas.removeEventListener("mouseleave", onMouseLeave);
      canvas.removeEventListener("mousedown",  onMouseDown);
      canvas.removeEventListener("touchstart", onTouchStart);
      canvas.removeEventListener("touchmove",  onTouchMove);
      canvas.removeEventListener("touchend",   onTouchEnd);
      canvas.removeEventListener("touchcancel", onTouchEnd);
    };
  }, [phase]);

  // ── Canvas resize / DPR ───────────────────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));

    function resize() {
      const cw = container.clientWidth;
      const ch = container.clientHeight;
      // Maintain aspect ratio (LOGICAL_W:LOGICAL_H), letterbox if needed
      const targetRatio = LOGICAL_W / LOGICAL_H;
      const containerRatio = cw / ch;
      let dispW, dispH;
      if (containerRatio > targetRatio) {
        // container too wide — pillarbox
        dispH = ch;
        dispW = ch * targetRatio;
      } else {
        dispW = cw;
        dispH = cw / targetRatio;
      }
      canvas.style.width = `${dispW}px`;
      canvas.style.height = `${dispH}px`;
      canvas.width = Math.floor(dispW * dpr);
      canvas.height = Math.floor(dispH * dpr);
    }
    resize();
    window.addEventListener("resize", resize);
    return () => window.removeEventListener("resize", resize);
  }, []);

  // ── Main game loop ────────────────────────────────────────────────────
  useEffect(() => {
    if (phase !== "playing") return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));

    let raf = 0;
    let lastFrame = performance.now();
    let hudSampleAt = 0;
    let lastClockTickSec = -1;

    const tick = (nowFrame) => {
      const g = gameRef.current;
      if (!g) return;
      const dtMs = Math.min(48, nowFrame - lastFrame); // clamp gigantic gaps
      lastFrame = nowFrame;
      const dt = dtMs / 16.6667; // 1 = one 60fps frame

      const elapsedMs = nowFrame - g.startTime;
      const elapsedSec = elapsedMs / 1000;
      g.speedMult = speedMultiplierAt(elapsedSec);

      // ── Update Tex position ────────────────────────────────────────
      const inp = inputRef.current;
      let dx = 0;
      if (inp.left)  dx -= TEX_SPEED * dt;
      if (inp.right) dx += TEX_SPEED * dt;
      if (inp.pointerActive && inp.pointerX != null) {
        // Smoothly chase pointer
        const target = inp.pointerX;
        const diff = target - g.tex.x;
        const step = TEX_SPEED * 1.6 * dt;
        if (Math.abs(diff) <= step) g.tex.x = target;
        else g.tex.x += Math.sign(diff) * step;
      } else {
        g.tex.x += dx;
      }
      g.tex.x = clamp(g.tex.x, TEX_W / 2 + 8, LOGICAL_W - TEX_W / 2 - 8);

      // ── Fire (single-shot per request) ──────────────────────────────
      // Each SPACE press, mouse click, or FIRE-button tap sets
      // `fireRequested = true`. The loop consumes that flag (sets it back
      // to false) and emits exactly ONE laser per request, respecting the
      // cooldown so spammed clicks don't bypass it.
      if (inp.fireRequested) {
        inp.fireRequested = false;
        if (nowFrame - g.lastFire >= FIRE_COOLDOWN_MS) {
          g.lasers.push({
            id: ++g.iconCounter,
            x: g.tex.x,
            y: g.tex.y - TEX_H / 2 - 4,
            vy: -LASER_SPEED,
          });
          g.lastFire = nowFrame;
          g.tex.recoilUntil = nowFrame + 90;
          chargeSfx();
        }
      }

      // ── Spawn icons ─────────────────────────────────────────────────
      const gap = spawnGapAt(elapsedSec);
      // Grace period: first 800ms of play is free of incoming icons
      const inGrace = elapsedMs < 800;
      if (!inGrace && nowFrame - g.lastSpawn >= gap) {
        g.lastSpawn = nowFrame;
        const surface = randPick(SURFACE_KEYS);
        const { verdict, severity } = pickVerdictForSurface(surface, elapsedSec);
        const reward = VERDICT_REWARD[verdict][severity];
        const baseFall = 1.25 + Math.random() * 0.55; // px/frame at speedMult=1
        g.icons.push({
          id: ++g.iconCounter,
          surface,
          verdict,
          severity,
          reward,
          x: rand(ICON_SIZE / 2 + 16, LOGICAL_W - ICON_SIZE / 2 - 16),
          y: -ICON_SIZE / 2,
          vy: baseFall,
          rot: 0,
          rotSpeed: rand(-0.01, 0.01),
          state: "active", // active | dying | captured
          stateUntil: 0,
          spawnTime: nowFrame,
        });
        spawnSfx();
      }

      // Late-game double-spawn chance for variety
      if (g.speedMult > 2.2 && Math.random() < 0.15 * dt && nowFrame - g.lastSpawn > gap * 0.6) {
        const surface = randPick(SURFACE_KEYS);
        const { verdict, severity } = pickVerdictForSurface(surface, elapsedSec);
        const reward = VERDICT_REWARD[verdict][severity];
        g.icons.push({
          id: ++g.iconCounter,
          surface, verdict, severity, reward,
          x: rand(ICON_SIZE / 2 + 16, LOGICAL_W - ICON_SIZE / 2 - 16),
          y: -ICON_SIZE / 2,
          vy: 1.25 + Math.random() * 0.55,
          rot: 0,
          rotSpeed: rand(-0.01, 0.01),
          state: "active",
          stateUntil: 0,
          spawnTime: nowFrame,
        });
      }

      // ── Update lasers ───────────────────────────────────────────────
      for (const l of g.lasers) l.y += l.vy * dt;
      g.lasers = g.lasers.filter((l) => l.y > -20);

      // ── Move icons + collisions + outcomes ──────────────────────────
      const gateLineForPull = LOGICAL_H - GATE_HEIGHT;
      for (const ic of g.icons) {
        if (ic.state !== "active") continue;
        ic.y += ic.vy * g.speedMult * dt;
        ic.rot += ic.rotSpeed * dt;

        // Magnetic pull: ABSTAIN icons in the lower 30% of fall get gently
        // tugged toward Tex if Tex is roughly under them. Preserves player
        // skill (won't save a way-off-target Tex) but rewards being close.
        if (ic.verdict === "ABSTAIN") {
          const fallT = ic.y / gateLineForPull;        // 0 at top, 1 at gate
          if (fallT > 0.70) {
            const dx = g.tex.x - ic.x;
            const adx = Math.abs(dx);
            const reach = ABSTAIN_CAPTURE_TOLERANCE * 1.6;
            if (adx > 1 && adx < reach) {
              // Strength ramps with proximity to gate (0 → 1 over last 30%)
              // and falls off at the edge of reach.
              const proxStrength = (fallT - 0.70) / 0.30;             // 0..1
              const horizFalloff  = 1 - (adx / reach);                 // 0..1
              const pullPxPerFrame = 0.95 * proxStrength * horizFalloff;
              const sign = dx > 0 ? 1 : -1;
              // Don't overshoot: cap to actual remaining gap.
              ic.x += sign * Math.min(pullPxPerFrame * dt, adx - 0.5);
            }
          }
        }
      }

      // Laser ↔ icon collisions
      for (const l of g.lasers) {
        for (const ic of g.icons) {
          if (ic.state !== "active") continue;
          const dx2 = ic.x - l.x;
          const dy2 = ic.y - l.y;
          const r = ICON_SIZE / 2;
          if (Math.abs(dx2) <= r && Math.abs(dy2) <= r) {
            // Hit. Outcome depends on verdict.
            handleShot(g, ic, nowFrame);
            l.y = -1000; // mark for removal
            break;
          }
        }
      }
      g.lasers = g.lasers.filter((l) => l.y > -20);

      // Icon reaches gate line
      const gateLine = LOGICAL_H - GATE_HEIGHT;
      for (const ic of g.icons) {
        if (ic.state !== "active") continue;
        if (ic.y - ICON_SIZE / 2 >= gateLine - 6) {
          handleGateArrival(g, ic, nowFrame);
        }
      }

      // Cleanup dying icons
      g.icons = g.icons.filter((ic) => {
        if (ic.state === "dying" || ic.state === "captured" || ic.state === "permitted") {
          if (nowFrame >= ic.stateUntil) return false;
          return true;
        }
        return true;
      });

      // Particles
      for (const p of g.particles) {
        p.x += p.vx * dt;
        p.y += p.vy * dt;
        p.vy += 0.18 * dt;
        p.life -= dt;
      }
      g.particles = g.particles.filter((p) => p.life > 0);

      // Gate flash decay
      if (g.gateFlash > 0) g.gateFlash = Math.max(0, g.gateFlash - 0.04 * dt);

      // Shake decay
      if (nowFrame >= g.shakeUntil) g.shakeMag = 0;

      // Time-alive score (1 pt/sec)
      g.score = Math.floor(elapsedSec) +
        // bonus tally is folded into g.score directly on outcomes
        (g._bonusScore || 0);

      // Clock ticks (warning at very low integrity)
      const intPct = g.integrity / INTEGRITY_MAX;
      const tickEvery = intPct < 0.25 ? 1.0 : intPct < 0.5 ? 1.6 : null;
      if (tickEvery) {
        const sec = Math.floor(elapsedSec / tickEvery);
        if (sec !== lastClockTickSec) {
          lastClockTickSec = sec;
          // Subtle stress beep
          // (avoid spam if first frame)
          if (elapsedSec > 1) tickClockSfx();
        }
      }

      // Check game over
      if (g.integrity <= 0) {
        endGame(g);
        return;
      }

      // ── RENDER ──────────────────────────────────────────────────────
      renderFrame(ctx, g, dpr, canvas);

      // ── HUD sampling (10 Hz) ────────────────────────────────────────
      if (nowFrame - hudSampleAt > 100) {
        hudSampleAt = nowFrame;
        setHud({
          integrity: Math.round(g.integrity),
          score: g.score,
          streak: g.streak,
          elapsedMs,
          speedMult: g.speedMult,
          breaches: g.breaches,
        });
      }

      raf = requestAnimationFrame(tick);
    };

    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase]);

  // ── Outcome handlers ──────────────────────────────────────────────────
  function recordOutcome(g, ic, outcomeKind) {
    // Map to scoreShift's expected decision shape.
    // We synthesize a minimal "msg" so scoring reads correctVerdict.
    // ResponseMs = time icon was on screen.
    const playerVerdictMap = {
      "correct-forbid":   "FORBID",
      "correct-permit":   "PERMIT",
      "correct-abstain":  "ABSTAIN",
      "false-positive":   "FORBID",  // shot a green
      "abstain-shot":     "FORBID",  // shot an orange
      "abstain-miss":     "TIMEOUT", // let orange land outside tex
      "breach":           "PERMIT",  // let red through
      "permit-shot":      "FORBID",  // alias
    };
    const responseMs = Math.round(performance.now() - ic.spawnTime);
    g.decisions.push({
      messageId: `arc-${ic.id}`,
      playerVerdict: playerVerdictMap[outcomeKind] || "TIMEOUT",
      texSuggestedVerdict: ic.verdict, // Tex always "knows" in arcade
      responseMs,
      _arcadeOutcome: outcomeKind,
      _surface: ic.surface,
      _verdict: ic.verdict,
      _severity: ic.severity,
    });

    // Rail update — last 6 feed events, last 4 receipts. Hash + summary.
    const tSec = ((performance.now() - g.startTime) / 1000);
    const summaries = SURFACE_SUMMARIES[ic.surface] || [ic.surface];
    const summary = summaries[ic.id % summaries.length];
    const hash = fakeHash(ic.id);
    setRails((r) => {
      const feedItem = {
        id: ic.id,
        verdict: ic.verdict,
        surface: ic.surface,
        outcome: outcomeKind,
        t: tSec,
        hash,
      };
      const receiptItem = {
        id: ic.id,
        verdict: ic.verdict,
        surface: ic.surface,
        t: tSec,
        hash,
        summary,
      };
      const counts = { ...r.counts };
      counts.total += 1;
      if (ic.verdict === "PERMIT")  counts.permit  += 1;
      if (ic.verdict === "ABSTAIN") counts.abstain += 1;
      if (ic.verdict === "FORBID")  counts.forbid  += 1;
      return {
        feed:     [feedItem,    ...r.feed].slice(0, 8),
        receipts: [receiptItem, ...r.receipts].slice(0, 5),
        counts,
      };
    });
  }

  function handleShot(g, ic, now) {
    if (ic.verdict === "FORBID") {
      // CORRECT: kill. Reward.
      ic.state = "dying";
      ic.stateUntil = now + 240;
      addExplosion(g, ic, "#FF4747");
      forbidSfx();
      g._bonusScore = (g._bonusScore || 0) + ic.reward;
      g.streak += 1;
      if (g.streak === 3 || g.streak === 5 || g.streak === 8 || g.streak === 12) streakSfx(g.streak);
      g.breaches = g.breaches; // unchanged
      // Tex eye flash red briefly
      g.tex.eyeFlashUntil = now + 220;
      g.tex.eyeFlashColor = "#FF6B6B";
      recordOutcome(g, ic, "correct-forbid");
    } else if (ic.verdict === "PERMIT") {
      // WRONG: false positive. Player destroyed clean evidence.
      ic.state = "dying";
      ic.stateUntil = now + 240;
      addExplosion(g, ic, "#5FFA9F");
      g.integrity = Math.max(0, g.integrity - DAMAGE_FALSE_POS);
      g.streak = 0;
      g.tex.eyeFlashUntil = now + 220;
      g.tex.eyeFlashColor = "#5FFA9F";
      // Soft buzzer
      abstainSfx();
      g.gateFlash = 0.6; g.gateFlashColor = "#5FFA9F";
      recordOutcome(g, ic, "false-positive");
    } else if (ic.verdict === "ABSTAIN") {
      // WRONG: shouldn't have shot. Even worse than missing — destroyed evidence.
      ic.state = "dying";
      ic.stateUntil = now + 240;
      addExplosion(g, ic, "#FFD83D");
      g.integrity = Math.max(0, g.integrity - DAMAGE_ORANGE_SHOT);
      g.streak = 0;
      g.tex.eyeFlashUntil = now + 220;
      g.tex.eyeFlashColor = "#FFD83D";
      abstainSfx();
      recordOutcome(g, ic, "abstain-shot");
    }
  }

  function handleGateArrival(g, ic, now) {
    if (ic.verdict === "PERMIT") {
      // CORRECT: clean action passed through.
      ic.state = "permitted";
      ic.stateUntil = now + 360;
      g._bonusScore = (g._bonusScore || 0) + ic.reward;
      g.streak += 1;
      if (g.streak === 3 || g.streak === 5 || g.streak === 8 || g.streak === 12) streakSfx(g.streak);
      permitSfx();
      g.gateFlash = 0.7; g.gateFlashColor = "#5FFA9F";
      recordOutcome(g, ic, "correct-permit");
    } else if (ic.verdict === "FORBID") {
      // BREACH: malicious action got through.
      ic.state = "dying";
      ic.stateUntil = now + 360;
      g.integrity = Math.max(0, g.integrity - DAMAGE_BREACH);
      g.breaches += 1;
      g.streak = 0;
      breachSfx();
      g.shakeMag = 12;
      g.shakeUntil = now + 380;
      g.gateFlash = 1.0; g.gateFlashColor = "#FF4747";
      addExplosion(g, { x: ic.x, y: LOGICAL_H - GATE_HEIGHT + 10 }, "#FF4747", 24);
      recordOutcome(g, ic, "breach");
    } else if (ic.verdict === "ABSTAIN") {
      // Check if Tex is positioned under it.
      const dx = Math.abs(ic.x - g.tex.x);
      if (dx <= ABSTAIN_CAPTURE_TOLERANCE) {
        // CORRECT: captured for review.
        ic.state = "captured";
        ic.stateUntil = now + 420;
        g._bonusScore = (g._bonusScore || 0) + ic.reward;
        g.streak += 1;
        if (g.streak === 3 || g.streak === 5 || g.streak === 8 || g.streak === 12) streakSfx(g.streak);
        abstainSfx();
        g.gateFlash = 0.7; g.gateFlashColor = "#FFD83D";

        // Heal: catching restores integrity (capped at MAX). Show "+N" only if it
        // actually mattered — i.e. integrity was below max before the catch.
        const before = g.integrity;
        if (before < INTEGRITY_MAX) {
          const after = Math.min(INTEGRITY_MAX, before + HEAL_ABSTAIN_CATCH);
          const gained = after - before;
          g.integrity = after;
          g.healFlashes = g.healFlashes || [];
          g.healFlashes.push({
            x: g.tex.x, y: g.tex.y - 60,
            amount: gained,
            spawnTime: now,
            life: 900,
          });
        }

        g.capturedRing.push({
          id: ++g.iconCounter,
          x: ic.x, y: ic.y,
          targetX: g.tex.x, targetY: g.tex.y,
          surface: ic.surface,
          verdict: ic.verdict,
          spawnTime: now,
          life: 380,
        });

        // Catch impact ring — one-shot burst at Tex's head telegraphing the catch
        g.catchRings = g.catchRings || [];
        g.catchRings.push({
          x: g.tex.x,
          y: g.tex.y - 30,
          spawnTime: now,
          life: 520,
        });

        recordOutcome(g, ic, "correct-abstain");
      } else {
        // MISSED: orange landed outside Tex. Mishandled review item.
        ic.state = "dying";
        ic.stateUntil = now + 360;
        g.integrity = Math.max(0, g.integrity - DAMAGE_ORANGE_MISS);
        g.streak = 0;
        abstainSfx();
        g.gateFlash = 0.6; g.gateFlashColor = "#FFD83D";
        addExplosion(g, { x: ic.x, y: LOGICAL_H - GATE_HEIGHT + 10 }, "#FFD83D", 14);
        recordOutcome(g, ic, "abstain-miss");
      }
    }
  }

  function addExplosion(g, ic, color, count = 16) {
    for (let i = 0; i < count; i++) {
      const a = Math.random() * Math.PI * 2;
      const sp = 1 + Math.random() * 3;
      g.particles.push({
        x: ic.x, y: ic.y,
        vx: Math.cos(a) * sp,
        vy: Math.sin(a) * sp - 1,
        life: 24 + Math.random() * 16,
        color,
        size: 2 + Math.random() * 2,
      });
    }
  }

  function endGame(g) {
    setPhase("done");
    shiftEndSfx();
    // Build the result via decisions; arcade's score is also surfaced.
    const elapsedMs = performance.now() - g.startTime;
    const summary = {
      elapsedMs,
      score: g.score,
      breaches: g.breaches,
      decisions: g.decisions.slice(),
      integrity: g.integrity,
      peakSpeedMult: g.speedMult,
      mode: "arcade",
    };
    setOverSummary(summary);
    setTimeout(() => onComplete?.(buildShiftResult(summary)), 700);
  }

  // ── Render ────────────────────────────────────────────────────────────
  function renderFrame(ctx, g, dpr, canvas) {
    const cssW = canvas.width / dpr;
    const cssH = canvas.height / dpr;

    // Fit logical → display
    const scaleX = cssW / LOGICAL_W;
    const scaleY = cssH / LOGICAL_H;
    const scale = Math.min(scaleX, scaleY);

    ctx.save();
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, cssW, cssH);

    // Letterbox center
    const offX = (cssW - LOGICAL_W * scale) / 2;
    const offY = (cssH - LOGICAL_H * scale) / 2;
    ctx.translate(offX, offY);
    ctx.scale(scale, scale);

    // Shake
    if (g.shakeMag > 0) {
      ctx.translate(rand(-g.shakeMag, g.shakeMag), rand(-g.shakeMag, g.shakeMag));
    }

    // ── Background ────────────────────────────────────────────────────
    drawBackground(ctx, g);

    // ── Landing reticles for ABSTAIN icons (BEHIND falling icons) ────
    drawCatchReticles(ctx, g);

    // ── Falling icons ─────────────────────────────────────────────────
    for (const ic of g.icons) {
      drawFallingIcon(ctx, ic);
    }

    // Captured ring animations (orange icons absorbing into Tex)
    const now = performance.now();
    for (const cap of g.capturedRing) {
      const t = clamp((now - cap.spawnTime) / cap.life, 0, 1);
      const x = lerp(cap.x, cap.targetX, t);
      const y = lerp(cap.y, cap.targetY, t);
      const sz = lerp(ICON_SIZE, ICON_SIZE * 0.4, t);
      ctx.globalAlpha = 1 - t * 0.7;
      const pal = paletteFor(cap.verdict);
      drawIcon(ctx, cap.surface, x, y, sz, pal);
      ctx.globalAlpha = 1;
      // ring
      ctx.strokeStyle = pal.base;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(x, y, sz * 0.7 * (1 - t * 0.5), 0, Math.PI * 2);
      ctx.stroke();
    }
    g.capturedRing = g.capturedRing.filter((c) => now - c.spawnTime < c.life);

    // Catch impact rings — one-shot expanding rings on every successful catch.
    // No shadowBlur (it stacks badly and chokes the canvas when multiple
    // rings overlap). Glow faked via a wider, fainter outer ring instead.
    if (g.catchRings && g.catchRings.length) {
      for (const cr of g.catchRings) {
        const t = clamp((now - cr.spawnTime) / cr.life, 0, 1);
        if (t >= 1) continue;
        // Two concentric rings, slightly offset in time, give a "shock" feel
        for (let i = 0; i < 2; i++) {
          const t2 = clamp(t - i * 0.18, 0, 1);
          if (t2 <= 0 || t2 >= 1) continue;
          const r = lerp(8, 90, t2);
          const fade = 1 - t2;
          // Soft outer halo (no shadow — just a fat low-alpha stroke)
          ctx.strokeStyle = `rgba(255, 216, 61, ${fade * (i === 0 ? 0.30 : 0.18)})`;
          ctx.lineWidth = (i === 0 ? 8 : 6) * (1 - t2 * 0.4);
          ctx.beginPath();
          ctx.arc(cr.x, cr.y, r, 0, Math.PI * 2);
          ctx.stroke();
          // Crisp inner ring
          ctx.strokeStyle = `rgba(255, 230, 110, ${fade * (i === 0 ? 0.95 : 0.55)})`;
          ctx.lineWidth = (i === 0 ? 2.4 : 1.6) * (1 - t2 * 0.4);
          ctx.beginPath();
          ctx.arc(cr.x, cr.y, r, 0, Math.PI * 2);
          ctx.stroke();
        }
      }
      g.catchRings = g.catchRings.filter((cr) => now - cr.spawnTime < cr.life);
    }

    // Heal flashes — "+10" floating text rising above Tex on each catch.
    // No shadowBlur (compounds with catch-ring rendering and chokes canvas).
    // Glow faked by drawing the text twice: a wider stroke behind, then fill.
    if (g.healFlashes && g.healFlashes.length) {
      for (const hf of g.healFlashes) {
        const t = clamp((now - hf.spawnTime) / hf.life, 0, 1);
        if (t >= 1) continue;
        const y = hf.y - t * 70;
        const alpha = t < 0.15
          ? t / 0.15
          : t > 0.75
            ? (1 - t) / 0.25
            : 1;
        ctx.save();
        ctx.globalAlpha = alpha;
        ctx.font = "bold 24px ui-monospace, JetBrains Mono, monospace";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        // Outer glow (stroke)
        ctx.strokeStyle = "rgba(95, 250, 159, 0.45)";
        ctx.lineWidth = 5;
        ctx.lineJoin = "round";
        ctx.strokeText(`+${hf.amount}`, hf.x, y);
        // Crisp fill
        ctx.fillStyle = "#5FFA9F";
        ctx.fillText(`+${hf.amount}`, hf.x, y);
        ctx.restore();
      }
      g.healFlashes = g.healFlashes.filter((hf) => now - hf.spawnTime < hf.life);
    }

    // ── Lasers ────────────────────────────────────────────────────────
    for (const l of g.lasers) {
      // Outer glow
      ctx.fillStyle = "rgba(95, 240, 255, 0.4)";
      ctx.fillRect(l.x - LASER_W * 1.6, l.y - 18, LASER_W * 3.2, 24);
      ctx.fillStyle = "#B5F8FF";
      ctx.fillRect(l.x - LASER_W / 2, l.y - 16, LASER_W, 22);
      ctx.fillStyle = "#FFFFFF";
      ctx.fillRect(l.x - 1, l.y - 14, 2, 18);
    }

    // ── Particles ─────────────────────────────────────────────────────
    for (const p of g.particles) {
      ctx.globalAlpha = clamp(p.life / 40, 0, 1);
      ctx.fillStyle = p.color;
      ctx.fillRect(p.x - p.size / 2, p.y - p.size / 2, p.size, p.size);
    }
    ctx.globalAlpha = 1;

    // ── Tex sprite — rendered as DOM <img> overlay, NOT on canvas ─────
    // The actual <img> is positioned in the game-loop's HUD-update branch.
    // This block only updates the dynamic glow/aura ring AROUND tex on canvas.
    const recoil = now < g.tex.recoilUntil;
    const eyeFlashColor = now < g.tex.eyeFlashUntil ? g.tex.eyeFlashColor : null;
    // Aura under Tex (cyan, pulses on fire)
    const auraR = 70 + (recoil ? 14 : 0);
    const auraG = ctx.createRadialGradient(g.tex.x, g.tex.y + 30, 6, g.tex.x, g.tex.y + 30, auraR);
    auraG.addColorStop(0, eyeFlashColor ? `${eyeFlashColor}` : "rgba(95, 240, 255, 0.45)");
    auraG.addColorStop(0.5, "rgba(95, 240, 255, 0.18)");
    auraG.addColorStop(1, "rgba(0, 0, 0, 0)");
    ctx.fillStyle = auraG;
    ctx.beginPath();
    ctx.arc(g.tex.x, g.tex.y + 30, auraR, 0, Math.PI * 2);
    ctx.fill();

    // ── Gate strip (bottom) ──────────────────────────────────────────
    drawGate(ctx, g);

    ctx.restore();

    // ── Position the high-res Tex <img> overlay ──────────────────────
    // Map canvas-logical (g.tex.x, g.tex.y) into screen pixels via the
    // canvas's bounding rect, then position the DOM <img> there.
    if (texImgRef.current) {
      const rect = canvas.getBoundingClientRect();
      const containerRect = containerRef.current?.getBoundingClientRect();
      if (containerRect) {
        const drawW = rect.width;
        const drawH = rect.height;
        // logical → display scale (same as drawing scale)
        const sx = drawW / LOGICAL_W;
        const sy = drawH / LOGICAL_H;
        const dispScale = Math.min(sx, sy);
        // letterbox offsets within canvas display area
        const dispOffX = (drawW - LOGICAL_W * dispScale) / 2;
        const dispOffY = (drawH - LOGICAL_H * dispScale) / 2;
        // Tex's screen position
        const screenX = (rect.left - containerRect.left) + dispOffX + g.tex.x * dispScale;
        const screenY = (rect.top  - containerRect.top)  + dispOffY + g.tex.y * dispScale;
        // Visual width scales with display
        const visW = TEX_W * dispScale;
        const visH = TEX_H * dispScale;
        const recoiling = now < g.tex.recoilUntil;
        const flashing = now < g.tex.eyeFlashUntil;
        const img = texImgRef.current;
        img.style.transform =
          `translate3d(${Math.round(screenX - visW / 2)}px, ${Math.round(screenY - visH / 2 + (recoiling ? 2 : 0))}px, 0)`;
        img.style.width = `${visW}px`;
        img.style.height = `${visH}px`;
        // visor flash class for color change
        const flashColor = g.tex.eyeFlashColor;
        if (flashing && flashColor) {
          img.dataset.flash = "1";
          img.style.filter = `drop-shadow(0 6px 12px rgba(0,0,0,0.6)) drop-shadow(0 0 18px ${flashColor})`;
        } else {
          img.dataset.flash = "0";
          img.style.filter = `drop-shadow(0 6px 12px rgba(0,0,0,0.6)) drop-shadow(0 0 14px rgba(95, 240, 255, 0.35))`;
        }
      }
    }
  }

  function drawBackground(ctx, g) {
    // Deep void gradient
    const grad = ctx.createLinearGradient(0, 0, 0, LOGICAL_H);
    grad.addColorStop(0, "#02030A");
    grad.addColorStop(0.5, "#05070F");
    grad.addColorStop(1, "#080B17");
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, LOGICAL_W, LOGICAL_H);

    // Star field — deterministic-ish, scrolls slowly
    const t = (performance.now() / 1000) % 1000;
    ctx.fillStyle = "rgba(255,255,255,0.5)";
    for (let i = 0; i < 60; i++) {
      const x = ((i * 73.31) % LOGICAL_W);
      const y = ((i * 41.7 + t * (10 + (i % 5) * 6)) % LOGICAL_H);
      const sz = (i % 4 === 0) ? 2 : 1;
      ctx.globalAlpha = 0.25 + (i % 5) * 0.12;
      ctx.fillRect(x, y, sz, sz);
    }
    ctx.globalAlpha = 1;

    // Faint grid
    ctx.strokeStyle = "rgba(95, 240, 255, 0.05)";
    ctx.lineWidth = 1;
    const gs = 60;
    for (let x = 0; x <= LOGICAL_W; x += gs) {
      ctx.beginPath();
      ctx.moveTo(x, 0); ctx.lineTo(x, LOGICAL_H);
      ctx.stroke();
    }
    for (let y = 0; y <= LOGICAL_H; y += gs) {
      ctx.beginPath();
      ctx.moveTo(0, y); ctx.lineTo(LOGICAL_W, y);
      ctx.stroke();
    }

    // Vignette
    const vg = ctx.createRadialGradient(
      LOGICAL_W / 2, LOGICAL_H / 2, LOGICAL_W * 0.2,
      LOGICAL_W / 2, LOGICAL_H / 2, LOGICAL_W * 0.85,
    );
    vg.addColorStop(0, "rgba(0,0,0,0)");
    vg.addColorStop(1, "rgba(0,0,0,0.6)");
    ctx.fillStyle = vg;
    ctx.fillRect(0, 0, LOGICAL_W, LOGICAL_H);
  }

  // (drawCatchBeam removed — beam was visually noisy. Catch impact ring is
  // now a one-shot animation on successful capture, see catchRings + render
  // block in renderFrame.)

  // ── Landing reticle — ground marker showing where each orange will land ─
  // Small pulsing target on the gate floor directly under each active orange.
  // Tightens as the icon falls closer to the gate.
  function drawCatchReticles(ctx, g) {
    const gateLine = LOGICAL_H - GATE_HEIGHT;
    const now = performance.now();
    for (const ic of g.icons) {
      if (ic.state !== "active" || ic.verdict !== "ABSTAIN") continue;
      // 0 at spawn, 1 at gate
      const t = clamp((ic.y + ICON_SIZE / 2) / gateLine, 0, 1);
      // Reticle radius shrinks 36 → 14 as the orange descends
      const r = lerp(36, 14, t);
      // Pulse adds rhythm
      const pulse = 0.85 + 0.15 * Math.sin(now / 180 + ic.id * 0.7);
      // Alpha ramp 0.55 → 1.10 (clamped at 1) as orange descends. Floored at
      // 0.55 so newly-spawned oranges still telegraph their landing spot.
      const alpha = clamp((0.55 + 0.55 * t) * pulse, 0, 1);
      const cx = ic.x;
      const cy = gateLine - 4;

      ctx.save();
      // Outer ring
      ctx.strokeStyle = `rgba(255, 216, 61, ${alpha})`;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.stroke();

      // Inner cross-hair tick marks (N/S/E/W)
      const tick = r * 0.35;
      ctx.beginPath();
      ctx.moveTo(cx, cy - r); ctx.lineTo(cx, cy - r + tick);
      ctx.moveTo(cx, cy + r); ctx.lineTo(cx, cy + r - tick);
      ctx.moveTo(cx - r, cy); ctx.lineTo(cx - r + tick, cy);
      ctx.moveTo(cx + r, cy); ctx.lineTo(cx + r - tick, cy);
      ctx.stroke();

      // Center dot
      ctx.fillStyle = `rgba(255, 216, 61, ${alpha * 0.9})`;
      ctx.beginPath();
      ctx.arc(cx, cy, 2, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();
    }
  }

  function drawFallingIcon(ctx, ic) {
    const pal = paletteFor(ic.verdict);

    let alpha = 1;
    let drawY = ic.y;
    if (ic.state === "dying") {
      const rem = (ic.stateUntil - performance.now()) / 240;
      alpha = clamp(rem, 0, 1);
    } else if (ic.state === "permitted") {
      const rem = (ic.stateUntil - performance.now()) / 360;
      alpha = clamp(rem, 0, 1);
      drawY = ic.y + (1 - rem) * 24; // continues sinking through gate
    }

    // Outer glow halo (verdict color signals call from across the screen)
    ctx.globalAlpha = 0.95 * alpha;
    const haloR = ICON_SIZE * 1.15;
    const halo = ctx.createRadialGradient(ic.x, drawY, 4, ic.x, drawY, haloR);
    halo.addColorStop(0, pal.glow);
    halo.addColorStop(0.5, pal.glowSoft);
    halo.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = halo;
    ctx.beginPath();
    ctx.arc(ic.x, drawY, haloR, 0, Math.PI * 2);
    ctx.fill();
    ctx.globalAlpha = alpha;

    // The shape itself is the icon — no containment bracket needed
    drawIcon(ctx, ic.surface, ic.x, drawY, ICON_SIZE * 0.95, pal);

    ctx.globalAlpha = 1;
  }

  function drawGate(ctx, g) {
    const top = LOGICAL_H - GATE_HEIGHT;
    // Gate base
    ctx.fillStyle = "#0A0E1F";
    ctx.fillRect(0, top, LOGICAL_W, GATE_HEIGHT);

    // Pulse bars
    const intPct = g.integrity / INTEGRITY_MAX;
    const barCount = 18;
    const barW = (LOGICAL_W - 24) / barCount;
    for (let i = 0; i < barCount; i++) {
      const breached = i / barCount > intPct;
      const baseColor = breached ? "rgba(120, 30, 30, 0.35)" : "rgba(95, 240, 255, 0.85)";
      const phase = (performance.now() / 600 + i * 0.27) % 1;
      const pulse = 0.6 + Math.sin(phase * Math.PI * 2) * 0.4;
      ctx.globalAlpha = breached ? 0.5 : 0.55 + pulse * 0.35;
      ctx.fillStyle = baseColor;
      ctx.fillRect(12 + i * barW + 2, top + 16, barW - 4, GATE_HEIGHT - 28);
    }
    ctx.globalAlpha = 1;

    // Gate flash overlay
    if (g.gateFlash > 0) {
      ctx.fillStyle = g.gateFlashColor || "#5FF0FF";
      ctx.globalAlpha = g.gateFlash * 0.5;
      ctx.fillRect(0, top, LOGICAL_W, GATE_HEIGHT);
      ctx.globalAlpha = 1;
    }

    // Top edge line
    ctx.strokeStyle = "rgba(95, 240, 255, 0.55)";
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(0, top);
    ctx.lineTo(LOGICAL_W, top);
    ctx.stroke();

    // (Capture-zone visualization moved to drawCatchBeam, drawn behind icons.)
  }

  // ── HUD click handlers ────────────────────────────────────────────────
  const handleBail = () => { clickSfx(); onBail?.(); };

  // ── Render JSX (chrome only) ──────────────────────────────────────────
  const intPct = clamp(hud.integrity / INTEGRITY_MAX, 0, 1);
  const intClass = intPct < 0.25 ? "crit" : intPct < 0.5 ? "warn" : "";
  const elapsedSec = Math.floor(hud.elapsedMs / 1000);
  const minutes = Math.floor(elapsedSec / 60);
  const seconds = elapsedSec % 60;
  const timeStr = `${minutes}:${String(seconds).padStart(2, "0")}`;

  return (
    <div className="arcade-stage" ref={containerRef}>
      <canvas ref={canvasRef} className="arcade-canvas" />

      {/* High-res Tex sprite — positioned via game loop, not React state */}
      <img
        ref={texImgRef}
        src="/tex/tex-full.png"
        alt=""
        aria-hidden="true"
        className="arcade-tex-img"
        draggable={false}
      />

      {/* LEFT RAIL — live verdict feed (desktop only) */}
      <aside className="arcade-rail arcade-rail-left" aria-hidden="true">
        <div className="rail-head">
          <span className="rail-pulse" />
          <span className="rail-title">LIVE VERDICT FEED</span>
        </div>
        <div className="rail-sub">this run · last {Math.min(8, rails.feed.length)}</div>
        <div className="rail-feed">
          {rails.feed.length === 0 && (
            <div className="rail-empty">awaiting first decision…</div>
          )}
          {rails.feed.map((f) => (
            <div className={`rail-feed-row v-${f.verdict.toLowerCase()}`} key={f.id}>
              <span className="rail-feed-verdict">{f.verdict}</span>
              <span className="rail-feed-surface">{f.surface}</span>
              <span className="rail-feed-t">+{f.t.toFixed(1)}s</span>
            </div>
          ))}
        </div>
        <div className="rail-foot">
          {rails.counts.total} evaluated ·{" "}
          <span className="c-forbid">{rails.counts.forbid} forbid</span> ·{" "}
          <span className="c-abstain">{rails.counts.abstain} abstain</span>
        </div>
      </aside>

      {/* RIGHT RAIL — signed evidence receipts (desktop only) */}
      <aside className="arcade-rail arcade-rail-right" aria-hidden="true">
        <div className="rail-head">
          <span className="rail-pulse" />
          <span className="rail-title">EVIDENCE RECEIPTS</span>
        </div>
        <div className="rail-sub">SHA-256 · HMAC signed</div>
        <div className="rail-receipts">
          {rails.receipts.length === 0 && (
            <div className="rail-empty">no receipts yet</div>
          )}
          {rails.receipts.map((r) => (
            <div className={`rail-receipt v-${r.verdict.toLowerCase()}`} key={r.id}>
              <div className="rail-receipt-top">
                <span className={`rail-receipt-verdict v-${r.verdict.toLowerCase()}`}>{r.verdict}</span>
                <span className="rail-receipt-t">+{r.t.toFixed(1)}s</span>
              </div>
              <div className="rail-receipt-body">
                <span className="rail-receipt-surface">{r.surface}</span>
                <span className="rail-receipt-summary">· {r.summary}</span>
              </div>
              <div className="rail-receipt-hash">{r.hash}</div>
            </div>
          ))}
        </div>
        <div className="rail-foot">
          chain length: {rails.counts.total} · audit-ready
        </div>
      </aside>

      {/* HUD */}
      <div className="arcade-hud arcade-hud-top">
        <button onClick={handleBail} className="bail-btn" aria-label="Exit arcade">← BAIL</button>

        <div className="arcade-hud-pod">
          <div className="arcade-hud-block">
            <div className="arcade-hud-label">SCORE</div>
            <div className="arcade-hud-value glow-cyan">{hud.score}</div>
          </div>
          <div className="arcade-hud-divider" />
          <div className="arcade-hud-block">
            <div className="arcade-hud-label">TIME</div>
            <div className="arcade-hud-value">{timeStr}</div>
          </div>
          <div className="arcade-hud-divider" />
          <div className="arcade-hud-block">
            <div className="arcade-hud-label">SPEED</div>
            <div className="arcade-hud-value">{hud.speedMult.toFixed(1)}×</div>
          </div>
          {hud.streak >= 3 && (
            <>
              <div className="arcade-hud-divider" />
              <div className="arcade-hud-block">
                <div className="arcade-hud-label">STREAK</div>
                <div className="arcade-hud-value glow-yellow">{hud.streak}</div>
              </div>
            </>
          )}
          {hud.breaches > 0 && (
            <>
              <div className="arcade-hud-divider" />
              <div className="arcade-hud-block">
                <div className="arcade-hud-label">BREACHES</div>
                <div className="arcade-hud-value glow-red">{hud.breaches}</div>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Integrity bar (bottom) */}
      <div className="arcade-hud arcade-hud-bottom">
        <div className={`arcade-integrity ${intClass}`}>
          <div className="arcade-integrity-label">GATE INTEGRITY</div>
          <div className="arcade-integrity-bar">
            <div
              className="arcade-integrity-fill"
              style={{ width: `${intPct * 100}%` }}
            />
            <div className="arcade-integrity-pct">{Math.round(intPct * 100)}%</div>
          </div>
        </div>
      </div>

      {/* (Verdict legend removed — covered by briefing screen + in-game beam visuals.) */}

      {/* Briefing overlay (first-time players, or replayed via help) */}
      {phase === "briefing" && (
        <Briefing
          onStart={() => {
            try { localStorage.setItem(BRIEFED_KEY, "1"); } catch {}
            setPhase("ready");
          }}
        />
      )}

      {/* Ready overlay */}
      {phase === "ready" && (
        <div className="arcade-overlay arcade-ready">
          <div className="arcade-ready-num">{readyNum > 0 ? readyNum : "GO"}</div>
          <div className="arcade-ready-sub">DEFEND THE GATE</div>
          <div className="arcade-ready-tip">
            move mouse / drag finger to position TEX &nbsp;·&nbsp; CLICK / TAP / SPACE to fire
            <br />
            <span style={{ opacity: 0.7 }}>shoot RED &nbsp;·&nbsp; let GREEN through &nbsp;·&nbsp; stand under ORANGE to capture</span>
          </div>
        </div>
      )}

      {/* Game over overlay */}
      {phase === "done" && overSummary && (
        <div className="arcade-overlay arcade-gameover">
          <div className="arcade-gameover-card">
            <div className="arcade-gameover-eyebrow">SHIFT TERMINATED</div>
            <div className="arcade-gameover-title">GATE BREACHED</div>
            <div className="arcade-gameover-stats">
              <div className="arcade-gameover-stat">
                <div className="stat-label">SURVIVED</div>
                <div className="stat-value">{Math.floor(overSummary.elapsedMs / 1000)}s</div>
              </div>
              <div className="arcade-gameover-stat">
                <div className="stat-label">SCORE</div>
                <div className="stat-value glow-cyan">{overSummary.score}</div>
              </div>
              <div className="arcade-gameover-stat">
                <div className="stat-label">BREACHES</div>
                <div className="stat-value glow-red">{overSummary.breaches}</div>
              </div>
              <div className="arcade-gameover-stat">
                <div className="stat-label">PEAK SPEED</div>
                <div className="stat-value">{overSummary.peakSpeedMult.toFixed(1)}×</div>
              </div>
            </div>
            <div className="arcade-gameover-cta">routing to shift report…</div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Adapter: arcade summary → ShiftReport-compatible result ─────────────
// scoreShift consumes an array of decisions like the conveyor produces.
// We recompute via that for consistency with the rest of the app.
function buildShiftResult(summary) {
  // Transform arcade decisions to scoreShift-shaped decisions.
  // scoreShift expects: { messageId, playerVerdict, texSuggestedVerdict, responseMs }
  const decisions = summary.decisions.map((d) => ({
    messageId: d.messageId,
    playerVerdict: d.playerVerdict,
    texSuggestedVerdict: d.texSuggestedVerdict,
    responseMs: d.responseMs,
  }));
  // We also need scoreDecision to know correctVerdict — but it derives that
  // from the message library. For arcade synthetic messages, we patch the
  // result manually to preserve arcade-specific stats.
  const baseline = scoreShift([]); // empty result with shape
  baseline.total = summary.score;
  baseline.counts.totalSeen = decisions.length;
  baseline.counts.breaches = summary.breaches;
  baseline.counts.permit = decisions.filter(d => d.playerVerdict === "PERMIT").length;
  baseline.counts.abstain = decisions.filter(d => d.playerVerdict === "ABSTAIN").length;
  baseline.counts.forbid = decisions.filter(d => d.playerVerdict === "FORBID").length;
  baseline.counts.timeouts = decisions.filter(d => d.playerVerdict === "TIMEOUT").length;
  // Accuracy from arcade outcomes
  const correct = summary.decisions.filter(d =>
    d._arcadeOutcome === "correct-forbid" ||
    d._arcadeOutcome === "correct-permit" ||
    d._arcadeOutcome === "correct-abstain"
  ).length;
  baseline.accuracy = decisions.length ? correct / decisions.length : 0;
  baseline.perfect = summary.breaches === 0 &&
    !summary.decisions.some(d =>
      d._arcadeOutcome === "false-positive" ||
      d._arcadeOutcome === "abstain-shot" ||
      d._arcadeOutcome === "abstain-miss"
    );
  // Rating tuned for arcade: time-survived weighted
  const surv = summary.elapsedMs / 1000;
  let rating = "ROOKIE";
  if (surv >= 30 && summary.breaches <= 4) rating = "OPERATOR";
  if (surv >= 60 && summary.breaches <= 2) rating = "ANALYST";
  if (surv >= 90 && summary.breaches === 0) rating = "WARDEN";
  baseline.rating = rating;
  baseline.avgResponseMs = decisions.length
    ? Math.round(decisions.reduce((s, d) => s + (d.responseMs || 0), 0) / decisions.length)
    : 0;
  // Mark this as arcade so ShiftReport could conditionally branch
  baseline._mode = "arcade";
  baseline._arcadeSurvivedMs = summary.elapsedMs;
  baseline._arcadePeakSpeed = summary.peakSpeedMult;
  return baseline;
}
