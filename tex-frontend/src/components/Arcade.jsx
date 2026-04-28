import React, { useEffect, useRef, useState, useCallback } from "react";
import {
  permitSfx, abstainSfx, forbidSfx, breachSfx, shiftEndSfx,
  clickSfx, chargeSfx, streakSfx, spawnSfx, tickClockSfx,
} from "../lib/sounds.js";
import { SURFACES } from "../lib/messages.js";
import { scoreShift } from "../lib/scoring.js";

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
const TEX_W = 72;
const TEX_H = 86;
const TEX_SPEED = 6.2;          // px / frame at 60fps
const GATE_HEIGHT = 80;         // bottom strip
const ICON_SIZE = 56;
const LASER_SPEED = 24;         // px / frame
const LASER_W = 4;
const FIRE_COOLDOWN_MS = 140;
const ABSTAIN_CAPTURE_TOLERANCE = ICON_SIZE * 0.65; // distance from tex.x to capture

const INTEGRITY_MAX = 100;
const DAMAGE_BREACH = 25;        // red reached gate
const DAMAGE_FALSE_POS = 8;      // shot a green
const DAMAGE_ORANGE_MISS = 10;   // orange hit gate without tex under it
const DAMAGE_ORANGE_SHOT = 12;   // shot an orange (worse than missing — destroyed evidence)

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

// ── Pixel-art draw routines for surface icons ───────────────────────────
// Each function paints a stylized pixel-art glyph centered in the given
// cell. They're intentionally chunky and silhouette-readable at speed.
// `palette` provides the fill / outline / accent colors per verdict.
function drawIcon(ctx, key, cx, cy, size, palette) {
  const s = size / 16; // each pixel = 1/16th of the cell
  const px = (gx, gy, w = 1, h = 1, color) => {
    ctx.fillStyle = color;
    ctx.fillRect(
      Math.round(cx - size / 2 + gx * s),
      Math.round(cy - size / 2 + gy * s),
      Math.ceil(w * s),
      Math.ceil(h * s),
    );
  };
  const { fill, outline, accent, dark } = palette;

  switch (key) {
    case "email": {
      // envelope
      px(2, 4, 12, 9, outline);
      px(3, 5, 10, 7, fill);
      // diagonals
      px(3, 5, 5, 1, dark);
      px(8, 5, 5, 1, dark);
      px(4, 6, 3, 1, dark);
      px(9, 6, 3, 1, dark);
      px(5, 7, 1, 1, dark);
      px(10, 7, 1, 1, dark);
      px(6, 7, 4, 1, dark);
      // accent dot
      px(7, 9, 2, 2, accent);
      break;
    }
    case "slack": {
      // hash with corner blocks
      px(3, 3, 2, 10, outline);
      px(8, 3, 2, 10, outline);
      px(2, 5, 12, 2, outline);
      px(2, 9, 12, 2, outline);
      px(3, 3, 2, 10, fill);
      px(8, 3, 2, 10, fill);
      px(2, 5, 12, 2, fill);
      px(2, 9, 12, 2, fill);
      // accent corners
      px(2, 3, 2, 2, accent);
      px(12, 11, 2, 2, accent);
      break;
    }
    case "sms": {
      // chat bubble
      px(2, 3, 12, 8, outline);
      px(3, 4, 10, 6, fill);
      // tail
      px(4, 11, 2, 2, outline);
      px(4, 11, 1, 1, fill);
      // dots
      px(5, 6, 2, 2, dark);
      px(8, 6, 2, 2, dark);
      px(11, 6, 1, 2, dark);
      break;
    }
    case "crm": {
      // person + chart bars
      px(6, 3, 4, 4, outline);
      px(7, 4, 2, 2, fill);
      px(4, 7, 8, 6, outline);
      px(5, 8, 6, 4, fill);
      // bars
      px(6, 10, 1, 2, accent);
      px(8, 9, 1, 3, accent);
      px(10, 8, 1, 4, accent);
      break;
    }
    case "db_api": {
      // database cylinder
      px(3, 3, 10, 2, outline);
      px(3, 5, 10, 2, fill);
      px(3, 7, 10, 1, outline);
      px(3, 8, 10, 2, fill);
      px(3, 10, 10, 1, outline);
      px(3, 11, 10, 2, fill);
      px(3, 13, 10, 1, outline);
      // top ellipse highlight
      px(5, 3, 6, 1, accent);
      break;
    }
    case "code_pr": {
      // angle brackets / commit
      px(3, 5, 2, 1, outline);
      px(2, 6, 2, 1, outline);
      px(3, 7, 2, 1, outline);
      px(11, 5, 2, 1, outline);
      px(12, 6, 2, 1, outline);
      px(11, 7, 2, 1, outline);
      // slash
      px(9, 4, 1, 1, fill);
      px(8, 5, 1, 1, fill);
      px(7, 6, 1, 1, fill);
      px(6, 7, 1, 1, fill);
      // commit dot
      px(7, 10, 2, 2, accent);
      px(7, 12, 2, 1, outline);
      break;
    }
    case "calendar": {
      // calendar
      px(3, 4, 10, 9, outline);
      px(4, 5, 8, 7, fill);
      // header band
      px(3, 4, 10, 2, accent);
      // pegs
      px(5, 3, 1, 2, outline);
      px(10, 3, 1, 2, outline);
      // day cells
      px(5, 7, 1, 1, dark);
      px(7, 7, 1, 1, dark);
      px(9, 7, 1, 1, dark);
      px(11, 7, 1, 1, dark);
      px(5, 9, 1, 1, dark);
      px(7, 9, 1, 1, dark);
      px(9, 9, 2, 2, accent); // a "marked" date
      break;
    }
    case "files": {
      // folder + share arrow
      px(2, 5, 6, 1, outline);
      px(2, 5, 12, 8, outline);
      px(3, 6, 10, 6, fill);
      // arrow up-right
      px(8, 9, 4, 1, accent);
      px(11, 8, 1, 3, accent);
      px(10, 7, 1, 1, accent);
      px(11, 6, 1, 2, accent);
      break;
    }
    case "financial": {
      // dollar sign / bill
      px(3, 3, 10, 10, outline);
      px(4, 4, 8, 8, fill);
      // S strokes
      px(6, 5, 4, 1, dark);
      px(6, 6, 1, 1, dark);
      px(6, 7, 4, 1, dark);
      px(9, 8, 1, 1, dark);
      px(6, 9, 4, 1, dark);
      // vertical bar
      px(7, 4, 1, 1, dark);
      px(7, 10, 1, 1, dark);
      // glint
      px(11, 4, 1, 1, accent);
      break;
    }
    default: {
      px(3, 3, 10, 10, outline);
      px(4, 4, 8, 8, fill);
    }
  }
}

// Verdict palette — tinted so even silhouette-readers see the call instantly
function paletteFor(verdict) {
  if (verdict === "PERMIT") return {
    fill:    "#1A4A2E",
    outline: "#5FFA9F",
    accent:  "#B5FFD0",
    dark:    "#0E2F1C",
    glow:    "rgba(95, 250, 159, 0.55)",
    aura:    "#5FFA9F",
  };
  if (verdict === "ABSTAIN") return {
    fill:    "#5A4410",
    outline: "#FFD83D",
    accent:  "#FFF1A8",
    dark:    "#3A2C08",
    glow:    "rgba(255, 216, 61, 0.55)",
    aura:    "#FFD83D",
  };
  // FORBID
  return {
    fill:    "#5A1414",
    outline: "#FF4747",
    accent:  "#FF8A8A",
    dark:    "#3A0808",
    glow:    "rgba(255, 71, 71, 0.6)",
    aura:    "#FF4747",
  };
}

// ── Tex sprite (canvas pixel-art) ───────────────────────────────────────
function drawTex(ctx, x, y, w, h, eyeFlash, recoil) {
  const sx = w / 16;
  const sy = h / 18;
  const px = (gx, gy, gw, gh, color) => {
    ctx.fillStyle = color;
    ctx.fillRect(
      Math.round(x - w / 2 + gx * sx),
      Math.round(y - h / 2 + gy * sy + (recoil ? 1 : 0)),
      Math.ceil(gw * sx),
      Math.ceil(gh * sy),
    );
  };

  // Helmet armor (dark plate)
  const armor = "#1B2150";
  const armorMid = "#2A3170";
  const armorLight = "#3D4690";
  const visor = eyeFlash || "#5FF0FF";

  // shoulders / lower body wedge
  px(1, 13, 14, 5, armor);
  px(2, 12, 12, 1, armorMid);
  px(0, 14, 16, 3, armor);
  px(1, 17, 14, 1, armorLight);

  // chest plate accent
  px(6, 14, 4, 2, armorMid);
  px(7, 14, 2, 1, "#5FF0FF");

  // helmet dome
  px(4, 2, 8, 1, armor);
  px(3, 3, 10, 1, armorMid);
  px(2, 4, 12, 8, armor);
  px(2, 4, 12, 1, armorLight);   // top edge highlight
  px(2, 11, 12, 1, armorLight);  // chin band

  // visor band (the iconic glowing strip)
  px(3, 6, 10, 3, "#000000");
  px(3, 6, 10, 1, visor);        // top glow line
  px(4, 7, 8, 1, visor);         // middle band
  px(3, 8, 10, 1, "#000000");

  // T-hex glyph on forehead
  px(7, 4, 2, 2, "#FF3D7A");

  // antenna / signal blip
  px(7, 0, 2, 2, "#FF3D7A");
  px(8, 1, 1, 1, "#FFFFFF");

  // recoil flash glow under chin
  if (recoil) {
    ctx.fillStyle = "rgba(95, 240, 255, 0.35)";
    ctx.fillRect(x - w / 2, y + h / 2 - 4, w, 4);
  }
}

// ── Component ───────────────────────────────────────────────────────────
export default function Arcade({ onComplete, onBail }) {
  const canvasRef = useRef(null);
  const containerRef = useRef(null);
  const gameRef = useRef(null);     // mutable game state (no React renders)
  const [phase, setPhase] = useState("ready"); // ready | playing | done
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

  const [overSummary, setOverSummary] = useState(null);

  // ── Input refs (so we don't rebind on every render) ───────────────────
  const inputRef = useRef({
    left: false, right: false, fire: false,
    pointerActive: false, pointerX: null,
    autoFire: true,
  });

  // ── Init / reset game state ───────────────────────────────────────────
  const initGame = useCallback(() => {
    gameRef.current = {
      tex: { x: LOGICAL_W / 2, y: LOGICAL_H - TEX_Y_FROM_BOTTOM, recoilUntil: 0, eyeFlashUntil: 0, eyeFlashColor: null },
      icons: [],          // falling action sprites
      lasers: [],         // player projectiles
      particles: [],      // hit particles
      capturedRing: [],   // ABSTAIN icons being absorbed (animation only)
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
  useEffect(() => {
    function onDown(e) {
      if (phase !== "playing") {
        if (e.key === "Escape") onBail?.();
        return;
      }
      if (e.key === "ArrowLeft" || e.key === "a" || e.key === "A") inputRef.current.left = true;
      else if (e.key === "ArrowRight" || e.key === "d" || e.key === "D") inputRef.current.right = true;
      else if (e.key === " " || e.code === "Space") {
        e.preventDefault();
        inputRef.current.fire = true;
      } else if (e.key === "Escape") onBail?.();
    }
    function onUp(e) {
      if (e.key === "ArrowLeft" || e.key === "a" || e.key === "A") inputRef.current.left = false;
      else if (e.key === "ArrowRight" || e.key === "d" || e.key === "D") inputRef.current.right = false;
      else if (e.key === " " || e.code === "Space") inputRef.current.fire = false;
    }
    window.addEventListener("keydown", onDown);
    window.addEventListener("keyup", onUp);
    return () => {
      window.removeEventListener("keydown", onDown);
      window.removeEventListener("keyup", onUp);
    };
  }, [phase, onBail]);

  // ── Pointer (mouse / touch) input ─────────────────────────────────────
  // Mouse: hover to move, hold left-click to fire.
  // Touch: drag anywhere to move; press the FIRE button (rendered as JSX
  // overlay) to fire. This separation prevents the "tap to move = accidental
  // shot" problem.
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    function localX(clientX) {
      const rect = canvas.getBoundingClientRect();
      const ratio = LOGICAL_W / rect.width;
      return (clientX - rect.left) * ratio;
    }
    function onPointerDown(e) {
      if (phase !== "playing") return;
      e.preventDefault();
      inputRef.current.pointerActive = true;
      inputRef.current.pointerX = localX(e.clientX ?? e.touches?.[0]?.clientX ?? 0);
      // Mouse button = fire. Touch = move only (fire button is separate).
      if (e.pointerType === "mouse" || e.type === "mousedown") {
        inputRef.current.fire = true;
      }
    }
    function onPointerMove(e) {
      if (!inputRef.current.pointerActive) return;
      e.preventDefault();
      inputRef.current.pointerX = localX(e.clientX ?? e.touches?.[0]?.clientX ?? 0);
    }
    function onPointerUp(e) {
      inputRef.current.pointerActive = false;
      inputRef.current.pointerX = null;
      if (e?.pointerType === "mouse" || e?.type === "mouseup") {
        inputRef.current.fire = false;
      }
    }

    canvas.addEventListener("pointerdown", onPointerDown);
    canvas.addEventListener("pointermove", onPointerMove);
    window.addEventListener("pointerup", onPointerUp);
    canvas.addEventListener("touchstart", onPointerDown, { passive: false });
    canvas.addEventListener("touchmove", onPointerMove,  { passive: false });
    canvas.addEventListener("touchend", onPointerUp);

    return () => {
      canvas.removeEventListener("pointerdown", onPointerDown);
      canvas.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", onPointerUp);
      canvas.removeEventListener("touchstart", onPointerDown);
      canvas.removeEventListener("touchmove", onPointerMove);
      canvas.removeEventListener("touchend", onPointerUp);
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

      // ── Fire ────────────────────────────────────────────────────────
      // Important: firing is a CHOICE — green icons should be let through.
      // Auto-fire would break that. So we require the player to actively
      // hold space (desktop) or tap-and-hold (mobile) to fire. The pointer
      // movement controls Tex; firing is a separate intentional action.
      const wantsFire = inp.fire;
      if (wantsFire && nowFrame - g.lastFire >= FIRE_COOLDOWN_MS) {
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
      for (const ic of g.icons) {
        if (ic.state !== "active") continue;
        ic.y += ic.vy * g.speedMult * dt;
        ic.rot += ic.rotSpeed * dt;
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
        g.capturedRing.push({
          id: ++g.iconCounter,
          x: ic.x, y: ic.y,
          targetX: g.tex.x, targetY: g.tex.y,
          surface: ic.surface,
          verdict: ic.verdict,
          spawnTime: now,
          life: 380,
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
      ctx.strokeStyle = pal.outline;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(x, y, sz * 0.7 * (1 - t * 0.5), 0, Math.PI * 2);
      ctx.stroke();
    }
    g.capturedRing = g.capturedRing.filter((c) => now - c.spawnTime < c.life);

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

    // ── Tex sprite ────────────────────────────────────────────────────
    const recoil = now < g.tex.recoilUntil;
    const eyeFlashColor = now < g.tex.eyeFlashUntil ? g.tex.eyeFlashColor : null;
    drawTex(ctx, g.tex.x, g.tex.y, TEX_W, TEX_H, eyeFlashColor, recoil);

    // ── Gate strip (bottom) ──────────────────────────────────────────
    drawGate(ctx, g);

    ctx.restore();
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

    // Glow halo
    ctx.globalAlpha = 0.85 * alpha;
    const haloR = ICON_SIZE * 1.05;
    const halo = ctx.createRadialGradient(ic.x, drawY, 4, ic.x, drawY, haloR);
    halo.addColorStop(0, pal.glow);
    halo.addColorStop(0.6, pal.glow.replace(/[\d.]+\)$/, "0.18)"));
    halo.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = halo;
    ctx.beginPath();
    ctx.arc(ic.x, drawY, haloR, 0, Math.PI * 2);
    ctx.fill();
    ctx.globalAlpha = alpha;

    // Containment frame (bracket corners) so it reads as "an action capsule"
    const half = ICON_SIZE / 2;
    ctx.strokeStyle = pal.outline;
    ctx.lineWidth = 2;
    const cl = 10;
    // top-left
    ctx.beginPath();
    ctx.moveTo(ic.x - half, drawY - half + cl); ctx.lineTo(ic.x - half, drawY - half); ctx.lineTo(ic.x - half + cl, drawY - half);
    // top-right
    ctx.moveTo(ic.x + half - cl, drawY - half); ctx.lineTo(ic.x + half, drawY - half); ctx.lineTo(ic.x + half, drawY - half + cl);
    // bot-left
    ctx.moveTo(ic.x - half, drawY + half - cl); ctx.lineTo(ic.x - half, drawY + half); ctx.lineTo(ic.x - half + cl, drawY + half);
    // bot-right
    ctx.moveTo(ic.x + half - cl, drawY + half); ctx.lineTo(ic.x + half, drawY + half); ctx.lineTo(ic.x + half, drawY + half - cl);
    ctx.stroke();

    // Pixel-art icon
    drawIcon(ctx, ic.surface, ic.x, drawY, ICON_SIZE * 0.78, pal);

    // Verdict tick mark in corner
    ctx.fillStyle = pal.outline;
    ctx.fillRect(ic.x + half - 8, drawY - half + 2, 6, 2);

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

    // Tex's column highlight (where ABSTAIN captures)
    const colCenter = g.tex.x;
    const colHalf = ABSTAIN_CAPTURE_TOLERANCE;
    const colGrad = ctx.createLinearGradient(colCenter - colHalf, 0, colCenter + colHalf, 0);
    colGrad.addColorStop(0, "rgba(95, 240, 255, 0)");
    colGrad.addColorStop(0.5, "rgba(95, 240, 255, 0.10)");
    colGrad.addColorStop(1, "rgba(95, 240, 255, 0)");
    ctx.fillStyle = colGrad;
    ctx.fillRect(colCenter - colHalf, 0, colHalf * 2, LOGICAL_H);
  }

  // ── HUD click handlers ────────────────────────────────────────────────
  const handleBail = () => { clickSfx(); onBail?.(); };

  // Mobile FIRE button — onTouchStart/End so we don't conflict with canvas
  // pointer events. The button only renders on touch devices via CSS.
  const fireBtnDown = (e) => { e.preventDefault(); inputRef.current.fire = true; };
  const fireBtnUp   = (e) => { e.preventDefault(); inputRef.current.fire = false; };

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

      {/* Mobile FIRE button — only shows on touch devices */}
      <button
        className="arcade-fire-btn"
        onTouchStart={fireBtnDown}
        onTouchEnd={fireBtnUp}
        onTouchCancel={fireBtnUp}
        onMouseDown={fireBtnDown}
        onMouseUp={fireBtnUp}
        onMouseLeave={fireBtnUp}
        aria-label="Fire laser"
      >
        <span className="arcade-fire-btn-glyph">⏵</span>
        <span className="arcade-fire-btn-label">FIRE</span>
      </button>

      {/* Verdict legend strip */}
      <div className="arcade-legend">
        <div className="arcade-legend-item">
          <span className="legend-swatch" style={{ background: "#5FFA9F" }} />
          <span><b>GREEN</b> · let through</span>
        </div>
        <div className="arcade-legend-item">
          <span className="legend-swatch" style={{ background: "#FFD83D" }} />
          <span><b>ORANGE</b> · stand under to capture</span>
        </div>
        <div className="arcade-legend-item">
          <span className="legend-swatch" style={{ background: "#FF4747" }} />
          <span><b>RED</b> · shoot it down</span>
        </div>
      </div>

      {/* Ready overlay */}
      {phase === "ready" && (
        <div className="arcade-overlay arcade-ready">
          <div className="arcade-ready-num">{readyNum > 0 ? readyNum : "GO"}</div>
          <div className="arcade-ready-sub">DEFEND THE GATE</div>
          <div className="arcade-ready-tip">
            ← / → or drag to move &nbsp;·&nbsp; HOLD SPACE / FIRE to shoot RED
            <br />
            <span style={{ opacity: 0.7 }}>let GREEN through &nbsp;·&nbsp; stand under ORANGE to capture</span>
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
