// ────────────────────────────────────────────────────────────────────
//  Tex sound library — Web Audio, no file deps. Mute respected.
// ────────────────────────────────────────────────────────────────────

const MUTE_KEY = "tex.arena.mute.v8";

let ctx = null;
function audio() {
  if (typeof window === "undefined") return null;
  if (!ctx) {
    try { ctx = new (window.AudioContext || window.webkitAudioContext)(); }
    catch { return null; }
  }
  return ctx;
}

export function isMuted() {
  if (typeof window === "undefined") return true;
  return localStorage.getItem(MUTE_KEY) === "1";
}
export function setMuted(m) {
  if (typeof window === "undefined") return;
  localStorage.setItem(MUTE_KEY, m ? "1" : "0");
}
export function toggleMute() {
  setMuted(!isMuted());
  return isMuted();
}

function beep(freq, duration = 0.12, type = "sine", gain = 0.08, when = 0) {
  if (isMuted()) return;
  const a = audio();
  if (!a) return;
  const t0 = a.currentTime + when;
  const osc = a.createOscillator();
  const g = a.createGain();
  osc.type = type;
  osc.frequency.setValueAtTime(freq, t0);
  g.gain.setValueAtTime(gain, t0);
  g.gain.exponentialRampToValueAtTime(0.0001, t0 + duration);
  osc.connect(g);
  g.connect(a.destination);
  osc.start(t0);
  osc.stop(t0 + duration);
}

// ─── Legacy / general ────────────────────────────────────────────────
export function clickSfx() { beep(620, 0.04, "square", 0.04); }
export function sendSfx() { beep(380, 0.06, "triangle", 0.06); }
export function tickSfx() { beep(260, 0.03, "square", 0.03); }

// ─── Conveyor verdicts ──────────────────────────────────────────────
export function permitSfx() {
  beep(720, 0.06, "sine", 0.06);
  beep(960, 0.10, "sine", 0.05, 0.04);
}
export function abstainSfx() {
  beep(540, 0.10, "triangle", 0.06);
}
export function forbidSfx() {
  // Laser — fast falling sweep
  if (isMuted()) return;
  const a = audio();
  if (!a) return;
  const t0 = a.currentTime;
  const osc = a.createOscillator();
  const g = a.createGain();
  osc.type = "sawtooth";
  osc.frequency.setValueAtTime(2200, t0);
  osc.frequency.exponentialRampToValueAtTime(220, t0 + 0.18);
  g.gain.setValueAtTime(0.10, t0);
  g.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.22);
  osc.connect(g);
  g.connect(a.destination);
  osc.start(t0);
  osc.stop(t0 + 0.24);
}

// ─── Breach (player let a leak through) ─────────────────────────────
export function breachSfx() {
  if (isMuted()) return;
  beep(180, 0.20, "sawtooth", 0.10);
  beep(140, 0.30, "sawtooth", 0.10, 0.18);
  beep(110, 0.40, "sawtooth", 0.08, 0.45);
}

// ─── End-of-shift cues ──────────────────────────────────────────────
export function shiftEndSfx() {
  beep(440, 0.10, "sine", 0.07);
  beep(523, 0.10, "sine", 0.07, 0.10);
  beep(659, 0.18, "sine", 0.07, 0.20);
}
export function rankUpSfx() {
  beep(523, 0.08, "sine", 0.08);
  beep(659, 0.08, "sine", 0.08, 0.08);
  beep(784, 0.08, "sine", 0.08, 0.16);
  beep(1047, 0.24, "sine", 0.08, 0.24);
}
export function tickClockSfx() { beep(880, 0.02, "square", 0.025); }

// ─── Backwards-compat shims ──────────────────────────────────────────
export const winSfx = permitSfx;
export const loseSfx = breachSfx;
export const partialSfx = abstainSfx;
