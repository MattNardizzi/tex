// ────────────────────────────────────────────────────────────────────
//  Tiny sound library — Web Audio API, no file deps.
//  Respects a user-toggleable mute flag in localStorage.
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

function beep(freq, duration = 0.12, type = "sine", gain = 0.08) {
  if (isMuted()) return;
  const a = audio();
  if (!a) return;
  const osc = a.createOscillator();
  const g = a.createGain();
  osc.type = type;
  osc.frequency.setValueAtTime(freq, a.currentTime);
  g.gain.setValueAtTime(gain, a.currentTime);
  g.gain.exponentialRampToValueAtTime(0.0001, a.currentTime + duration);
  osc.connect(g);
  g.connect(a.destination);
  osc.start();
  osc.stop(a.currentTime + duration);
}

export function clickSfx() { beep(620, 0.04, "square", 0.04); }
export function sendSfx() { beep(380, 0.06, "triangle", 0.06); }
export function tickSfx() { beep(260, 0.03, "square", 0.03); }

export function winSfx() {
  beep(660, 0.1, "sine", 0.08);
  setTimeout(() => beep(990, 0.16, "sine", 0.08), 90);
  setTimeout(() => beep(1320, 0.22, "sine", 0.08), 220);
}
export function loseSfx() {
  beep(180, 0.2, "sawtooth", 0.06);
  setTimeout(() => beep(110, 0.3, "sawtooth", 0.06), 160);
}
export function partialSfx() {
  beep(520, 0.12, "triangle", 0.06);
  setTimeout(() => beep(440, 0.12, "triangle", 0.06), 110);
}
export function rankUpSfx() {
  beep(523, 0.08, "sine", 0.08);
  setTimeout(() => beep(659, 0.08, "sine", 0.08), 80);
  setTimeout(() => beep(784, 0.08, "sine", 0.08), 160);
  setTimeout(() => beep(1047, 0.24, "sine", 0.08), 240);
}
