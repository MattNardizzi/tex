// ────────────────────────────────────────────────────────────────────
//  Tex sound library — Web Audio, layered with body weight.
//  Mute persisted to localStorage.
// ────────────────────────────────────────────────────────────────────

const MUTE_KEY = "tex.arena.mute.v8";

let ctx = null;
let masterGain = null;
function audio() {
  if (typeof window === "undefined") return null;
  if (!ctx) {
    try {
      ctx = new (window.AudioContext || window.webkitAudioContext)();
      masterGain = ctx.createGain();
      masterGain.gain.value = 0.85;
      masterGain.connect(ctx.destination);
    } catch { return null; }
  }
  return ctx;
}
function dest() { audio(); return masterGain; }

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

// ── Primitive: tone ────────────────────────────────────────────────
function tone({ freq, freqEnd, dur = 0.12, type = "sine", gain = 0.08, when = 0, attack = 0.005 }) {
  if (isMuted()) return;
  const a = audio(); if (!a) return;
  const t0 = a.currentTime + when;
  const osc = a.createOscillator();
  const g = a.createGain();
  osc.type = type;
  osc.frequency.setValueAtTime(freq, t0);
  if (freqEnd != null) osc.frequency.exponentialRampToValueAtTime(Math.max(20, freqEnd), t0 + dur);
  g.gain.setValueAtTime(0.0001, t0);
  g.gain.exponentialRampToValueAtTime(gain, t0 + attack);
  g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
  osc.connect(g); g.connect(dest());
  osc.start(t0);
  osc.stop(t0 + dur + 0.02);
}

// ── Primitive: noise burst (filtered) ──────────────────────────────
function noise({ dur = 0.08, gain = 0.06, when = 0, filterFreq = 1800, filterType = "lowpass", q = 0.7 }) {
  if (isMuted()) return;
  const a = audio(); if (!a) return;
  const t0 = a.currentTime + when;
  const buf = a.createBuffer(1, Math.floor(a.sampleRate * dur), a.sampleRate);
  const data = buf.getChannelData(0);
  for (let i = 0; i < data.length; i++) data[i] = Math.random() * 2 - 1;
  const src = a.createBufferSource();
  src.buffer = buf;
  const filter = a.createBiquadFilter();
  filter.type = filterType;
  filter.frequency.value = filterFreq;
  filter.Q.value = q;
  const g = a.createGain();
  g.gain.setValueAtTime(0.0001, t0);
  g.gain.exponentialRampToValueAtTime(gain, t0 + 0.005);
  g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
  src.connect(filter); filter.connect(g); g.connect(dest());
  src.start(t0);
  src.stop(t0 + dur + 0.01);
}

// ── UI ─────────────────────────────────────────────────────────────
export function clickSfx() {
  tone({ freq: 620, dur: 0.04, type: "square", gain: 0.04 });
}
export function sendSfx()  { tone({ freq: 380, dur: 0.06, type: "triangle", gain: 0.06 }); }
export function tickSfx()  { tone({ freq: 260, dur: 0.03, type: "square",   gain: 0.03 }); }
export function tickClockSfx() { tone({ freq: 880, dur: 0.02, type: "square", gain: 0.025 }); }

// ── Verdict thunks (layered: synth + low thump for weight) ─────────
export function permitSfx() {
  // Bright two-tone chime + soft body thud
  tone({ freq: 720, dur: 0.06, type: "sine", gain: 0.06 });
  tone({ freq: 960, dur: 0.10, type: "sine", gain: 0.05, when: 0.04 });
  tone({ freq: 80, freqEnd: 50, dur: 0.10, type: "sine", gain: 0.04 });
}
export function abstainSfx() {
  // Single mid-tone with body
  tone({ freq: 540, dur: 0.10, type: "triangle", gain: 0.06 });
  tone({ freq: 90, freqEnd: 60, dur: 0.10, type: "sine", gain: 0.04 });
  noise({ dur: 0.04, gain: 0.02, filterFreq: 1200, filterType: "highpass" });
}
export function forbidSfx() {
  // Laser sweep + impact thump + crackle
  tone({ freq: 2200, freqEnd: 220, dur: 0.18, type: "sawtooth", gain: 0.10 });
  tone({ freq: 90,   freqEnd: 50,  dur: 0.22, type: "sine",     gain: 0.08, when: 0.06 });
  noise({ dur: 0.10, gain: 0.05, filterFreq: 800, filterType: "lowpass", when: 0.06 });
}

// ── Breach (low industrial throb + sub drop) ───────────────────────
export function breachSfx() {
  if (isMuted()) return;
  tone({ freq: 220, freqEnd: 90,  dur: 0.40, type: "sawtooth", gain: 0.10 });
  tone({ freq: 60,  freqEnd: 40,  dur: 0.50, type: "sine",     gain: 0.10, when: 0.04 });
  tone({ freq: 180, freqEnd: 140, dur: 0.30, type: "sawtooth", gain: 0.08, when: 0.20 });
  tone({ freq: 110, freqEnd:  70, dur: 0.40, type: "sawtooth", gain: 0.06, when: 0.45 });
  noise({ dur: 0.30, gain: 0.04, filterFreq: 400, filterType: "lowpass", when: 0.05 });
}

// ── Shift end / rank up ────────────────────────────────────────────
export function shiftEndSfx() {
  tone({ freq: 440, dur: 0.10, type: "sine", gain: 0.07 });
  tone({ freq: 523, dur: 0.10, type: "sine", gain: 0.07, when: 0.10 });
  tone({ freq: 659, dur: 0.18, type: "sine", gain: 0.07, when: 0.20 });
  tone({ freq: 80,  dur: 0.36, type: "sine", gain: 0.05 });
}
export function rankUpSfx() {
  tone({ freq: 523,  dur: 0.08, type: "sine", gain: 0.08 });
  tone({ freq: 659,  dur: 0.08, type: "sine", gain: 0.08, when: 0.08 });
  tone({ freq: 784,  dur: 0.08, type: "sine", gain: 0.08, when: 0.16 });
  tone({ freq: 1047, dur: 0.24, type: "sine", gain: 0.08, when: 0.24 });
  tone({ freq: 100,  dur: 0.40, type: "sine", gain: 0.06 });
}

// ── Charge bloom (fired right before laser) ────────────────────────
export function chargeSfx() {
  tone({ freq: 200, freqEnd: 1200, dur: 0.12, type: "sawtooth", gain: 0.05 });
}

// ── Combo / streak ping ────────────────────────────────────────────
export function streakSfx(level = 1) {
  const base = 600 + level * 80;
  tone({ freq: base, dur: 0.06, type: "sine", gain: 0.05 });
  tone({ freq: base * 1.5, dur: 0.10, type: "sine", gain: 0.04, when: 0.05 });
}

// ── Card spawn (whoosh) ────────────────────────────────────────────
export function spawnSfx() {
  noise({ dur: 0.08, gain: 0.025, filterFreq: 600, filterType: "highpass", q: 1.5 });
}

// ── Compat shims ───────────────────────────────────────────────────
export const winSfx = permitSfx;
export const loseSfx = breachSfx;
export const partialSfx = abstainSfx;
