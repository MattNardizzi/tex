// ────────────────────────────────────────────────────────────────────────
//  TEX ARENA — Sound engine
// ────────────────────────────────────────────────────────────────────────
//  All sounds generated via Web Audio API. Zero audio files. No network
//  cost. Muted by default. User-toggleable from the corner button.
//  Persisted preference in localStorage.
// ────────────────────────────────────────────────────────────────────────

const KEY_SOUND = "tex-arena/sound-on/v1";

let _ctx = null;
let _masterGain = null;
let _enabled = null;   // lazy-read from storage on first access

function getEnabled() {
  if (_enabled !== null) return _enabled;
  try {
    _enabled = localStorage.getItem(KEY_SOUND) === "1";
  } catch {
    _enabled = false;
  }
  return _enabled;
}

export function setSoundEnabled(on) {
  _enabled = Boolean(on);
  try {
    localStorage.setItem(KEY_SOUND, _enabled ? "1" : "0");
  } catch {}
  // When enabling sound, also try to resume the audio context
  // (browsers suspend it until user gesture — this call often IS the gesture)
  if (_enabled && _ctx && _ctx.state === "suspended") {
    _ctx.resume().catch(() => {});
  }
}

export function isSoundEnabled() {
  return getEnabled();
}

function ensureCtx() {
  if (typeof window === "undefined") return null;
  if (_ctx) return _ctx;
  const Ctx = window.AudioContext || window.webkitAudioContext;
  if (!Ctx) return null;
  _ctx = new Ctx();
  _masterGain = _ctx.createGain();
  _masterGain.gain.value = 0.25;  // moderate overall volume
  _masterGain.connect(_ctx.destination);
  return _ctx;
}

function nowPlus(ctx, t) {
  return ctx.currentTime + t;
}

// Generic tone with ADSR envelope
function tone({ freq, type = "sine", duration = 0.2, attack = 0.005, decay = 0.05, sustain = 0.3, release = 0.08, vol = 0.5, delay = 0 }) {
  if (!getEnabled()) return;
  const ctx = ensureCtx();
  if (!ctx) return;

  const osc = ctx.createOscillator();
  const gain = ctx.createGain();
  osc.type = type;
  osc.frequency.value = freq;

  const t0 = nowPlus(ctx, delay);
  gain.gain.setValueAtTime(0, t0);
  gain.gain.linearRampToValueAtTime(vol, t0 + attack);
  gain.gain.linearRampToValueAtTime(vol * sustain, t0 + attack + decay);
  gain.gain.linearRampToValueAtTime(0, t0 + duration + release);

  osc.connect(gain).connect(_masterGain);
  osc.start(t0);
  osc.stop(t0 + duration + release + 0.05);
}

// Short noise burst (for thuds, hits)
function noiseBurst({ duration = 0.08, vol = 0.35, freq = 400, filterType = "lowpass", delay = 0 }) {
  if (!getEnabled()) return;
  const ctx = ensureCtx();
  if (!ctx) return;

  const bufferSize = Math.max(1, Math.floor(ctx.sampleRate * duration));
  const buffer = ctx.createBuffer(1, bufferSize, ctx.sampleRate);
  const data = buffer.getChannelData(0);
  for (let i = 0; i < bufferSize; i++) {
    data[i] = (Math.random() * 2 - 1) * (1 - i / bufferSize);  // decay envelope
  }

  const src = ctx.createBufferSource();
  src.buffer = buffer;
  const filter = ctx.createBiquadFilter();
  filter.type = filterType;
  filter.frequency.value = freq;
  const gain = ctx.createGain();
  gain.gain.value = vol;

  const t0 = nowPlus(ctx, delay);
  src.connect(filter).connect(gain).connect(_masterGain);
  src.start(t0);
}

// ────────────────────────────────────────────────────────────────────────
//  Public sound events — tuned for arcade boxing feel
// ────────────────────────────────────────────────────────────────────────

// Soft UI click — round selection, button presses
export function clickSound() {
  tone({ freq: 880, type: "square", duration: 0.04, attack: 0.002, decay: 0.01, sustain: 0.0, release: 0.03, vol: 0.18 });
}

// Round-start bell (ding ding)
export function bellSound() {
  tone({ freq: 1568, type: "triangle", duration: 0.35, attack: 0.002, decay: 0.1, sustain: 0.3, release: 0.6, vol: 0.45 });
  tone({ freq: 1568, type: "triangle", duration: 0.35, attack: 0.002, decay: 0.1, sustain: 0.3, release: 0.6, vol: 0.45, delay: 0.18 });
  // Add a little harmonic
  tone({ freq: 3136, type: "sine", duration: 0.5, attack: 0.002, decay: 0.1, sustain: 0.2, release: 0.5, vol: 0.12 });
}

// Punch thud when player submits
export function punchSound() {
  noiseBurst({ duration: 0.12, vol: 0.6, freq: 180, filterType: "lowpass" });
  tone({ freq: 120, type: "sine", duration: 0.1, attack: 0.001, decay: 0.03, sustain: 0.3, release: 0.1, vol: 0.5 });
}

// Thinking beep — subtle radar blip during evaluation
export function thinkBlip() {
  tone({ freq: 1200, type: "sine", duration: 0.04, attack: 0.002, decay: 0.01, sustain: 0.0, release: 0.05, vol: 0.1 });
}

// WIN — triumphant fanfare + cheer
export function winFanfare() {
  // Rising major triad
  const notes = [523.25, 659.25, 783.99, 1046.5];  // C5 E5 G5 C6
  notes.forEach((n, i) => {
    tone({ freq: n, type: "triangle", duration: 0.18, attack: 0.01, decay: 0.05, sustain: 0.6, release: 0.2, vol: 0.38, delay: i * 0.08 });
  });
  // Sustained chord
  tone({ freq: 523.25, type: "sawtooth", duration: 0.4, attack: 0.02, decay: 0.1, sustain: 0.5, release: 0.5, vol: 0.2, delay: 0.32 });
  tone({ freq: 783.99, type: "sawtooth", duration: 0.4, attack: 0.02, decay: 0.1, sustain: 0.5, release: 0.5, vol: 0.2, delay: 0.32 });
  // Crowd-like noise swell
  noiseBurst({ duration: 0.8, vol: 0.15, freq: 1200, filterType: "bandpass", delay: 0.1 });
}

// LOSE — low brass buzz, K.O. stinger
export function loseSting() {
  tone({ freq: 220, type: "sawtooth", duration: 0.3, attack: 0.01, decay: 0.1, sustain: 0.5, release: 0.2, vol: 0.35 });
  tone({ freq: 185, type: "sawtooth", duration: 0.3, attack: 0.01, decay: 0.1, sustain: 0.5, release: 0.2, vol: 0.3, delay: 0.08 });
  tone({ freq: 147, type: "sawtooth", duration: 0.5, attack: 0.01, decay: 0.15, sustain: 0.4, release: 0.4, vol: 0.28, delay: 0.16 });
  noiseBurst({ duration: 0.2, vol: 0.25, freq: 200, filterType: "lowpass" });
}

// DRAW — short ambiguous chime
export function drawChime() {
  tone({ freq: 440, type: "sine", duration: 0.22, attack: 0.01, decay: 0.05, sustain: 0.4, release: 0.3, vol: 0.3 });
  tone({ freq: 466.16, type: "sine", duration: 0.22, attack: 0.01, decay: 0.05, sustain: 0.4, release: 0.3, vol: 0.28, delay: 0.04 });
}

// Coin sound for points
export function coinSound() {
  tone({ freq: 987.77, type: "square", duration: 0.06, attack: 0.002, decay: 0.01, sustain: 0.3, release: 0.05, vol: 0.2 });
  tone({ freq: 1318.5, type: "square", duration: 0.1, attack: 0.002, decay: 0.01, sustain: 0.3, release: 0.1, vol: 0.2, delay: 0.05 });
}

// Rank up — the celebratory unlock sound
export function rankUpSound() {
  const notes = [523.25, 659.25, 783.99, 1046.5, 1318.5];
  notes.forEach((n, i) => {
    tone({ freq: n, type: "triangle", duration: 0.12, attack: 0.005, decay: 0.03, sustain: 0.5, release: 0.15, vol: 0.3, delay: i * 0.06 });
  });
}
