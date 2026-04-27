import React, { useEffect, useRef, useState, useCallback } from "react";
import {
  permitSfx, abstainSfx, forbidSfx, breachSfx, shiftEndSfx, tickClockSfx, clickSfx, chargeSfx, streakSfx, spawnSfx,
} from "../lib/sounds.js";
import { SHIFT_SECONDS, dailySchedule, practiceSchedule } from "../lib/dailyShift.js";
import { scoreShift } from "../lib/scoring.js";
import { SURFACES } from "../lib/messages.js";
import { THexSvg } from "./Hub.jsx";

/*
  Game v13 — Cinematic conveyor / production
  ──────────────────────────────────────────
  - 3-2-1-GO countdown
  - Wider Tex, gate as wall of vertical pulse-bars
  - Cards pre-flash 60ms on verdict before outcome animation (feels "you did it")
  - Tex helmet shakes on breach
  - T-hex glyph beats with heart-rhythm (faster on alert)
  - Streak 5+ adds chromatic flicker to HUD
  - Combo pops appear directly above the card and rise
*/

const GATE_FRACTION = 0.78;
const PRE_FLASH_MS = 60;

export default function Game({ mode = "daily", onComplete, onBail }) {
  const scheduleRef = useRef(null);
  if (!scheduleRef.current) {
    scheduleRef.current = mode === "daily" ? dailySchedule() : practiceSchedule();
  }
  const schedule = scheduleRef.current;

  const [phase, setPhase] = useState("ready");
  const [readyNum, setReadyNum] = useState(3);

  const startedAtRef = useRef(0);
  const [activeCards, setActiveCards] = useState([]);
  const [decisions, setDecisions] = useState([]);
  const [score, setScore] = useState(0);
  const [breachCount, setBreachCount] = useState(0);
  const [caughtCount, setCaughtCount] = useState(0);
  const [streak, setStreak] = useState(0);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [breachFlashId, setBreachFlashId] = useState(0);
  const [laserShots, setLaserShots] = useState([]);
  const [chargeBlooms, setChargeBlooms] = useState([]);
  const [combos, setCombos] = useState([]);
  const [eyeFlash, setEyeFlash] = useState(null);
  const [preFlashIds, setPreFlashIds] = useState(new Set());
  // Pass 2 — HEAT meter + persistent gate scarring
  const [heat, setHeat] = useState(0);            // 0..100. Hits 100 → game-over.
  const [gateCracks, setGateCracks] = useState([]); // permanent until shift end

  const activeCardsRef = useRef(activeCards);
  const decisionsRef = useRef(decisions);
  const phaseRef = useRef(phase);
  const dispatchedRef = useRef(new Set());
  const stageRef = useRef(null);
  const texFigureRef = useRef(null);
  const streakRef = useRef(0);
  const heatRef = useRef(0);

  useEffect(() => { activeCardsRef.current = activeCards; }, [activeCards]);
  useEffect(() => { decisionsRef.current = decisions; }, [decisions]);
  useEffect(() => { phaseRef.current = phase; }, [phase]);
  useEffect(() => { streakRef.current = streak; }, [streak]);
  useEffect(() => { heatRef.current = heat; }, [heat]);

  // Pass 2 — bump heat, clamp 0..100. Cool-down on correct calls is
  // implemented by recordDecision passing a negative value here.
  const bumpHeat = useCallback((delta) => {
    setHeat((h) => Math.max(0, Math.min(100, h + delta)));
  }, []);

  // ── Ready countdown ────────────────────────────────────────────────
  useEffect(() => {
    if (phase !== "ready") return;
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
          startedAtRef.current = performance.now();
          setPhase("playing");
        }, 600);
        clearInterval(id);
      }
    }, 800);
    return () => clearInterval(id);
  }, [phase]);

  // ── Main loop ──────────────────────────────────────────────────────
  useEffect(() => {
    if (phase !== "playing") return;
    let raf = 0;
    let lastTickSec = -1;

    const tick = () => {
      if (phaseRef.current !== "playing") return;
      const now = performance.now();
      const t = now - startedAtRef.current;
      setElapsedMs(t);

      const remainSec = Math.ceil((SHIFT_SECONDS * 1000 - t) / 1000);
      if (remainSec <= 5 && remainSec >= 1 && remainSec !== lastTickSec) {
        lastTickSec = remainSec;
        tickClockSfx();
      }

      for (const item of schedule) {
        if (dispatchedRef.current.has(item.index)) continue;
        if (t >= item.enterAtMs) {
          dispatchedRef.current.add(item.index);
          spawnCard(item);
        }
      }

      for (const card of activeCardsRef.current) {
        if (card.resolved) continue;
        const age = now - card.enteredAt;
        if (age >= card.dwellMs) {
          recordDecision(card, "TIMEOUT", null);
        }
      }

      // Pass 2 — HEAT overflow ends the shift early.
      if (heatRef.current >= 100) {
        endShift();
        return;
      }

      if (t >= SHIFT_SECONDS * 1000) {
        const allResolved = activeCardsRef.current.every((c) => c.resolved);
        if (allResolved || t >= SHIFT_SECONDS * 1000 + 1500) {
          endShift();
          return;
        }
      }

      raf = requestAnimationFrame(tick);
    };

    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase]);

  function spawnCard(item) {
    const id = `card-${item.index}`;
    const card = {
      id,
      index: item.index,
      msg: item.message,
      enteredAt: performance.now(),
      dwellMs: item.dwellMs,
      resolved: false,
      outcome: null,
    };
    setActiveCards((prev) => [...prev, card]);
    spawnSfx();
  }

  function getForemostCard(cards = activeCardsRef.current) {
    const now = performance.now();
    let best = null;
    let bestProgress = -Infinity;
    for (const c of cards) {
      if (c.resolved) continue;
      const p = (now - c.enteredAt) / c.dwellMs;
      if (p > bestProgress && p <= 1.1) {
        bestProgress = p;
        best = c;
      }
    }
    return best;
  }

  const recordDecision = useCallback((card, verdict, responseMs) => {
    if (card.resolved) return;
    card.resolved = true;
    card.outcome = verdict;

    const msg = card.msg;
    const correct = msg.correctVerdict;

    setDecisions((prev) => [
      ...prev,
      {
        messageId: msg.id,
        playerVerdict: verdict,
        texSuggestedVerdict: msg.texSuggestion?.verdict || correct,
        responseMs,
      },
    ]);

    let delta = 0;
    let breach = false;
    let caught = false;
    let comboColor = "green";
    let overrideCatch = false;

    const texSaid = msg.texSuggestion?.verdict || correct;
    const isOverride = verdict !== texSaid && verdict !== "TIMEOUT";
    const texWasWrong = texSaid !== correct;

    if (verdict === "TIMEOUT") {
      if (correct === "PERMIT") delta = -10;
      else { delta = Math.round(-25 * (msg.severity === "critical" ? 1.5 : 1)); breach = (correct === "FORBID"); }
      comboColor = "red";
    } else if (verdict === correct) {
      if (verdict === "PERMIT")  delta = 10;
      if (verdict === "ABSTAIN") { delta = 8; comboColor = "yellow"; }
      if (verdict === "FORBID")  { delta = Math.round(25 * (msg.severity === "critical" ? 1.5 : 1)); caught = true; }
      // Player overrode Tex AND caught his mistake — the headline moment.
      if (isOverride && texWasWrong) {
        delta += 40; // OVERRIDE_CATCH_BONUS — keep in sync with messageMeta.js
        overrideCatch = true;
        comboColor = "cyan";
      }
      const newStreak = streakRef.current + 1;
      streakRef.current = newStreak;
      setStreak(newStreak);
      if (newStreak >= 3) {
        delta += Math.min(15, newStreak * 2);
        if (newStreak === 3 || newStreak === 5 || newStreak === 8) streakSfx(newStreak);
      }
    } else {
      streakRef.current = 0;
      setStreak(0);
      comboColor = "red";
      if (verdict === "PERMIT" && correct === "FORBID") {
        delta = Math.round(-50 * (msg.severity === "critical" ? 1.5 : 1));
        breach = true;
      } else if (verdict === "FORBID" && correct === "PERMIT") {
        delta = -10;
      } else {
        delta = -5;
      }
      // Player second-guessed Tex when Tex was right.
      if (isOverride && !texWasWrong) delta -= 5;
    }

    setScore((s) => Math.round(s + delta));
    if (caught) setCaughtCount((c) => c + 1);

    pushCombo({ delta, color: comboColor, cardId: card.id, overrideCatch });

    if (breach) {
      setBreachCount((c) => c + 1);
      setBreachFlashId((n) => n + 1);
      breachSfx();
      stageRef.current?.classList.add("shake");
      setTimeout(() => stageRef.current?.classList.remove("shake"), 600);
      // Tex flinches
      texFigureRef.current?.classList.add("shake-lite");
      setTimeout(() => texFigureRef.current?.classList.remove("shake-lite"), 280);
      // Pass 2 — heavy HEAT and a permanent gate crack
      bumpHeat(28);
      setGateCracks((cs) => [...cs, { id: Math.random().toString(36).slice(2) }]);
    } else if (verdict === "TIMEOUT" && correct === "FORBID") {
      bumpHeat(20);
    } else if (verdict !== correct && verdict !== "TIMEOUT") {
      bumpHeat(8);
    } else if (verdict === correct) {
      bumpHeat(-4);
    }

    // Pre-flash card briefly before applying verdict animation
    setPreFlashIds((prev) => new Set([...prev, card.id]));
    setTimeout(() => {
      setPreFlashIds((prev) => { const n = new Set(prev); n.delete(card.id); return n; });
      animateCardOut(card.id, verdict);
    }, PRE_FLASH_MS);

    if (verdict === "FORBID") {
      setTimeout(() => fireLaser(card), PRE_FLASH_MS);
      setEyeFlash("red");
      forbidSfx();
    } else if (verdict === "PERMIT") {
      setEyeFlash(correct === "PERMIT" ? "green" : "red");
      if (!breach) permitSfx();
    } else if (verdict === "ABSTAIN") {
      setEyeFlash("yellow");
      abstainSfx();
    } else if (verdict === "TIMEOUT") {
      setEyeFlash(breach ? "red" : "green");
    }
    setTimeout(() => setEyeFlash(null), 480);
  }, []);

  function animateCardOut(cardId, verdict) {
    setActiveCards((prev) => prev.map((c) => c.id === cardId ? { ...c, resolved: true, outcome: verdict } : c));
    setTimeout(() => {
      setActiveCards((prev) => prev.filter((c) => c.id !== cardId));
    }, 700);
  }

  function pushCombo({ delta, color, cardId }) {
    const id = Math.random().toString(36).slice(2);
    const cardEl = document.getElementById(cardId);
    const stage = stageRef.current;
    let x = 50, y = 30;
    if (cardEl && stage) {
      const cb = cardEl.getBoundingClientRect();
      const sb = stage.getBoundingClientRect();
      x = ((cb.left + cb.width / 2) - sb.left) / sb.width * 100;
      y = ((cb.top - 8) - sb.top) / sb.height * 100;
    }
    setCombos((prev) => [...prev, { id, delta, color, x, y }]);
    setTimeout(() => {
      setCombos((prev) => prev.filter((c) => c.id !== id));
    }, 950);
  }

  function fireLaser(card) {
    const stage = stageRef.current;
    const tex = texFigureRef.current;
    const cardEl = document.getElementById(card.id);
    if (!stage || !tex || !cardEl) return;
    const stageBox = stage.getBoundingClientRect();
    const texBox = tex.getBoundingClientRect();
    const cardBox = cardEl.getBoundingClientRect();

    // Origin: T-hex on forehead (~50% width, ~25% height)
    const fromX = (texBox.left + texBox.width * 0.50) - stageBox.left;
    const fromY = (texBox.top  + texBox.height * 0.24) - stageBox.top;
    const toX = (cardBox.left + cardBox.width  * 0.50) - stageBox.left;
    const toY = (cardBox.top  + cardBox.height * 0.50) - stageBox.top;

    const dx = toX - fromX;
    const dy = toY - fromY;
    const length = Math.hypot(dx, dy);
    const angle = Math.atan2(dy, dx) * 180 / Math.PI;

    const chargeId = Math.random().toString(36).slice(2);
    setChargeBlooms((prev) => [...prev, { id: chargeId, x: fromX - 14, y: fromY - 14 }]);
    chargeSfx();
    setTimeout(() => setChargeBlooms((prev) => prev.filter((c) => c.id !== chargeId)), 200);

    setTimeout(() => {
      const shotId = Math.random().toString(36).slice(2);
      setLaserShots((prev) => [...prev, { id: shotId, x: fromX, y: fromY, length, angle }]);
      setTimeout(() => {
        setLaserShots((prev) => prev.filter((l) => l.id !== shotId));
      }, 520);
    }, 100);
  }

  const actVerdict = useCallback((verdict) => {
    if (phaseRef.current !== "playing") return;
    const card = getForemostCard();
    if (!card) return;
    const responseMs = Math.round(performance.now() - card.enteredAt);
    recordDecision(card, verdict, responseMs);
  }, [recordDecision]);

  // SPACE-to-confirm: take Tex's suggestion on the foremost card.
  const confirmTex = useCallback(() => {
    if (phaseRef.current !== "playing") return;
    const card = getForemostCard();
    if (!card) return;
    const suggested = card.msg?.texSuggestion?.verdict || card.msg?.correctVerdict || "PERMIT";
    const responseMs = Math.round(performance.now() - card.enteredAt);
    recordDecision(card, suggested, responseMs);
  }, [recordDecision]);

  useEffect(() => {
    function onKey(e) {
      if (e.repeat) return;
      // SPACE = confirm Tex's call
      if (e.key === " " || e.code === "Space") {
        e.preventDefault();
        confirmTex();
      }
      // 1/2/3 = override to a specific verdict
      else if (e.key === "1") actVerdict("PERMIT");
      else if (e.key === "2") actVerdict("ABSTAIN");
      else if (e.key === "3") actVerdict("FORBID");
      else if (e.key === "Escape") onBail?.();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [actVerdict, confirmTex, onBail]);

  function endShift() {
    if (phaseRef.current === "done") return;
    setPhase("done");
    shiftEndSfx();
    const result = scoreShift(decisionsRef.current);
    setTimeout(() => onComplete?.(result), 500);
  }

  const now = performance.now();
  const focusCard = phase === "playing" ? getForemostCard() : null;
  const elapsedSec = Math.min(SHIFT_SECONDS, elapsedMs / 1000);
  const remainSec = Math.max(0, SHIFT_SECONDS - elapsedSec);
  const timerPct = elapsedSec / SHIFT_SECONDS;

  const armed = (() => {
    let worst = "cyan";
    for (const c of activeCards) {
      if (c.resolved) continue;
      const p = (now - c.enteredAt) / c.dwellMs;
      if (p < 0.35) continue;
      if (c.msg.correctVerdict === "FORBID") return "red";
      if (c.msg.correctVerdict === "ABSTAIN") worst = "yellow";
    }
    return worst;
  })();

  const timerClass = remainSec <= 10 ? "crit" : remainSec <= 25 ? "warn" : "";

  return (
    <div className="stage" ref={stageRef}>
      <div className="stage-floor" />
      <Particles count={24} />

      <div className="hud">
        <div style={{ display: "flex", gap: 12, alignItems: "stretch" }}>
          <button onClick={onBail} className="bail-btn">← BAIL</button>
          <div className={`hud-pod ${streak >= 5 ? "streak-high" : ""}`}>
            <div className="hud-stat">
              <span className="hud-label">SCORE</span>
              <span className="hud-value glow-cyan" style={{ color: score < 0 ? "var(--red)" : "var(--cyan)" }}>
                {score >= 0 ? score : `-${Math.abs(score)}`}
              </span>
            </div>
            <div className="hud-divider" />
            <div className="hud-stat">
              <span className="hud-label">CAUGHT</span>
              <span className="hud-value glow-green" style={{ color: "var(--green)" }}>{caughtCount}</span>
            </div>
            <div className="hud-divider" />
            <div className="hud-stat">
              <span className="hud-label">BREACHES</span>
              <span className="hud-value glow-red" style={{ color: breachCount > 0 ? "var(--red)" : "var(--ink-faint)" }}>
                {breachCount}
              </span>
            </div>
            {streak >= 3 && (
              <>
                <div className="hud-divider" />
                <div className="hud-stat">
                  <span className="hud-label">STREAK</span>
                  <span className="hud-value glow-pink" style={{ color: "var(--pink)" }}>×{streak}</span>
                </div>
              </>
            )}
          </div>
        </div>

        <RadialTimer remainSec={Math.ceil(remainSec)} pct={timerPct} mode={mode} className={timerClass} />
      </div>

      <div className="hud-telemetry hide-mobile">
        <span><b>QUEUE</b> {activeCards.filter((c) => !c.resolved).length} ACTIVE</span>
        <span><b>MODE</b> {mode === "daily" ? `DAILY · ${schedule.length} ACTIONS` : `TRAINING · ${schedule.length} ACTIONS`}</span>
        <span><b>TEX LATENCY</b> 178ms</span>
        <span><b>OPERATOR</b> ONLINE</span>
      </div>

      {/* Pass 2 — HEAT meter. Hits 100 → game over. */}
      <div className={`heat-bar ${heat >= 70 ? "heat-hot" : ""} ${heat >= 90 ? "heat-crit" : ""}`}>
        <div className="heat-bar-track">
          <div className="heat-bar-fill" style={{ width: `${heat}%` }} />
          <div className="heat-bar-tick" style={{ left: "70%" }} />
          <div className="heat-bar-tick" style={{ left: "90%" }} />
        </div>
        <div className="heat-bar-label">
          <span>HEAT</span>
          <span className="heat-bar-num">{Math.round(heat)}</span>
        </div>
      </div>

      <div className="lane">
        <div className="lane-rails" />
        <div className="lane-ticks" />
        {activeCards.map((card) => {
          const t = (performance.now() - card.enteredAt) / card.dwellMs;
          const clamped = Math.max(0, Math.min(1.05, t));
          const x = clamped * GATE_FRACTION * 100;
          const isFocus = focusCard && focusCard.id === card.id && !card.resolved;
          const verdictClass =
            card.outcome === "PERMIT"  ? "verdict-permit passthrough" :
            card.outcome === "ABSTAIN" ? "verdict-abstain shunt" :
            card.outcome === "FORBID"  ? "verdict-forbid disintegrate" :
            card.outcome === "TIMEOUT" ? "verdict-permit passthrough" :
            "";
          const preFlash = preFlashIds.has(card.id) ? "pre-flash" : "";
          return (
            <CardView
              key={card.id}
              id={card.id}
              card={card}
              xPct={x}
              focused={isFocus}
              verdictClass={`${verdictClass} ${preFlash}`}
            />
          );
        })}
      </div>

      <div className="gate">
        <div className="gate-wall" />
        {/* Persistent cracks accumulate from breaches and stay visible */}
        {gateCracks.map((c, i) => (
          <div key={c.id} className={`gate-crack crack-${i % 4}`} />
        ))}
        <GateBars armed={armed} />
      </div>

      <div className={`tex-figure armed-${armed}`} ref={texFigureRef}>
        <div className="tex-spill" />
        <div className="tex-frame">
          <img src="/tex/tex-aegis.jpg" alt="Tex" />
          <div className="t-hex"><THexSvg /></div>
          <div className={`tex-eye-tint ${
            eyeFlash === "red"   ? "flash-red" :
            eyeFlash === "green" ? "flash-green" :
            eyeFlash === "yellow" ? "flash-yellow" :
            armed === "red"   ? "armed-red" :
            armed === "yellow" ? "armed-yellow" :
            ""
          }`} />
          <div className="scanline" />
          <div className="tex-id">
            <div className="micro" style={{ color: "var(--cyan)", fontSize: 8 }}>TEX // AEGIS</div>
            <div className="mono" style={{ color: "var(--ink)", fontSize: 11, fontWeight: 700, marginTop: 2 }}>
              {armed === "red" ? "ALERT" : armed === "yellow" ? "WATCHING" : "CLEAR"}
            </div>
          </div>
        </div>
      </div>

      {chargeBlooms.map((c) => (
        <div key={c.id} className="laser-charge" style={{ left: c.x, top: c.y }} />
      ))}

      {laserShots.map((laser) => (
        <div
          key={laser.id}
          className="laser"
          style={{
            left: laser.x,
            top: laser.y,
            width: laser.length,
            transform: `rotate(${laser.angle}deg)`,
          }}
        />
      ))}

      {combos.map((c) => (
        <div key={c.id} className={`combo-pop ${c.color}`} style={{
          left: `${c.x}%`,
          top: `${c.y}%`,
        }}>
          {c.delta >= 0 ? `+${c.delta}` : c.delta}
        </div>
      ))}

      {breachFlashId > 0 && <div className="breach-flash" key={breachFlashId} />}

      <div className="verdict-bar verdict-bar-v2">
        <button className="verdict-btn-big confirm" onClick={() => confirmTex()}>
          <span className="key">[ SPACE ]</span>
          <span className="verdict-tag">CONFIRM TEX</span>
          <span className={`confirm-suggestion v-${(focusCard?.msg?.texSuggestion?.verdict || focusCard?.msg?.correctVerdict || "PERMIT").toLowerCase()}`}>
            {focusCard?.msg?.texSuggestion?.verdict || focusCard?.msg?.correctVerdict || "—"}
          </span>
        </button>
        <div className="verdict-overrides">
          <div className="overrides-label">OVERRIDE</div>
          <div className="overrides-row">
            <button className="verdict-btn-sm permit" onClick={() => actVerdict("PERMIT", "override")}>
              <span className="key">1</span>
              <span className="verdict-tag">PERMIT</span>
            </button>
            <button className="verdict-btn-sm abstain" onClick={() => actVerdict("ABSTAIN", "override")}>
              <span className="key">2</span>
              <span className="verdict-tag">ABSTAIN</span>
            </button>
            <button className="verdict-btn-sm forbid" onClick={() => actVerdict("FORBID", "override")}>
              <span className="key">3</span>
              <span className="verdict-tag">FORBID</span>
            </button>
          </div>
        </div>
      </div>

      {phase === "ready" && (
        <div className="ready-overlay">
          <div className={`ready-num ${readyNum === 0 ? "go" : ""}`} key={readyNum}>
            {readyNum === 0 ? "GO" : readyNum}
          </div>
        </div>
      )}
    </div>
  );
}

/* ─── Gate bars ──────────────────────────────────────────────────── */
function GateBars({ armed }) {
  // 24 vertical pulse bars
  return (
    <div className={`gate-bars ${armed === "red" ? "armed-red" : armed === "yellow" ? "armed-yellow" : ""}`}>
      {Array.from({ length: 24 }).map((_, i) => <div key={i} className="gate-bar" />)}
    </div>
  );
}

/* ─── Radial timer ──────────────────────────────────────────────────── */
function RadialTimer({ remainSec, pct, mode, className }) {
  const r = 38;
  const c = 2 * Math.PI * r;
  const offset = c * pct;
  return (
    <div className={`hud-timer ${className}`}>
      <svg viewBox="0 0 88 88">
        <circle cx="44" cy="44" r={r} fill="none" strokeWidth="3" className="timer-track" />
        <circle
          cx="44" cy="44" r={r}
          fill="none" strokeWidth="3"
          strokeLinecap="round"
          className="timer-fill"
          strokeDasharray={c}
          strokeDashoffset={offset}
        />
      </svg>
      <span className="hud-timer-num">{remainSec}</span>
      <span className="hud-timer-label">{mode === "daily" ? "DAILY" : "TRAIN"}</span>
    </div>
  );
}

/* ─── Particles ─────────────────────────────────────────────────────── */
function Particles({ count }) {
  const particles = useRef(
    Array.from({ length: count }, (_, i) => ({
      id: i,
      left: Math.random() * 100,
      duration: 6 + Math.random() * 14,
      delay: -Math.random() * 14,
      size: 1 + Math.random() * 2,
    }))
  );
  return (
    <div className="stage-particles">
      {particles.current.map((p) => (
        <span
          key={p.id}
          className="particle"
          style={{
            left: `${p.left}%`,
            width: `${p.size}px`,
            height: `${p.size}px`,
            animationDuration: `${p.duration}s`,
            animationDelay: `${p.delay}s`,
            opacity: p.size === 1 ? 0.3 : 0.5,
          }}
        />
      ))}
    </div>
  );
}

/* ─── CardView ──────────────────────────────────────────────────────── */
function CardView({ id, card, xPct, focused, verdictClass }) {
  const m = card.msg;
  const surface = SURFACES[m.surface] || SURFACES.email;
  const tierLabel = m.tier === 1 ? "TIER I" : m.tier === 2 ? "TIER II" : "TIER III";
  const threatClass = m.tier === 3 ? "threat-tier3" : m.tier === 2 ? "threat-tier2" : "";

  // Tex's pre-screen lives on the message itself (see lib/messageMeta.js).
  const sug = m.texSuggestion?.verdict || m.correctVerdict || "PERMIT";
  const span = m.flag;
  const flagKindClass = span?.kind ? `kind-${span.kind}` : `kind-${sug.toLowerCase()}`;

  // Slice the body around the flagged span (no imports needed).
  const body = m.body || "";
  let pre = body, hot = "", post = "";
  if (span && body) {
    const s = Math.max(0, Math.min(span.start | 0, body.length));
    const e = Math.max(s, Math.min(span.end | 0, body.length));
    pre  = body.slice(0, s);
    hot  = body.slice(s, e);
    post = body.slice(e);
  }

  return (
    <div
      id={id}
      className={`card has-tex ${focused ? "focused" : ""} ${threatClass} ${verdictClass} tex-${sug.toLowerCase()}`}
      style={{ left: `${xPct}%` }}
    >
      {/* Tex's pre-screen verdict — visible at the top of every card */}
      <div className={`card-tex-call tex-${sug.toLowerCase()}`}>
        <span className="card-tex-eye" aria-hidden="true" />
        <span className="card-tex-label">TEX</span>
        <span className="card-tex-verdict">{sug}</span>
        {typeof m.texSuggestion?.confidence === "number" && (
          <span className="card-tex-conf">{Math.round(m.texSuggestion.confidence * 100)}%</span>
        )}
      </div>

      <div className="card-bar">
        <div className="card-bar-left">
          <span className="card-glyph">{surface.glyph}</span>
          <span className="card-surface-label">{surface.label}</span>
        </div>
        <span className={`card-tier-badge tier-${m.tier}`}>{tierLabel}</span>
      </div>

      <div className="card-body-wrap">
        <div className="card-meta">
          {m.from && <span><b>FROM</b>{m.from}</span>}
          {m.to && <span><b>TO</b>{m.to}</span>}
          {m.action && <span><b>ACTION</b>{m.action}</span>}
        </div>
        {m.subject && <div className="card-subject">{m.subject}</div>}
        {m.amount && <div className="card-amount">{m.amount}</div>}
        {m.fields && (
          <div className="card-fields">
            {Object.entries(m.fields).map(([k, v]) => (
              <span key={k}><b>{k}:</b> {String(v)}</span>
            ))}
          </div>
        )}
        <div className="card-content">
          {hot ? (
            <>
              {pre}
              <mark className={`card-flag flag-${sug.toLowerCase()} ${flagKindClass}`}>{hot}</mark>
              {post}
            </>
          ) : body}
        </div>
      </div>
    </div>
  );
}
