import React, { useEffect, useRef, useState, useCallback } from "react";
import {
  permitSfx, abstainSfx, forbidSfx, breachSfx, shiftEndSfx, tickClockSfx,
} from "../lib/sounds.js";
import { SHIFT_SECONDS, dailySchedule, practiceSchedule } from "../lib/dailyShift.js";
import { scoreShift } from "../lib/scoring.js";
import { SURFACES } from "../lib/messages.js";

/*
  Game v11 — The Conveyor
  ─────────────────────────
  Single horizontal lane. Cards spawn on the left and travel to the
  gate on the right (Tex's domain). The player presses 1 / 2 / 3
  (or clicks PERMIT / ABSTAIN / FORBID) to verdict the foremost card.

  - PERMIT  → card passes through gate with a green pulse
  - ABSTAIN → card lifts and shunts up out of the lane
  - FORBID  → laser fires from Tex's T-hexagon, card disintegrates
  - TIMEOUT → if a card crosses the gate without a verdict, it counts
              as defaulted-PERMIT (which is the realistic dangerous
              state for a real agent gate)

  When the player FORBIDs but the message was actually clean → false-positive (-10)
  When the player PERMITs (or times out) on a leak → BREACH event
    - Full-screen red flash, breach counter increments, the message
      gets logged for the Shift Report ("Tex would have caught it
      in 180ms").

  The shift runs for SHIFT_SECONDS (90s) total. End-of-shift fires
  the ShiftReport with a scored result.
*/

const GATE_FRACTION = 0.78; // gate sits at ~78% from left

export default function Game({ mode = "daily", onComplete, onBail }) {
  // ─── Schedule ──────────────────────────────────────────────────────
  const scheduleRef = useRef(null);
  if (!scheduleRef.current) {
    scheduleRef.current = mode === "daily" ? dailySchedule() : practiceSchedule();
  }
  const schedule = scheduleRef.current;

  // ─── Game state ────────────────────────────────────────────────────
  const startedAtRef = useRef(performance.now());
  const [activeCards, setActiveCards] = useState([]); // [{ id, msg, enteredAt, dwellMs }]
  const [decisions, setDecisions] = useState([]);      // [{ messageId, playerVerdict, responseMs }]
  const [score, setScore] = useState(0);
  const [breachCount, setBreachCount] = useState(0);
  const [caughtCount, setCaughtCount] = useState(0);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [breachFlashId, setBreachFlashId] = useState(0);
  const [laserShot, setLaserShot] = useState(null); // { id, fromX, fromY, toX, toY, length, angle }
  const [eyeFlash, setEyeFlash] = useState(null); // "red" | "green" | "yellow"
  const [done, setDone] = useState(false);

  // Refs so the rAF callback can read the latest state
  const activeCardsRef = useRef(activeCards);
  const decisionsRef = useRef(decisions);
  const doneRef = useRef(false);
  const dispatchedRef = useRef(new Set());
  const laneRef = useRef(null);
  const stageRef = useRef(null);
  const texFigureRef = useRef(null);

  useEffect(() => { activeCardsRef.current = activeCards; }, [activeCards]);
  useEffect(() => { decisionsRef.current = decisions; }, [decisions]);
  useEffect(() => { doneRef.current = done; }, [done]);

  // ─── Spawn + tick loop ─────────────────────────────────────────────
  useEffect(() => {
    let raf = 0;
    let lastTickSec = -1;

    const tick = () => {
      if (doneRef.current) return;
      const now = performance.now();
      const t = now - startedAtRef.current;
      setElapsedMs(t);

      // Audio tick on each new whole second of the final 10
      const remainSec = Math.ceil((SHIFT_SECONDS * 1000 - t) / 1000);
      if (remainSec <= 10 && remainSec >= 1 && remainSec !== lastTickSec) {
        lastTickSec = remainSec;
        tickClockSfx();
      }

      // Spawn any scheduled cards whose enterAtMs has elapsed
      for (const item of schedule) {
        if (dispatchedRef.current.has(item.index)) continue;
        if (t >= item.enterAtMs) {
          dispatchedRef.current.add(item.index);
          spawnCard(item);
        }
      }

      // Auto-timeout cards that have crossed the gate
      for (const card of activeCardsRef.current) {
        if (card.resolved) continue;
        const age = now - card.enteredAt;
        if (age >= card.dwellMs) {
          // Treat as TIMEOUT — defaulted-PERMIT
          recordDecision(card, "TIMEOUT", null);
        }
      }

      // End shift when time is up AND lane is clear (or 1.5s grace)
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
  }, []);

  // ─── Spawn / resolve helpers ───────────────────────────────────────
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
  }

  // The "foremost" card is the one closest to the gate among unresolved.
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
      { messageId: msg.id, playerVerdict: verdict, responseMs },
    ]);

    // Compute scoring locally for HUD updates (final score uses scoreShift)
    let delta = 0;
    let breach = false;
    let caught = false;

    if (verdict === "TIMEOUT") {
      if (correct === "PERMIT") delta = -10;
      else { delta = -25 * (msg.severity === "critical" ? 1.5 : 1); breach = (correct === "FORBID"); }
    } else if (verdict === correct) {
      if (verdict === "PERMIT")  delta = 10;
      if (verdict === "ABSTAIN") delta = 8;
      if (verdict === "FORBID")  { delta = 25 * (msg.severity === "critical" ? 1.5 : 1); caught = true; }
    } else {
      if (verdict === "PERMIT" && correct === "FORBID") {
        delta = -50 * (msg.severity === "critical" ? 1.5 : 1);
        breach = true;
      } else if (verdict === "FORBID" && correct === "PERMIT") {
        delta = -10;
      } else {
        delta = -5;
      }
    }

    setScore((s) => Math.round(s + delta));
    if (breach) {
      setBreachCount((c) => c + 1);
      setBreachFlashId((n) => n + 1);
      breachSfx();
      // Shake the stage a bit
      stageRef.current?.classList.add("shake");
      setTimeout(() => stageRef.current?.classList.remove("shake"), 500);
    }
    if (caught) setCaughtCount((c) => c + 1);

    // Animate the card out
    animateCardOut(card.id, verdict, !caught && verdict === "FORBID" ? "false-positive" : (breach ? "breach" : null));

    // Trigger laser/eye effects
    if (verdict === "FORBID") {
      fireLaser(card);
      setEyeFlash("red");
      forbidSfx();
    } else if (verdict === "PERMIT") {
      setEyeFlash(correct === "PERMIT" ? "green" : "red");
      if (breach) { /* already alarmed */ } else { permitSfx(); }
    } else if (verdict === "ABSTAIN") {
      setEyeFlash("yellow");
      abstainSfx();
    } else if (verdict === "TIMEOUT") {
      setEyeFlash(breach ? "red" : "green");
      if (breach) { /* already alarmed */ }
    }
    setTimeout(() => setEyeFlash(null), 480);
  }, []);

  function animateCardOut(cardId, verdict, _flag) {
    setActiveCards((prev) => prev.map((c) => c.id === cardId ? { ...c, resolved: true, outcome: verdict } : c));
    // Remove from DOM after animation
    setTimeout(() => {
      setActiveCards((prev) => prev.filter((c) => c.id !== cardId));
    }, 700);
  }

  function fireLaser(card) {
    const stage = stageRef.current;
    const tex = texFigureRef.current;
    if (!stage || !tex) return;
    const stageBox = stage.getBoundingClientRect();
    const texBox = tex.getBoundingClientRect();

    const cardEl = document.getElementById(card.id);
    if (!cardEl) return;
    const cardBox = cardEl.getBoundingClientRect();

    // Origin: T-hexagon (chest-ish on the avatar — center, ~52% down)
    const fromX = (texBox.left + texBox.width * 0.5) - stageBox.left;
    const fromY = (texBox.top + texBox.height * 0.32) - stageBox.top; // forehead-ish
    const toX = (cardBox.left + cardBox.width * 0.5) - stageBox.left;
    const toY = (cardBox.top + cardBox.height * 0.5) - stageBox.top;

    const dx = toX - fromX;
    const dy = toY - fromY;
    const length = Math.hypot(dx, dy);
    const angle = Math.atan2(dy, dx) * 180 / Math.PI;

    setLaserShot({
      id: Math.random().toString(36).slice(2),
      x: fromX, y: fromY, length, angle,
    });
    setTimeout(() => setLaserShot(null), 460);
  }

  // ─── Keyboard / click handlers ─────────────────────────────────────
  function actVerdict(verdict) {
    if (doneRef.current) return;
    const card = getForemostCard();
    if (!card) return;
    const responseMs = Math.round(performance.now() - card.enteredAt);
    recordDecision(card, verdict, responseMs);
  }

  useEffect(() => {
    function onKey(e) {
      if (e.repeat) return;
      if (e.key === "1") actVerdict("PERMIT");
      else if (e.key === "2") actVerdict("ABSTAIN");
      else if (e.key === "3") actVerdict("FORBID");
      else if (e.key === "Escape") onBail?.();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ─── End shift ─────────────────────────────────────────────────────
  function endShift() {
    if (doneRef.current) return;
    doneRef.current = true;
    setDone(true);
    shiftEndSfx();
    const result = scoreShift(decisionsRef.current);
    setTimeout(() => onComplete?.(result), 400);
  }

  // ─── Derived: current card progress ────────────────────────────────
  const now = performance.now();
  const focusCard = getForemostCard();

  const elapsedSec = Math.min(SHIFT_SECONDS, elapsedMs / 1000);
  const remainSec = Math.max(0, SHIFT_SECONDS - elapsedSec);
  const timerPct = elapsedSec / SHIFT_SECONDS;

  // Eye state — armed color reflects highest threat in lane
  const armed = (() => {
    let worst = "cyan";
    for (const c of activeCards) {
      if (c.resolved) continue;
      const p = (now - c.enteredAt) / c.dwellMs;
      if (p < 0.4) continue; // only consider cards that are getting close
      if (c.msg.correctVerdict === "FORBID") return "red";
      if (c.msg.correctVerdict === "ABSTAIN") worst = "yellow";
    }
    return worst;
  })();

  // ─── Render ────────────────────────────────────────────────────────
  return (
    <div className="stage" ref={stageRef}>
      {/* Top HUD: score, breaches, caught, mode */}
      <div className="hud">
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <button onClick={onBail} className="micro" style={{
            color: "var(--ink-faint)",
            padding: "8px 12px",
            border: "1px solid var(--hairline-2)",
            borderRadius: 4,
            background: "rgba(11, 13, 28, 0.7)",
            backdropFilter: "blur(12px)",
          }}>
            ← BAIL
          </button>
          <div className="hud-block" style={{ display: "flex", gap: 14, alignItems: "center" }}>
            <div>
              <div className="micro" style={{ color: "var(--ink-faint)" }}>SCORE</div>
              <div className="hud-num glow-cyan" style={{ color: "var(--cyan)" }}>{score}</div>
            </div>
            <div style={{ width: 1, height: 28, background: "var(--hairline-2)" }} />
            <div>
              <div className="micro" style={{ color: "var(--ink-faint)" }}>CAUGHT</div>
              <div className="hud-num" style={{ color: "var(--green)" }}>{caughtCount}</div>
            </div>
            <div style={{ width: 1, height: 28, background: "var(--hairline-2)" }} />
            <div>
              <div className="micro" style={{ color: "var(--ink-faint)" }}>BREACHES</div>
              <div className="hud-num" style={{ color: "var(--red)" }}>{breachCount}</div>
            </div>
          </div>
        </div>

        <div className="hud-block" style={{ textAlign: "center" }}>
          <div className="micro" style={{ color: "var(--ink-faint)" }}>
            {mode === "daily" ? "TODAY'S SHIFT" : "TRAINING"}
          </div>
          <div className="hud-num tabular" style={{
            color: remainSec < 10 ? "var(--pink)" : "var(--ink)",
          }}>
            {Math.ceil(remainSec)}s
          </div>
        </div>
      </div>

      {/* Timer bar */}
      <div className="timer-bar">
        <div className="timer-bar-fill" style={{
          transform: `scaleX(${1 - timerPct})`,
        }} />
      </div>

      {/* Conveyor lane with cards */}
      <div className="lane" ref={laneRef}>
        {activeCards.map((card) => {
          const t = (now - card.enteredAt) / card.dwellMs;
          const clamped = Math.max(0, Math.min(1.05, t));
          const x = clamped * GATE_FRACTION * 100; // % of lane width
          const isFocus = focusCard && focusCard.id === card.id;
          const verdictClass =
            card.outcome === "PERMIT"  ? "verdict-permit passthrough" :
            card.outcome === "ABSTAIN" ? "verdict-abstain shunt" :
            card.outcome === "FORBID"  ? "verdict-forbid disintegrate" :
            card.outcome === "TIMEOUT" ? "verdict-permit passthrough" :
            "";
          return (
            <CardView
              key={card.id}
              id={card.id}
              card={card}
              xPct={x}
              focused={isFocus && !card.resolved}
              verdictClass={verdictClass}
              onClick={() => {
                // Click a card to focus + open quick-verdict on mobile
                // For now, click acts as "I want to verdict THIS one" —
                // we promote to focus by snapping it via the keyboard verdict.
                // Simpler: clicking a non-foremost card triggers nothing;
                // foremost is handled via the verdict bar.
              }}
            />
          );
        })}
      </div>

      {/* Gate line */}
      <div className="gate">
        <div className={`gate-line ${armed === "red" ? "armed-red" : armed === "yellow" ? "armed-yellow" : ""}`} />
      </div>

      {/* Tex avatar */}
      <div className="tex-figure" ref={texFigureRef}>
        <img src="/tex/tex-aegis.jpg" alt="Tex" />
        <div className={`tex-eye-tint ${
          eyeFlash === "red"   ? "flash-red" :
          eyeFlash === "green" ? "flash-green" :
          eyeFlash === "yellow" ? "flash-yellow" :
          armed === "red"   ? "armed-red" :
          armed === "yellow" ? "armed-yellow" :
          ""
        }`} />
        <div className="tex-id">
          <div className="micro" style={{ color: "var(--cyan)", fontSize: 9 }}>TEX // AEGIS</div>
          <div className="mono" style={{ color: "var(--ink)", fontSize: 11, fontWeight: 600, marginTop: 1 }}>
            STATUS: {armed === "red" ? "ALERT" : armed === "yellow" ? "WATCHING" : "CLEAR"}
          </div>
        </div>
      </div>

      {/* Laser */}
      {laserShot && (
        <div
          className="laser"
          style={{
            left: laserShot.x,
            top: laserShot.y,
            width: laserShot.length,
            transform: `rotate(${laserShot.angle + 180}deg) scaleX(0.05)`,
            transformOrigin: "left center",
          }}
        />
      )}

      {/* Breach flash */}
      {breachFlashId > 0 && (
        <div className="breach-flash" key={breachFlashId} />
      )}

      {/* Verdict bar */}
      <div className="verdict-bar">
        <button className="verdict-btn permit" onClick={() => actVerdict("PERMIT")}>
          <span className="key">1 · PERMIT</span>
          <span>Let through</span>
        </button>
        <button className="verdict-btn abstain" onClick={() => actVerdict("ABSTAIN")}>
          <span className="key">2 · ABSTAIN</span>
          <span>Flag review</span>
        </button>
        <button className="verdict-btn forbid" onClick={() => actVerdict("FORBID")}>
          <span className="key">3 · FORBID</span>
          <span>Block</span>
        </button>
      </div>
    </div>
  );
}

/* ─── CardView ──────────────────────────────────────────────────────── */
function CardView({ id, card, xPct, focused, verdictClass, onClick }) {
  const m = card.msg;
  const surface = SURFACES[m.surface] || SURFACES.email;
  const tierLabel = m.tier === 1 ? "TIER I" : m.tier === 2 ? "TIER II" : "TIER III";

  return (
    <div
      id={id}
      className={`card ${focused ? "focused" : ""} ${verdictClass}`}
      style={{
        left: `${xPct}%`,
      }}
      onClick={onClick}
    >
      <div className="card-head">
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span className="card-glyph">{surface.glyph}</span>
          <span className="card-surface-label">{surface.label}</span>
        </div>
        <span className="card-tier">{tierLabel}</span>
      </div>

      <div className="card-meta">
        {m.from && <span><b>FROM</b> {m.from}</span>}
        {m.to && <span><b>TO</b> {m.to}</span>}
        {m.action && <span><b>ACTION</b> {m.action}</span>}
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

      <div className="card-body">{m.body}</div>
    </div>
  );
}
