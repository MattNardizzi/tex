import React, { useEffect, useRef, useState } from 'react';
import texHero from './tex-hero.png';

/* ────────────────────────────────────────────────────────────────────
 * The Sevenfold — texaegis.com homepage hero (v5).
 *
 * Brief locked from the founder:
 *   - Buyer: non-technical exec (CISO, GC, Chief Risk, Head of AI)
 *   - Feeling: AUTHORITY. The verdict lands hard.
 *   - Reference: Apple Vision Pro keynote — floating object, deep
 *     black, single key light, slow zoom.
 *   - No ring. No transcript. No technical jargon.
 *   - Headline: "The adjudicator for every AI agent action."
 *   - Bottom on verdict: big serif word + "Cannot be erased." subtext.
 *
 * Composition:
 *   Tex stands centered, full-height. 75% of the viewport vertical.
 *   Single key light from upper-left rims his shoulder. Pure black
 *   void. No grid, no floor disc, no orbiting decoration. Headline
 *   floats top-center. Verdict lands big-serif at bottom-center.
 *
 * The seven layers are implied by SEVEN HEARTBEAT PULSES on his chest
 * emblem as the verdict builds. The buyer sees seven beats, then a
 * verdict. They don't need labels here. The architecture page does
 * the explaining.
 *
 * Driven by the existing Bridge — `activeLayers` (0..7), `phase`
 * ('idle'|'streaming'|'fused'|'verdict'), `activeVerdict`,
 * `activeAction`, `chain`. The motion timeline matches what the real
 * pipeline does, slowed and dramatized for cinema.
 * ──────────────────────────────────────────────────────────────────── */

/* ─── Reduced motion ──────────────────────────────────────────────── */

function useReducedMotion() {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduced(mq.matches);
    const handler = (e) => setReduced(e.matches);
    mq.addEventListener?.('change', handler);
    return () => mq.removeEventListener?.('change', handler);
  }, []);
  return reduced;
}

/* ─── A single continuous clock ───────────────────────────────────── */

function useTick(reducedMotion) {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (reducedMotion) { setTick(0); return; }
    const start = performance.now();
    let raf = 0;
    const step = (now) => {
      setTick(now - start);
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [reducedMotion]);
  return tick;
}

/* ─── Component ───────────────────────────────────────────────────── */

export default function Sevenfold({
  verdict, phase, chain, activeAction, activeLayers,
}) {
  const reducedMotion = useReducedMotion();
  const tick = useTick(reducedMotion);
  const stageRef = useRef(null);

  // Subtle breathing — Tex is alive
  const breathOffset = reducedMotion ? 0 : Math.sin(tick / 2400) * 3;

  // Ambient cyan emblem pulse on his chest, even when idle
  const emblemAmbient = reducedMotion ? 0.55 : 0.45 + Math.sin(tick / 1900) * 0.12;

  // The seven heartbeat pulses — one per layer activation
  // activeLayers is 0..7 from the bridge; each layer that lights is
  // a pulse that radiates from the chest emblem.
  const heartbeats = useHeartbeats(activeLayers, reducedMotion);

  const verdictKey = verdict || 'idle';
  const verdictPhase = phase === 'verdict' || phase === 'fused';

  // Verdict word that fades up at the bottom of the frame
  const verdictWord =
    verdict === 'permit'  ? 'PERMITTED' :
    verdict === 'abstain' ? 'WITHHELD'  :
    verdict === 'forbid'  ? 'BLOCKED'   :
                            null;

  // Chain seal flash — fires when chain length increments
  const sealFlash = useSealFlash(chain, reducedMotion);

  return (
    <section
      ref={stageRef}
      className={`sf sf-verdict-${verdictKey} sf-phase-${phase || 'idle'} ${verdictPhase ? 'is-verdict' : ''} ${sealFlash ? 'is-sealed' : ''}`}
      aria-label="Tex — the adjudicator for every AI agent action"
    >
      {/* Pure black void with one keylight gradient */}
      <div className="sf-void" aria-hidden="true">
        <div className="sf-keylight" />
        <div className="sf-rim" />
        <div className="sf-vignette" />
      </div>

      {/* Headline floats top-center over the void */}
      <div className="sf-headline-wrap">
        <div className="sf-eyebrow">
          <span className="sf-eyebrow-pip" aria-hidden="true" />
          <span>TEX&nbsp;·&nbsp;ON&nbsp;DUTY</span>
        </div>
        <h1 className="sf-headline">
          The adjudicator for <em>every</em> AI&nbsp;agent&nbsp;action.
        </h1>
      </div>

      {/* Tex — the subject. Centered, large, alive. */}
      <div
        className="sf-figure"
        style={{ transform: `translateX(-50%) translateY(${breathOffset}px)` }}
      >
        <img
          src={texHero}
          alt=""
          aria-hidden="true"
          className="sf-figure-img"
        />
        {/* Verdict-colored eye tint — overlay behind the figure so it
            wraps the head with light, not a smear on his face */}
        <div className={`sf-figure-tint sf-figure-tint-${verdictKey}`} aria-hidden="true" />
        {/* Heartbeat pulses radiating from chest emblem */}
        <div className="sf-emblem" style={{ opacity: emblemAmbient }} aria-hidden="true">
          {heartbeats.map((hb) => (
            <span
              key={hb.id}
              className={`sf-heartbeat sf-heartbeat-${verdictKey}`}
              style={{
                animationDelay: `${hb.delay}ms`,
                animationDuration: `${hb.duration}ms`,
              }}
            />
          ))}
          {sealFlash && (
            <span className={`sf-seal-flash sf-seal-flash-${verdictKey}`} />
          )}
        </div>
      </div>

      {/* Verdict word — fades up large at the bottom of the frame */}
      <div className={`sf-verdict-block ${verdictPhase ? 'is-visible' : ''}`}>
        {verdictWord && (
          <>
            <div className="sf-verdict-rule" aria-hidden="true">
              <span className="sf-verdict-rule-line" />
              <span className="sf-verdict-rule-mark" />
              <span className="sf-verdict-rule-line" />
            </div>
            <h2 className={`sf-verdict-word sf-verdict-word-${verdictKey}`}>
              {verdictWord}
            </h2>
            <p className="sf-verdict-sub">
              Written into the chain. <span className="sf-verdict-sub-em">Cannot be erased.</span>
            </p>
          </>
        )}
      </div>

      {/* On-duty status sits bottom-left — a quiet "Tex is watching" */}
      <div className="sf-duty">
        <div className="sf-duty-pip" aria-hidden="true" />
        <div className="sf-duty-meta">
          <div className="sf-duty-status">{activeAction ? 'Action received' : 'Listening for next action'}</div>
          {activeAction && (
            <div className="sf-duty-detail">
              <span className="sf-duty-agent">{activeAction.agent}</span>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

/* ─── Heartbeat pulses ────────────────────────────────────────────── */
/*
 * Each time `activeLayers` increments, we push a new pulse that
 * radiates from the chest emblem. Seven pulses = the seven layers
 * checking. The buyer sees a heartbeat building toward a verdict
 * without needing to read seven labels.
 */

function useHeartbeats(activeLayers, reducedMotion) {
  const [pulses, setPulses] = useState([]);
  const lastLayersRef = useRef(0);
  const idRef = useRef(0);

  useEffect(() => {
    if (reducedMotion) return;
    const layers = activeLayers || 0;
    if (layers > lastLayersRef.current) {
      const added = layers - lastLayersRef.current;
      const newPulses = [];
      for (let i = 0; i < added; i++) {
        idRef.current += 1;
        newPulses.push({
          id: idRef.current,
          delay: i * 0,
          duration: 1400,
          createdAt: performance.now(),
        });
      }
      setPulses((prev) => [...prev, ...newPulses]);
    } else if (layers < lastLayersRef.current) {
      // Cycle reset — clear old pulses
      setPulses([]);
    }
    lastLayersRef.current = layers;
  }, [activeLayers, reducedMotion]);

  // Garbage-collect finished pulses
  useEffect(() => {
    if (pulses.length === 0) return;
    const t = setTimeout(() => {
      const now = performance.now();
      setPulses((cur) => cur.filter((p) => now - p.createdAt < 1600));
    }, 1700);
    return () => clearTimeout(t);
  }, [pulses]);

  return pulses;
}

/* ─── Chain seal flash ────────────────────────────────────────────── */

function useSealFlash(chain, reducedMotion) {
  const [flash, setFlash] = useState(false);
  const lastLenRef = useRef(0);
  useEffect(() => {
    if (reducedMotion) return;
    if (!chain || chain.length === 0) return;
    if (chain.length === lastLenRef.current) return;
    lastLenRef.current = chain.length;
    setFlash(true);
    const t = setTimeout(() => setFlash(false), 1100);
    return () => clearTimeout(t);
  }, [chain, reducedMotion]);
  return flash;
}
