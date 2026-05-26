import React, { useEffect, useRef, useState } from 'react';
import './EvolutionSection.css';

/* =============================================================
   EVOLUTION SECTION — screen five

   The only claim no competitor in the category can make:

     "I learn your environment.
      I evolve with your agents.
      I get smarter every day."

   The animation is the unifying move on the page. Each line
   resolves from depth — beginning as a blurred cloud below
   its resting position and sharpening into serif. Then, once
   all three lines are present, a single horizontal light sweep
   passes across them, left to right, the same glass material
   that lives in the hero's "Absolute."

   The metaphor: the marketing site behaves like one piece of
   glass with light moving through it at the moments that
   matter. The hero word breathes with light. Section five
   sees that light pass over the three sentences once, tying
   them together, and goes quiet.

   No loop. No second pass. The light comes once.
   ============================================================= */

const LINES = [
  'I learn your environment.',
  'I evolve with your agents.',
  'I get smarter every day.',
];

// Each line waits ~1100ms after the previous one *finishes* —
// the slowness is the point. A hurried section five would
// betray the page.
const ENTRY_DELAY_MS = 400;
const STAGGER_MS = 1700;

// The light sweep begins after the third line has fully
// settled. With ENTRY_DELAY (400) + 2 * STAGGER (3400) +
// transition duration (~1400) = ~5200ms, we start the sweep
// at 5600ms to give the third line a moment to hold first.
const SWEEP_DELAY_MS = 5600;

export default function EvolutionSection() {
  const sectionRef = useRef(null);
  const [armed, setArmed] = useState(false);
  const [sweep, setSweep] = useState(false);

  // Arm the arrival once, when the section first enters the
  // viewport. After that we don't re-trigger.
  useEffect(() => {
    const node = sectionRef.current;
    if (!node) return;
    const io = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setArmed(true);
          io.disconnect();
        }
      },
      { threshold: 0.3 }
    );
    io.observe(node);
    return () => io.disconnect();
  }, []);

  // Once armed, schedule the single light sweep across the
  // three lines. It runs once. No loop.
  useEffect(() => {
    if (!armed) return;
    const t = setTimeout(() => setSweep(true), SWEEP_DELAY_MS);
    return () => clearTimeout(t);
  }, [armed]);

  const rootClass = [
    'tex-evolution',
    armed ? 'tex-evolution--armed' : '',
    sweep ? 'tex-evolution--sweep' : '',
  ].filter(Boolean).join(' ');

  return (
    <section
      ref={sectionRef}
      className={rootClass}
      id="evolution"
      aria-label="Tex evolves specifically inside your company"
    >
      {/* Same warm light as the other sections in the room.
          Cool top-right, rose bottom-left. The continuity tells
          the user we are still in the same place. */}
      <div className="tex-evolution-wash tex-evolution-wash--cool" aria-hidden="true" />
      <div className="tex-evolution-wash tex-evolution-wash--rose" aria-hidden="true" />

      <div className="tex-evolution-stage">
        {LINES.map((text, i) => (
          <p
            key={i}
            className="tex-evolution-line"
            style={{
              transitionDelay: `${ENTRY_DELAY_MS + i * STAGGER_MS}ms`,
            }}
          >
            <span className="tex-evolution-line-ink">{text}</span>
            {/* The light sweep — a single soft glass pass that
                lights up the line once the third line has
                settled. The same material as the hero. */}
            <span
              className="tex-evolution-sweep"
              aria-hidden="true"
              style={{
                /* Each line's sweep starts slightly after the
                   previous one, so the light moves diagonally
                   across the three sentences as a group rather
                   than hitting them in parallel. */
                animationDelay: `${i * 220}ms`,
              }}
            />
          </p>
        ))}
      </div>

      {/* Screen-reader summary for assistive tech. */}
      <p className="tex-sr-only">
        Tex evolves specifically: I learn your environment. I evolve
        with your agents. I get smarter every day.
      </p>
    </section>
  );
}
