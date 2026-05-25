import React, { useEffect, useRef, useState } from 'react';
import './SelfSection.css';

/* =============================================================
   SELF SECTION — screen two

   The hero ends on "Absolute." This section is Tex's own
   reply — a colleague describing themselves in six plain
   sentences. No grid. No numbers. No icons. No subheads.

   The lines are a poem, not a feature list. They arrive on
   scroll, one beat at a time, and accumulate. By the end of
   the section all six are present, the way a person's full
   sentence is present in your ear after they've finished
   speaking. Tex says it once.

   The fourth line — "I act, or I don't." — is the pivot.
   The three lines above it describe what Tex does to the
   world. The two lines below describe what Tex owes the
   human. The pivot is the moment of consequence, and it gets
   a little more vertical breathing room above and below than
   the other line breaks. The silence is the emphasis. Not
   italic, not bigger, not colored. Just space.

   The MomentSection that follows ("I stopped something")
   is the proof of this section. If Tex says it acts or it
   doesn't, the next scroll has to show Tex not acting.
   ============================================================= */

const LINES = [
  'I find every agent.',
  'I verify who they are.',
  'I watch behavior over time.',
  "I act, or I don't.",
  'I show my work.',
  'I get sharper.',
];

// Index of the pivot line — receives extra breathing room.
const PIVOT_INDEX = 3;

// Stagger between arrivals. The first line lands ~400ms after
// the section enters view, so the user has a moment to settle
// before Tex begins speaking. Each subsequent line follows ~720ms
// later — slow enough to read, quick enough that the rhythm holds.
const ENTRY_DELAY_MS = 400;
const STAGGER_MS = 720;

export default function SelfSection() {
  const sectionRef = useRef(null);
  const [armed, setArmed] = useState(false);

  // Arm the arrival once, when the section first enters the
  // viewport. After that we don't re-trigger on subsequent
  // intersections — the section says it once, like a person.
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
      { threshold: 0.25 }
    );
    io.observe(node);
    return () => io.disconnect();
  }, []);

  return (
    <section
      ref={sectionRef}
      className={`tex-self${armed ? ' tex-self--armed' : ''}`}
      id="self"
      aria-label="Tex, on what it does"
    >
      {/* Same warm light as MomentSection — cool top-right,
          rose bottom-left. The continuity tells the eye we are
          still in the same room as the hero, just deeper in. */}
      <div className="tex-self-wash tex-self-wash--cool" aria-hidden="true" />
      <div className="tex-self-wash tex-self-wash--rose" aria-hidden="true" />

      <div className="tex-self-stage">
        <ol className="tex-self-lines">
          {LINES.map((text, i) => (
            <li
              key={i}
              className={
                'tex-self-line' +
                (i === PIVOT_INDEX ? ' tex-self-line--pivot' : '')
              }
              style={{
                /* The line waits its turn. The CSS owns the
                   actual transition; we just hand it the delay. */
                transitionDelay: `${ENTRY_DELAY_MS + i * STAGGER_MS}ms`,
              }}
            >
              {text}
            </li>
          ))}
        </ol>
      </div>

      {/* Screen-reader summary — the six lines read as one
          sentence for assistive tech, in Tex's voice. */}
      <p className="tex-sr-only">
        Tex describes itself: I find every agent. I verify who they
        are. I watch behavior over time. I act, or I don&rsquo;t. I
        show my work. I get sharper.
      </p>
    </section>
  );
}
