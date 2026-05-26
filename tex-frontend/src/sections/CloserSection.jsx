import React from 'react';
import './CloserSection.css';

/* =============================================================
   CLOSER SECTION — screen six

   The room is the same. The voice changes.

     "The weight is mine now."

   Until this line, every Tex sentence on the page begins with
   "I" and describes what Tex does. This sentence still begins
   with "the weight," but its subject is the thing it lifts off
   the user — what the user has been carrying without saying so.

   The line doesn't tell the user how they feel. It states what
   Tex absorbs, and lets the user recognize the weight on the
   way past. Recognition is more powerful than being told.

   This is the only section on the page where the canvas warms
   back to bg-1 — the same warm cream the user landed on at the
   hero. The page opens loud and ends quiet, but the light comes
   home. Six beats. One room. One voice that, at the end, turns
   to face the reader.

   The italic line is one size larger than Lifecycle and
   Evolution to signal that this is the closer — not by shouting,
   but by giving the sentence the same scale the user first saw
   "Absolute." in. The first word and the last word are at the
   same altitude. The arc closes.
   ============================================================= */

export default function CloserSection() {
  return (
    <section
      className="tex-closer"
      id="closer"
      aria-label="Tex absorbs the responsibility you have been carrying"
    >
      {/* Same warm light as the rest of the room, slightly
          softer than the middle sections so the page feels
          like it's exhaling at the end. */}
      <div className="tex-closer-wash tex-closer-wash--cool" aria-hidden="true" />
      <div className="tex-closer-wash tex-closer-wash--rose" aria-hidden="true" />

      <div className="tex-closer-stage">
        <p className="tex-closer-line">
          The weight is mine now.
        </p>
      </div>
    </section>
  );
}
