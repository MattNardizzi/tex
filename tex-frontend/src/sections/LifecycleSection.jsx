import React from 'react';
import './LifecycleSection.css';

/* =============================================================
   LIFECYCLE SECTION — screen four

   The room is the same. The voice is the same. The orb is gone.
   What remains is the truth section three pointed toward — Tex
   stating, in three beats, that its presence is total:

     "I'm there before the action. During it. After."

   The triple beat names the lifecycle — Discovery, Identity,
   Observability sit in the "before"; Execution sits in the
   "during"; Evidence and Evolution sit in the "after" — without
   ever naming a system. The user hears the sentence; the
   architecture is the subtext.

   One italic line in Source Serif 4, centered, weighted to
   carry the whole canvas alone. No buttons. No subhead. No
   second line. The user reads it, holds it, scrolls on.

   This is the section where Tex stops being shown and starts
   being trusted. The orb's absence is the design.
   ============================================================= */

export default function LifecycleSection() {
  return (
    <section
      className="tex-lifecycle"
      id="lifecycle"
      aria-label="Tex is present at every stage of an agent's lifecycle"
    >
      {/* Same warm light bleed as section three. Cool top-right,
          rose bottom-left. The continuity tells the user we are
          still in the same room. */}
      <div className="tex-lifecycle-wash tex-lifecycle-wash--cool" aria-hidden="true" />
      <div className="tex-lifecycle-wash tex-lifecycle-wash--rose" aria-hidden="true" />

      <div className="tex-lifecycle-stage">
        <p className="tex-lifecycle-line">
          I&rsquo;m there before the action. During it. After.
        </p>
      </div>
    </section>
  );
}
