import React from 'react';
import './LifecycleSection.css';

/* =============================================================
   LIFECYCLE SECTION — screen three

   The room is the same. The voice is the same. The orb is gone.
   What remains is the truth section two pointed toward:

     "I'm there the whole time."

   One italic sentence in Source Serif 4, centered, weighted to
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
      aria-label="Tex governs the entire lifecycle of an agent"
    >
      {/* Same warm light bleed as section two. Cool top-right,
          rose bottom-left. The continuity tells the user we are
          still in the same room. */}
      <div className="tex-lifecycle-wash tex-lifecycle-wash--cool" aria-hidden="true" />
      <div className="tex-lifecycle-wash tex-lifecycle-wash--rose" aria-hidden="true" />

      <div className="tex-lifecycle-stage">
        <p className="tex-lifecycle-line">
          I&rsquo;m there the whole time.
        </p>
      </div>
    </section>
  );
}
