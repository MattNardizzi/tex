import React from 'react';
import './MomentSection.css';

/* =============================================================
   MOMENT SECTION — screen two

   The promise from screen one ("Quiet.") is fulfilled here by
   the product itself, in its own voice, doing the exact thing
   it was built to do.

   No header. No annotations. No feature list. One italic
   timestamp line above the card; the card; whitespace below.

   The card is identical to the live Execution component in the
   product. The marketing site and the product share one surface.

   Props
   -----
   onShowMe:  () => void   — opens the Execution room / demo
   onThanks:  () => void   — quiet acknowledgement, dismisses
   ============================================================= */

export default function MomentSection({
  onShowMe = () => {},
  onThanks = () => {},
}) {
  return (
    <section className="tex-moment" id="moment" aria-label="A real decision Tex made this morning">
      <div className="tex-moment-wash tex-moment-wash--blue" aria-hidden="true" />
      <div className="tex-moment-wash tex-moment-wash--rose" aria-hidden="true" />

      <div className="tex-moment-stage">
        <p className="tex-moment-timestamp">
          Monday, 9:14 a.m. &nbsp;·&nbsp; A real decision Tex made this morning.
        </p>

        <article
          className="tex-moment-card"
          aria-label="Decision awaiting your review"
        >
          <span className="tex-moment-card-edge" aria-hidden="true" />
          <span className="tex-moment-card-dot" aria-hidden="true" />

          <p className="tex-moment-verdict">
            Kestrel asked to wire fifty thousand dollars in your CEO's name.
          </p>
          <p className="tex-moment-aside">I said no.</p>

          <div className="tex-moment-actions">
            <button
              type="button"
              className="tex-btn tex-btn--primary"
              onClick={onShowMe}
            >
              Show me
            </button>
            <button
              type="button"
              className="tex-btn tex-btn--ghost"
              onClick={onThanks}
            >
              Thank you
            </button>
          </div>
        </article>
      </div>
    </section>
  );
}
