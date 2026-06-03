/* =============================================================
   Calendly — the only outbound action on the site.

   Two "Show me" buttons (Hero top-bar and Moment) both lead
   here. We don't navigate away from tex.systems; Calendly's
   widget.js opens an inline modal over the current page. The
   widget script is loaded once, globally, in index.html.

   If for any reason the widget script hasn't finished loading
   when the user clicks (rare — async script, no render block),
   we fall back to opening Calendly in a new tab so the click
   never feels dead.
   ============================================================= */

export const CALENDLY_URL = 'https://calendly.com/matt-vortexblack/tex-trial';

export function openCalendly() {
  if (typeof window === 'undefined') return;

  if (window.Calendly && typeof window.Calendly.initPopupWidget === 'function') {
    window.Calendly.initPopupWidget({ url: CALENDLY_URL });
    return;
  }

  // Fallback — widget script not ready yet.
  window.open(CALENDLY_URL, '_blank', 'noopener,noreferrer');
}
