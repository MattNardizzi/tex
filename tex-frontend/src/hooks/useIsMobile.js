import { useEffect, useState } from 'react';

/* =============================================================
   useIsMobile — single source of truth for which experience to render.

   Tex ships two completely separate front-ends. The desktop site
   is a long white scroll. The mobile site is an eight-card breath
   designed for a phone held at thumb distance. This hook tells App
   which one is in front of the user.

   The cut-off is 720px. That number is the desktop CSS's existing
   mobile breakpoint, and we use the same one so a browser that
   crosses the line by resizing also crosses the line in the JS.

   matchMedia is the right primitive here — it fires on viewport
   change, on orientation change, and on dev-tools resize, without
   needing a resize listener. We render on the server / initial
   client tick as desktop (the safer default for SEO) and re-render
   on mount once we know.
   ============================================================= */

const MOBILE_QUERY = '(max-width: 720px)';

export function useIsMobile() {
  const [isMobile, setIsMobile] = useState(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return false;
    return window.matchMedia(MOBILE_QUERY).matches;
  });

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const mql = window.matchMedia(MOBILE_QUERY);
    const onChange = (e) => setIsMobile(e.matches);
    setIsMobile(mql.matches);

    // Modern browsers support addEventListener on MediaQueryList; older
    // Safari needs addListener. Try the modern API first.
    if (mql.addEventListener) {
      mql.addEventListener('change', onChange);
      return () => mql.removeEventListener('change', onChange);
    } else {
      mql.addListener(onChange);
      return () => mql.removeListener(onChange);
    }
  }, []);

  return isMobile;
}
