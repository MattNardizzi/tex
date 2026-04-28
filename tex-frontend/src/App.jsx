import React, { useEffect, useState } from "react";
import Hub from "./components/Hub.jsx";
import Arcade from "./components/Arcade.jsx";
import ShiftReport from "./components/ShiftReport.jsx";
import WhatIsTex from "./components/WhatIsTex.jsx";

/*
  App v16 — Arcade-only release
  ──────────────────────────────
  Routes:
    hub          → landing + leaderboard
    arcade       → vertical-shooter gate defense (the only playable mode)
    shiftReport  → end-of-shift cinema
    whatIsTex    → scrolling explainer

  Deep links:
    /arcade           → start arcade
    /daily, /training → REDIRECT to /arcade (legacy paths from prior build)
    /what-is-tex      → explainer

  The conveyor (Game.jsx, daily/training modes) is intentionally NOT
  imported in this build. Source files remain on disk so the mode can be
  re-enabled later without re-implementation.
*/

export default function App() {
  const [phase, setPhase] = useState("hub");
  const [result, setResult] = useState(null);
  const [whipKey, setWhipKey] = useState(0);

  useEffect(() => {
    const path = (typeof window !== "undefined" ? window.location.pathname : "") || "";
    // Legacy /daily and /training redirect to /arcade — no broken links.
    if (
      path.startsWith("/arcade") ||
      path.startsWith("/daily") ||
      path.startsWith("/training")
    ) {
      setPhase("arcade");
    } else if (path.startsWith("/what-is-tex")) {
      setPhase("whatIsTex");
    }
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const map = {
      hub: "/",
      arcade: "/arcade",
      shiftReport: "/report",
      whatIsTex: "/what-is-tex",
    };
    const next = map[phase] || "/";
    if (window.location.pathname !== next) {
      window.history.replaceState(null, "", next);
    }
    setWhipKey((k) => k + 1);
  }, [phase]);

  function go(nextPhase) {
    setPhase(nextPhase);
  }

  return (
    <>
      {phase === "hub" && (
        <Hub
          onPlayArcade={() => go("arcade")}
          onOpenWhatIsTex={() => go("whatIsTex")}
        />
      )}

      {phase === "arcade" && (
        <Arcade
          onComplete={(r) => { setResult(r); go("shiftReport"); }}
          onBail={() => go("hub")}
        />
      )}

      {phase === "shiftReport" && result && (
        <ShiftReport
          result={result}
          mode="arcade"
          onPlayAgain={() => go("arcade")}
          onHome={() => go("hub")}
        />
      )}

      {phase === "whatIsTex" && (
        <WhatIsTex
          onBack={() => go("hub")}
          onPlayDaily={() => go("arcade")}
        />
      )}

      {whipKey > 0 && <div key={whipKey} className="phase-whip" aria-hidden="true" />}
    </>
  );
}
