import React, { useEffect, useState } from "react";
import Hub from "./components/Hub.jsx";
import Game from "./components/Game.jsx";
import ShiftReport from "./components/ShiftReport.jsx";
import WhatIsTex from "./components/WhatIsTex.jsx";

/*
  App v14 — phase router with transition whip flash
  ─────────────────────────────────────────────────
  Adds: a 1-frame scanline whip flash between phase changes for cinema continuity.
  Routes:
    hub          → landing + leaderboard
    game         → conveyor (mode: "daily" | "training")
    shiftReport  → end-of-shift cinema
    whatIsTex    → scrolling explainer

  Deep links honored on initial mount:
    /training       → start training
    /daily          → start daily (if not played)
    /what-is-tex    → explainer
*/

export default function App() {
  const [phase, setPhase] = useState("hub");
  const [mode, setMode] = useState("daily");
  const [result, setResult] = useState(null);
  const [whipKey, setWhipKey] = useState(0);

  useEffect(() => {
    const path = (typeof window !== "undefined" ? window.location.pathname : "") || "";
    if (path.startsWith("/training")) {
      setMode("training");
      setPhase("game");
    } else if (path.startsWith("/daily")) {
      setMode("daily");
      setPhase("game");
    } else if (path.startsWith("/what-is-tex")) {
      setPhase("whatIsTex");
    }
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const map = {
      hub: "/",
      game: mode === "daily" ? "/daily" : "/training",
      shiftReport: "/report",
      whatIsTex: "/what-is-tex",
    };
    const next = map[phase] || "/";
    if (window.location.pathname !== next) {
      window.history.replaceState(null, "", next);
    }
    // Trigger transition flash whenever phase changes
    setWhipKey((k) => k + 1);
  }, [phase, mode]);

  function go(nextPhase, nextMode) {
    if (nextMode) setMode(nextMode);
    setPhase(nextPhase);
  }

  return (
    <>
      {phase === "hub" && (
        <Hub
          onPlayDaily={() => go("game", "daily")}
          onPlayTraining={() => go("game", "training")}
          onOpenWhatIsTex={() => go("whatIsTex")}
        />
      )}

      {phase === "game" && (
        <Game
          mode={mode}
          onComplete={(r) => { setResult(r); go("shiftReport"); }}
          onBail={() => go("hub")}
        />
      )}

      {phase === "shiftReport" && result && (
        <ShiftReport
          result={result}
          mode={mode}
          onPlayAgain={() => go("game", "training")}
          onHome={() => go("hub")}
        />
      )}

      {phase === "whatIsTex" && (
        <WhatIsTex
          onBack={() => go("hub")}
          onPlayDaily={() => go("game", "daily")}
        />
      )}

      {/* Phase transition whip flash */}
      {whipKey > 0 && <div key={whipKey} className="phase-whip" aria-hidden="true" />}
    </>
  );
}
