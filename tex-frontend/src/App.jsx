import React, { useEffect, useState } from "react";
import Hub from "./components/Hub.jsx";
import Game from "./components/Game.jsx";
import Arcade from "./components/Arcade.jsx";
import ShiftReport from "./components/ShiftReport.jsx";
import WhatIsTex from "./components/WhatIsTex.jsx";

/*
  App v15 — phase router with arcade route
  ─────────────────────────────────────────
  Routes:
    hub          → landing + leaderboard
    game         → conveyor (mode: "daily" | "training")
    arcade       → vertical-shooter gate defense
    shiftReport  → end-of-shift cinema
    whatIsTex    → scrolling explainer

  Deep links honored on initial mount:
    /training       → start training
    /daily          → start daily (if not played)
    /arcade         → start arcade
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
    } else if (path.startsWith("/arcade")) {
      setPhase("arcade");
    } else if (path.startsWith("/what-is-tex")) {
      setPhase("whatIsTex");
    }
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const map = {
      hub: "/",
      game: mode === "daily" ? "/daily" : "/training",
      arcade: "/arcade",
      shiftReport: "/report",
      whatIsTex: "/what-is-tex",
    };
    const next = map[phase] || "/";
    if (window.location.pathname !== next) {
      window.history.replaceState(null, "", next);
    }
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
          onPlayArcade={() => go("arcade")}
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

      {phase === "arcade" && (
        <Arcade
          onComplete={(r) => { setResult(r); go("shiftReport"); }}
          onBail={() => go("hub")}
        />
      )}

      {phase === "shiftReport" && result && (
        <ShiftReport
          result={result}
          mode={result?._mode === "arcade" ? "arcade" : mode}
          onPlayAgain={() => go(result?._mode === "arcade" ? "arcade" : "game", "training")}
          onHome={() => go("hub")}
        />
      )}

      {phase === "whatIsTex" && (
        <WhatIsTex
          onBack={() => go("hub")}
          onPlayDaily={() => go("game", "daily")}
        />
      )}

      {whipKey > 0 && <div key={whipKey} className="phase-whip" aria-hidden="true" />}
    </>
  );
}
