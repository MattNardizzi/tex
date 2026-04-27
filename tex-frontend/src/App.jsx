import React, { useEffect, useState } from "react";
import Hub from "./components/Hub.jsx";
import Game from "./components/Game.jsx";
import ShiftReport from "./components/ShiftReport.jsx";
import WhatIsTex from "./components/WhatIsTex.jsx";

/*
  App v11 — phase router
  ──────────────────────
  Phases:
    hub          → landing + leaderboard
    game         → conveyor (mode: "daily" | "training")
    shiftReport  → end-of-shift screen
    whatIsTex    → simple explainer page

  Deep links honored on initial mount:
    /training       → start training
    /daily          → start daily (if not played)
    /what-is-tex    → explainer
*/

export default function App() {
  const [phase, setPhase] = useState("hub");
  const [mode, setMode] = useState("daily");
  const [result, setResult] = useState(null);

  // Deep-link routing on first mount
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

  // Update URL as phases change so users can share links
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
  }, [phase, mode]);

  return (
    <>
      {phase === "hub" && (
        <Hub
          onPlayDaily={() => { setMode("daily"); setPhase("game"); }}
          onPlayTraining={() => { setMode("training"); setPhase("game"); }}
          onOpenWhatIsTex={() => setPhase("whatIsTex")}
        />
      )}

      {phase === "game" && (
        <Game
          mode={mode}
          onComplete={(r) => { setResult(r); setPhase("shiftReport"); }}
          onBail={() => setPhase("hub")}
        />
      )}

      {phase === "shiftReport" && result && (
        <ShiftReport
          result={result}
          mode={mode}
          onPlayAgain={() => { setMode(mode === "daily" ? "training" : "training"); setPhase("game"); }}
          onHome={() => setPhase("hub")}
        />
      )}

      {phase === "whatIsTex" && (
        <WhatIsTex onBack={() => setPhase("hub")} />
      )}
    </>
  );
}
