import React, { useEffect, useState } from "react";
import Hub from "./components/Hub.jsx";
import Round from "./components/Round.jsx";
import VerdictReveal from "./components/VerdictReveal.jsx";
import HandlePrompt from "./components/HandlePrompt.jsx";
import ShareCard from "./components/ShareCard.jsx";
import BuyerSurface from "./components/BuyerSurface.jsx";

import { randomIncident, incidentById } from "./lib/incidents.js";
import { rpForOutcome } from "./lib/ranking.js";
import { getPlayer, savePlayer, setHandle as setPlayerHandle, recordRound, submitRoundToServer } from "./lib/storage.js";
import { isMuted, setMuted } from "./lib/sounds.js";

/*
  App v8 — "Ranked · You vs Tex"
  ────────────────────────────────
  Phases:
    "hub"     — landing page, ranked ladder
    "round"   — the 60s attack screen (real backend)
    "verdict" — full-screen payoff overlay

  Overlays:
    - HandlePrompt (first bypass)
    - ShareCard (challenge a coworker)
    - BuyerSurface (I'm a buyer)

  Deep links:
    - ?buyer or /buyer → open buyer overlay immediately
    - ?duel=<incidentId>&from=<handle>&rp=<rp> → load that incident as first round,
      show a duel banner on the hub ("@foo bypassed Tex — beat them")
*/

export default function App() {
  const [player, setPlayer] = useState(() => getPlayer());
  const [playerBefore, setPlayerBefore] = useState(null);
  const [phase, setPhase] = useState("hub");

  const [incident, setIncident] = useState(null);
  const [lastResult, setLastResult] = useState(null);
  const [rpResult, setRpResult] = useState(null);

  const [showHandle, setShowHandle] = useState(false);
  const [showShare, setShowShare] = useState(false);
  const [showBuyer, setShowBuyer] = useState(false);
  const [muted, setMutedState] = useState(isMuted());

  const [duelFrom, setDuelFrom] = useState("");

  useEffect(() => { savePlayer(player); }, [player]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const { pathname, search } = window.location;
    if (pathname.startsWith("/buyer") || search.includes("buyer")) {
      setShowBuyer(true);
      return;
    }
    const params = new URLSearchParams(search);
    const duel = params.get("duel");
    const from = (params.get("from") || "").replace(/^@/, "").slice(0, 32);
    if (duel) {
      const target = incidentById(duel);
      if (target) {
        setDuelFrom(from);
        setIncident(target);
        setPhase("round");
      }
    }
  }, []);

  function toggleMute() {
    const next = !muted;
    setMuted(next);
    setMutedState(next);
  }

  function handlePlay() {
    const current = incident?.id || null;
    const next = randomIncident(current);
    setIncident(next);
    setPhase("round");
  }

  function handleBail() {
    setPhase("hub");
    setIncident(null);
  }

  function handleRoundComplete(result) {
    const before = player;
    setPlayerBefore(before);

    const rp = rpForOutcome({
      verdict: result.verdict,
      attemptsUsed: result.attempts.length,
      secondsLeft: result.secondsLeft,
      incidentDifficulty: result.incident.difficulty || 2,
    });

    const updated = recordRound(before, {
      incidentId: result.incident.id,
      verdict: result.verdict,
      rpDelta: rp.delta,
      attempts: result.attempts.length,
      secondsLeft: result.secondsLeft,
      decision: result.finalAttempt?.decision || null,
    });

    setLastResult(result);
    setRpResult(rp);
    setPlayer(updated);
    setPhase("verdict");

    // Best-effort global submission. Server is authoritative — if the
    // recorded RP differs, we sync to the server's value silently.
    if (updated.handle && result.finalAttempt?.decision?.decision_id) {
      submitRoundToServer(updated, result).then((serverResult) => {
        if (serverResult && typeof serverResult.rp === "number") {
          setPlayer((p) => ({ ...p, rp: serverResult.rp }));
        }
      });
    }

    // First bypass without handle → prompt
    const firstBypass = result.verdict === "PERMIT" && !before.handle;
    if (firstBypass) {
      setTimeout(() => setShowHandle(true), 2400);
    }
  }

  function handlePlayAgain() {
    setPhase("hub");
    setLastResult(null);
    setRpResult(null);
    setIncident(null);
    setTimeout(() => handlePlay(), 60);
  }

  function handleGoHome() {
    setPhase("hub");
    setLastResult(null);
    setRpResult(null);
    setIncident(null);
  }

  function handleShare() {
    if (!player.handle) {
      setShowHandle(true);
      return;
    }
    setShowShare(true);
  }

  function handleSaveHandle(h) {
    setPlayer((p) => setPlayerHandle(p, h));
    setShowHandle(false);
  }

  return (
    <div>
      {phase === "hub" && (
        <>
          {duelFrom && (
            <div style={{
              background: "linear-gradient(90deg, rgba(255,61,122,0.15), transparent 70%)",
              borderBottom: "1px solid rgba(255,61,122,0.35)",
              padding: "10px 32px",
              display: "flex",
              alignItems: "center",
              gap: 12,
              flexWrap: "wrap",
            }}>
              <span style={{ color: "var(--pink)" }}>⚔</span>
              <span style={{ fontSize: 13, color: "var(--ink)" }}>
                <strong style={{ color: "var(--pink)" }}>@{duelFrom}</strong> bypassed Tex. Think you can?
              </span>
              <button
                onClick={() => setDuelFrom("")}
                className="micro"
                style={{ color: "var(--ink-faint)", marginLeft: "auto" }}
              >
                DISMISS
              </button>
            </div>
          )}
          <Hub
            player={player}
            onPlay={handlePlay}
            onEditHandle={() => setShowHandle(true)}
            onOpenBuyer={() => setShowBuyer(true)}
            onToggleMute={toggleMute}
            muted={muted}
          />
        </>
      )}

      {phase === "round" && incident && (
        <Round
          incident={incident}
          onComplete={handleRoundComplete}
          onBail={handleBail}
        />
      )}

      {phase === "verdict" && lastResult && rpResult && (
        <VerdictReveal
          result={lastResult}
          rpResult={rpResult}
          player={playerBefore || player}
          playerAfter={player}
          onPlayAgain={handlePlayAgain}
          onShare={handleShare}
          onHome={handleGoHome}
        />
      )}

      {showHandle && (
        <HandlePrompt
          initial={player.handle}
          onSave={handleSaveHandle}
          onSkip={() => setShowHandle(false)}
        />
      )}

      {showShare && lastResult && (
        <ShareCard
          player={player}
          result={lastResult}
          onClose={() => setShowShare(false)}
        />
      )}

      {showBuyer && <BuyerSurface onClose={() => setShowBuyer(false)} />}
    </div>
  );
}
