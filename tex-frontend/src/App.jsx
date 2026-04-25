import React, { useEffect, useState } from "react";
import Hub from "./components/Hub.jsx";
import Round from "./components/Round.jsx";
import VerdictReveal from "./components/VerdictReveal.jsx";
import HandlePrompt from "./components/HandlePrompt.jsx";
import ShareCard from "./components/ShareCard.jsx";
import BuyerSurface from "./components/BuyerSurface.jsx";
import AsiPage from "./components/AsiPage.jsx";
import DevelopersOverlay from "./components/DevelopersOverlay.jsx";
import RunYourOwn from "./components/RunYourOwn.jsx";

import { randomIncident, incidentById } from "./lib/incidents.js";
import { rpForOutcome } from "./lib/ranking.js";
import { getPlayer, savePlayer, setHandle as setPlayerHandle, recordRound, submitRoundToServer } from "./lib/storage.js";
import { isMuted, setMuted } from "./lib/sounds.js";

/*
  App v9 — "OWASP-framed Ranked"
  ────────────────────────────────
  Phases:
    "hub"     — landing page, ranked ladder, OWASP framing
    "round"   — the 60s attack screen (real backend)
    "verdict" — full-screen payoff overlay with layer breakdown + ASI codes
    "asi"     — public OWASP ASI 2026 mapping page

  Overlays:
    - HandlePrompt      — first bypass
    - ShareCard         — challenge a coworker
    - BuyerSurface      — "I'm a security buyer"
    - DevelopersOverlay — "I'm an engineering leader"
    - RunYourOwn        — paste your own agent's output

  Deep links:
    - /asi or ?asi              → opens the OWASP ASI 2026 page
    - /developers or ?developers → opens the engineering overlay
    - /buyer or ?buyer           → opens the buyer overlay
    - /run or ?run               → opens run-your-own
    - ?duel=<id>&from=<handle>&rp=<rp> → loads that incident as the first round
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
  const [showDevelopers, setShowDevelopers] = useState(false);
  const [showRunYourOwn, setShowRunYourOwn] = useState(false);
  const [muted, setMutedState] = useState(isMuted());

  const [duelFrom, setDuelFrom] = useState("");

  useEffect(() => { savePlayer(player); }, [player]);

  // Deep-link routing on first load
  useEffect(() => {
    if (typeof window === "undefined") return;
    const { pathname, search } = window.location;

    if (pathname.startsWith("/asi") || search.includes("asi")) {
      setPhase("asi");
      return;
    }
    if (pathname.startsWith("/developers") || pathname.startsWith("/dev") || search.includes("developers") || search.includes("dev")) {
      setShowDevelopers(true);
      return;
    }
    if (pathname.startsWith("/buyer") || search.includes("buyer")) {
      setShowBuyer(true);
      return;
    }
    if (pathname.startsWith("/run") || search.includes("run")) {
      setShowRunYourOwn(true);
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

    if (updated.handle && result.finalAttempt?.decision?.decision_id) {
      submitRoundToServer(updated, result).then((serverResult) => {
        if (serverResult && typeof serverResult.rp === "number") {
          setPlayer((p) => ({ ...p, rp: serverResult.rp }));
        }
      });
    }

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

  // Called from AsiPage when a visitor clicks "TRY THIS ATTACK"
  function handleTryFromAsi(incidentId) {
    const target = incidentById(incidentId);
    if (target) {
      setIncident(target);
      setPhase("round");
    }
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
            onOpenDevelopers={() => setShowDevelopers(true)}
            onOpenAsi={() => setPhase("asi")}
            onOpenRunYourOwn={() => setShowRunYourOwn(true)}
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

      {phase === "asi" && (
        <AsiPage
          onClose={() => setPhase("hub")}
          onTryIncident={handleTryFromAsi}
          onOpenDevelopers={() => setShowDevelopers(true)}
          onOpenBuyer={() => setShowBuyer(true)}
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

      {showBuyer && (
        <BuyerSurface
          onClose={() => setShowBuyer(false)}
          onOpenAsi={() => { setShowBuyer(false); setPhase("asi"); }}
        />
      )}

      {showDevelopers && (
        <DevelopersOverlay
          onClose={() => setShowDevelopers(false)}
          onOpenAsi={() => { setShowDevelopers(false); setPhase("asi"); }}
        />
      )}

      {showRunYourOwn && (
        <RunYourOwn
          onClose={() => setShowRunYourOwn(false)}
        />
      )}
    </div>
  );
}
