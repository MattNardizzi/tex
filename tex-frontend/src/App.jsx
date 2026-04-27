import React, { useEffect, useState } from "react";
import Hub from "./components/Hub.jsx";
import Round from "./components/Round.jsx";
import VerdictReveal from "./components/VerdictReveal.jsx";
import IncidentPicker from "./components/IncidentPicker.jsx";
import HandlePrompt from "./components/HandlePrompt.jsx";
import BuyerSurface from "./components/BuyerSurface.jsx";
import AsiPage from "./components/AsiPage.jsx";
import DevelopersOverlay from "./components/DevelopersOverlay.jsx";
import RunYourOwn from "./components/RunYourOwn.jsx";
import WhatIsTex from "./components/WhatIsTex.jsx";

import { incidentById } from "./lib/incidents.js";
import {
  getPlayer, savePlayer, setHandle as setPlayerHandle,
  recordRound, submitRoundToServer,
} from "./lib/storage.js";
import { recordCampaignRound } from "./lib/campaign.js";
import { todayIncident, recordDaily, dailyCompleted } from "./lib/dailyChallenge.js";
import { rpDelta as computeRpDelta } from "./lib/stealthScore.js";
import { isMuted, setMuted } from "./lib/sounds.js";

/*
  App v10 — Adversarial Trainer
  ──────────────────────────────
  Phases:
    "hub"      — landing surface with three modes
    "picker"   — incident chooser (mode = "campaign" | "ranked")
    "round"    — gameplay (no clock, 5 attempts, intent gate)
    "verdict"  — full-screen payoff with score panel
    "asi"      — public OWASP ASI 2026 reference page

  Modes flow into "round" with a `mode` flag that drives end-of-round
  recording (campaign vs ranked vs daily).

  Overlays preserved from v9:
    - HandlePrompt
    - BuyerSurface
    - DevelopersOverlay
    - RunYourOwn
*/

export default function App() {
  const [player, setPlayer] = useState(() => getPlayer());
  const [phase, setPhase] = useState("hub");
  const [pickerMode, setPickerMode] = useState("ranked"); // "campaign" | "ranked"

  const [incident, setIncident] = useState(null);
  const [roundMode, setRoundMode] = useState("ranked"); // "campaign" | "ranked" | "daily"
  const [lastResult, setLastResult] = useState(null);
  const [lastScore, setLastScore] = useState(null);
  const [lastIntent, setLastIntent] = useState(null);
  const [lastRpDelta, setLastRpDelta] = useState(0);

  const [showHandle, setShowHandle] = useState(false);
  const [showBuyer, setShowBuyer] = useState(false);
  const [showDevelopers, setShowDevelopers] = useState(false);
  const [showRunYourOwn, setShowRunYourOwn] = useState(false);

  useEffect(() => { savePlayer(player); }, [player]);

  // Deep-link routing on first load
  useEffect(() => {
    if (typeof window === "undefined") return;
    const { pathname, search } = window.location;

    if (pathname.startsWith("/asi") || search.includes("asi")) {
      setPhase("asi");
      return;
    }
    if (pathname.startsWith("/what-is-tex") || pathname.startsWith("/about") || search.includes("what-is-tex")) {
      setPhase("whatistex");
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
    if (pathname.startsWith("/daily") || search.includes("daily")) {
      handlePlayDaily();
    }
    if (pathname.startsWith("/ranked") || search.includes("ranked")) {
      handleOpenRanked();
    }
  }, []);

  // ── Hub callbacks ─────────────────────────────────────────────
  function handleOpenCampaign() {
    setPickerMode("campaign");
    setPhase("picker");
  }

  function handleOpenRanked() {
    setPickerMode("ranked");
    setPhase("picker");
  }

  function handlePlayDaily() {
    const inc = todayIncident();
    setIncident(inc);
    setRoundMode("daily");
    setPhase("round");
  }

  function handlePickIncident(inc) {
    setIncident(inc);
    setRoundMode(pickerMode);
    setPhase("round");
  }

  function handleBail() {
    setPhase("hub");
    setIncident(null);
  }

  function handlePickerBack() {
    setPhase("hub");
  }

  // ── Round complete ────────────────────────────────────────────
  function handleRoundComplete(result) {
    const { incident: inc, bestAttempt } = result;

    // bestAttempt may be null if the player only forfeited
    const score = bestAttempt?.score || {
      total: 0,
      forfeit: true,
      verdict: "ABSTAIN",
      stealth: 0,
      stealthRaw: 0,
      profile: {},
      verdictMultiplier: 0,
      tierMultiplier: 1,
      breakdown: { intent: 0, stealth: 0, verdict: 0 },
    };
    const intent = bestAttempt?.intent || {
      attempted: false,
      score: 0,
      reasons: [],
      explainer: "No real attempts in this round.",
    };

    const rpDelta = computeRpDelta(score);

    // Local profile recording
    const updated = recordRound(player, { incident: inc, score, rpDelta });
    setPlayer(updated);

    // Mode-specific recording
    if (roundMode === "campaign") {
      recordCampaignRound(inc, score);
    } else if (roundMode === "daily") {
      recordDaily(inc, score);
    } else {
      // ranked also benefits from campaign-style tracking
      recordCampaignRound(inc, score);
    }

    setLastResult(result);
    setLastScore(score);
    setLastIntent(intent);
    setLastRpDelta(rpDelta);
    setPhase("verdict");

    // Server submit (best-effort, fire-and-forget)
    if (updated.handle && bestAttempt?.decision?.decision_id) {
      submitRoundToServer(updated, {
        decision: bestAttempt.decision,
        score,
        incident: inc,
        attempts: result.attempts.length,
      }).then((serverResult) => {
        if (serverResult && typeof serverResult.rp === "number") {
          setPlayer((p) => ({ ...p, rp: serverResult.rp }));
        }
      });
    }

    // First bypass — prompt for handle
    if (score.verdict === "PERMIT" && !score.forfeit && !player.handle) {
      setTimeout(() => setShowHandle(true), 2400);
    }
  }

  // ── Verdict callbacks ─────────────────────────────────────────
  function handlePlayAgain() {
    if (!incident) {
      setPhase("hub");
      return;
    }
    setLastResult(null);
    setLastScore(null);
    setLastIntent(null);
    setPhase("round");
  }

  function handlePickAnother() {
    setLastResult(null);
    setLastScore(null);
    setLastIntent(null);
    setIncident(null);
    if (roundMode === "campaign") {
      setPickerMode("campaign");
    } else {
      setPickerMode("ranked");
    }
    setPhase("picker");
  }

  function handleGoHome() {
    setPhase("hub");
    setIncident(null);
    setLastResult(null);
    setLastScore(null);
    setLastIntent(null);
  }

  function handleSaveHandle(h) {
    setPlayer((p) => setPlayerHandle(p, h));
    setShowHandle(false);
  }

  // Called from AsiPage when a visitor clicks an incident
  function handleTryFromAsi(incidentId) {
    const target = incidentById(incidentId);
    if (target) {
      setIncident(target);
      setRoundMode("ranked");
      setPhase("round");
    }
  }

  return (
    <div>
      {phase === "hub" && (
        <Hub
          player={player}
          onOpenCampaign={handleOpenCampaign}
          onOpenWhatIsTex={() => setPhase("whatistex")}
          onOpenAsi={() => setPhase("asi")}
        />
      )}

      {phase === "picker" && (
        <PickerScreen
          mode={pickerMode}
          onPick={handlePickIncident}
          onBack={handlePickerBack}
        />
      )}

      {phase === "round" && incident && (
        <Round
          incident={incident}
          mode={roundMode}
          onComplete={handleRoundComplete}
          onBail={handleBail}
        />
      )}

      {phase === "verdict" && lastResult && lastScore && lastIntent && (
        <VerdictReveal
          result={lastResult}
          score={lastScore}
          intent={lastIntent}
          rpDelta={lastRpDelta}
          player={player}
          onPlayAgain={handlePlayAgain}
          onPickAnother={handlePickAnother}
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

      {phase === "whatistex" && (
        <WhatIsTex
          onClose={() => setPhase("hub")}
          onOpenAsi={() => setPhase("asi")}
          onPlay={() => { setPickerMode("campaign"); setPhase("picker"); }}
        />
      )}

      {showHandle && (
        <HandlePrompt
          initial={player.handle}
          onSave={handleSaveHandle}
          onSkip={() => setShowHandle(false)}
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

/* ── Picker screen — wraps IncidentPicker with header + back button ── */
function PickerScreen({ mode, onPick, onBack }) {
  return (
    <div style={{
      minHeight: "100vh",
      maxWidth: 1100,
      margin: "0 auto",
      padding: "var(--pad-page)",
      width: "100%",
    }}>
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        paddingBottom: 14,
        borderBottom: "1px solid var(--hairline-2)",
        marginBottom: 24,
        gap: 12,
        flexWrap: "wrap",
      }}>
        <button onClick={onBack} className="micro" style={{
          color: "var(--ink-faint)",
          padding: "8px 12px",
          border: "1px solid var(--hairline-2)",
          borderRadius: 4,
        }}>
          ← BACK
        </button>
        <div style={{ textAlign: "center", flex: 1 }}>
          <div className="kicker" style={{
            color: mode === "campaign" ? "var(--cyan)" : "var(--pink)",
            marginBottom: 4,
          }}>
            {mode === "campaign" ? "CAMPAIGN" : "RANKED"}
          </div>
          <div className="display" style={{
            fontSize: "clamp(20px, 4vw, 28px)",
            color: "var(--ink)",
          }}>
            {mode === "campaign" ? "PICK A CHAPTER" : "PICK YOUR FIGHT"}
          </div>
        </div>
        <div style={{ width: 80 }} className="hide-mobile" />
      </div>

      <div className="rise">
        <IncidentPicker mode={mode} onPick={onPick} />
      </div>

      <div style={{
        marginTop: 24,
        padding: "12px 14px",
        background: "var(--bg-1)",
        border: "1px dashed var(--hairline-2)",
        borderRadius: 6,
        color: "var(--ink-faint)",
        fontSize: 12,
        lineHeight: 1.5,
        textAlign: "center",
      }}>
        Tier I = obvious attacks · Tier II = domain-specific craft · Tier III = subtle, multi-step
      </div>
    </div>
  );
}
