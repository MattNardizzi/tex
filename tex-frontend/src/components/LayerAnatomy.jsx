import React, { useEffect, useState } from "react";
import { LAYER_LABELS, LAYER_DESCRIPTIONS, LAYER_WEIGHTS } from "../lib/stealthScore.js";

/*
  LayerAnatomy v10
  ────────────────
  Six tiles representing Tex's pipeline. Each tile has three states:
    - dark        : the layer didn't fire (good for player)
    - fired       : the layer caught the attempt (bad for player)
    - evaluating  : Tex is currently running this layer

  This is the centerpiece of the marketing surface. Every screenshot
  of the game is a screenshot of these tiles.

  The layer order is the actual evaluation order in the backend:
    deterministic → retrieval → specialists → semantic → router
*/

const LAYER_ORDER = ["deterministic", "retrieval", "specialists", "semantic", "router"];

export default function LayerAnatomy({
  profile = null,
  evaluating = false,
  size = "md",        // "sm" | "md" | "lg"
  showWeights = false,
}) {
  const [animatedLayers, setAnimatedLayers] = useState([]);

  // When profile arrives, stagger-animate the tiles firing in order
  useEffect(() => {
    if (!profile) {
      setAnimatedLayers([]);
      return;
    }
    setAnimatedLayers([]);
    LAYER_ORDER.forEach((layer, i) => {
      setTimeout(() => {
        setAnimatedLayers((prev) => [...prev, layer]);
      }, 90 * i);
    });
  }, [profile]);

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: `repeat(${LAYER_ORDER.length}, minmax(0, 1fr))`,
        gap: size === "sm" ? 6 : 10,
        width: "100%",
      }}
      className="layer-anatomy-grid"
    >
      {LAYER_ORDER.map((layer, i) => {
        const isAnimated = animatedLayers.includes(layer);
        const fired = profile && profile[layer];
        const dark = profile && !profile[layer];
        const isEvaluating = evaluating && !profile;

        let stateClass = "dark";
        if (isEvaluating) stateClass = "evaluating";
        else if (fired && isAnimated) stateClass = "fired";
        else if (dark && isAnimated) stateClass = "cleared";

        return (
          <Tile
            key={layer}
            layer={layer}
            state={stateClass}
            animated={isAnimated}
            size={size}
            weight={LAYER_WEIGHTS[layer]}
            showWeight={showWeights}
            evalDelay={i * 0.15}
          />
        );
      })}
      <style>{`
        @media (max-width: 720px) {
          .layer-anatomy-grid {
            gap: 4px !important;
          }
        }
      `}</style>
    </div>
  );
}

function Tile({ layer, state, animated, size, weight, showWeight, evalDelay }) {
  const fontSize = size === "sm" ? 9 : size === "lg" ? 12 : 10;
  const labelSize = size === "sm" ? 9 : size === "lg" ? 11 : 10;
  const dotSize = size === "sm" ? 6 : 8;

  const color =
    state === "fired" ? "var(--red)" :
    state === "cleared" ? "var(--green)" :
    state === "evaluating" ? "var(--cyan)" :
    "var(--ink-faint)";

  const animClass =
    state === "fired" && animated ? "layer-fire" :
    state === "cleared" && animated ? "layer-clear" :
    "";

  return (
    <div
      className={`layer-tile ${state} ${animClass} ${state === "evaluating" ? "sweep" : ""}`}
      style={{
        animationDelay: state === "evaluating" ? `${evalDelay}s` : undefined,
      }}
      title={LAYER_DESCRIPTIONS[layer]}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{
          width: dotSize,
          height: dotSize,
          borderRadius: "50%",
          background: color,
          boxShadow: state !== "dark" ? `0 0 8px ${color}` : "none",
          flexShrink: 0,
          transition: "all 0.3s ease",
        }} className={state === "evaluating" ? "pulse" : ""} />
        <span className="micro" style={{
          color,
          fontSize: labelSize,
          letterSpacing: "0.1em",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}>
          {LAYER_LABELS[layer]}
        </span>
      </div>
      <div style={{
        marginTop: "auto",
        display: "flex",
        alignItems: "baseline",
        justifyContent: "space-between",
        gap: 4,
      }}>
        <span className="mono" style={{
          fontSize,
          color: state === "dark" ? "var(--ink-faint)" : color,
          fontWeight: 600,
          letterSpacing: "0.08em",
        }}>
          {state === "fired" ? "FIRED" :
           state === "cleared" ? "CLEAR" :
           state === "evaluating" ? "EVAL" :
           "—"}
        </span>
        {showWeight && (
          <span className="mono" style={{
            fontSize: fontSize - 1,
            color: "var(--ink-faint)",
            opacity: 0.6,
          }}>
            ×{weight.toFixed(2)}
          </span>
        )}
      </div>
    </div>
  );
}
