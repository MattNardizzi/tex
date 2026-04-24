import React from "react";

export default function RankBadge({ tier, size = 56 }) {
  if (!tier) return null;
  return (
    <div
      style={{
        width: size,
        height: size,
        background: tier.color,
        borderRadius: 6,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        color: "#0B0410",
        fontFamily: "var(--font-display)",
        boxShadow: `0 0 20px ${tier.color}55`,
      }}
    >
      <div style={{ fontSize: Math.round(size * 0.16), opacity: 0.8, letterSpacing: "0.1em" }}>TIER</div>
      <div style={{ fontSize: Math.round(size * 0.4), lineHeight: 1, marginTop: -2 }}>{tier.short}</div>
    </div>
  );
}
