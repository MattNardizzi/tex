export function formatPercent(value, digits = 0) {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  return `${(value * 100).toFixed(digits)}%`;
}

export function formatScore(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  return value.toFixed(2);
}

export function truncate(text, n = 120) {
  if (!text) return "";
  return text.length > n ? text.slice(0, n - 1) + "…" : text;
}

export function ms(n) {
  if (typeof n !== "number" || !Number.isFinite(n)) return "—";
  return `${n}ms`;
}
