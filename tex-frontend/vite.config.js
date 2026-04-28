import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Proxy /api/* to the Tex backend in dev. Same target as the prod
// Vercel rewrite in vercel.json — keep them in sync.
//
// Override locally with VITE_API_PROXY=http://127.0.0.1:8000 npm run dev
// when developing against a local backend.
const TARGET = process.env.VITE_API_PROXY || "https://tex-2far.onrender.com";

// Build-time stamp baked into the bundle so we can verify which version is
// actually running in a browser. Useful for diagnosing CDN/cache issues.
// Format: YYYYMMDD-HHMM (UTC). Exposed as __TEX_BUILD__ in app code.
const BUILD_STAMP = (() => {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}` +
    `-${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}`
  );
})();

export default defineConfig({
  plugins: [react()],
  define: {
    __TEX_BUILD__: JSON.stringify(BUILD_STAMP),
  },
  server: {
    proxy: {
      "/api": {
        target: TARGET,
        changeOrigin: true,
        secure: true,
        rewrite: (p) => p.replace(/^\/api/, ""),
      },
    },
  },
});
