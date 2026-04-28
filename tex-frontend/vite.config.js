import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Proxy /api/* to the Tex backend in dev. Same target as the prod
// Vercel rewrite in vercel.json — keep them in sync.
//
// Override locally with VITE_API_PROXY=http://127.0.0.1:8000 npm run dev
// when developing against a local backend.
const TARGET = process.env.VITE_API_PROXY || "https://tex-2far.onrender.com";

export default defineConfig({
  plugins: [react()],
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
