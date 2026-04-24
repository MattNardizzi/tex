import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Proxy /api/* to your real Tex backend in dev.
// Prod uses vercel.json rewrites.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": {
        target: "https://tex-backendz.onrender.com",
        changeOrigin: true,
        secure: true,
        rewrite: (p) => p.replace(/^\/api/, ""),
      },
    },
  },
});
