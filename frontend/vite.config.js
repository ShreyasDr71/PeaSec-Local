import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": "http://127.0.0.1:18001" } },
  base: "./",                       // relative asset URLs so the same build works under /demo/<id>/
  build: { outDir: "../static", emptyOutDir: true, assetsDir: "assets" },
});
