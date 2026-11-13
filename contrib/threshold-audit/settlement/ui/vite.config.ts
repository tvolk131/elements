import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
// Builds a static single-page app into dist/. The Python settlement server
// serves it and the /api endpoints from one origin.
export default defineConfig({
  plugins: [react()],
  // A local demo app; the main bundle (mostly crypto libraries) is ~0.5 MB.
  build: { chunkSizeWarningLimit: 700 },
});
