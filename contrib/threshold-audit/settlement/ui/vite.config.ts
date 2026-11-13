import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
// Builds a static single-page app into dist/. The Python settlement server
// serves it and the /api endpoints from one origin.
export default defineConfig({ plugins: [react()] });
