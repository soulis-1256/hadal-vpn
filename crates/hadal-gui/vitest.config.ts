import path from "node:path";
import { defineConfig } from "vitest/config";
import solidPlugin from "vite-plugin-solid";

export default defineConfig({
  plugins: [solidPlugin()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
    conditions: ["development", "browser"],
  },
  test: {
    environment: "jsdom",
    globals: false,
    include: ["tests/**/*.test.{ts,tsx}"],
  },
});
