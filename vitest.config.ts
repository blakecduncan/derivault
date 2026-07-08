import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    // @scopelift/stealth-address-sdk (a dev-only interop reference) ships ESM
    // with directory imports Node's strict resolver rejects; let Vite transform it.
    server: { deps: { inline: ["@scopelift/stealth-address-sdk"] } },
  },
});
