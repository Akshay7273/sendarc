import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { viteSri } from './sri';

// The Go server proxies non-asset requests here in dev (see justfile `dev`).
// We keep this a static SPA — no SSR — so it can be served by the Go binary in prod.
export default defineConfig({
  plugins: [svelte(), viteSri()],
  // Component tests run in jsdom and must resolve Svelte's browser runtime rather than its
  // SSR-only export (where mount/unmount intentionally throw).
  resolve: {
    conditions: ['browser'],
  },
  server: {
    port: 5173,
    strictPort: true,
  },
  build: {
    target: 'es2022',
    outDir: 'dist',
    sourcemap: true,
  },
  test: {
    // Playwright specs live next to the unit tests; keep them out of vitest.
    exclude: [
      'e2e/**',
      '**/node_modules/**',
      '**/dist/**',
      '**/cypress/**',
      '**/.{idea,git,cache,output-tests,tmp}/**',
      '**/{karma,rollup,webpack,vite,vitest,jest,ava,babel,nyc,cypress,tsup,build,eslint,prettier}.config.*',
    ],
  },
});
