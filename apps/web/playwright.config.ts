import { defineConfig, devices } from '@playwright/test';

// E2E against the real web app + signaling server on loopback. The Go server serves the built
// bundle and the WebSocket endpoint on one origin, so browser tests run over the same origin the
// production deployment uses. WebRTC needs no STUN here: both peers live in the same browser.
export default defineConfig({
  testDir: './e2e',
  timeout: 90_000,
  expect: { timeout: 30_000 },
  // One transfer at a time — the signaling server pairs rooms 1:1 and room numbers are global.
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 2 : 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:8443',
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    // WebKit support on Linux is best-effort; opt in locally with E2E_WEBKIT=1.
    ...(process.env.E2E_WEBKIT === '1'
      ? [{ name: 'webkit', use: { ...devices['Desktop Safari'] } }]
      : []),
  ],
  webServer: {
    command: 'pnpm e2e:serve',
    url: 'http://127.0.0.1:8443/healthz',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
