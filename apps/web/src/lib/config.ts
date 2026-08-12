import { parseIceServer, type ICEEntry } from '@sendbeam/protocol';

interface ServerConfig {
  publicUrl: string;
  lanIp: string;
  /** Operator-published ICE servers for direct-path candidate gathering. */
  iceServers?: ICEEntry[];
}

let cfg: ServerConfig | undefined;
// The last time /config.json was fetched, for TTL-guarded refresh (see ICEEntry credentials).
let fetchedAt = 0;

// Runtime ICE config can carry short-lived credentials; never reuse a stale config past this
// bound. Mirrors wire.ICEConfigTTL in the Go module.
const ICE_CONFIG_TTL_MS = 15 * 60 * 1000;

export async function loadConfig(): Promise<void> {
  try {
    const res = await fetch('/config.json', { cache: 'no-store' });
    if (!res.ok) return;
    cfg = (await res.json()) as ServerConfig;
    fetchedAt = Date.now();
  } catch {
    // config.json is optional; fall through to auto-detection.
  }
}

/** The base URL for invite links. */
export function baseUrl(): string {
  if (!cfg || !('publicUrl' in cfg))
    return typeof window === 'undefined' ? '' : window.location.href;
  if (cfg.publicUrl) return cfg.publicUrl;
  // No explicit public URL: use the LAN IP when running on localhost.
  const host = typeof window !== 'undefined' ? window.location.hostname : '';
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') {
    if (cfg.lanIp) {
      const port = typeof window !== 'undefined' ? window.location.port : '';
      return `${window.location.protocol}//${cfg.lanIp}${port ? ':' + port : ''}`;
    }
  }
  return typeof window === 'undefined' ? '' : window.location.href;
}

/**
 * The operator-published ICE servers as browser `RTCIceServer[]`, or undefined when the server
 * published none (the client keeps its bundled default STUN). The config is validated URL by
 * URL; malformed entries are dropped rather than crashing the transfer. A config older than
 * the credential TTL is treated as absent so short-lived credentials are never reused.
 */
export function iceServers(): RTCIceServer[] | undefined {
  if (!cfg) return undefined;
  if (Date.now() - fetchedAt >= ICE_CONFIG_TTL_MS) return undefined;
  if (!Array.isArray(cfg.iceServers)) return undefined;

  const rtc: RTCIceServer[] = [];
  for (const entry of cfg.iceServers) {
    if (!entry || !Array.isArray(entry.urls)) continue;
    const urls: string[] = [];
    let valid = true;
    for (const u of entry.urls) {
      if (typeof u !== 'string') {
        valid = false;
        break;
      }
      try {
        parseIceServer(u);
      } catch {
        valid = false;
        break;
      }
      urls.push(u);
    }
    if (!valid || urls.length === 0) continue;
    const s: RTCIceServer = { urls };
    if (entry.username) {
      s.username = entry.username;
      s.credential = entry.credential ?? '';
    }
    rtc.push(s);
  }
  return rtc.length > 0 ? rtc : undefined;
}
