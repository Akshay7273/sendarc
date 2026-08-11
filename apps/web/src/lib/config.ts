interface ServerConfig {
  publicUrl: string;
  lanIp: string;
}

let cfg: ServerConfig | undefined;

export async function loadConfig(): Promise<void> {
  try {
    const res = await fetch('/config.json');
    if (!res.ok) return;
    cfg = await res.json();
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
