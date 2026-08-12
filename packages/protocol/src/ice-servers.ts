/**
 * ICE server configuration — the TypeScript counterpart of `packages/wire/iceservers.go`.
 *
 * The signaling server publishes the operator's ICE servers in `/config.json` as an array of
 * `ICEEntry`; the web app parses and validates them with the same rules as the CLI so both
 * clients select direct-path candidates against the same logical set.
 */

/** One STUN/TURN server. Mirrors the browser's `RTCIceServer` and Go's `wire.ICEEntry`. */
export interface ICEEntry {
  /** One or more STUN/TURN URLs that refer to the same server/credentials. */
  urls: string[];
  /** Username for TURN; absent for plain STUN. */
  username?: string;
  /** Credential for TURN; absent for plain STUN. */
  credential?: string;
  /** "password" (default) or "oauth". */
  credentialType?: string;
}

const ICE_SCHEMES = new Set(['stun', 'stuns', 'turn', 'turns']);

/**
 * Validate and fold a single ICE URL into an {@link ICEEntry}. Throws on malformed or unsafe
 * URLs (unknown scheme, empty host, missing/invalid port). STUN entries carry no credentials.
 */
export function parseIceServer(raw: string): ICEEntry {
  const trimmed = raw.trim();
  const schemeEnd = trimmed.indexOf(':');
  if (schemeEnd <= 0) throw new Error(`ice: unsupported scheme in "${raw}"`);
  const scheme = trimmed.slice(0, schemeEnd).toLowerCase();
  if (!ICE_SCHEMES.has(scheme)) {
    throw new Error(`ice: unsupported scheme "${scheme}" in "${raw}" (want stun/stuns/turn/turns)`);
  }

  // Strip credentials in the opaque form (user:cred@host:port) or authority userinfo (//user:cred@host:port).
  let rest = trimmed.slice(schemeEnd + 1);
  if (rest.startsWith('//')) rest = rest.slice(2);
  const at = rest.lastIndexOf('@');
  const userInfo = at >= 0 ? rest.slice(0, at) : '';
  if (at >= 0) rest = rest.slice(at + 1);

  const hostPort = splitHostPort(rest);
  if (hostPort.host === '' || hostPort.port === '') {
    throw new Error(`ice: missing or invalid host:port in "${raw}"`);
  }

  if (scheme === 'turn' || scheme === 'turns') {
    let username = '';
    let credential = '';
    if (userInfo !== '') {
      const i = userInfo.indexOf(':');
      if (i >= 0) {
        username = userInfo.slice(0, i);
        credential = userInfo.slice(i + 1);
      } else {
        username = userInfo;
      }
    }
    const entry: ICEEntry = { urls: [raw] };
    if (username !== '') {
      entry.username = username;
      entry.credential = credential;
    }
    return entry;
  }
  return { urls: [raw] };
}

/** Fold a list of ICE URLs into entries, grouping credential-less STUN URLs together. */
export function parseIceServers(urls: string[]): ICEEntry[] {
  const entries: ICEEntry[] = [];
  for (const raw of urls) {
    if (raw.trim() === '') continue;
    const entry = parseIceServer(raw);
    const last = entries[entries.length - 1];
    if (last !== undefined && sameCreds(last, entry)) {
      last.urls.push(...entry.urls);
    } else {
      entries.push(entry);
    }
  }
  return entries;
}

function sameCreds(a: ICEEntry, b: ICEEntry): boolean {
  const aScheme = a.urls[0]?.split(':')[0]?.toLowerCase();
  const bScheme = b.urls[0]?.split(':')[0]?.toLowerCase();
  return aScheme === bScheme && a.username === b.username && a.credential === b.credential;
}

/**
 * Convert a validated {@link ICEEntry} list into browser `RTCIceServer` objects for
 * `RTCPeerConnection`. Returns undefined when there is nothing to override (caller keeps its
 * bundled defaults).
 */
export function toRTCIceServers(entries: ICEEntry[]): RTCIceServer[] | undefined {
  if (entries.length === 0) return undefined;
  return entries.map((e) => {
    const s: RTCIceServer = { urls: e.urls };
    if (e.username !== undefined && e.username !== '') {
      s.username = e.username;
      s.credential = e.credential ?? '';
    }
    return s;
  });
}

function splitHostPort(rest: string): { host: string; port: string } {
  // IPv6 literals are bracketed: [::1]:3478. Everything else splits on the last ':'.
  if (rest.startsWith('[')) {
    const end = rest.indexOf(']');
    if (end === -1) return { host: '', port: '' };
    const host = rest.slice(1, end);
    const port = rest[end + 1] === ':' ? rest.slice(end + 2) : '';
    return { host, port };
  }
  const i = rest.lastIndexOf(':');
  if (i === -1) return { host: rest, port: '' };
  return { host: rest.slice(0, i), port: rest.slice(i + 1) };
}
