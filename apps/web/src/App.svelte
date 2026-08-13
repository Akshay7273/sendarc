<script lang="ts">
  import type { CapsPayload, RendezvousPhase, RendezvousResult, Role } from '@sendbeam/protocol';
  import { RendezvousError } from '@sendbeam/protocol';

  import { offer, join, type RendezvousController } from './lib/session/rendezvous.js';
  import type { SignalChannel } from './lib/signaling/client.js';
  import type { ReceiveDestinationSpec } from './lib/transfer/wire.js';
  import { baseUrl, iceServers, loadConfig } from './lib/config.js';
  import { toJSON } from './lib/transfer/diagnostics.js';
  import QrCode from './lib/QrCode.svelte';

  loadConfig();
  import {
    runSend,
    runReceive,
    type TransferController,
    type TransferOutcome,
  } from './lib/session/transfer.js';
  import {
    codeFromHash,
    describeCaps,
    describeError,
    inviteLinkFor,
    phaseLabel,
    progressLabel,
    progressPercent,
    rateLabel,
    etaLabel,
    sasFingerprint,
    type ErrorLike,
  } from './lib/session/present.js';

  type Screen = 'home' | 'sending' | 'receiving' | 'done' | 'failed';

  let screen = $state<Screen>('home');
  let phase = $state<RendezvousPhase>('idle');
  let code = $state('');
  let link = $state('');
  let codeInput = $state(readHashCode());
  let copied = $state(false);
  let fingerprint = $state('');
  let peerCaps = $state<CapsPayload | undefined>(undefined);
  let errorText = $state('');
  // Sanitized failure diagnostics (V12-PR06 / ADR 0003) shown on the failure screen.
  let failureDiag = $state('');

  // Transfer state, live once the handshake settles and the socket is adopted.
  let role = $state<Role | undefined>(undefined);
  let pickedFiles = $state.raw<File[]>([]);
  let receiveTarget = $state<'auto' | 'direct-file' | 'direct-directory'>('auto');
  let receiveDestination = $state.raw<ReceiveDestinationSpec>({ kind: 'auto' });
  // TransferController is an imperative identity-bearing object (methods + a terminal Promise),
  // not a reactive data model. Deep-proxying it makes `transfer !== ctrl` even immediately after
  // assignment, so the stale-controller guard below discards the real completion callback and
  // leaves both peers stuck at 100%. Keep the controller raw; its progress is polled explicitly.
  let transfer = $state.raw<TransferController | null>(null);
  let sentBytes = $state(0);
  let totalBytes = $state(0);
  let rateBps = $state(0);
  let etaSeconds = $state<number | undefined>(undefined);
  let transferState = $state<'running' | 'paused' | 'canceled'>('running');
  let transportPath = $state<'connecting' | 'direct' | 'recovering' | 'relay'>('connecting');
  let outcome = $state<TransferOutcome | null>(null);
  let downloadUrl = $state<string | null>(null);

  let controller: RendezvousController | undefined;
  let handshake: RendezvousResult | undefined;
  let signaling: SignalChannel | undefined;
  let copyTimer: ReturnType<typeof setTimeout> | undefined;
  let progressTimer: ReturnType<typeof setInterval> | undefined;

  interface PickerWindow extends Window {
    showSaveFilePicker?: () => Promise<FileSystemFileHandle>;
    showDirectoryPicker?: () => Promise<FileSystemDirectoryHandle>;
  }

  function readHashCode(): string {
    return typeof window === 'undefined' ? '' : codeFromHash(window.location.hash);
  }

  function browserCaps(): Partial<CapsPayload> {
    const pickerWindow = window as PickerWindow;
    const storage = navigator.storage as StorageManager | undefined;
    const hasOpfs = typeof storage?.getDirectory === 'function';
    const features: CapsPayload['features'] = [];
    const sinkHints: CapsPayload['sinkHints'] = [];
    if (hasOpfs || pickerWindow.showDirectoryPicker) features.push('folders');
    if (hasOpfs) {
      features.push('archive');
      sinkHints.push('opfs', 'archive');
    }
    if (pickerWindow.showSaveFilePicker) sinkHints.push('direct-file');
    features.push('relay');
    return { features, sinkHints };
  }

  function startSend() {
    reset();
    screen = 'sending';
    track(
      offer({
        localCaps: browserCaps(),
        onPhase: (p) => (phase = p),
        onCode: (c) => {
          code = c;
          link = inviteLinkFor(baseUrl(), c);
        },
      }),
    );
  }

  async function startReceive() {
    const trimmed = codeInput.trim();
    if (trimmed === '') return;
    let destination: ReceiveDestinationSpec = { kind: 'auto' };
    try {
      const pickerWindow = window as PickerWindow;
      if (receiveTarget === 'direct-file') {
        if (!pickerWindow.showSaveFilePicker) throw new Error('Direct file saving is unavailable.');
        destination = { kind: 'direct-file', handle: await pickerWindow.showSaveFilePicker() };
      } else if (receiveTarget === 'direct-directory') {
        if (!pickerWindow.showDirectoryPicker)
          throw new Error('Direct folder saving is unavailable.');
        destination = {
          kind: 'direct-directory',
          handle: await pickerWindow.showDirectoryPicker(),
        };
      }
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') return;
      errorText = err instanceof Error ? err.message : String(err);
      screen = 'failed';
      return;
    }
    reset();
    receiveDestination = destination;
    screen = 'receiving';
    track(
      join({
        code: trimmed,
        localCaps: browserCaps(),
        onPhase: (p) => (phase = p),
      }),
    );
  }

  // Bind a controller's terminal outcome to the success/failure screens. The `done` promise
  // settles exactly once — either the peers confirmed the same key (show the fingerprint) or
  // the handshake failed closed (show why).
  function track(ctrl: RendezvousController) {
    controller = ctrl;
    ctrl.done.then(
      async (res) => {
        if (controller !== ctrl) return; // superseded by a restart
        // Take over the still-open signaling socket before the first await: the rendezvous
        // layer auto-closes an unadopted socket on the next macrotask, and computing the
        // fingerprint can yield past that point (slow WebCrypto on some engines).
        signaling = ctrl.adoptSignaling();
        fingerprint = await sasFingerprint(res.master);
        peerCaps = res.remoteCaps;
        handshake = res;
        role = res.role;
        // The WebRTC negotiation reuses the adopted socket; the offerer waits for a file pick,
        // the joiner begins receiving straight away.
        screen = 'done';
        startTransferIfReady();
      },
      (err: unknown) => {
        if (controller !== ctrl) return;
        errorText = describeError(asErrorLike(err));
        screen = 'failed';
      },
    );
  }

  function asErrorLike(err: unknown): ErrorLike {
    if (err instanceof RendezvousError) return { code: err.code, message: err.message };
    return { code: 'unknown', message: err instanceof Error ? err.message : String(err) };
  }

  function onPick(ev: Event) {
    const input = ev.currentTarget as HTMLInputElement;
    pickedFiles = Array.from(input.files ?? []);
    startTransferIfReady();
  }

  /**
   * Kick off the transfer once everything it needs is in hand. The joiner receives as soon as the
   * channel is adopted; the offerer waits until a file has been picked. Guarded so it runs once.
   */
  function startTransferIfReady() {
    if (transfer || handshake === undefined || signaling === undefined) return;
    const ice = iceServers();
    if (role === 'offerer') {
      if (pickedFiles.length === 0) return;
      beginTransfer(
        runSend(handshake, signaling, {
          files: pickedFiles,
          ...(ice ? { iceServers: ice } : {}),
        }),
      );
    } else {
      beginTransfer(
        runReceive(handshake, signaling, receiveDestination, ice ? { iceServers: ice } : {}),
      );
    }
  }

  /** Bind a running transfer's live progress and terminal outcome to the UI. */
  function beginTransfer(ctrl: TransferController) {
    transfer = ctrl;
    sentBytes = 0;
    totalBytes = ctrl.total() ?? 0;
    rateBps = 0;
    etaSeconds = undefined;
    transferState = 'running';
    progressTimer = setInterval(() => {
      const snapshot = ctrl.snapshot();
      sentBytes = snapshot.bytes;
      totalBytes = snapshot.total ?? totalBytes;
      rateBps = snapshot.rateBps;
      etaSeconds = snapshot.etaSeconds;
      transferState = snapshot.state;
      transportPath = ctrl.transport();
    }, 100);
    ctrl.done.then(
      (result) => {
        if (transfer !== ctrl) return; // superseded by a restart
        clearInterval(progressTimer);
        sentBytes = result.size;
        totalBytes = result.size;
        outcome = result;
        if (result.file) downloadUrl = URL.createObjectURL(result.file);
      },
      (err: unknown) => {
        if (transfer !== ctrl) return;
        clearInterval(progressTimer);
        try {
          failureDiag = toJSON(ctrl.diagnostics());
        } catch {
          failureDiag = '';
        }
        errorText = describeError(asErrorLike(err));
        screen = 'failed';
      },
    );
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
      clearTimeout(copyTimer);
      copyTimer = setTimeout(() => (copied = false), 1500);
    } catch {
      // Clipboard blocked (permission/insecure context): the code stays on screen to copy by hand.
    }
  }

  /** Tear down any in-flight rendezvous and clear the transient handshake state. */
  function reset() {
    controller?.cancel();
    controller = undefined;
    transfer?.cancel();
    transfer = null;
    clearInterval(progressTimer);
    progressTimer = undefined;
    if (downloadUrl) URL.revokeObjectURL(downloadUrl);
    downloadUrl = null;
    void outcome?.cleanup?.();
    handshake = undefined;
    signaling = undefined;
    role = undefined;
    pickedFiles = [];
    receiveDestination = { kind: 'auto' };
    sentBytes = 0;
    totalBytes = 0;
    rateBps = 0;
    etaSeconds = undefined;
    transferState = 'running';
    transportPath = 'connecting';
    outcome = null;
    phase = 'idle';
    code = '';
    link = '';
    copied = false;
    fingerprint = '';
    peerCaps = undefined;
    errorText = '';
    failureDiag = '';
  }

  function backHome() {
    reset();
    screen = 'home';
  }
</script>

<div class="backdrop" aria-hidden="true">
  <div class="glow glow-a"></div>
  <div class="glow glow-b"></div>
  <div class="grid"></div>
</div>

<main>
  <header class="masthead">
    <div class="brand">
      <svg class="mark" viewBox="0 0 24 24" aria-hidden="true">
        <defs>
          <linearGradient id="beam" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="#8b7cf6" />
            <stop offset="1" stop-color="#4cc9f0" />
          </linearGradient>
        </defs>
        <path
          d="M12 1.8 4.6 13.2a1.4 1.4 0 0 0 1.18 2.18h4.3l-1.4 6.82 8.72-12.2a1.4 1.4 0 0 0-1.13-2.2h-4.9L13.3 1.9A1.3 1.3 0 0 0 12 1.8Z"
          fill="url(#beam)"
        />
        <circle cx="12" cy="12" r="3" fill="rgba(255,255,255,0.9)" opacity="0.9" />
      </svg>
      <h1>SendBeam</h1>
    </div>
    <p class="tagline">Secure, end-to-end-encrypted, peer-to-peer file transfer.</p>
  </header>

  {#if screen === 'home'}
    <section class="home-grid">
      <article class="card send-card">
        <div class="card-head">
          <span class="chip chip-send">Send</span>
          <h2>Beam a file</h2>
          <p>Share a link or invite code. Your files never touch our servers.</p>
        </div>
        <button class="primary big" onclick={startSend}>
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M12 3 19 10H15V15H9V10H5L12 3ZM5 18H19V20H5V18Z" fill="currentColor" />
          </svg>
          Send a file
        </button>
        <p class="hint">Files are encrypted end-to-end and wiped after the transfer.</p>
      </article>

      <article class="card receive-card">
        <div class="card-head">
          <span class="chip chip-receive">Receive</span>
          <h2>Catch a file</h2>
          <p>Enter the invite code the sender shared with you.</p>
        </div>
        <form
          class="receive"
          onsubmit={(e) => {
            e.preventDefault();
            void startReceive();
          }}
        >
          <label for="code">Invite code</label>
          <div class="row">
            <input
              id="code"
              type="text"
              placeholder="e.g. 4-brave-otter"
              autocomplete="off"
              spellcheck="false"
              bind:value={codeInput}
            />
            <button class="primary" type="submit" disabled={codeInput.trim() === ''}>
              Receive
            </button>
          </div>
          <label for="destination">Save to</label>
          <select id="destination" bind:value={receiveTarget}>
            <option value="auto">Download when verified</option>
            <option value="direct-file">Save directly to one file</option>
            <option value="direct-directory">Save directly to a folder</option>
          </select>
        </form>
      </article>
    </section>
  {:else if screen === 'sending'}
    <section class="stage card">
      {#if code}
        <div class="stage-head">
          <h2>Ready to beam</h2>
          <p class="muted">Share the invite code — or scan the link — with the receiver.</p>
        </div>
        <div class="code-card">
          <span class="code">{code}</span>
          <button
            class="copy"
            onclick={() => copy(code)}
            aria-label={copied ? 'Code copied' : 'Copy invite code'}
          >
            {#if copied}
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M9 16.2 4.8 12l-1.4 1.4L9 19 21 7l-1.4-1.4L9 16.2Z" fill="currentColor" />
              </svg>
              Copied
            {:else}
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path
                  d="M16 1H4C2.9 1 2 1.9 2 3V17H4V3H16V1ZM19 5H8C6.9 5 6 5.9 6 7V21C6 22.1 6.9 23 8 23H19C20.1 23 21 22.1 21 21V7C21 5.9 20.1 5 19 5ZM19 21H8V7H19V21Z"
                  fill="currentColor"
                />
              </svg>
              Copy
            {/if}
          </button>
        </div>
        {#if link}
          <div class="invite">
            <div class="qr">
              <QrCode data={link} size={128} />
              <button class="link" onclick={() => copy(link)} title="Copy invite link">
                {#if copied}
                  Link copied
                {:else}
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                    <path
                      d="M16 1H4C2.9 1 2 1.9 2 3V17H4V3H16V1ZM19 5H8C6.9 5 6 5.9 6 7V21C6 22.1 6.9 23 8 23H19C20.1 23 21 22.1 21 21V7C21 5.9 20.1 5 19 5ZM19 21H8V7H19V21Z"
                      fill="currentColor"
                    />
                  </svg>
                  Copy invite link
                {/if}
              </button>
            </div>
          </div>
        {/if}
      {:else}
        <div class="stage-head">
          <h2>Allocating a secure room</h2>
          <p class="muted">One room per transfer — destroyed the moment it completes.</p>
        </div>
      {/if}

      <div class="phase" aria-live="polite">
        <span class={phase === 'established' ? 'spinner ok' : 'spinner'} aria-hidden="true"></span>
        {phaseLabel(phase)}
      </div>

      <button class="ghost" onclick={backHome}>Cancel</button>
    </section>
  {:else if screen === 'receiving'}
    <section class="stage card">
      <div class="stage-head">
        <h2>Connecting securely</h2>
        <p class="muted">Verifying the code with the sender — no server sees it.</p>
      </div>
      <div class="phase" aria-live="polite">
        <span class={phase === 'established' ? 'spinner ok' : 'spinner'} aria-hidden="true"></span>
        {phaseLabel(phase)}
      </div>
      <button class="ghost" onclick={backHome}>Cancel</button>
    </section>
  {:else if screen === 'done'}
    <section class="stage card result ok">
      <div class="stage-head">
        <h2>Secure channel established</h2>
        <p class="muted">
          Compare this fingerprint with the other side — it must match on both screens.
        </p>
      </div>

      <div class="fingerprint-wrap">
        <span class="fingerprint-label">Channel fingerprint</span>
        <span class="fingerprint">{fingerprint}</span>
        <span class="fingerprint-hint">End-to-end encryption verified</span>
      </div>

      {#if peerCaps}
        <p class="caps muted">Peer: {describeCaps(peerCaps)}</p>
      {/if}

      {#if outcome}
        {#if downloadUrl}
          <div class="outcome">
            <p class="muted">
              Received
              <strong
                >{outcome.files.length === 1
                  ? outcome.name
                  : `${outcome.files.length} files`}</strong
              >
              — verified.
            </p>
            <a class="primary big download" href={downloadUrl} download={outcome.name}>
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M5 20H19V18H5V20ZM19 9H15V3H9V9H5L12 16L19 9Z" fill="currentColor" />
              </svg>
              Save {outcome.name}
            </a>
          </div>
        {:else if outcome.savedDirectly}
          <div class="outcome">
            <p class="muted">
              Received
              <strong
                >{outcome.files.length === 1
                  ? outcome.name
                  : `${outcome.files.length} files`}</strong
              >
              — verified and saved.
            </p>
          </div>
        {:else}
          <div class="outcome">
            <p class="muted">
              Sent <strong>{outcome.name}</strong> — verified by the receiver.
            </p>
          </div>
        {/if}
      {:else if transfer}
        <div class="transfer-block">
          <div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax="100">
            <div class="bar-fill" style={`width:${progressPercent(sentBytes, totalBytes)}%`}></div>
          </div>
          <p class="status" aria-live="polite">{progressLabel(sentBytes, totalBytes)}</p>
          <div class="stats">
            <div class="stat">
              <span class="stat-label">Rate</span>
              <span class="stat-value">{rateLabel(rateBps)}</span>
            </div>
            <div class="stat">
              <span class="stat-label">Remaining</span>
              <span class="stat-value">{etaLabel(etaSeconds)}</span>
            </div>
            <div class="stat">
              <span class="stat-label">Path</span>
              <span class="stat-value">
                {transportPath === 'relay'
                  ? 'Encrypted relay'
                  : transportPath === 'direct'
                    ? 'Direct P2P'
                    : transportPath === 'recovering'
                      ? 'Recovering connection…'
                      : 'Connecting…'}
              </span>
            </div>
          </div>
          <div class="transfer-controls">
            {#if transferState === 'paused'}
              <button class="ghost" onclick={() => transfer?.resume()}>Resume</button>
            {:else}
              <button class="ghost" onclick={() => transfer?.pause()}>Pause</button>
            {/if}
            <button class="danger" onclick={() => transfer?.cancel()}>Cancel transfer</button>
          </div>
        </div>
      {:else if role === 'offerer'}
        <div class="pick-zone">
          <p class="muted">Choose what to beam</p>
          <label class="filepick">
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path
                d="M6 2C4.9 2 4 2.9 4 4V20C4 21.1 4.9 22 6 22H18C19.1 22 20 21.1 20 20V8L14 2H6ZM13 9V3.5L18.5 9H13Z"
                fill="currentColor"
              />
            </svg>
            <span class="filepick-title">Send file{'\u{2026}'}</span>
            <span class="filepick-sub">or drop multiple</span>
            <input type="file" multiple onchange={onPick} />
          </label>
          <label class="filepick">
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path
                d="M10 4H4C2.9 4 2 4.9 2 6V18C2 19.1 2.9 20 4 20H20C21.1 20 22 19.1 22 18V8C22 6.9 21.1 6 20 6H12L10 4Z"
                fill="currentColor"
              />
            </svg>
            <span class="filepick-title">Send folder{'\u{2026}'}</span>
            <span class="filepick-sub">all files inside</span>
            <input type="file" multiple webkitdirectory onchange={onPick} />
          </label>
        </div>
      {:else}
        <div class="phase" aria-live="polite">
          <span class="spinner" aria-hidden="true"></span>
          Waiting for the sender to choose a file…
        </div>
      {/if}

      <button class="ghost" onclick={backHome}>Start over</button>
    </section>
  {:else if screen === 'failed'}
    <section class="stage card result bad">
      <div class="stage-head">
        <span class="error-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24">
            <path
              d="M12 2 1 21H23L12 2ZM13 18H11V16H13V18ZM13 14H11V9H13V14Z"
              fill="currentColor"
            />
          </svg>
        </span>
        <h2>Connection failed</h2>
        <p class="muted">{errorText}</p>
        {#if failureDiag}
          <div class="diag-block">
            <button class="link-btn" onclick={() => copy(failureDiag)}>
              {copied ? 'Copied' : 'Copy diagnostics'}
            </button>
            <pre class="diag-json">{failureDiag}</pre>
          </div>
        {/if}
      </div>
      <button class="primary" onclick={backHome}>Try again</button>
    </section>
  {/if}
</main>

<style>
  :global(:root) {
    --muted: #93a0b8;
  }
  :global(body) {
    margin: 0;
    min-height: 100vh;
    background: #070b16;
    color: #e8ecf8;
    font-family:
      system-ui,
      -apple-system,
      'Segoe UI',
      Roboto,
      sans-serif;
    -webkit-font-smoothing: antialiased;
  }

  /* ————— ambient backdrop ————— */
  .backdrop {
    position: fixed;
    inset: 0;
    z-index: -1;
    overflow: hidden;
    background:
      radial-gradient(1200px 600px at 80% -10%, rgba(76, 201, 240, 0.14), transparent 60%),
      radial-gradient(1000px 700px at -10% 110%, rgba(139, 124, 246, 0.18), transparent 60%),
      #070b16;
  }
  .glow {
    position: absolute;
    border-radius: 50%;
    filter: blur(90px);
    opacity: 0.5;
    animation: drift 24s ease-in-out infinite alternate;
  }
  .glow-a {
    width: 480px;
    height: 480px;
    left: -140px;
    top: -120px;
    background: rgba(139, 124, 246, 0.32);
  }
  .glow-b {
    width: 420px;
    height: 420px;
    right: -120px;
    bottom: -140px;
    background: rgba(76, 201, 240, 0.24);
    animation-delay: -12s;
  }
  .grid {
    position: absolute;
    inset: 0;
    background-image:
      linear-gradient(rgba(255, 255, 255, 0.028) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255, 255, 255, 0.028) 1px, transparent 1px);
    background-size: 44px 44px;
    mask-image: radial-gradient(ellipse 90% 70% at 50% 30%, black, transparent 75%);
  }
  @keyframes drift {
    from {
      transform: translate(0, 0) scale(1);
    }
    to {
      transform: translate(60px, 40px) scale(1.12);
    }
  }

  main {
    max-width: 44rem;
    margin: 0 auto;
    padding: 3.5rem 1.5rem 4rem;
    line-height: 1.5;
  }

  /* ————— masthead ————— */
  .masthead {
    margin-bottom: 2.5rem;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 0.7rem;
  }
  .mark {
    width: 2rem;
    height: 2rem;
    filter: drop-shadow(0 0 12px rgba(139, 124, 246, 0.6));
  }
  h1 {
    margin: 0;
    font-size: 1.7rem;
    font-weight: 700;
    letter-spacing: -0.02em;
  }
  .tagline {
    margin: 0.35rem 0 0 2.7rem;
    color: var(--muted);
    font-size: 0.95rem;
  }
  .muted {
    color: var(--muted);
    margin: 0;
  }

  /* ————— cards ————— */
  .card {
    background: rgba(255, 255, 255, 0.045);
    border: 1px solid rgba(255, 255, 255, 0.09);
    border-radius: 1.25rem;
    box-shadow:
      0 24px 60px -24px rgba(0, 0, 0, 0.65),
      inset 0 1px 0 rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(14px);
    padding: 1.75rem;
  }
  .card-head h2 {
    margin: 0.6rem 0 0.3rem;
    font-size: 1.15rem;
    letter-spacing: -0.01em;
  }
  .card-head p {
    margin: 0;
  }
  .chip {
    display: inline-block;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    padding: 0.22rem 0.6rem;
    border-radius: 999px;
  }
  .chip-send {
    color: #c4b5fd;
    background: rgba(139, 124, 246, 0.16);
    border: 1px solid rgba(139, 124, 246, 0.35);
  }
  .chip-receive {
    color: #7dd3fc;
    background: rgba(76, 201, 240, 0.12);
    border: 1px solid rgba(76, 201, 240, 0.35);
  }

  .home-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.25rem;
  }
  @media (max-width: 720px) {
    .home-grid {
      grid-template-columns: 1fr;
    }
  }
  .send-card,
  .receive-card {
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
  }

  /* ————— controls ————— */
  button,
  input,
  select {
    font: inherit;
  }
  button {
    cursor: pointer;
    border: 1px solid transparent;
    border-radius: 0.75rem;
    padding: 0.6rem 1.1rem;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    transition:
      transform 0.12s ease,
      box-shadow 0.2s ease,
      background 0.2s ease,
      border-color 0.2s ease;
  }
  button:active:not(:disabled) {
    transform: translateY(1px);
  }
  button:disabled {
    opacity: 0.45;
    cursor: default;
  }
  .primary {
    background: linear-gradient(135deg, #8b7cf6, #4cc9f0);
    color: #081019;
    box-shadow:
      0 8px 28px -8px rgba(124, 160, 246, 0.65),
      inset 0 1px 0 rgba(255, 255, 255, 0.35);
  }
  .primary:hover:not(:disabled) {
    box-shadow:
      0 10px 34px -8px rgba(124, 160, 246, 0.85),
      inset 0 1px 0 rgba(255, 255, 255, 0.4);
  }
  .big {
    padding: 0.85rem 1.4rem;
    font-size: 1.05rem;
    border-radius: 0.9rem;
    width: 100%;
  }
  .big svg {
    width: 1.15rem;
    height: 1.15rem;
  }
  .ghost {
    background: rgba(255, 255, 255, 0.05);
    border-color: rgba(255, 255, 255, 0.14);
    color: #c8d2ea;
  }
  .ghost:hover {
    background: rgba(255, 255, 255, 0.09);
    border-color: rgba(255, 255, 255, 0.22);
  }
  .danger {
    background: rgba(248, 113, 113, 0.1);
    border-color: rgba(248, 113, 113, 0.35);
    color: #fca5a5;
  }
  .danger:hover {
    background: rgba(248, 113, 113, 0.18);
  }
  .copy {
    background: rgba(139, 124, 246, 0.14);
    border-color: rgba(139, 124, 246, 0.4);
    color: #c4b5fd;
    white-space: nowrap;
  }
  .copy svg {
    width: 0.95rem;
    height: 0.95rem;
  }

  .receive {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .receive label {
    font-size: 0.85rem;
    font-weight: 600;
    color: #aab6d0;
  }
  .row {
    display: flex;
    gap: 0.5rem;
  }
  .row input {
    min-width: 0;
  }
  input,
  select {
    padding: 0.65rem 0.85rem;
    font-size: 1rem;
    border-radius: 0.75rem;
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.14);
    color: #e8ecf8;
    outline: none;
  }
  input::placeholder {
    color: #5f6c88;
  }
  input:focus,
  select:focus {
    border-color: rgba(139, 124, 246, 0.75);
    box-shadow: 0 0 0 3px rgba(139, 124, 246, 0.22);
  }
  select option {
    background: #101730;
    color: #e8ecf8;
  }
  .hint {
    margin: 0;
    font-size: 0.82rem;
    color: #77849f;
  }

  /* ————— stage screens ————— */
  .stage {
    display: flex;
    flex-direction: column;
    gap: 1.4rem;
    align-items: flex-start;
  }
  .stage-head h2 {
    margin: 0 0 0.3rem;
    font-size: 1.3rem;
    letter-spacing: -0.01em;
  }
  .stage-head {
    width: 100%;
  }

  .code-card {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    width: 100%;
    padding: 1.1rem 1.3rem;
    border-radius: 1rem;
    background: linear-gradient(135deg, rgba(139, 124, 246, 0.14), rgba(76, 201, 240, 0.1));
    border: 1px solid rgba(139, 124, 246, 0.4);
    box-shadow: inset 0 0 32px rgba(139, 124, 246, 0.12);
  }
  .code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 1.55rem;
    font-weight: 600;
    letter-spacing: 0.03em;
    color: #f2f5ff;
    text-shadow: 0 0 24px rgba(139, 124, 246, 0.55);
  }

  .invite {
    display: flex;
    justify-content: center;
    width: 100%;
  }
  .qr {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.75rem;
    padding: 1.1rem;
    border-radius: 1rem;
    background: #f8faff;
    border: 1px solid rgba(255, 255, 255, 0.14);
  }
  .qr :global(canvas) {
    border-radius: 0.4rem;
  }
  .link {
    background: none;
    border: none;
    padding: 0;
    color: #7dd3fc;
    font-size: 0.85rem;
    text-align: center;
  }
  .link svg {
    width: 0.9rem;
    height: 0.9rem;
  }
  .link:hover {
    text-decoration: underline;
  }

  .phase {
    display: flex;
    align-items: center;
    gap: 0.65rem;
    color: #aab6d0;
    font-weight: 500;
  }
  .spinner {
    width: 1rem;
    height: 1rem;
    border-radius: 50%;
    border: 2px solid rgba(139, 124, 246, 0.3);
    border-top-color: #8b7cf6;
    animation: spin 0.9s linear infinite;
    flex: none;
  }
  .spinner.ok {
    border-color: rgba(52, 211, 153, 0.35);
    border-top-color: #34d399;
    animation: none;
    background: radial-gradient(circle, #34d399 35%, transparent 40%);
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  /* ————— verification ————— */
  .fingerprint-wrap {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.5rem;
    width: 100%;
    padding: 1.4rem;
    border-radius: 1rem;
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid rgba(255, 255, 255, 0.1);
  }
  .fingerprint-label {
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: #77849f;
  }
  .fingerprint {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 1.9rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    color: #4ade80;
    text-shadow: 0 0 28px rgba(52, 211, 153, 0.45);
  }
  .fingerprint-hint {
    font-size: 0.8rem;
    color: #77849f;
  }
  .caps {
    font-size: 0.85rem;
  }

  .outcome {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    width: 100%;
  }
  .outcome strong {
    color: #e8ecf8;
  }
  .download {
    text-decoration: none;
  }

  /* ————— transfer ————— */
  .transfer-block {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    width: 100%;
  }
  .bar {
    width: 100%;
    height: 0.7rem;
    background: rgba(255, 255, 255, 0.08);
    border-radius: 999px;
    overflow: hidden;
    box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.5);
  }
  .bar-fill {
    height: 100%;
    background: linear-gradient(90deg, #8b7cf6, #4cc9f0);
    border-radius: inherit;
    transition: width 0.15s linear;
    box-shadow: 0 0 18px rgba(124, 160, 246, 0.7);
    position: relative;
    overflow: hidden;
  }
  .bar-fill::after {
    content: '';
    position: absolute;
    inset: 0;
    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.4), transparent);
    transform: translateX(-100%);
    animation: shimmer 1.6s infinite;
  }
  @keyframes shimmer {
    to {
      transform: translateX(100%);
    }
  }
  .status {
    margin: 0;
    color: #c8d2ea;
    font-variant-numeric: tabular-nums;
  }
  .stats {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 0.75rem;
    width: 100%;
  }
  @media (max-width: 560px) {
    .stats {
      grid-template-columns: 1fr;
    }
  }
  .stat {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    padding: 0.8rem 1rem;
    border-radius: 0.85rem;
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid rgba(255, 255, 255, 0.08);
  }
  .stat-label {
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: #77849f;
  }
  .stat-value {
    font-size: 0.95rem;
    color: #dbe4f7;
  }
  .transfer-controls {
    display: flex;
    gap: 0.75rem;
  }

  /* ————— file picking ————— */
  .pick-zone {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.85rem;
    width: 100%;
  }
  @media (max-width: 560px) {
    .pick-zone {
      grid-template-columns: 1fr;
    }
  }
  .pick-zone > .muted {
    grid-column: 1 / -1;
  }
  .filepick {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.35rem;
    padding: 1.4rem 1rem;
    border-radius: 1rem;
    border: 1.5px dashed rgba(139, 124, 246, 0.45);
    background: rgba(139, 124, 246, 0.07);
    cursor: pointer;
    transition:
      background 0.2s ease,
      border-color 0.2s ease,
      transform 0.12s ease;
  }
  .filepick:hover {
    background: rgba(139, 124, 246, 0.14);
    border-color: rgba(139, 124, 246, 0.8);
  }
  .filepick:active {
    transform: scale(0.99);
  }
  .filepick svg {
    width: 1.6rem;
    height: 1.6rem;
    color: #c4b5fd;
  }
  .filepick-title {
    font-weight: 600;
    color: #e8ecf8;
  }
  .filepick-sub {
    font-size: 0.8rem;
    color: #77849f;
  }
  .filepick input {
    display: none;
  }

  /* ————— failure ————— */
  .error-icon {
    width: 3rem;
    height: 3rem;
    border-radius: 1rem;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: rgba(248, 113, 113, 0.12);
    border: 1px solid rgba(248, 113, 113, 0.4);
    color: #fca5a5;
  }
  .error-icon svg {
    width: 1.6rem;
    height: 1.6rem;
  }
  .result.bad h2 {
    color: #fca5a5;
  }
  .diag-block {
    margin-top: 0.75rem;
    text-align: left;
  }
  .link-btn {
    background: none;
    border: none;
    color: #7aa2f7;
    cursor: pointer;
    padding: 0;
    font: inherit;
    text-decoration: underline;
  }
  .diag-json {
    margin-top: 0.5rem;
    padding: 0.5rem 0.75rem;
    background: rgba(0, 0, 0, 0.3);
    border: 1px solid rgba(147, 160, 184, 0.25);
    border-radius: 0.5rem;
    font-size: 0.72rem;
    line-height: 1.4;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 12rem;
    overflow: auto;
  }

  @media (prefers-reduced-motion: reduce) {
    .glow,
    .spinner,
    .bar-fill::after {
      animation: none;
    }
  }
</style>
