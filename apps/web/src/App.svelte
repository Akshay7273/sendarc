<script lang="ts">
  import type { CapsPayload, RendezvousPhase, RendezvousResult, Role } from '@sendbeam/protocol';
  import { RendezvousError } from '@sendbeam/protocol';

  import { offer, join, type RendezvousController } from './lib/session/rendezvous.js';
  import type { SignalChannel } from './lib/signaling/client.js';
  import type { ReceiveDestinationSpec } from './lib/transfer/wire.js';
  import { baseUrl, loadConfig } from './lib/config.js';
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
  let transportPath = $state<'connecting' | 'direct' | 'relay'>('connecting');
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
    if (role === 'offerer') {
      if (pickedFiles.length === 0) return;
      beginTransfer(runSend(handshake, signaling, { files: pickedFiles }));
    } else {
      beginTransfer(runReceive(handshake, signaling, receiveDestination));
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
  }

  function backHome() {
    reset();
    screen = 'home';
  }
</script>

<main>
  <header>
    <h1>SendBeam</h1>
    <p class="tagline">Secure, end-to-end-encrypted, peer-to-peer file transfer.</p>
  </header>

  {#if screen === 'home'}
    <section class="choices">
      <button class="primary" onclick={startSend}>Send a file</button>

      <form
        class="receive"
        onsubmit={(e) => {
          e.preventDefault();
          void startReceive();
        }}
      >
        <label for="code">Have an invite code?</label>
        <div class="row">
          <input
            id="code"
            type="text"
            placeholder="e.g. 4-brave-otter"
            autocomplete="off"
            spellcheck="false"
            bind:value={codeInput}
          />
          <button type="submit" disabled={codeInput.trim() === ''}>Receive</button>
        </div>
        <label for="destination">Destination</label>
        <select id="destination" bind:value={receiveTarget}>
          <option value="auto">Download when verified</option>
          <option value="direct-file">Save directly to one file</option>
          <option value="direct-directory">Save directly to a folder</option>
        </select>
      </form>
    </section>
  {:else if screen === 'sending'}
    <section class="progress">
      {#if code}
        <p class="lead">Share this code with the person receiving the file:</p>
        <div class="code-card">
          <span class="code">{code}</span>
          <button class="copy" onclick={() => copy(code)}>{copied ? 'Copied' : 'Copy'}</button>
        </div>
        {#if link}
          <div class="link-row">
            <button class="link" onclick={() => copy(link)} title="Copy invite link">{link}</button>
            <QrCode data={link} size={120} />
          </div>
        {/if}
      {/if}
      <p class="status" aria-live="polite">{phaseLabel(phase)}</p>
      <button class="ghost" onclick={backHome}>Cancel</button>
    </section>
  {:else if screen === 'receiving'}
    <section class="progress">
      <p class="status" aria-live="polite">{phaseLabel(phase)}</p>
      <button class="ghost" onclick={backHome}>Cancel</button>
    </section>
  {:else if screen === 'done'}
    <section class="result ok">
      <h2>✓ Secure channel established</h2>
      <p>Compare this fingerprint with the other side — it must match on both screens.</p>
      <p class="fingerprint">{fingerprint}</p>
      {#if peerCaps}
        <p class="caps">Peer: {describeCaps(peerCaps)}</p>
      {/if}

      {#if outcome}
        {#if downloadUrl}
          <p class="status">
            Received <strong
              >{outcome.files.length === 1 ? outcome.name : `${outcome.files.length} files`}</strong
            >
            — verified.
          </p>
          <a class="primary download" href={downloadUrl} download={outcome.name}>
            Save {outcome.name}
          </a>
        {:else if outcome.savedDirectly}
          <p class="status">
            Received <strong
              >{outcome.files.length === 1 ? outcome.name : `${outcome.files.length} files`}</strong
            >
            — verified and saved.
          </p>
        {:else}
          <p class="status">Sent <strong>{outcome.name}</strong> — verified by the receiver.</p>
        {/if}
      {:else if transfer}
        <div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax="100">
          <div class="bar-fill" style={`width:${progressPercent(sentBytes, totalBytes)}%`}></div>
        </div>
        <p class="status" aria-live="polite">{progressLabel(sentBytes, totalBytes)}</p>
        <p class="transfer-detail" aria-live="polite">
          {transferState === 'paused'
            ? 'Paused'
            : `${rateLabel(rateBps)} · ${etaLabel(etaSeconds)}${transportPath === 'relay' ? ' · encrypted relay' : transportPath === 'direct' ? ' · direct' : ''}`}
        </p>
        <div class="transfer-controls">
          {#if transferState === 'paused'}
            <button class="ghost" onclick={() => transfer?.resume()}>Resume</button>
          {:else}
            <button class="ghost" onclick={() => transfer?.pause()}>Pause</button>
          {/if}
          <button class="cancel" onclick={() => transfer?.cancel()}>Cancel transfer</button>
        </div>
      {:else if role === 'offerer'}
        <label class="filepick">
          <span>Choose files to send</span>
          <input type="file" multiple onchange={onPick} />
        </label>
        <label class="filepick">
          <span>Choose a folder to send</span>
          <input type="file" multiple webkitdirectory onchange={onPick} />
        </label>
      {:else}
        <p class="status" aria-live="polite">Waiting for the sender to choose a file…</p>
      {/if}

      <button class="ghost" onclick={backHome}>Start over</button>
    </section>
  {:else if screen === 'failed'}
    <section class="result bad">
      <h2>Connection failed</h2>
      <p>{errorText}</p>
      <button class="primary" onclick={backHome}>Try again</button>
    </section>
  {/if}
</main>

<style>
  main {
    max-width: 32rem;
    margin: 4rem auto;
    padding: 0 1.5rem;
    font-family:
      system-ui,
      -apple-system,
      sans-serif;
    line-height: 1.5;
    color: #1a1a1a;
  }
  header {
    margin-bottom: 2rem;
  }
  h1 {
    margin: 0 0 0.25rem;
  }
  .tagline {
    margin: 0;
    color: #666;
  }

  .choices {
    display: flex;
    flex-direction: column;
    gap: 2rem;
  }
  .receive {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .receive label {
    font-weight: 600;
  }
  .row {
    display: flex;
    gap: 0.5rem;
  }
  input {
    flex: 1;
    padding: 0.6rem 0.75rem;
    font-size: 1rem;
    border: 1px solid #ccc;
    border-radius: 0.5rem;
  }
  input:focus {
    outline: 2px solid #3b5bdb;
    outline-offset: 1px;
    border-color: transparent;
  }

  button {
    font: inherit;
    cursor: pointer;
    border: 1px solid transparent;
    border-radius: 0.5rem;
    padding: 0.6rem 1rem;
  }
  button:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .primary {
    background: #3b5bdb;
    color: #fff;
    font-weight: 600;
  }
  .primary:hover:not(:disabled) {
    background: #364fc7;
  }
  .ghost {
    background: none;
    border-color: #ccc;
    color: #555;
  }
  .ghost:hover {
    background: #f1f3f5;
  }

  .progress,
  .result {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    align-items: flex-start;
  }
  .lead {
    margin: 0;
  }
  .code-card {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    background: #f8f9fa;
    border: 1px solid #e9ecef;
    border-radius: 0.5rem;
    padding: 0.75rem 1rem;
  }
  .code {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 1.4rem;
    letter-spacing: 0.02em;
  }
  .copy {
    background: #e7eaf6;
    color: #3b5bdb;
    font-weight: 600;
  }
  .link {
    background: none;
    border: none;
    padding: 0;
    color: #3b5bdb;
    font-size: 0.85rem;
    text-align: left;
    word-break: break-all;
    text-decoration: underline;
  }
  .status {
    color: #555;
    margin: 0;
  }
  .transfer-detail {
    color: #666;
    font-size: 0.9rem;
    margin: -0.5rem 0 0;
  }
  .transfer-controls {
    display: flex;
    gap: 0.5rem;
  }
  .cancel {
    background: #fff5f5;
    border-color: #ffc9c9;
    color: #c92a2a;
  }

  .result h2 {
    margin: 0;
  }
  .fingerprint {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 1.6rem;
    letter-spacing: 0.08em;
    background: #f8f9fa;
    border: 1px solid #e9ecef;
    border-radius: 0.5rem;
    padding: 0.5rem 1rem;
    margin: 0;
  }
  .ok h2 {
    color: #2b8a3e;
  }
  .bad h2 {
    color: #c92a2a;
  }
  .caps {
    color: #555;
    font-size: 0.9rem;
    margin: 0;
  }

  .filepick {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    width: 100%;
  }
  .filepick span {
    font-weight: 600;
  }
  .filepick input {
    padding: 0.5rem 0;
    border: none;
    font: inherit;
  }

  .bar {
    width: 100%;
    height: 0.5rem;
    background: #e9ecef;
    border-radius: 999px;
    overflow: hidden;
  }
  .bar-fill {
    height: 100%;
    background: #3b5bdb;
    border-radius: inherit;
    transition: width 0.15s linear;
  }

  .download {
    text-decoration: none;
    display: inline-block;
  }
</style>
