<script lang="ts">
  import type { CapsPayload, RendezvousPhase } from '@sendarc/protocol';
  import { RendezvousError } from '@sendarc/protocol';

  import { offer, join, type RendezvousController } from './lib/session/rendezvous.js';
  import {
    codeFromHash,
    describeCaps,
    describeError,
    inviteLinkFor,
    phaseLabel,
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

  let controller: RendezvousController | undefined;
  let copyTimer: ReturnType<typeof setTimeout> | undefined;

  function readHashCode(): string {
    return typeof window === 'undefined' ? '' : codeFromHash(window.location.hash);
  }

  function startSend() {
    reset();
    screen = 'sending';
    track(
      offer({
        onPhase: (p) => (phase = p),
        onCode: (c) => {
          code = c;
          link = typeof window === 'undefined' ? '' : inviteLinkFor(window.location.href, c);
        },
      }),
    );
  }

  function startReceive() {
    const trimmed = codeInput.trim();
    if (trimmed === '') return;
    reset();
    screen = 'receiving';
    track(
      join({
        code: trimmed,
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
        fingerprint = await sasFingerprint(res.master);
        peerCaps = res.remoteCaps;
        screen = 'done';
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
    <h1>SendArc</h1>
    <p class="tagline">Secure, end-to-end-encrypted, peer-to-peer file transfer.</p>
  </header>

  {#if screen === 'home'}
    <section class="choices">
      <button class="primary" onclick={startSend}>Send a file</button>

      <form
        class="receive"
        onsubmit={(e) => {
          e.preventDefault();
          startReceive();
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
          <button class="link" onclick={() => copy(link)} title="Copy invite link">{link}</button>
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
      <p class="hint">File transfer arrives in the next milestone.</p>
      <button class="primary" onclick={backHome}>Start over</button>
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
  .hint {
    color: #868e96;
    font-size: 0.85rem;
    margin: 0;
  }
</style>
