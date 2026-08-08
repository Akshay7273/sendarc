<script lang="ts">
  import { PROTOCOL_VERSION } from '@agy/protocol';

  // M0 hello route: proves the toolchain, the workspace import of @agy/protocol,
  // and secure-context APIs are wired. Real send/receive screens arrive in M1.
  const secureContext = typeof window !== 'undefined' && window.isSecureContext;
  const hasWebCrypto = typeof crypto !== 'undefined' && 'subtle' in crypto;
</script>

<main>
  <h1>agy</h1>
  <p>Secure, end-to-end-encrypted, peer-to-peer file transfer.</p>
  <dl>
    <dt>Protocol</dt>
    <dd>{PROTOCOL_VERSION}</dd>
    <dt>Secure context</dt>
    <dd>{secureContext ? 'yes' : 'no'}</dd>
    <dt>WebCrypto</dt>
    <dd>{hasWebCrypto ? 'available' : 'missing'}</dd>
  </dl>
  <p class="hint">M0 foundation — the transfer UI lands in M1.</p>
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
  }
  h1 {
    margin-bottom: 0.25rem;
  }
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.25rem 1rem;
    margin: 1.5rem 0;
  }
  dt {
    font-weight: 600;
  }
  .hint {
    color: #666;
    font-size: 0.9rem;
  }
</style>
