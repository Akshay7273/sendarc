<script lang="ts">
  import type { IncomingTransferRequest } from './types.js';
  import { humanBytes } from '../session/present.js';

  interface Props {
    request: IncomingTransferRequest | null;
    onAccept: () => void;
    onDecline: () => void;
  }

  let { request, onAccept, onDecline }: Props = $props();
</script>

{#if request}
  <div class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="incoming-title">
    <div class="modal-content">
      <div class="incoming-header">
        <div class="incoming-icon">📥</div>
        <h3 id="incoming-title">Incoming Transfer</h3>
        <p class="sender-info">
          From <strong>{request.senderLabel}</strong>
          <code class="fp-badge">{request.senderFingerprint}</code>
        </p>
      </div>

      <div class="transfer-details">
        <div class="meta-row">
          <span>Files:</span>
          <strong>{request.fileCount} file(s)</strong>
        </div>
        <div class="meta-row">
          <span>Total Size:</span>
          <strong>{humanBytes(request.totalBytes)}</strong>
        </div>

        {#if request.files.length > 0}
          <div class="file-list">
            {#each request.files.slice(0, 5) as file}
              <div class="file-item">
                <span class="file-name">{file.name}</span>
                <span class="file-size">{humanBytes(file.size)}</span>
              </div>
            {/each}
            {#if request.files.length > 5}
              <div class="more-files">
                + {request.files.length - 5} more file(s)
              </div>
            {/if}
          </div>
        {/if}
      </div>

      <div class="modal-actions">
        <button class="btn-accept" onclick={onAccept}>Accept & Download</button>
        <button class="btn-decline" onclick={onDecline}>Decline</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.75);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    padding: 1rem;
    backdrop-filter: blur(4px);
  }

  .modal-content {
    background: #18181b;
    border: 1px solid #3f3f46;
    border-radius: 12px;
    width: 100%;
    max-width: 440px;
    padding: 1.5rem;
    color: #f4f4f5;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
  }

  .incoming-header {
    text-align: center;
    margin-bottom: 1.25rem;
  }

  .incoming-icon {
    font-size: 2.25rem;
    margin-bottom: 0.5rem;
  }

  .incoming-header h3 {
    margin: 0 0 0.5rem 0;
    font-size: 1.25rem;
    font-weight: 600;
  }

  .sender-info {
    color: #a1a1aa;
    font-size: 0.875rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.35rem;
    margin: 0;
  }

  .fp-badge {
    background: #27272a;
    border: 1px solid #3f3f46;
    padding: 0.15rem 0.4rem;
    border-radius: 4px;
    font-size: 0.75rem;
    color: #e4e4e7;
  }

  .transfer-details {
    background: #27272a;
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    font-size: 0.875rem;
  }

  .meta-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .file-list {
    margin-top: 0.5rem;
    border-top: 1px solid #3f3f46;
    padding-top: 0.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
  }

  .file-item {
    display: flex;
    justify-content: space-between;
    font-size: 0.8125rem;
    color: #d4d4d8;
  }

  .file-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 240px;
  }

  .file-size {
    color: #a1a1aa;
  }

  .more-files {
    font-size: 0.75rem;
    color: #a1a1aa;
    text-align: center;
    margin-top: 0.25rem;
  }

  .modal-actions {
    display: flex;
    gap: 0.75rem;
  }

  .btn-accept {
    flex: 1;
    background: #10b981;
    color: white;
    border: none;
    padding: 0.6rem 1rem;
    border-radius: 6px;
    font-weight: 500;
    cursor: pointer;
  }

  .btn-accept:hover {
    background: #059669;
  }

  .btn-decline {
    flex: 1;
    background: #3f3f46;
    color: #e4e4e7;
    border: none;
    padding: 0.6rem 1rem;
    border-radius: 6px;
    font-weight: 500;
    cursor: pointer;
  }

  .btn-decline:hover {
    background: #52525b;
  }
</style>
