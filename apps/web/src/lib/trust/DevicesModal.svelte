<script lang="ts">
  import { onMount } from 'svelte';
  import type { TrustedDeviceUI } from './types.js';
  import type { TrustPolicy } from '@sendbeam/protocol';
  import {
    listTrustedDevices,
    renameTrustedDevice,
    updateTrustedDevicePolicy,
    unpairTrustedDevice,
    pairTrustedDevice,
    isDesktopApp,
  } from './devices.js';

  interface Props {
    open: boolean;
    onClose: () => void;
    onSendToDevice: (device: TrustedDeviceUI) => void;
  }

  let { open = $bindable(), onClose, onSendToDevice }: Props = $props();

  let devices = $state<TrustedDeviceUI[]>([]);
  let loading = $state(false);
  let errorMessage = $state('');

  // Editing label state
  let editingDeviceId = $state<string | null>(null);
  let editingLabelText = $state('');

  // Policy editing modal state
  let policyModalDevice = $state<TrustedDeviceUI | null>(null);
  let policyAutoAccept = $state(false);
  let policyDestDir = $state('');

  // Pairing modal state
  let showPairModal = $state(false);
  let pairInviteCode = $state('');
  let pairCustomName = $state('');
  let pairAutoAccept = $state(false);
  let pairDestDir = $state('');
  let pairingInProgress = $state(false);

  // Unpair confirmation modal state
  let unpairConfirmDevice = $state<TrustedDeviceUI | null>(null);

  // Copied indicator per device
  let copiedFp = $state<string | null>(null);

  async function loadDevices() {
    loading = true;
    errorMessage = '';
    try {
      devices = await listTrustedDevices();
    } catch (err: unknown) {
      errorMessage = err instanceof Error ? err.message : String(err);
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    if (open) {
      void loadDevices();
    }
  });

  onMount(() => {
    if (typeof window !== 'undefined' && window.runtime?.EventsOn) {
      const cleanup = window.runtime.EventsOn('sendbeam:devices', (data: unknown) => {
        if (Array.isArray(data)) {
          devices = data as TrustedDeviceUI[];
        } else {
          void loadDevices();
        }
      });
      return cleanup;
    }
  });

  async function handleSaveRename(deviceId: string) {
    if (!editingLabelText.trim()) return;
    try {
      await renameTrustedDevice(deviceId, editingLabelText.trim());
      editingDeviceId = null;
      await loadDevices();
    } catch (err: unknown) {
      errorMessage = err instanceof Error ? err.message : String(err);
    }
  }

  function openPolicyEditor(dev: TrustedDeviceUI) {
    policyModalDevice = dev;
    policyAutoAccept = dev.policy.autoAccept;
    policyDestDir = dev.policy.autoAcceptDestDir || '';
  }

  async function handleSavePolicy() {
    if (!policyModalDevice) return;
    try {
      const newPolicy: TrustPolicy = {
        ...policyModalDevice.policy,
        autoAccept: policyAutoAccept,
      };
      if (policyAutoAccept && policyDestDir.trim()) {
        newPolicy.autoAcceptDestDir = policyDestDir.trim();
      } else {
        delete newPolicy.autoAcceptDestDir;
      }
      await updateTrustedDevicePolicy(policyModalDevice.deviceId, newPolicy);
      policyModalDevice = null;
      await loadDevices();
    } catch (err: unknown) {
      errorMessage = err instanceof Error ? err.message : String(err);
    }
  }

  async function handleConfirmUnpair(purge: boolean) {
    if (!unpairConfirmDevice) return;
    try {
      await unpairTrustedDevice(unpairConfirmDevice.deviceId, purge);
      unpairConfirmDevice = null;
      await loadDevices();
    } catch (err: unknown) {
      errorMessage = err instanceof Error ? err.message : String(err);
    }
  }

  async function handleStartPair() {
    if (!pairInviteCode.trim()) return;
    pairingInProgress = true;
    errorMessage = '';
    try {
      await pairTrustedDevice(
        '',
        pairInviteCode.trim(),
        pairCustomName.trim(),
        pairAutoAccept,
        pairAutoAccept ? pairDestDir.trim() : '',
      );
      showPairModal = false;
      pairInviteCode = '';
      pairCustomName = '';
      pairAutoAccept = false;
      pairDestDir = '';
      await loadDevices();
    } catch (err: unknown) {
      errorMessage = err instanceof Error ? err.message : String(err);
    } finally {
      pairingInProgress = false;
    }
  }

  async function copyFingerprint(fp: string) {
    try {
      await navigator.clipboard.writeText(fp);
      copiedFp = fp;
      setTimeout(() => {
        if (copiedFp === fp) copiedFp = null;
      }, 2000);
    } catch {
      // Ignore clipboard write failures
    }
  }
</script>

{#if open}
  <div class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <div class="modal-content">
      <div class="modal-header">
        <div class="header-title">
          <h2 id="modal-title">Trusted Devices</h2>
          <span class="device-count">{devices.length} paired</span>
        </div>
        <div class="header-actions">
          <button
            class="btn-pair"
            onclick={() => {
              showPairModal = true;
            }}
          >
            + Pair Device
          </button>
          <button class="btn-close" onclick={onClose} aria-label="Close">✕</button>
        </div>
      </div>

      {#if errorMessage}
        <div class="error-banner" role="alert">
          <span>{errorMessage}</span>
          <button
            class="btn-dismiss"
            onclick={() => {
              errorMessage = '';
            }}>✕</button
          >
        </div>
      {/if}

      {#if !isDesktopApp()}
        <div class="browser-storage-notice">
          <span class="notice-icon">ℹ</span>
          <span class="notice-text">
            <strong>Browser Storage:</strong> Paired device identities are saved locally in this browser's
            IndexedDB. Clearing browser data will revoke local pairings.
          </span>
        </div>
      {/if}

      <div class="device-list-container">
        {#if loading && devices.length === 0}
          <div class="loading-state">Loading trusted devices…</div>
        {:else if devices.length === 0}
          <div class="empty-state">
            <p class="empty-title">No paired devices</p>
            <p class="empty-subtitle">
              Pair your laptops, workstations, or mobile devices once to send files directly without
              entering one-time room codes.
            </p>
            <button
              class="btn-pair-hero"
              onclick={() => {
                showPairModal = true;
              }}
            >
              Pair First Device
            </button>
          </div>
        {:else}
          <div class="device-cards">
            {#each devices as dev (dev.deviceId)}
              <div class="device-card" class:revoked={dev.revoked}>
                <div class="device-card-header">
                  <div class="device-title-row">
                    {#if editingDeviceId === dev.deviceId}
                      <input
                        type="text"
                        class="input-rename"
                        bind:value={editingLabelText}
                        onkeydown={(e) => {
                          if (e.key === 'Enter') void handleSaveRename(dev.deviceId);
                          if (e.key === 'Escape') editingDeviceId = null;
                        }}
                      />
                      <button
                        class="btn-sm btn-primary"
                        onclick={() => void handleSaveRename(dev.deviceId)}>Save</button
                      >
                      <button class="btn-sm" onclick={() => (editingDeviceId = null)}>Cancel</button
                      >
                    {:else}
                      <h3 class="device-name">{dev.localLabel}</h3>
                      <button
                        class="btn-icon"
                        title="Rename device"
                        onclick={() => {
                          editingDeviceId = dev.deviceId;
                          editingLabelText = dev.localLabel;
                        }}
                      >
                        ✎
                      </button>
                    {/if}
                  </div>

                  <div class="status-badge status-{dev.status}">
                    <span class="status-dot"></span>
                    <span class="status-text">
                      {#if dev.status === 'lan_direct'}
                        LAN Direct
                      {:else if dev.status === 'online'}
                        Online
                      {:else if dev.status === 'revoked'}
                        Revoked
                      {:else}
                        Offline
                      {/if}
                    </span>
                  </div>
                </div>

                <div class="device-meta">
                  <div class="meta-row">
                    <span class="meta-label">Fingerprint:</span>
                    <button
                      class="meta-value fp-tag"
                      title="Click to copy public key fingerprint"
                      onclick={() => void copyFingerprint(dev.fingerprint)}
                    >
                      <code>{dev.fingerprint}</code>
                      {#if copiedFp === dev.fingerprint}
                        <span class="copied-indicator">Copied!</span>
                      {/if}
                    </button>
                  </div>

                  <div class="meta-row">
                    <span class="meta-label">Last Seen:</span>
                    <span class="meta-value">
                      {#if dev.lastSeenAt === 'never'}
                        Never
                      {:else}
                        {new Date(dev.lastSeenAt).toLocaleString()}
                      {/if}
                    </span>
                  </div>

                  <div class="meta-row">
                    <span class="meta-label">Auto-Accept:</span>
                    <span class="meta-value">
                      {#if dev.policy.autoAccept}
                        <span class="policy-on">Enabled ({dev.policy.autoAcceptDestDir})</span>
                      {:else}
                        <span class="policy-off">Disabled (confirmation required)</span>
                      {/if}
                    </span>
                  </div>
                </div>

                <div class="device-card-actions">
                  {#if !dev.revoked}
                    <button
                      class="btn-action btn-send"
                      onclick={() => {
                        onSendToDevice(dev);
                        onClose();
                      }}
                    >
                      Send Files…
                    </button>
                    <button class="btn-action btn-secondary" onclick={() => openPolicyEditor(dev)}>
                      Policy
                    </button>
                  {/if}
                  <button class="btn-action btn-danger" onclick={() => (unpairConfirmDevice = dev)}>
                    Unpair
                  </button>
                </div>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    </div>
  </div>
{/if}

<!-- Policy Editor Modal -->
{#if policyModalDevice}
  <div class="submodal-backdrop" role="dialog">
    <div class="submodal-content">
      <h3>Auto-Accept Policy: {policyModalDevice.localLabel}</h3>
      <p class="submodal-desc">Configure automated receiving settings for this trusted device.</p>

      <div class="form-group checkbox-group">
        <label>
          <input type="checkbox" bind:checked={policyAutoAccept} />
          Automatically accept incoming file transfers from this device
        </label>
      </div>

      {#if policyAutoAccept}
        <div class="form-group">
          <label for="dest-dir">Destination Directory (absolute path required):</label>
          <input
            id="dest-dir"
            type="text"
            placeholder="/home/user/Downloads/trusted"
            bind:value={policyDestDir}
          />
        </div>
      {/if}

      <div class="submodal-actions">
        <button class="btn-primary" onclick={() => void handleSavePolicy()}>Save Policy</button>
        <button class="btn-secondary" onclick={() => (policyModalDevice = null)}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

<!-- Pair Device Modal -->
{#if showPairModal}
  <div class="submodal-backdrop" role="dialog">
    <div class="submodal-content">
      <h3>Pair New Device</h3>
      <p class="submodal-desc">
        Enter the one-time invite code displayed on the device you want to pair.
      </p>

      <div class="form-group">
        <label for="invite-code">Invite Code:</label>
        <input
          id="invite-code"
          type="text"
          placeholder="e.g. 7-acoustic-salmon-guitar"
          bind:value={pairInviteCode}
        />
      </div>

      <div class="form-group">
        <label for="custom-name">Local Device Label (optional):</label>
        <input
          id="custom-name"
          type="text"
          placeholder="e.g. Work Laptop"
          bind:value={pairCustomName}
        />
      </div>

      <div class="form-group checkbox-group">
        <label>
          <input type="checkbox" bind:checked={pairAutoAccept} />
          Auto-accept transfers from this device
        </label>
      </div>

      {#if pairAutoAccept}
        <div class="form-group">
          <label for="pair-dest">Destination Directory:</label>
          <input
            id="pair-dest"
            type="text"
            placeholder="/home/user/Downloads"
            bind:value={pairDestDir}
          />
        </div>
      {/if}

      <div class="submodal-actions">
        <button
          class="btn-primary"
          disabled={pairingInProgress || !pairInviteCode.trim()}
          onclick={() => void handleStartPair()}
        >
          {pairingInProgress ? 'Pairing…' : 'Pair Device'}
        </button>
        <button
          class="btn-secondary"
          disabled={pairingInProgress}
          onclick={() => (showPairModal = false)}
        >
          Cancel
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- Unpair Confirm Modal -->
{#if unpairConfirmDevice}
  <div class="submodal-backdrop" role="dialog">
    <div class="submodal-content">
      <h3>Unpair Device: {unpairConfirmDevice.localLabel}</h3>
      <p class="submodal-desc">
        Are you sure you want to remove trust for this device? You will no longer receive automated
        or trusted transfers from it.
      </p>

      <div class="submodal-actions unpair-actions">
        <button class="btn-danger" onclick={() => void handleConfirmUnpair(false)}>
          Revoke Trust
        </button>
        <button class="btn-danger-outline" onclick={() => void handleConfirmUnpair(true)}>
          Purge Record
        </button>
        <button class="btn-secondary" onclick={() => (unpairConfirmDevice = null)}> Cancel </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .modal-backdrop,
  .submodal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 999;
    padding: 1rem;
    backdrop-filter: blur(4px);
  }

  .submodal-backdrop {
    z-index: 1000;
  }

  .modal-content {
    background: #18181b;
    border: 1px solid #27272a;
    border-radius: 12px;
    width: 100%;
    max-width: 680px;
    max-height: 85vh;
    display: flex;
    flex-direction: column;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
    color: #f4f4f5;
  }

  .submodal-content {
    background: #18181b;
    border: 1px solid #3f3f46;
    border-radius: 10px;
    width: 100%;
    max-width: 480px;
    padding: 1.5rem;
    color: #f4f4f5;
  }

  .submodal-desc {
    color: #a1a1aa;
    font-size: 0.875rem;
    margin: 0.5rem 0 1.25rem 0;
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.25rem 1.5rem;
    border-bottom: 1px solid #27272a;
  }

  .header-title {
    display: flex;
    align-items: baseline;
    gap: 0.75rem;
  }

  .header-title h2 {
    margin: 0;
    font-size: 1.25rem;
    font-weight: 600;
  }

  .device-count {
    color: #a1a1aa;
    font-size: 0.875rem;
  }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .btn-pair {
    background: #2563eb;
    color: white;
    border: none;
    padding: 0.4rem 0.8rem;
    border-radius: 6px;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
  }

  .btn-pair:hover {
    background: #1d4ed8;
  }

  .btn-close {
    background: transparent;
    border: none;
    color: #a1a1aa;
    font-size: 1.25rem;
    cursor: pointer;
    padding: 0.25rem;
  }

  .btn-close:hover {
    color: white;
  }

  .error-banner {
    background: #7f1d1d;
    color: #fecaca;
    padding: 0.75rem 1rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.875rem;
  }

  .btn-dismiss {
    background: transparent;
    border: none;
    color: #fecaca;
    cursor: pointer;
  }

  .browser-storage-notice {
    background: rgba(37, 99, 235, 0.1);
    border-bottom: 1px solid rgba(37, 99, 235, 0.2);
    color: #93c5fd;
    padding: 0.6rem 1.5rem;
    font-size: 0.8125rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    line-height: 1.4;
  }

  .browser-storage-notice .notice-icon {
    font-size: 0.875rem;
    color: #60a5fa;
  }

  .browser-storage-notice strong {
    color: #bfdbfe;
  }

  .device-list-container {
    padding: 1.5rem;
    overflow-y: auto;
    flex: 1;
  }

  .empty-state {
    text-align: center;
    padding: 2.5rem 1rem;
  }

  .empty-title {
    font-size: 1.125rem;
    font-weight: 600;
    margin-bottom: 0.5rem;
  }

  .empty-subtitle {
    color: #a1a1aa;
    font-size: 0.875rem;
    max-width: 420px;
    margin: 0 auto 1.5rem auto;
    line-height: 1.4;
  }

  .btn-pair-hero {
    background: #2563eb;
    color: white;
    border: none;
    padding: 0.6rem 1.25rem;
    border-radius: 6px;
    font-weight: 500;
    cursor: pointer;
  }

  .device-cards {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .device-card {
    background: #27272a;
    border: 1px solid #3f3f46;
    border-radius: 8px;
    padding: 1rem 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .device-card.revoked {
    opacity: 0.65;
    border-color: #7f1d1d;
  }

  .device-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .device-title-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .device-name {
    margin: 0;
    font-size: 1rem;
    font-weight: 600;
  }

  .status-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    font-size: 0.75rem;
    font-weight: 500;
    padding: 0.2rem 0.5rem;
    border-radius: 9999px;
  }

  .status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
  }

  .status-lan_direct {
    background: rgba(16, 185, 129, 0.2);
    color: #34d399;
  }
  .status-lan_direct .status-dot {
    background: #34d399;
  }

  .status-online {
    background: rgba(59, 130, 246, 0.2);
    color: #60a5fa;
  }
  .status-online .status-dot {
    background: #60a5fa;
  }

  .status-offline {
    background: rgba(113, 113, 122, 0.2);
    color: #a1a1aa;
  }
  .status-offline .status-dot {
    background: #a1a1aa;
  }

  .status-revoked {
    background: rgba(239, 68, 68, 0.2);
    color: #f87171;
  }
  .status-revoked .status-dot {
    background: #f87171;
  }

  .device-meta {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    font-size: 0.8125rem;
    color: #a1a1aa;
  }

  .meta-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .meta-label {
    min-width: 80px;
  }

  .fp-tag {
    background: #18181b;
    border: 1px solid #3f3f46;
    padding: 0.15rem 0.4rem;
    border-radius: 4px;
    color: #e4e4e7;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
  }

  .fp-tag:hover {
    border-color: #71717a;
  }

  .copied-indicator {
    color: #34d399;
    font-size: 0.75rem;
  }

  .policy-on {
    color: #34d399;
  }

  .policy-off {
    color: #a1a1aa;
  }

  .device-card-actions {
    display: flex;
    gap: 0.5rem;
    margin-top: 0.25rem;
  }

  .btn-action {
    padding: 0.35rem 0.75rem;
    font-size: 0.8125rem;
    border-radius: 6px;
    font-weight: 500;
    cursor: pointer;
    border: none;
  }

  .btn-send {
    background: #2563eb;
    color: white;
  }
  .btn-send:hover {
    background: #1d4ed8;
  }

  .btn-secondary {
    background: #3f3f46;
    color: #e4e4e7;
  }
  .btn-secondary:hover {
    background: #52525b;
  }

  .btn-danger {
    background: #991b1b;
    color: #fecaca;
  }
  .btn-danger:hover {
    background: #b91c1c;
  }

  .btn-danger-outline {
    background: transparent;
    border: 1px solid #991b1b;
    color: #f87171;
  }
  .btn-danger-outline:hover {
    background: #991b1b;
    color: #fecaca;
  }

  .btn-icon {
    background: transparent;
    border: none;
    color: #a1a1aa;
    cursor: pointer;
    font-size: 0.875rem;
    padding: 0.2rem;
  }

  .btn-icon:hover {
    color: white;
  }

  .input-rename {
    background: #18181b;
    border: 1px solid #3f3f46;
    color: white;
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    font-size: 0.875rem;
  }

  .form-group {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    margin-bottom: 1rem;
  }

  .form-group label {
    font-size: 0.8125rem;
    color: #d4d4d8;
  }

  .form-group input[type='text'] {
    background: #27272a;
    border: 1px solid #3f3f46;
    color: white;
    padding: 0.5rem;
    border-radius: 6px;
    font-size: 0.875rem;
  }

  .checkbox-group label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
  }

  .submodal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
    margin-top: 1.5rem;
  }

  .unpair-actions {
    justify-content: space-between;
  }

  .btn-primary {
    background: #2563eb;
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
  }

  .btn-primary:hover {
    background: #1d4ed8;
  }

  .btn-primary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
</style>
