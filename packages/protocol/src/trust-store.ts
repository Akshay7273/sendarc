/**
 * Trust Database schema, policy validation, and in-memory/browser trust stores.
 * Matches Go `packages/wire/trust_record.go` and `packages/engine/trust/trust_store.go`.
 */

import { hexToBytes } from './bytes.js';
import { deriveDeviceId, validateDeviceId } from './identity.js';

export const CAP_TRANSFER_V1 = 'transfer.v1';
export const CAP_TRANSFER_V2 = 'transfer.v2';
export const CAP_AUTO_ACCEPT = 'auto_accept';
export const CAP_LAN_DIRECT = 'lan_direct';
export const CAP_RELAY_FALLBACK = 'relay_fallback';

export interface TrustPolicy {
  /** Auto-accept incoming transfers from this device without manual prompt. */
  autoAccept: boolean;
  /** Designated destination subpath or directory handle identifier. */
  autoAcceptDestDir?: string;
  /** Max file size in bytes for auto-acceptance (0 = default 10GB cap). */
  maxFileSizeBytes?: number;
  /** Optional whitelist of permitted MIME types. */
  allowedMimeTypes?: string[];
}

export function defaultTrustPolicy(): TrustPolicy {
  return {
    autoAccept: false,
    maxFileSizeBytes: 10 * 1024 * 1024 * 1024,
  };
}

export interface TrustRecord {
  deviceId: string;
  publicKey: string; // 64-char lowercase hex string (32 bytes)
  localLabel: string;
  pairCredentialRef: string;
  capabilities: string[];
  firstSeenAt: string; // ISO 8601 string
  lastSeenAt: string; // ISO 8601 string
  revoked: boolean;
  revokedAt?: string;
  policy: TrustPolicy;
}

/**
 * Validate a TrustRecord for structural integrity, key binding, and policy safety.
 */
export async function validateTrustRecord(record: TrustRecord): Promise<void> {
  if (!record) throw new Error('invalid trust record: null or undefined');
  if (!validateDeviceId(record.deviceId)) {
    throw new Error(`invalid trust record: invalid device id ${record.deviceId}`);
  }
  const pubBytes = hexToBytes(record.publicKey);
  if (pubBytes.length !== 32) {
    throw new Error('invalid trust record: public key must be 32 bytes');
  }
  const derivedId = await deriveDeviceId(pubBytes);
  if (derivedId !== record.deviceId) {
    throw new Error(
      `device id ${record.deviceId} does not match public key derived id ${derivedId}`,
    );
  }
  if (!record.localLabel || record.localLabel.trim() === '') {
    throw new Error('invalid trust record: local label cannot be empty');
  }
  if (!record.firstSeenAt) {
    throw new Error('invalid trust record: firstSeenAt must be set');
  }
  if (record.policy?.autoAccept) {
    if (record.policy.maxFileSizeBytes && record.policy.maxFileSizeBytes < 0) {
      throw new Error('invalid trust policy: maxFileSizeBytes cannot be negative');
    }
  }
}

/**
 * TrustStore interface for persistent trusted device management.
 */
export interface TrustStore {
  getDevice(deviceId: string): Promise<TrustRecord | null>;
  listDevices(): Promise<TrustRecord[]>;
  addOrUpdateDevice(record: TrustRecord): Promise<void>;
  revokeDevice(deviceId: string): Promise<void>;
  unpairDevice(deviceId: string): Promise<void>;
  isTrusted(deviceId: string): Promise<boolean>;
  updateLastSeen(deviceId: string, seenAt?: string): Promise<void>;
  updatePolicy(deviceId: string, policy: TrustPolicy): Promise<void>;
}

/**
 * MemoryTrustStore is an in-memory implementation for tests, headless nodes, and ephemeral sessions.
 */
export class MemoryTrustStore implements TrustStore {
  private readonly records = new Map<string, TrustRecord>();

  async getDevice(deviceId: string): Promise<TrustRecord | null> {
    const rec = this.records.get(deviceId);
    if (!rec) return null;
    return JSON.parse(JSON.stringify(rec)) as TrustRecord;
  }

  async listDevices(): Promise<TrustRecord[]> {
    return Array.from(this.records.values()).map(
      (r) => JSON.parse(JSON.stringify(r)) as TrustRecord,
    );
  }

  async addOrUpdateDevice(record: TrustRecord): Promise<void> {
    await validateTrustRecord(record);
    this.records.set(record.deviceId, JSON.parse(JSON.stringify(record)) as TrustRecord);
  }

  async revokeDevice(deviceId: string): Promise<void> {
    const rec = this.records.get(deviceId);
    if (!rec) throw new Error(`device not found: ${deviceId}`);
    rec.revoked = true;
    rec.revokedAt = new Date().toISOString();
  }

  async unpairDevice(deviceId: string): Promise<void> {
    this.records.delete(deviceId);
  }

  async isTrusted(deviceId: string): Promise<boolean> {
    const rec = this.records.get(deviceId);
    return rec !== undefined && !rec.revoked;
  }

  async updateLastSeen(deviceId: string, seenAt?: string): Promise<void> {
    const rec = this.records.get(deviceId);
    if (!rec) throw new Error(`device not found: ${deviceId}`);
    rec.lastSeenAt = seenAt || new Date().toISOString();
  }

  async updatePolicy(deviceId: string, policy: TrustPolicy): Promise<void> {
    const rec = this.records.get(deviceId);
    if (!rec) throw new Error(`device not found: ${deviceId}`);
    rec.policy = JSON.parse(JSON.stringify(policy)) as TrustPolicy;
    await validateTrustRecord(rec);
  }
}
