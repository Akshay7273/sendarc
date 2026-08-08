/**
 * JSON codec for the transfer control messages (design §5.4). These travel as the plaintext
 * inside AES-GCM frames whose header `type` names the message; `block_data` is raw file bytes
 * and is not handled here. Decoders validate shape so a decrypted-but-malformed frame fails
 * loudly rather than corrupting state.
 */

import {
  FrameType,
  type BlockHash,
  type BlockRecv,
  type Complete,
  type Fail,
  type FileEntry,
  type Manifest,
  type TransferMsg,
} from './transfer.js';
import { utf8 } from './bytes.js';

const decoder = new TextDecoder();

export function encodeControl(msg: TransferMsg): Uint8Array {
  return utf8(JSON.stringify(msg));
}

export function decodeControl(payload: Uint8Array): TransferMsg {
  let obj: unknown;
  try {
    obj = JSON.parse(decoder.decode(payload));
  } catch {
    throw new Error('control frame: invalid JSON');
  }
  if (typeof obj !== 'object' || obj === null) throw new Error('control frame: not an object');
  const m = obj as Record<string, unknown>;
  switch (m.type) {
    case FrameType.Manifest:
      return asManifest(m);
    case FrameType.BlockHash:
      return asBlockHash(m);
    case FrameType.BlockRecv:
      return asBlockRecv(m);
    case FrameType.Complete:
      return asComplete(m);
    case FrameType.Done:
      return { type: FrameType.Done };
    case FrameType.Fail:
      return asFail(m);
    default:
      throw new Error(`control frame: unexpected type ${String(m.type)}`);
  }
}

function num(m: Record<string, unknown>, k: string): number {
  const v = m[k];
  if (typeof v !== 'number' || !Number.isFinite(v))
    throw new Error(`control frame: ${k} not a number`);
  return v;
}
function str(m: Record<string, unknown>, k: string): string {
  const v = m[k];
  if (typeof v !== 'string') throw new Error(`control frame: ${k} not a string`);
  return v;
}

function asFileEntry(v: unknown): FileEntry {
  if (typeof v !== 'object' || v === null) throw new Error('control frame: bad file entry');
  const f = v as Record<string, unknown>;
  return {
    idx: num(f, 'idx'),
    name: str(f, 'name'),
    size: num(f, 'size'),
    mime: str(f, 'mime'),
    lastModified: num(f, 'lastModified'),
    blockSize: num(f, 'blockSize'),
    blocks: num(f, 'blocks'),
    fileDigest: str(f, 'fileDigest'),
  };
}

function asManifest(m: Record<string, unknown>): Manifest {
  if (!Array.isArray(m.files) || m.files.length === 0)
    throw new Error('control frame: manifest.files');
  return {
    type: FrameType.Manifest,
    files: m.files.map(asFileEntry),
    totalSize: num(m, 'totalSize'),
  };
}
function asBlockHash(m: Record<string, unknown>): BlockHash {
  return {
    type: FrameType.BlockHash,
    fileIdx: num(m, 'fileIdx'),
    blockIdx: num(m, 'blockIdx'),
    sha256: str(m, 'sha256'),
  };
}
function asBlockRecv(m: Record<string, unknown>): BlockRecv {
  return { type: FrameType.BlockRecv, fileIdx: num(m, 'fileIdx'), blockIdx: num(m, 'blockIdx') };
}
function asComplete(m: Record<string, unknown>): Complete {
  return { type: FrameType.Complete, fileDigest: str(m, 'fileDigest') };
}
function asFail(m: Record<string, unknown>): Fail {
  const reason = str(m, 'reason');
  const allowed = ['digest_mismatch', 'integrity', 'sink_error', 'canceled', 'quota'];
  if (!allowed.includes(reason)) throw new Error(`control frame: bad fail reason ${reason}`);
  return { type: FrameType.Fail, reason: reason as Fail['reason'] };
}
