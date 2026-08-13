/**
 * Streaming, store-only ZIP primitives (no compression). Shared by the browser archive sink
 * and the durable-receive finalize step, which builds a ZIP from verified partials.
 */

export interface ZipEntry {
  name: Uint8Array;
  crc: number;
  size: number;
  offset: number;
}

const crcTable = Array.from({ length: 256 }, (_, value) => {
  let crc = value;
  for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  return crc >>> 0;
});

export function crc32Update(crc: number, bytes: Uint8Array): number {
  for (const byte of bytes) crc = (crc >>> 8) ^ crcTable[(crc ^ byte) & 0xff]!;
  return crc >>> 0;
}

function record(size: number, write: (view: DataView) => void): Uint8Array {
  const out = new Uint8Array(size);
  write(new DataView(out.buffer));
  return out;
}

export function localHeader(name: Uint8Array): Uint8Array {
  const header = record(30, (v) => {
    v.setUint32(0, 0x04034b50, true);
    v.setUint16(4, 20, true);
    v.setUint16(6, 0x0808, true);
    v.setUint16(26, name.length, true);
  });
  return join(header, name);
}

export function dataDescriptor(crc: number, size: number): Uint8Array {
  return record(16, (v) => {
    v.setUint32(0, 0x08074b50, true);
    v.setUint32(4, crc, true);
    v.setUint32(8, size, true);
    v.setUint32(12, size, true);
  });
}

export function centralHeader(entry: ZipEntry): Uint8Array {
  const header = record(46, (v) => {
    v.setUint32(0, 0x02014b50, true);
    v.setUint16(4, 20, true);
    v.setUint16(6, 20, true);
    v.setUint16(8, 0x0808, true);
    v.setUint32(16, entry.crc, true);
    v.setUint32(20, entry.size, true);
    v.setUint32(24, entry.size, true);
    v.setUint16(28, entry.name.length, true);
    v.setUint32(42, entry.offset, true);
  });
  return join(header, entry.name);
}

export function endOfCentralDirectory(count: number, size: number, offset: number): Uint8Array {
  return record(22, (v) => {
    v.setUint32(0, 0x06054b50, true);
    v.setUint16(8, count, true);
    v.setUint16(10, count, true);
    v.setUint32(12, size, true);
    v.setUint32(16, offset, true);
  });
}

function join(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
