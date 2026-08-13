/**
 * OPFS declarations the stock DOM lib omits: the dedicated-worker-only
 * `FileSystemSyncAccessHandle` (used by the durable receive writer, V13-PR03),
 * `createSyncAccessHandle()` on file handles, and async iteration over directory
 * handles. Mirrors the WHATWG File System standard surface.
 */

interface FileSystemSyncAccessHandle {
  read(buffer: ArrayBuffer | ArrayBufferView, options?: { at?: number }): number;
  write(buffer: ArrayBuffer | ArrayBufferView, options?: { at?: number }): number;
  truncate(newSize: number): void;
  getSize(): number;
  flush(): void;
  close(): void;
}

interface FileSystemFileHandle {
  createSyncAccessHandle(): Promise<FileSystemSyncAccessHandle>;
}

interface FileSystemDirectoryHandle {
  entries(): AsyncIterableIterator<[string, FileSystemHandle]>;
  [Symbol.asyncIterator](): AsyncIterableIterator<[string, FileSystemHandle]>;
}
