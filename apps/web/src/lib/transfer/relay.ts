import type { SignalMsg } from '@sendbeam/protocol';
import type { SignalChannel } from '../signaling/client.js';

const WINDOW_BYTES = 1024 * 1024;
const CREDIT_BATCH = WINDOW_BYTES / 2;

/** Credit-gated opaque binary transport over the adopted signaling WebSocket. */
export class RelayTransport {
  private opened = false;
  private isReady = false;
  private closed = false;
  private credit = 0;
  private consumedBytes = 0;
  private handler: ((frame: ArrayBuffer) => void) | undefined;
  private readonly pending: ArrayBuffer[] = [];
  private pendingBytes = 0;
  private readonly creditWaiters: Array<() => void> = [];
  private outbound: Promise<void> = Promise.resolve();
  private resolveReady!: () => void;
  private rejectReady!: (err: Error) => void;
  readonly ready = new Promise<void>((resolve, reject) => {
    this.resolveReady = resolve;
    this.rejectReady = reject;
  });

  constructor(private readonly signaling: SignalChannel) {
    // A direct path may remain healthy after signaling disappears; suppress an unhandled
    // readiness rejection while preserving it for a later attempted relay switch.
    this.ready.catch(() => {});
  }

  open(): void {
    if (this.opened || this.closed) return;
    this.opened = true;
    this.signaling.send({ type: 'relay_open' });
  }

  /** Consume a relay control message; false leaves SDP/ICE for the direct peer. */
  handleMessage(msg: SignalMsg): boolean {
    switch (msg.type) {
      case 'relay_required':
        this.open();
        return true;
      case 'relay_ready':
        if (!this.isReady) {
          this.isReady = true;
          this.signaling.send({ type: 'relay_credit', bytes: WINDOW_BYTES });
          this.resolveReady();
          this.wakeCredit();
        }
        return true;
      case 'credit':
        if (Number.isSafeInteger(msg.bytes) && msg.bytes > 0) {
          this.credit += msg.bytes;
          this.wakeCredit();
        }
        return true;
      default:
        return false;
    }
  }

  handleBinary(frame: ArrayBuffer): void {
    if (this.closed) return;
    if (this.handler) {
      this.handler(frame);
      return;
    }
    if (this.pendingBytes + frame.byteLength <= WINDOW_BYTES) {
      this.pending.push(frame);
      this.pendingBytes += frame.byteLength;
    }
  }

  onData(handler: (frame: ArrayBuffer) => void): void {
    if (this.handler) return;
    this.handler = handler;
    for (const frame of this.pending) handler(frame);
    this.pending.length = 0;
    this.pendingBytes = 0;
  }

  /** Queue one frame in order; the promise resolves only after receiver credit permits the send. */
  write(frame: ArrayBuffer): Promise<void> {
    const task = this.outbound.then(async () => {
      await this.waitForCredit(frame.byteLength);
      if (this.closed) throw new Error('relay closed');
      this.credit -= frame.byteLength;
      this.signaling.sendBinary(frame);
    });
    this.outbound = task.catch(() => {});
    return task;
  }

  /** Replenish server credit only after the worker has authenticated and consumed the frame. */
  consumed(bytes: number): void {
    if (!Number.isSafeInteger(bytes) || bytes <= 0 || this.closed) return;
    this.consumedBytes += bytes;
    if (this.consumedBytes >= CREDIT_BATCH) {
      this.signaling.send({ type: 'relay_credit', bytes: this.consumedBytes });
      this.consumedBytes = 0;
    }
  }

  close(): void {
    this.closed = true;
    this.wakeCredit();
  }

  /** Fail pending readiness and credit waits when the carrying WebSocket is lost. */
  fail(err: Error): void {
    if (this.closed) return;
    this.closed = true;
    if (!this.isReady) this.rejectReady(err);
    this.wakeCredit();
  }

  private async waitForCredit(bytes: number): Promise<void> {
    while (!this.closed && (!this.isReady || this.credit < bytes)) {
      await new Promise<void>((resolve) => this.creditWaiters.push(resolve));
    }
  }

  private wakeCredit(): void {
    const waiters = this.creditWaiters.splice(0);
    for (const resolve of waiters) resolve();
  }
}
