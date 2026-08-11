/**
 * Best-effort SCTP-buffer guard over an RTCDataChannel. The worker's in-flight window is the real
 * memory bound; this only keeps `bufferedAmount` from ballooning: queue while above the high
 * watermark, flush in order when the channel signals it has drained below the low watermark.
 */

import { BUFFERED_AMOUNT_HIGH, BUFFERED_AMOUNT_LOW } from '@sendbeam/protocol';

export interface ChannelLike {
  bufferedAmount: number;
  bufferedAmountLowThreshold: number;
  send(data: ArrayBuffer): void;
  onbufferedamountlow: ((ev: Event) => unknown) | null;
}

export class ChannelWriter {
  private queue: ArrayBuffer[] = [];

  constructor(private readonly channel: ChannelLike) {
    this.channel.bufferedAmountLowThreshold = BUFFERED_AMOUNT_LOW;
    this.channel.onbufferedamountlow = () => this.flush();
  }

  get pending(): number {
    return this.queue.length;
  }

  write(frame: ArrayBuffer): void {
    // Once anything is queued, everything queues behind it — FIFO holds even if bufferedAmount
    // has since dipped, since the low-watermark event is what authorises a drain.
    if (this.queue.length === 0 && this.channel.bufferedAmount < BUFFERED_AMOUNT_HIGH) {
      this.channel.send(frame);
    } else {
      this.queue.push(frame);
    }
  }

  /** Wait briefly for queued and SCTP-buffered bytes to drain before graceful teardown. */
  async drain(timeoutMs = 500): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while ((this.queue.length > 0 || this.channel.bufferedAmount > 0) && Date.now() < deadline) {
      this.flush();
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }

  private flush(): void {
    while (this.queue.length > 0 && this.channel.bufferedAmount < BUFFERED_AMOUNT_HIGH) {
      const next = this.queue.shift()!;
      this.channel.send(next);
    }
  }
}
