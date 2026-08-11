import { describe, expect, it, vi } from 'vitest';
import type { SignalMsg } from '@sendbeam/protocol';
import type { SignalChannel } from '../signaling/client.js';
import { RelayTransport } from './relay.js';

function fakeChannel() {
  const messages: SignalMsg[] = [];
  const binary: ArrayBuffer[] = [];
  const channel: SignalChannel = {
    send: (message) => messages.push(message),
    sendBinary: (frame) => binary.push(frame),
    onMessage: vi.fn(),
    onBinary: vi.fn(),
    onClose: vi.fn(),
    close: vi.fn(),
  };
  return { channel, messages, binary };
}

describe('RelayTransport', () => {
  it('coordinates opt-in and sends only within granted credit', async () => {
    const { channel, messages, binary } = fakeChannel();
    const relay = new RelayTransport(channel);
    relay.open();
    expect(messages).toEqual([{ type: 'relay_open' }]);
    relay.handleMessage({ type: 'relay_ready' });
    relay.handleMessage({ type: 'credit', bytes: 32 });
    const frame = new Uint8Array([1, 2, 3]).buffer;
    await relay.write(frame);
    expect(binary).toEqual([frame]);
    expect(messages[1]).toEqual({ type: 'relay_credit', bytes: 1024 * 1024 });
  });

  it('buffers early binary within one window and credits only worker-consumed bytes', () => {
    const { channel, messages } = fakeChannel();
    const relay = new RelayTransport(channel);
    relay.handleMessage({ type: 'relay_ready' });
    const frame = new Uint8Array(512 * 1024).buffer;
    relay.handleBinary(frame);
    const received: ArrayBuffer[] = [];
    relay.onData((data) => received.push(data));
    expect(received).toEqual([frame]);
    relay.consumed(frame.byteLength);
    expect(messages.at(-1)).toEqual({ type: 'relay_credit', bytes: 512 * 1024 });
  });

  it('opens automatically when the partner requires relay', () => {
    const { channel, messages } = fakeChannel();
    const relay = new RelayTransport(channel);
    expect(relay.handleMessage({ type: 'relay_required' })).toBe(true);
    expect(messages).toEqual([{ type: 'relay_open' }]);
  });

  it('rejects readiness and blocked writes when the WebSocket is lost', async () => {
    const { channel } = fakeChannel();
    const relay = new RelayTransport(channel);
    const ready = relay.ready;
    const blocked = relay.write(new Uint8Array([1]).buffer);
    relay.fail(new Error('signaling lost'));
    await expect(ready).rejects.toThrow('signaling lost');
    await expect(blocked).rejects.toThrow('relay closed');
  });
});
