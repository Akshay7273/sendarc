import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { expect, test } from '@playwright/test';

/** Deterministic pseudo-random payload so every engine compares against the same digest. */
function payload(size: number): Buffer {
  let seed = 0x5eed_1234;
  const bytes = Buffer.alloc(size);
  for (let i = 0; i < size; i++) {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    bytes[i] = seed >> 24;
  }
  return bytes;
}

function sha256(buffer: Buffer): string {
  return createHash('sha256').update(buffer).digest('hex');
}

const BYTES = payload(4 * 1024 * 1024);
const DIGEST = sha256(BYTES);

/** Open the send screen and return the room-words invite code it shows. */
async function openSender(page: import('@playwright/test').Page): Promise<string> {
  await page.goto('/');
  await page.getByRole('button', { name: 'Send a file' }).click();
  const codeCard = page.locator('.code-card');
  await expect(codeCard).toBeVisible({ timeout: 15_000 });
  const code = (await codeCard.locator('.code').textContent())?.trim() ?? '';
  expect(code).toMatch(/^\d+-[a-z]+-[a-z]+$/);
  return code;
}

/** Join the given code on a fresh tab. */
async function joinReceiver(page: import('@playwright/test').Page, code: string): Promise<void> {
  await page.goto('/');
  await page.locator('#code').fill(code);
  await page.getByRole('button', { name: 'Receive' }).click();
}

test('send → receive round-trips the file with a verified digest', async ({ context }) => {
  const sender = await context.newPage();
  const code = await openSender(sender);

  const receiver = await context.newPage();
  await joinReceiver(receiver, code);

  // Both peers authenticate and land on the secure-channel screen with a matching fingerprint.
  await expect(receiver.locator('.result.ok')).toBeVisible({ timeout: 30_000 });
  await expect(sender.locator('.result.ok')).toBeVisible({ timeout: 30_000 });
  const senderFingerprint = (await sender.locator('.fingerprint').textContent())?.trim();
  const receiverFingerprint = (await receiver.locator('.fingerprint').textContent())?.trim();
  expect(senderFingerprint).toBe(receiverFingerprint);

  await sender.setInputFiles('input[type="file"]', {
    name: 'payload.bin',
    mimeType: 'application/octet-stream',
    buffer: BYTES,
  });

  await expect(sender.getByText(/verified by the receiver/)).toBeVisible({ timeout: 60_000 });
  await expect(receiver.getByText(/verified\./)).toBeVisible({ timeout: 60_000 });

  // Save through the OPFS download link and verify the bytes match sha256sum of the source.
  const downloadPromise = receiver.waitForEvent('download');
  await receiver.locator('a.download').click();
  const download = await downloadPromise;
  const path = await download.path();
  expect(path).not.toBeNull();
  const received = readFileSync(path!);
  expect(received.equals(BYTES)).toBe(true);
  expect(sha256(received)).toBe(DIGEST);
});

test('a wrong code fails closed on the receiver', async ({ context }) => {
  const sender = await context.newPage();
  const code = await openSender(sender);
  const [room, firstWord] = code.split('-');
  const wrongCode = `${room}-${firstWord}-different`;

  const receiver = await context.newPage();
  await joinReceiver(receiver, wrongCode);

  await expect(receiver.locator('.result.bad')).toBeVisible({ timeout: 30_000 });
  await expect(receiver.locator('.result.bad')).toContainText(/did not match/i);
});
