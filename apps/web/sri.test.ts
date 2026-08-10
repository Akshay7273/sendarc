import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { computeIntegrity, injectSriAttributes } from './sri';

describe('computeIntegrity', () => {
  it('returns the sha384 base64 digest with the sha384- prefix', () => {
    const expected = `sha384-${createHash('sha384').update('hello world').digest('base64')}`;
    expect(computeIntegrity('hello world')).toBe(expected);
  });

  it('hashes raw bytes, not the string encoding', () => {
    const bytes = new Uint8Array([0x00, 0xff, 0x10]);
    expect(computeIntegrity(bytes)).toBe(
      `sha384-${createHash('sha384').update(bytes).digest('base64')}`,
    );
  });
});

describe('injectSriAttributes', () => {
  const integrity = new Map([
    ['assets/main-abc123.js', 'sha384-JS'],
    ['assets/main-abc123.css', 'sha384-CSS'],
  ]);

  it('adds integrity and crossorigin to local scripts and stylesheets', () => {
    const html = `
      <script type="module" src="/assets/main-abc123.js"></script>
      <link rel="stylesheet" href="/assets/main-abc123.css" />
    `;
    const out = injectSriAttributes(html, integrity);
    expect(out).toContain(
      'src="/assets/main-abc123.js" integrity="sha384-JS" crossorigin="anonymous"',
    );
    expect(out).toContain(
      'href="/assets/main-abc123.css" integrity="sha384-CSS" crossorigin="anonymous"',
    );
  });

  it('handles hashed filenames with query strings', () => {
    const out = injectSriAttributes(
      '<script src="/assets/main-abc123.js?v=1"></script>',
      integrity,
    );
    expect(out).toContain('integrity="sha384-JS"');
  });

  it('does not duplicate crossorigin when the tag already has it', () => {
    const html = '<script type="module" crossorigin src="/assets/main-abc123.js"></script>';
    const out = injectSriAttributes(html, integrity);
    expect(out).toContain('integrity="sha384-JS"');
    expect(out.match(/crossorigin/g)).toHaveLength(1);
  });

  it('leaves external and unknown URLs untouched', () => {
    const html = `
      <script src="https://cdn.example.com/x.js"></script>
      <script src="/assets/unknown.js"></script>
    `;
    const out = injectSriAttributes(html, integrity);
    expect(out).not.toContain('integrity');
  });
});
