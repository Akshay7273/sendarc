import { describe, it, expect } from 'vitest';
import {
  WORDLIST,
  normalizeCode,
  formatCode,
  parseCode,
  generateWords,
  generateCode,
} from './words.js';
import { WORDLIST_SIZE, DEFAULT_WORD_COUNT } from './constants.js';

describe('wordlist', () => {
  it(`has exactly ${WORDLIST_SIZE} entries`, () => {
    expect(WORDLIST).toHaveLength(WORDLIST_SIZE);
  });

  it('has no duplicates', () => {
    expect(new Set(WORDLIST).size).toBe(WORDLIST.length);
  });

  it('contains only short lowercase ASCII words', () => {
    for (const w of WORDLIST) {
      expect(w).toMatch(/^[a-z]{2,8}$/);
    }
  });
});

describe('normalizeCode', () => {
  it('lowercases letters and keeps digits', () => {
    expect(normalizeCode('4-Brave-Otter')).toBe('4-brave-otter');
  });

  it('collapses any run of separators into a single dash', () => {
    expect(normalizeCode('4  brave   otter')).toBe('4-brave-otter');
    expect(normalizeCode('4_brave.otter')).toBe('4-brave-otter');
    expect(normalizeCode('4 :: brave // otter')).toBe('4-brave-otter');
  });

  it('trims leading and trailing separators', () => {
    expect(normalizeCode('  4-brave-otter  ')).toBe('4-brave-otter');
    expect(normalizeCode('--4-brave-otter--')).toBe('4-brave-otter');
  });

  it('is idempotent', () => {
    const once = normalizeCode('4 Brave  Otter!');
    expect(normalizeCode(once)).toBe(once);
  });

  it('drops non-ASCII characters', () => {
    expect(normalizeCode('4-bravé-otter')).toBe('4-brav-otter');
  });
});

describe('formatCode / parseCode', () => {
  it('formats a room and word part into a code', () => {
    expect(formatCode(4, 'brave-otter')).toBe('4-brave-otter');
  });

  it('parses a well-formed code back into room and words', () => {
    expect(parseCode('4-brave-otter')).toEqual({ room: 4, words: 'brave-otter' });
  });

  it('round-trips format → parse', () => {
    const code = formatCode(1234, 'wolf-fjord-comet');
    expect(parseCode(code)).toEqual({ room: 1234, words: 'wolf-fjord-comet' });
  });

  it('normalizes messy input before parsing', () => {
    expect(parseCode('  0042  Brave  Otter ')).toEqual({ room: 42, words: 'brave-otter' });
  });

  it('rejects a code with no room', () => {
    expect(() => parseCode('brave-otter')).toThrow();
  });

  it('rejects a code with a non-numeric room', () => {
    expect(() => parseCode('abc-brave-otter')).toThrow();
  });

  it('rejects a code with no words', () => {
    expect(() => parseCode('4')).toThrow();
    expect(() => parseCode('4-')).toThrow();
  });
});

describe('generateWords / generateCode', () => {
  it('generates the default number of words', () => {
    const words = generateWords();
    expect(words.split('-')).toHaveLength(DEFAULT_WORD_COUNT);
  });

  it('generates the requested number of words, all from the list', () => {
    const words = generateWords(4);
    const parts = words.split('-');
    expect(parts).toHaveLength(4);
    for (const p of parts) expect(WORDLIST).toContain(p);
  });

  it('rejects a word count below one', () => {
    expect(() => generateWords(0)).toThrow();
  });

  it('generates a full code that parses back to the room', () => {
    const code = generateCode(7);
    const parsed = parseCode(code);
    expect(parsed.room).toBe(7);
    expect(parsed.words.split('-')).toHaveLength(DEFAULT_WORD_COUNT);
  });

  it('is a normalized password (survives a normalize round-trip)', () => {
    const code = generateCode(7);
    expect(normalizeCode(code)).toBe(code);
  });
});
