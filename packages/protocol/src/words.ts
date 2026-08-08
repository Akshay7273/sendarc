/**
 * Invite-code words. The sender generates a short word code (e.g. `brave-otter`) from
 * this 256-word list — exactly one byte of entropy per word — which the server never
 * sees. The full normalized string `<room>-<words>` is the SPAKE2 password.
 *
 * The list and the normalization rules are part of the wire contract: they are mirrored
 * byte-for-byte by the Go `words` package in `packages/wire`, and a cross-language
 * vector test asserts the list digest matches. Words are short, lowercase ASCII, and
 * chosen to be distinct when written down.
 */

import { CODE_SEPARATOR, DEFAULT_WORD_COUNT, WORDLIST_SIZE } from './constants.js';

/** The 256-word code list. Order is significant — index is the byte value. */
export const WORDLIST: readonly string[] = [
  'ant',
  'ape',
  'bat',
  'bear',
  'bee',
  'bird',
  'bison',
  'boar',
  'bug',
  'calf',
  'camel',
  'carp',
  'cat',
  'chick',
  'clam',
  'cobra',
  'colt',
  'coral',
  'cow',
  'crab',
  'crane',
  'crow',
  'cub',
  'deer',
  'dingo',
  'dodo',
  'dog',
  'dove',
  'duck',
  'eagle',
  'eel',
  'elk',
  'emu',
  'ewe',
  'falcon',
  'fawn',
  'ferret',
  'finch',
  'fish',
  'flea',
  'fly',
  'foal',
  'fox',
  'frog',
  'gecko',
  'goat',
  'goose',
  'gull',
  'hare',
  'hawk',
  'hen',
  'heron',
  'hog',
  'horse',
  'hound',
  'ibex',
  'jay',
  'koala',
  'lamb',
  'lark',
  'lion',
  'lizard',
  'llama',
  'lynx',
  'mole',
  'moose',
  'moth',
  'mouse',
  'mule',
  'newt',
  'otter',
  'owl',
  'ox',
  'panda',
  'pig',
  'pika',
  'pony',
  'pug',
  'puma',
  'quail',
  'rabbit',
  'ram',
  'rat',
  'raven',
  'ray',
  'robin',
  'seal',
  'shark',
  'sheep',
  'shrew',
  'shrimp',
  'skunk',
  'sloth',
  'slug',
  'snail',
  'snake',
  'sole',
  'sparrow',
  'spider',
  'squid',
  'stag',
  'stork',
  'swan',
  'tapir',
  'teal',
  'tiger',
  'toad',
  'trout',
  'tuna',
  'turkey',
  'viper',
  'vole',
  'walrus',
  'wasp',
  'weasel',
  'whale',
  'wolf',
  'wombat',
  'worm',
  'wren',
  'yak',
  'zebra',
  'beetle',
  'bream',
  'cod',
  'dolphin',
  'gnu',
  'hyena',
  'acorn',
  'amber',
  'ash',
  'aspen',
  'bark',
  'bay',
  'beach',
  'birch',
  'bloom',
  'branch',
  'breeze',
  'brook',
  'bush',
  'cave',
  'cedar',
  'cliff',
  'cloud',
  'clover',
  'coast',
  'comet',
  'cove',
  'creek',
  'dawn',
  'delta',
  'dew',
  'dune',
  'dusk',
  'earth',
  'ember',
  'fern',
  'field',
  'fjord',
  'flame',
  'fog',
  'forest',
  'frost',
  'glade',
  'glen',
  'grove',
  'gust',
  'hail',
  'hill',
  'ice',
  'island',
  'ivy',
  'lake',
  'leaf',
  'lily',
  'maple',
  'marsh',
  'meadow',
  'mist',
  'moon',
  'moss',
  'mount',
  'oak',
  'ocean',
  'palm',
  'peak',
  'pebble',
  'pine',
  'plain',
  'pond',
  'rain',
  'reef',
  'ridge',
  'river',
  'rock',
  'root',
  'rose',
  'sand',
  'sea',
  'seed',
  'shade',
  'shell',
  'shore',
  'sky',
  'sleet',
  'snow',
  'spring',
  'star',
  'stone',
  'storm',
  'stream',
  'summit',
  'sun',
  'surf',
  'swamp',
  'thaw',
  'tide',
  'trail',
  'tree',
  'tulip',
  'valley',
  'vine',
  'wave',
  'well',
  'wind',
  'wood',
  'anchor',
  'arrow',
  'badge',
  'beacon',
  'bell',
  'boat',
  'bolt',
  'book',
  'boot',
  'bottle',
  'bowl',
  'brick',
  'bridge',
  'broom',
  'brush',
  'bucket',
  'candle',
  'cape',
  'cart',
  'chain',
  'chair',
  'clock',
  'coal',
  'coin',
  'comb',
  'cord',
  'crown',
  'cup',
  'dial',
];

/**
 * Canonicalize a raw code into the exact string used as the SPAKE2 password. Lowercases
 * ASCII letters, treats every run of other characters as one separator, and trims
 * separators from the ends. Deterministic and mirrored in Go — the two must agree
 * byte-for-byte or the handshake fails closed.
 */
export function normalizeCode(raw: string): string {
  let out = '';
  let pendingSep = false;
  for (const ch of raw) {
    const code = ch.charCodeAt(0);
    let mapped = '';
    if (code >= 0x41 && code <= 0x5a)
      mapped = String.fromCharCode(code + 0x20); // A-Z → a-z
    else if ((code >= 0x61 && code <= 0x7a) || (code >= 0x30 && code <= 0x39)) mapped = ch; // a-z 0-9
    if (mapped === '') {
      pendingSep = out.length > 0;
      continue;
    }
    if (pendingSep) {
      out += CODE_SEPARATOR;
      pendingSep = false;
    }
    out += mapped;
  }
  return out;
}

/** Format an invite code from a room number and its word part. */
export function formatCode(room: number, words: string): string {
  return `${room}${CODE_SEPARATOR}${words}`;
}

/** The room number and word part parsed from a code. */
export interface ParsedCode {
  readonly room: number;
  readonly words: string;
}

/**
 * Parse a raw code into its room number and word part. The first segment must be the
 * digits of the room; the remainder is the (already normalized) word part. Throws on a
 * missing room, a non-numeric room, or an empty word part.
 */
export function parseCode(raw: string): ParsedCode {
  const normalized = normalizeCode(raw);
  const sep = normalized.indexOf(CODE_SEPARATOR);
  if (sep <= 0) throw new Error('code must be "<room>-<words>"');
  const roomPart = normalized.slice(0, sep);
  const words = normalized.slice(sep + 1);
  if (!/^[0-9]+$/.test(roomPart)) throw new Error('room must be a number');
  if (words.length === 0) throw new Error('code is missing its words');
  return { room: Number.parseInt(roomPart, 10), words };
}

/**
 * Generate a random word part with `count` words (default 2). Each word is chosen by one
 * uniformly random byte — the list is exactly 256 entries, so the mapping is unbiased.
 */
export function generateWords(count: number = DEFAULT_WORD_COUNT): string {
  if (!Number.isInteger(count) || count < 1) throw new RangeError('word count must be >= 1');
  const bytes = crypto.getRandomValues(new Uint8Array(count));
  const picked: string[] = [];
  for (const b of bytes) picked.push(WORDLIST[b % WORDLIST_SIZE]!);
  return picked.join(CODE_SEPARATOR);
}

/** Generate a full invite code for a server-allocated room. */
export function generateCode(room: number, count: number = DEFAULT_WORD_COUNT): string {
  return formatCode(room, generateWords(count));
}
