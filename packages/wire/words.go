package wire

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
)

// Invite-code words. The sender generates a short word code (e.g. "brave-otter") from
// this 256-word list — one byte of entropy per word — which the server never sees. The
// full normalized string "<room>-<words>" is the SPAKE2 password. This list and the
// normalization rules are the wire contract; they must match packages/protocol/src/
// words.ts byte-for-byte or the handshake fails closed.

const (
	defaultWordCount = 2
	wordlistSize     = 256
	codeSeparator    = "-"
)

// wordlist matches WORDLIST in packages/protocol/src/words.ts byte-for-byte. Order is
// significant — the index is the byte value.
var wordlist = [wordlistSize]string{
	"ant", "ape", "bat", "bear", "bee", "bird", "bison", "boar",
	"bug", "calf", "camel", "carp", "cat", "chick", "clam", "cobra",
	"colt", "coral", "cow", "crab", "crane", "crow", "cub", "deer",
	"dingo", "dodo", "dog", "dove", "duck", "eagle", "eel", "elk",
	"emu", "ewe", "falcon", "fawn", "ferret", "finch", "fish", "flea",
	"fly", "foal", "fox", "frog", "gecko", "goat", "goose", "gull",
	"hare", "hawk", "hen", "heron", "hog", "horse", "hound", "ibex",
	"jay", "koala", "lamb", "lark", "lion", "lizard", "llama", "lynx",
	"mole", "moose", "moth", "mouse", "mule", "newt", "otter", "owl",
	"ox", "panda", "pig", "pika", "pony", "pug", "puma", "quail",
	"rabbit", "ram", "rat", "raven", "ray", "robin", "seal", "shark",
	"sheep", "shrew", "shrimp", "skunk", "sloth", "slug", "snail", "snake",
	"sole", "sparrow", "spider", "squid", "stag", "stork", "swan", "tapir",
	"teal", "tiger", "toad", "trout", "tuna", "turkey", "viper", "vole",
	"walrus", "wasp", "weasel", "whale", "wolf", "wombat", "worm", "wren",
	"yak", "zebra", "beetle", "bream", "cod", "dolphin", "gnu", "hyena",
	"acorn", "amber", "ash", "aspen", "bark", "bay", "beach", "birch",
	"bloom", "branch", "breeze", "brook", "bush", "cave", "cedar", "cliff",
	"cloud", "clover", "coast", "comet", "cove", "creek", "dawn", "delta",
	"dew", "dune", "dusk", "earth", "ember", "fern", "field", "fjord",
	"flame", "fog", "forest", "frost", "glade", "glen", "grove", "gust",
	"hail", "hill", "ice", "island", "ivy", "lake", "leaf", "lily",
	"maple", "marsh", "meadow", "mist", "moon", "moss", "mount", "oak",
	"ocean", "palm", "peak", "pebble", "pine", "plain", "pond", "rain",
	"reef", "ridge", "river", "rock", "root", "rose", "sand", "sea",
	"seed", "shade", "shell", "shore", "sky", "sleet", "snow", "spring",
	"star", "stone", "storm", "stream", "summit", "sun", "surf", "swamp",
	"thaw", "tide", "trail", "tree", "tulip", "valley", "vine", "wave",
	"well", "wind", "wood", "anchor", "arrow", "badge", "beacon", "bell",
	"boat", "bolt", "book", "boot", "bottle", "bowl", "brick", "bridge",
	"broom", "brush", "bucket", "candle", "cape", "cart", "chain", "chair",
	"clock", "coal", "coin", "comb", "cord", "crown", "cup", "dial",
}

// NormalizeCode canonicalizes a raw code into the exact string used as the SPAKE2
// password. It lowercases ASCII letters, treats every run of other characters as one
// separator, and trims separators from the ends. It is mirrored in TypeScript — the two
// must agree byte-for-byte or the handshake fails closed.
func NormalizeCode(raw string) string {
	var b strings.Builder
	pendingSep := false
	for _, ch := range raw {
		var mapped rune
		switch {
		case ch >= 'A' && ch <= 'Z':
			mapped = ch + ('a' - 'A')
		case (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9'):
			mapped = ch
		default:
			pendingSep = b.Len() > 0
			continue
		}
		if pendingSep {
			b.WriteString(codeSeparator)
			pendingSep = false
		}
		b.WriteRune(mapped)
	}
	return b.String()
}

// FormatCode formats an invite code from a room number and its word part.
func FormatCode(room int, words string) string {
	return strconv.Itoa(room) + codeSeparator + words
}

// ParsedCode is the room number and word part parsed from a code.
type ParsedCode struct {
	Room  int
	Words string
}

// ParseCode parses a raw code into its room number and word part. The first segment must
// be the digits of the room; the remainder is the (already normalized) word part.
func ParseCode(raw string) (ParsedCode, error) {
	normalized := NormalizeCode(raw)
	sep := strings.Index(normalized, codeSeparator)
	if sep <= 0 {
		return ParsedCode{}, fmt.Errorf(`code must be "<room>-<words>"`)
	}
	roomPart := normalized[:sep]
	words := normalized[sep+1:]
	room, err := strconv.Atoi(roomPart)
	if err != nil {
		return ParsedCode{}, fmt.Errorf("room must be a number")
	}
	if words == "" {
		return ParsedCode{}, fmt.Errorf("code is missing its words")
	}
	return ParsedCode{Room: room, Words: words}, nil
}

// GenerateWords generates a random word part with count words. Each word is chosen by one
// uniformly random byte — the list is exactly 256 entries, so the mapping is unbiased.
func GenerateWords(count int) (string, error) {
	if count < 1 {
		return "", fmt.Errorf("word count must be >= 1")
	}
	buf := make([]byte, count)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	picked := make([]string, count)
	for i, b := range buf {
		picked[i] = wordlist[int(b)%wordlistSize]
	}
	return strings.Join(picked, codeSeparator), nil
}

// GenerateCode generates a full invite code for a server-allocated room, using the
// default word count.
func GenerateCode(room int) (string, error) {
	words, err := GenerateWords(defaultWordCount)
	if err != nil {
		return "", err
	}
	return FormatCode(room, words), nil
}
