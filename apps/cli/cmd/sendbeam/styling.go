package main

import (
	"os"
	"strings"
	"unicode/utf8"
)

// ANSI SGR codes. Colors are applied only when the destination is a terminal and
// NO_COLOR is unset, so piped output and CI logs stay plain.
const (
	sgrReset  = "\x1b[0m"
	sgrBold   = "\x1b[1m"
	sgrDim    = "\x1b[2m"
	sgrRed    = "\x1b[31m"
	sgrGreen  = "\x1b[32m"
	sgrYellow = "\x1b[33m"
	sgrCyan   = "\x1b[36m"
	sgrGrey   = "\x1b[90m"
)

// style bundles a terminal handle with its color decision so callers render the
// same text differently on a TTY (styled) and in a pipe (plain).
type style struct {
	on bool
}

func newStyle(w *os.File) *style {
	return &style{on: isTerminal(w) && os.Getenv("NO_COLOR") == ""}
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func (s *style) paint(code, text string) string {
	if !s.on {
		return text
	}
	return code + text + sgrReset
}

func (s *style) bold(text string) string   { return s.paint(sgrBold, text) }
func (s *style) dim(text string) string    { return s.paint(sgrDim, text) }
func (s *style) cyan(text string) string   { return s.paint(sgrCyan, text) }
func (s *style) green(text string) string  { return s.paint(sgrGreen, text) }
func (s *style) yellow(text string) string { return s.paint(sgrYellow, text) }
func (s *style) grey(text string) string   { return s.paint(sgrGrey, text) }

// check and cross render the ✔/✘ glyphs with color; plain output keeps the glyph
// so piped logs read the same as the original plain output.
func (s *style) check(text string) string {
	glyph := s.paint(sgrGreen, "\u2714")
	if !s.on {
		glyph = "\u2714"
	}
	return glyph + " " + text
}

func (s *style) cross(text string) string {
	glyph := s.paint(sgrRed, "\u2718")
	if !s.on {
		glyph = "\u2718"
	}
	return glyph + " " + text
}

// visibleLen returns the rune count of s with ANSI escapes stripped, for aligning
// framed output regardless of styling.
func visibleLen(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			j := i + 1
			if j < len(s) && s[j] == '[' {
				j++
			}
			for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
				j++
			}
			i = j + 1
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		n++
		i += size
	}
	return n
}

// frame draws a single-line box around content, with an optional title in the
// top border:
//
//	┌─ SendBeam ─────────────┐
//	│  one                    │
//	│  two                    │
//	└─────────────────────────┘
//
// ANSI styling inside the content is preserved; width accounts for it.
func frame(title string, content ...string) string {
	width := 0
	for _, line := range content {
		if w := visibleLen(line); w > width {
			width = w
		}
	}
	// The top border needs room for the title plus a space on each side; widen the
	// box so the border always fits and every line aligns.
	if tw := visibleLen(title) + 2; tw > width {
		width = tw
	}
	var b strings.Builder
	b.WriteString("\u250c\u2500 " + title + " " + strings.Repeat("\u2500", width-visibleLen(title)-2) + " \u2510\n")
	for _, line := range content {
		pad := strings.Repeat(" ", width-visibleLen(line))
		b.WriteString("\u2502 " + line + pad + " \u2502\n")
	}
	b.WriteString("\u2514" + strings.Repeat("\u2500", width+2) + "\u2518")
	return b.String()
}
