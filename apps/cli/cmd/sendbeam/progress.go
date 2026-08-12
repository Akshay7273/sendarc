package main

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	clitransfer "github.com/sendbeam/cli/internal/transfer"
	"github.com/sendbeam/wire"
)

type progressSample struct {
	at    time.Time
	bytes int64
}

type progressFile struct {
	name string
	size int64
}

// progress renders acknowledged bytes, a five-second rolling rate, and ETA on stderr,
// with a live percentage bar when the total is known.
type progress struct {
	mu        sync.Mutex
	total     int64
	bytes     int64
	lastPct   int
	reported  bool
	paused    bool
	samples   []progressSample
	now       func() time.Time
	files     []progressFile
	fileIdx   int
	fileBytes int64
	st        *style
}

func newProgress(total int64) *progress {
	return newProgressWithClock(total, time.Now)
}

func newProgressWithClock(total int64, now func() time.Time) *progress {
	return &progress{total: total, lastPct: -1, fileIdx: -1, now: now, st: newStyle(os.Stderr)}
}

func (p *progress) setTotal(total int64) {
	p.mu.Lock()
	p.total = total
	p.mu.Unlock()
}

func (p *progress) setFiles(files []progressFile) {
	p.mu.Lock()
	p.files = append([]progressFile(nil), files...)
	p.mu.Unlock()
}

func (p *progress) reportFile(fileIdx int, fileBytes, acknowledgedBytes int64) {
	p.mu.Lock()
	p.fileIdx = fileIdx
	p.fileBytes = fileBytes
	p.reportLocked(acknowledgedBytes)
	p.mu.Unlock()
}

func (p *progress) setState(state wire.TransferState) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paused = state == wire.TransferPaused
	if state == wire.TransferRunning {
		p.samples = nil
	}
	if state == wire.TransferPaused {
		p.reported = true
		fmt.Fprintln(os.Stderr, "\n  "+p.st.yellow("Paused — buffered network data may still drain."))
	}
}

func (p *progress) report(n int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reportLocked(n)
}

func (p *progress) reportLocked(n int64) {
	if n < p.bytes {
		return
	}
	p.bytes = n
	p.reported = true
	p.recordSample()
	if p.total <= 0 {
		fmt.Fprintf(os.Stderr, "\r  %s", humanBytes(n))
		return
	}
	pct := int(n * 100 / p.total)
	if pct == p.lastPct {
		return
	}
	p.lastPct = pct
	rate, eta := p.rateAndETA()
	detail := "calculating speed"
	if rate > 0 {
		detail = fmt.Sprintf("%s · %s", formatRate(rate), formatETA(eta))
	}
	if p.fileIdx >= 0 && p.fileIdx < len(p.files) {
		file := p.files[p.fileIdx]
		detail = fmt.Sprintf("%s · %s / %s", p.st.dim(file.name), humanBytes(p.fileBytes), humanBytes(file.size)) + " · " + detail
	}
	fmt.Fprintf(os.Stderr, "\r  %s %s  %s", bar(pct, 18), p.st.cyan(fmt.Sprintf("%d%%", pct)), detail)
}

func (p *progress) recordSample() {
	if p.paused {
		return
	}
	now := p.now()
	p.samples = append(p.samples, progressSample{at: now, bytes: p.bytes})
	cutoff := now.Add(-5 * time.Second)
	for len(p.samples) > 2 && !p.samples[1].at.After(cutoff) {
		p.samples = p.samples[1:]
	}
}

func (p *progress) rateAndETA() (float64, time.Duration) {
	if len(p.samples) < 2 {
		return 0, 0
	}
	first := p.samples[0]
	last := p.samples[len(p.samples)-1]
	elapsed := last.at.Sub(first.at).Seconds()
	if elapsed <= 0 || last.bytes <= first.bytes {
		return 0, 0
	}
	rate := float64(last.bytes-first.bytes) / elapsed
	remaining := p.total - p.bytes
	if remaining < 0 {
		remaining = 0
	}
	return rate, time.Duration(float64(time.Second) * float64(remaining) / rate)
}

func (p *progress) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reported {
		fmt.Fprintln(os.Stderr)
	}
}

// bar renders a filled progress bar of the given cell width using block glyphs.
func bar(pct, width int) string {
	filled := pct * width / 100
	if pct > 0 && filled == 0 {
		filled = 1
	}
	return "[" + strings.Repeat("\u25b0", filled) + strings.Repeat("\u25b1", width-filled) + "]"
}

func formatRate(bytesPerSecond float64) string {
	switch {
	case bytesPerSecond >= 1<<20:
		return fmt.Sprintf("%.1f MiB/s", bytesPerSecond/(1<<20))
	case bytesPerSecond >= 1<<10:
		return fmt.Sprintf("%.1f KiB/s", bytesPerSecond/(1<<10))
	default:
		return fmt.Sprintf("%.0f B/s", bytesPerSecond)
	}
}

func formatETA(eta time.Duration) string {
	seconds := int64(math.Ceil(eta.Seconds()))
	if seconds < 60 {
		return fmt.Sprintf("%ds remaining", seconds)
	}
	return fmt.Sprintf("%dm %ds remaining", seconds/60, seconds%60)
}

// terminalControls enables line-oriented controls only for an interactive stdin. Piped CLI use
// stays quiet and non-blocking.
func terminalControls() func(clitransfer.Controls) {
	s := newStyle(os.Stderr)
	return func(controls clitransfer.Controls) {
		info, err := os.Stdin.Stat()
		if err != nil || info.Mode()&os.ModeCharDevice == 0 {
			return
		}
		fmt.Fprintln(os.Stderr, s.dim("Controls: p + Enter pause · r + Enter resume · c + Enter cancel"))
		go func() {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				switch strings.ToLower(strings.TrimSpace(scanner.Text())) {
				case "p", "pause":
					if err := controls.Pause(); err != nil {
						fmt.Fprintf(os.Stderr, "\nPause failed: %v\n", err)
					}
				case "r", "resume":
					if err := controls.Resume(); err != nil {
						fmt.Fprintf(os.Stderr, "\nResume failed: %v\n", err)
					}
				case "c", "cancel":
					_ = controls.Cancel("canceled from terminal")
					return
				}
			}
		}()
	}
}
