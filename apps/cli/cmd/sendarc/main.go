// Command sendarc is the terminal client for SendArc. It authenticates through the blind
// rendezvous server, then uses the same socket to negotiate an end-to-end-encrypted direct
// file transfer:
//
//	sendarc send <file>     # allocate a room, print the invite code + link, send the file
//	sendarc receive <code>  # join with a code (or a pasted invite link), receive the file
//
// Both ends run SPAKE2 over the invite code, confirm the key (failing closed on a
// mismatch), exchange sealed capabilities, then bring up an authenticated WebRTC channel
// and stream the file sealed under the session key. The word half of the code never
// reaches the server, and the server never sees the file bytes.
package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sendarc/cli/internal/rendezvous"
	"github.com/sendarc/cli/internal/transfer"
	"github.com/sendarc/cli/internal/wsclient"
	"github.com/sendarc/wire"
)

const defaultServer = "wss://localhost:8443/ws"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "send":
		os.Exit(runSend(os.Args[2:]))
	case "receive", "recv":
		os.Exit(runReceive(os.Args[2:]))
	case "-h", "--help", "help":
		usage(os.Stdout)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "sendarc: unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	_, _ = fmt.Fprint(w, `sendarc — secure peer-to-peer file transfer

Usage:
  sendarc send <file> [flags]
  sendarc receive <code|link> [flags]

Flags:
  --server URL             signaling server (default `+defaultServer+`)
  --insecure-skip-verify   skip TLS verification; self-signed dev certs only
  --words N                number of words in the invite code (send only; 0 = default)
  --out DIR                directory to write the received file into (receive only; default .)
`)
}

func runSend(args []string) int {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	server := fs.String("server", defaultServer, "signaling server URL")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS verification (self-signed dev certs only)")
	words := fs.Int("words", 0, "number of words in the invite code (0 = default)")
	positionals := parseArgs(fs, args)

	if len(positionals) == 0 {
		fmt.Fprintln(os.Stderr, "sendarc send: a file to send is required")
		return 2
	}
	src, err := transfer.NewOSFileSource(positionals[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "sendarc send: %s\n", err)
		return 1
	}
	meta := src.Meta()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := dial(ctx, *server, *insecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed: %s\n", handshakeError(err))
		return 1
	}
	defer client.Close()

	progress := newProgress(meta.Size)
	out, err := transfer.Run(ctx, client, transfer.Spec{
		Session: rendezvous.Options{
			Role:      rendezvous.RoleOfferer,
			WordCount: *words,
			OnCode:    codePrinter(*server),
			OnPhase:   phasePrinter(rendezvous.RoleOfferer),
		},
		Source:     src,
		OnConnect:  connectPrinter(fmt.Sprintf("Sending %s (%s) …", meta.Name, humanBytes(meta.Size))),
		OnProgress: progress.report,
	})
	progress.finish()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed: %s\n", handshakeError(err))
		return 1
	}
	fmt.Printf("\n✓ Sent %s (%s).\n", out.Name, humanBytes(out.Size))
	fmt.Printf("  Fingerprint:  %s\n", fingerprint(out.Handshake.Master))
	fmt.Printf("  SHA-256:      %s\n", out.Digest)
	return 0
}

func runReceive(args []string) int {
	fs := flag.NewFlagSet("receive", flag.ExitOnError)
	server := fs.String("server", defaultServer, "signaling server URL")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS verification (self-signed dev certs only)")
	outDir := fs.String("out", ".", "directory to write the received file into")
	positionals := parseArgs(fs, args)

	code := ""
	if len(positionals) > 0 {
		code = normalizeCodeArg(positionals[0])
	}
	if code == "" {
		fmt.Fprintln(os.Stderr, "sendarc receive: an invite code (or link) is required")
		return 2
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "sendarc receive: %s\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := dial(ctx, *server, *insecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed: %s\n", handshakeError(err))
		return 1
	}
	defer client.Close()

	fmt.Fprintf(os.Stderr, "Joining %s …\n", code)
	progress := newProgress(0)
	out, err := transfer.Run(ctx, client, transfer.Spec{
		Session: rendezvous.Options{
			Role:    rendezvous.RoleJoiner,
			Code:    code,
			OnPhase: phasePrinter(rendezvous.RoleJoiner),
		},
		DestDir: *outDir,
		OnManifest: func(file wire.FileEntry) {
			progress.setTotal(file.Size)
			connectPrinter(fmt.Sprintf("Receiving %s (%s) …", file.Name, humanBytes(file.Size)))()
		},
		OnProgress: progress.report,
	})
	progress.finish()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed: %s\n", handshakeError(err))
		return 1
	}
	fmt.Printf("\n✓ Received %s (%s) → %s\n", out.Name, humanBytes(out.Size), out.Path)
	fmt.Printf("  Fingerprint:  %s\n", fingerprint(out.Handshake.Master))
	fmt.Printf("  SHA-256:      %s\n", out.Digest)
	return 0
}

// dial opens the signaling socket, reporting the server it is contacting. The transfer
// driver adopts the returned client for the whole exchange and closes it when done.
func dial(ctx context.Context, server string, insecure bool) (*wsclient.Client, error) {
	fmt.Fprintf(os.Stderr, "Connecting to %s …\n", server)
	return wsclient.Dial(ctx, server, wsclient.DialOptions{InsecureSkipVerify: insecure})
}

// parseArgs parses flags that may appear before or after positional arguments. Go's flag
// package stops at the first non-flag token, so `receive <code> --server X` would otherwise
// silently ignore --server; this re-parses past each positional and returns the collected
// positionals in order.
func parseArgs(fs *flag.FlagSet, args []string) []string {
	var positionals []string
	for {
		_ = fs.Parse(args)
		if fs.NArg() == 0 {
			break
		}
		positionals = append(positionals, fs.Arg(0))
		args = fs.Args()[1:]
	}
	return positionals
}

// codePrinter shows the invite code and the matching web-app link once the room is
// allocated, so the sender can hand either to the recipient.
func codePrinter(server string) func(string) {
	return func(code string) {
		fmt.Println()
		fmt.Printf("  Invite code:  %s\n", code)
		if link := inviteLink(server, code); link != "" {
			fmt.Printf("  Invite link:  %s\n", link)
		}
		fmt.Println()
	}
}

// phasePrinter surfaces the two transitions worth a human's attention — waiting for the
// peer (offerer only) and the start of the key handshake — and stays quiet for the rest so
// the output reads as progress, not a state-machine trace.
func phasePrinter(role rendezvous.Role) func(rendezvous.Phase) {
	return func(p rendezvous.Phase) {
		switch p {
		case rendezvous.PhaseWaiting:
			if role == rendezvous.RoleOfferer {
				fmt.Fprintln(os.Stderr, "Waiting for the receiver to join …")
			}
		case rendezvous.PhaseHandshaking:
			fmt.Fprintln(os.Stderr, "Establishing a secure channel …")
		}
	}
}

// connectPrinter returns a one-shot callback that prints line once the direct channel is
// open, just before the bytes begin to move.
func connectPrinter(line string) func() {
	return func() { fmt.Fprintln(os.Stderr, line) }
}

// progress renders a single, rewriting transfer-progress line on stderr. The total may be
// unknown at first (the receiver learns it from the manifest), in which case only the byte
// count is shown until setTotal is called.
type progress struct {
	total    int64
	lastPct  int
	reported bool
}

func newProgress(total int64) *progress { return &progress{total: total, lastPct: -1} }

func (p *progress) setTotal(total int64) { p.total = total }

// report prints cumulative bytes. It is invoked from the engine goroutine while the main
// goroutine blocks in transfer.Run, so it needs no locking; it throttles to whole-percent
// changes to keep the terminal quiet.
func (p *progress) report(n int64) {
	p.reported = true
	if p.total <= 0 {
		fmt.Fprintf(os.Stderr, "\r  %s", humanBytes(n))
		return
	}
	pct := int(n * 100 / p.total)
	if pct == p.lastPct {
		return
	}
	p.lastPct = pct
	fmt.Fprintf(os.Stderr, "\r  %s / %s (%d%%)", humanBytes(n), humanBytes(p.total), pct)
}

// finish terminates the progress line with a newline if anything was printed on it.
func (p *progress) finish() {
	if p.reported {
		fmt.Fprintln(os.Stderr)
	}
}

// handshakeError renders a transfer failure as a human-readable line, translating the
// stable rendezvous codes into plain guidance where it helps and falling back to the raw
// message for transport and transfer errors.
func handshakeError(err error) string {
	var re *rendezvous.Error
	if errorsAs(err, &re) {
		switch re.Code {
		case rendezvous.CodeConfirmationFailed:
			return "the invite codes did not match — double-check the code and try again"
		case rendezvous.CodePeerLeft:
			return "the other side disconnected"
		case rendezvous.CodeAborted:
			return "cancelled"
		}
		return re.Msg
	}
	return err.Error()
}

func errorsAs(err error, target **rendezvous.Error) bool {
	re, ok := err.(*rendezvous.Error)
	if ok {
		*target = re
	}
	return ok
}

// fingerprint is a short authentication string derived from the master key: a hash (so no
// raw key bytes are exposed) truncated to 32 bits and shown as two hex groups. Both peers
// derive the same value, giving the humans an out-of-band check on top of SPAKE2.
func fingerprint(master []byte) string {
	sum := sha256.Sum256(append([]byte("sendarc/sas\x00"), master...))
	return fmt.Sprintf("%02x%02x %02x%02x", sum[0], sum[1], sum[2], sum[3])
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%d KiB", n>>10)
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// inviteLink turns the signaling URL into the web app's join link for the same deployment:
// wss/ws → https/http, drop the /ws path, and carry the code in the fragment so it never
// hits the server. Returns "" if the server URL cannot be parsed.
func inviteLink(serverURL, code string) string {
	u, err := url.Parse(serverURL)
	if err != nil || u.Host == "" {
		return ""
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	}
	u.Path = "/"
	u.RawQuery = ""
	u.Fragment = code
	return u.String()
}

// normalizeCodeArg accepts either a bare code or a full invite link and returns the code.
func normalizeCodeArg(arg string) string {
	arg = strings.TrimSpace(arg)
	if i := strings.LastIndex(arg, "#"); i >= 0 {
		return arg[i+1:]
	}
	return arg
}
