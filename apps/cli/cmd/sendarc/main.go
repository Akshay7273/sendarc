// Command sendarc is the terminal client for a SendArc transfer. It drives one M1
// rendezvous over the blind signaling server:
//
//	sendarc send            # allocate a room, print the invite code + link, wait
//	sendarc receive <code>  # join with a code (or a pasted invite link)
//
// Both ends run SPAKE2 over the invite code, confirm the key (failing closed on a
// mismatch), and exchange sealed capabilities — the point where the M2 encrypted file
// transfer will begin. The word half of the code never reaches the server.
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
	"github.com/sendarc/cli/internal/wsclient"
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
  sendarc send [flags]
  sendarc receive <code|link> [flags]

Flags:
  --server URL             signaling server (default `+defaultServer+`)
  --insecure-skip-verify   skip TLS verification; self-signed dev certs only
  --words N                number of words in the invite code (send only; 0 = default)
`)
}

func runSend(args []string) int {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	server := fs.String("server", defaultServer, "signaling server URL")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS verification (self-signed dev certs only)")
	words := fs.Int("words", 0, "number of words in the invite code (0 = default)")
	parseArgs(fs, args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "Connecting to %s …\n", *server)
	res, err := wsclient.Rendezvous(ctx, *server, wsclient.DialOptions{InsecureSkipVerify: *insecure},
		rendezvous.Options{
			Role:      rendezvous.RoleOfferer,
			WordCount: *words,
			OnCode: func(code string) {
				fmt.Println()
				fmt.Printf("  Invite code:  %s\n", code)
				if link := inviteLink(*server, code); link != "" {
					fmt.Printf("  Invite link:  %s\n", link)
				}
				fmt.Println()
			},
			OnPhase: phasePrinter(rendezvous.RoleOfferer),
		})
	return report("receiver", res, err)
}

func runReceive(args []string) int {
	fs := flag.NewFlagSet("receive", flag.ExitOnError)
	server := fs.String("server", defaultServer, "signaling server URL")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS verification (self-signed dev certs only)")
	positionals := parseArgs(fs, args)

	code := ""
	if len(positionals) > 0 {
		code = normalizeCodeArg(positionals[0])
	}
	if code == "" {
		fmt.Fprintln(os.Stderr, "sendarc receive: an invite code (or link) is required")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "Connecting to %s …\n", *server)
	fmt.Fprintf(os.Stderr, "Joining %s …\n", code)
	res, err := wsclient.Rendezvous(ctx, *server, wsclient.DialOptions{InsecureSkipVerify: *insecure},
		rendezvous.Options{
			Role:    rendezvous.RoleJoiner,
			Code:    code,
			OnPhase: phasePrinter(rendezvous.RoleJoiner),
		})
	return report("sender", res, err)
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

// report prints the outcome and returns the process exit code. peer names the other side
// for the success line ("receiver" for a sender, "sender" for a receiver).
func report(peer string, res *rendezvous.Result, err error) int {
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed: %s\n", handshakeError(err))
		return 1
	}
	fmt.Printf("\n✓ Secure channel established with the %s.\n", peer)
	fmt.Printf("  Fingerprint:  %s\n", fingerprint(res.Master))
	fmt.Printf("  Peer:         %s\n", describeCaps(res.RemoteCaps))
	fmt.Fprintln(os.Stderr, "\nBoth sides should see the same fingerprint. File transfer arrives in the next milestone.")
	return 0
}

// handshakeError renders a rendezvous failure as a human-readable line, translating the
// stable codes into plain guidance where it helps.
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

func describeCaps(c rendezvous.Caps) string {
	return fmt.Sprintf("%s (frame %s, block %s)", c.Version, humanBytes(c.MaxFrame), humanBytes(c.BlockSize))
}

func humanBytes(n int) string {
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
