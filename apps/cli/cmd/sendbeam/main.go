// Command sendbeam is the terminal client for SendBeam. It authenticates through the blind
// rendezvous server, then negotiates an end-to-end-encrypted direct or relayed
// file transfer:
//
//	sendbeam send <file>     # allocate a room, print the invite code + link, send the file
//	sendbeam receive <code>  # join with a code (or a pasted invite link), receive the file
//
// Both ends run SPAKE2 over the invite code, confirm the key (failing closed on a
// mismatch), exchange sealed capabilities, then prefer an authenticated WebRTC channel
// with an encrypted WebSocket relay fallback. The word half of the code never reaches
// the server, and the server never sees plaintext file bytes.
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

	"github.com/sendbeam/cli/internal/rendezvous"
	"github.com/sendbeam/cli/internal/transfer"
	"github.com/sendbeam/cli/internal/wsclient"
	"github.com/sendbeam/wire"

	"github.com/pion/webrtc/v4"
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
		fmt.Fprintf(os.Stderr, "sendbeam: unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	s := newStyle(w)
	_, _ = fmt.Fprintln(w, s.bold("SendBeam — secure peer-to-peer file transfer"))
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam send")+" <file-or-folder>... [flags]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam receive")+" <code|link> [flags]")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, s.dim("Common flags:"))
	_, _ = fmt.Fprintln(w, "  --server URL             signaling server (default "+defaultServer+")")
	_, _ = fmt.Fprintln(w, "  --insecure-skip-verify   skip TLS verification; self-signed dev certs only")
	_, _ = fmt.Fprintln(w, "  --ice-server URL         STUN server for direct-path candidates")
	_, _ = fmt.Fprintln(w, "                           (repeatable; default stun:stun.l.google.com:19302)")
	_, _ = fmt.Fprintln(w, "  --relay-only             force the encrypted WebSocket relay instead of WebRTC")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, s.dim("Send flags:"))
	_, _ = fmt.Fprintln(w, "  --words N                number of words in the invite code (0 = default)")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, s.dim("Receive flags:"))
	_, _ = fmt.Fprintln(w, "  --out DIR                directory to write the received file into (default .)")
}

func runSend(args []string) int {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	server := fs.String("server", defaultServer, "signaling server URL")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS verification (self-signed dev certs only)")
	words := fs.Int("words", 0, "number of words in the invite code (0 = default)")
	relayOnly := fs.Bool("relay-only", false, "force the encrypted WebSocket relay")
	iceServer := fs.String("ice-server", "", "STUN server URL for direct-path candidates (repeatable; default stun:stun.l.google.com:19302)")
	positionals := parseArgs(fs, args)

	if len(positionals) == 0 {
		fmt.Fprintln(os.Stderr, "sendbeam send: a file to send is required")
		return 2
	}
	sources, totalSize, err := transfer.NewOSFileSources(positionals)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sendbeam send: %s\n", err)
		return 1
	}
	progressFiles := make([]progressFile, len(sources))
	for i, source := range sources {
		meta := source.Meta()
		progressFiles[i] = progressFile{name: meta.Name, size: meta.Size}
	}
	label := progressFiles[0].name
	if len(progressFiles) > 1 {
		label = fmt.Sprintf("%d files", len(progressFiles))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := dial(ctx, *server, *insecure)
	if err != nil {
		s := newStyle(os.Stderr)
		fmt.Fprintf(os.Stderr, "\n%s\n", s.cross("Failed: "+handshakeError(err)))
		return 1
	}
	defer client.Close()

	progress := newProgress(totalSize)
	progress.setFiles(progressFiles)
	out, err := transfer.Run(ctx, client, transfer.Spec{
		Session: rendezvous.Options{
			Role:      rendezvous.RoleOfferer,
			WordCount: *words,
			OnCode:    codePrinter(*server),
			OnPhase:   phasePrinter(rendezvous.RoleOfferer),
		},
		Sources:        sources,
		ForceRelay:     *relayOnly,
		ICEServers:     iceServers(*iceServer),
		OnTransport:    transportPrinter,
		OnConnect:      connectPrinter(fmt.Sprintf("Sending %s (%s) …", label, humanBytes(totalSize))),
		OnFileProgress: progress.reportFile,
		OnControls:     terminalControls(),
		OnStateChange:  progress.setState,
	})
	progress.finish()
	s := newStyle(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n%s\n", s.cross("Failed: "+handshakeError(err)))
		return 1
	}
	fmt.Println()
	if len(out.Files) == 1 {
		fmt.Println(s.green("✓") + " Sent " + s.bold(out.Name) + " (" + humanBytes(out.Size) + ").")
	} else {
		fmt.Println(s.green("✓") + " Sent " + s.bold(fmt.Sprintf("%d files", len(out.Files))) + " (" + humanBytes(out.Size) + ").")
	}
	fmt.Printf("  %s  %s\n", s.grey("Fingerprint:"), fingerprint(out.Handshake.Master))
	if len(out.Files) == 1 {
		fmt.Printf("  %s  %s\n", s.grey("SHA-256:"), out.Digest)
	} else {
		fmt.Printf("  %s  %s\n", s.grey("File-set SHA-256:"), out.Digest)
	}
	return 0
}

func runReceive(args []string) int {
	fs := flag.NewFlagSet("receive", flag.ExitOnError)
	server := fs.String("server", defaultServer, "signaling server URL")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS verification (self-signed dev certs only)")
	outDir := fs.String("out", ".", "directory to write the received file into")
	relayOnly := fs.Bool("relay-only", false, "force the encrypted WebSocket relay")
	iceServer := fs.String("ice-server", "", "STUN server URL for direct-path candidates (repeatable; default stun:stun.l.google.com:19302)")
	positionals := parseArgs(fs, args)

	code := ""
	if len(positionals) > 0 {
		code = normalizeCodeArg(positionals[0])
	}
	if code == "" {
		fmt.Fprintln(os.Stderr, "sendbeam receive: an invite code (or link) is required")
		return 2
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "sendbeam receive: %s\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := dial(ctx, *server, *insecure)
	if err != nil {
		s := newStyle(os.Stderr)
		fmt.Fprintf(os.Stderr, "\n%s\n", s.cross("Failed: "+handshakeError(err)))
		return 1
	}
	defer client.Close()

	s := newStyle(os.Stderr)
	fmt.Fprintln(os.Stderr, s.dim("Joining "+code+" …"))
	progress := newProgress(0)
	out, err := transfer.Run(ctx, client, transfer.Spec{
		Session: rendezvous.Options{
			Role:    rendezvous.RoleJoiner,
			Code:    code,
			OnPhase: phasePrinter(rendezvous.RoleJoiner),
		},
		DestDir:     *outDir,
		ForceRelay:  *relayOnly,
		ICEServers:  iceServers(*iceServer),
		OnTransport: transportPrinter,
		OnManifestSet: func(manifest wire.Manifest) {
			progress.setTotal(manifest.TotalSize)
			files := make([]progressFile, len(manifest.Files))
			for i, file := range manifest.Files {
				files[i] = progressFile{name: file.Name, size: file.Size}
			}
			progress.setFiles(files)
			label := files[0].name
			if len(files) > 1 {
				label = fmt.Sprintf("%d files", len(files))
			}
			connectPrinter(fmt.Sprintf("Receiving %s (%s) …", label, humanBytes(manifest.TotalSize)))()
		},
		OnFileProgress: progress.reportFile,
		OnControls:     terminalControls(),
		OnStateChange:  progress.setState,
	})
	progress.finish()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n%s\n", s.cross("Failed: "+handshakeError(err)))
		return 1
	}
	fmt.Println()
	if len(out.Files) == 1 {
		fmt.Println(s.check("Received " + s.bold(out.Name) + " (" + humanBytes(out.Size) + ") → " + out.Path + "."))
	} else {
		fmt.Println(s.check("Received " + s.bold(fmt.Sprintf("%d files", len(out.Files))) + " (" + humanBytes(out.Size) + ") → " + *outDir + "."))
	}
	fmt.Printf("  %s  %s\n", s.grey("Fingerprint:"), fingerprint(out.Handshake.Master))
	if len(out.Files) == 1 {
		fmt.Printf("  %s  %s\n", s.grey("SHA-256:"), out.Digest)
	} else {
		fmt.Printf("  %s  %s\n", s.grey("File-set SHA-256:"), out.Digest)
	}
	return 0
}

// iceServers parses a --ice-server URL list into pion ICE server config. The flag is
// repeatable; an empty value leaves the package default (Google STUN) in place.
func iceServers(flagValue string) []webrtc.ICEServer {
	if flagValue == "" {
		return nil
	}
	return []webrtc.ICEServer{{URLs: []string{flagValue}}}
}

// dial opens the signaling socket, reporting the server it is contacting. The transfer
// driver adopts the returned client for the whole exchange and closes it when done.
func dial(ctx context.Context, server string, insecure bool) (*wsclient.Client, error) {
	s := newStyle(os.Stderr)
	fmt.Fprintln(os.Stderr, s.dim("Connecting to "+server+" …"))
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
	s := newStyle(os.Stderr)
	return func(code string) {
		fmt.Fprintln(os.Stderr)
		if link := inviteLink(server, code); link != "" {
			fmt.Fprintln(os.Stderr, frame("SendBeam invite", s.cyan(code), s.dim("link: "+link)))
		} else {
			fmt.Fprintln(os.Stderr, frame("SendBeam invite", s.cyan(code)))
		}
		fmt.Fprintln(os.Stderr)
	}
}

// phasePrinter surfaces the two transitions worth a human's attention — waiting for the
// peer (offerer only) and the start of the key handshake — and stays quiet for the rest so
// the output reads as progress, not a state-machine trace.
func phasePrinter(role rendezvous.Role) func(rendezvous.Phase) {
	s := newStyle(os.Stderr)
	return func(p rendezvous.Phase) {
		switch p {
		case rendezvous.PhaseWaiting:
			if role == rendezvous.RoleOfferer {
				fmt.Fprintln(os.Stderr, s.dim("Waiting for the receiver to join …"))
			}
		case rendezvous.PhaseHandshaking:
			fmt.Fprintln(os.Stderr, s.cyan("Establishing a secure channel …"))
		}
	}
}

// connectPrinter returns a one-shot callback that prints line once the direct channel is
// open, just before the bytes begin to move.
func connectPrinter(line string) func() {
	s := newStyle(os.Stderr)
	return func() { fmt.Fprintln(os.Stderr, s.bold(line)) }
}

func transportPrinter(path string) {
	s := newStyle(os.Stderr)
	if path == "relay" {
		fmt.Fprintln(os.Stderr, s.dim("Transport: encrypted WebSocket relay"))
	} else {
		fmt.Fprintln(os.Stderr, s.dim("Transport: direct WebRTC"))
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
		return "[" + string(wire.CodeOf(err)) + "] " + re.Msg
	}
	return "[" + string(wire.CodeOf(err)) + "] " + err.Error()
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
	sum := sha256.Sum256(append([]byte("sendbeam/sas\x00"), master...))
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
