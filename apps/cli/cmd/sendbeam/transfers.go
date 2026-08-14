package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sendbeam/cli/internal/rendezvous"
	clitransfer "github.com/sendbeam/cli/internal/transfer"
	"github.com/sendbeam/wire"
)

// transfersUsage prints the management-command help.
func transfersUsage(w *os.File) {
	s := newStyle(w)
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam transfers list")+" [--out DIR]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam transfers inspect")+" <id> [--out DIR]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam transfers resume")+" <id> --code <code> [--out DIR]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam transfers discard")+" <id>... [--out DIR] [--all] [--yes]")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, s.dim("Manage durable receive state kept under DIR/.sendbeam (default .):"))
	_, _ = fmt.Fprintln(w, "  list     show every journal, unreadable journal, and orphaned partial tree")
	_, _ = fmt.Fprintln(w, "  inspect  validate one journal against its partial data (never deletes)")
	_, _ = fmt.Fprintln(w, "  resume   resume an interrupted transfer: join the sender's fresh rendezvous")
	_, _ = fmt.Fprintln(w, "           with --code and authenticate the original sender (PR07 resume-auth)")
	_, _ = fmt.Fprintln(w, "           before any verified progress is reused (fresh keys every attempt)")
	_, _ = fmt.Fprintln(w, "  discard  explicitly delete a journal and its partials (idempotent)")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, s.dim("Session classes (used consistently in list statuses):"))
	_, _ = fmt.Fprintln(w, "  reconnect      same live transfer; transport direct<->relay / outage recovery")
	_, _ = fmt.Fprintln(w, "  durable resume  process/session died; both peers authenticate via resume-auth,")
	_, _ = fmt.Fprintln(w, "                 then continue from the verified checkpoint with fresh keys")
	_, _ = fmt.Fprintln(w, "  restart        no compatible credential; start from zero, old state kept")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, s.dim("Sender records (kept under the user config dir):"))
	_, _ = fmt.Fprintln(w, "  list     also shows interrupted sends and their source paths")
	_, _ = fmt.Fprintln(w, "  discard  also removes the matching sender record (idempotent)")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, s.dim("Resume/other flags:"))
	_, _ = fmt.Fprintln(w, "  --code   fresh invite code from the sender's re-run (resume)")
	_, _ = fmt.Fprintln(w, "  --all    discard every journal and orphaned partial tree in the store")
	_, _ = fmt.Fprintln(w, "  --yes    confirm --all without prompting")
}

// senderStore opens the sender-state store, reporting honest failures.
func senderStore() (*clitransfer.SenderStore, error) {
	dir, err := clitransfer.SenderStoreDir()
	if err != nil {
		return nil, err
	}
	return clitransfer.OpenSenderStore(dir)
}

// runTransfers dispatches the transfers subcommand group.
func runTransfers(args []string) int {
	if len(args) == 0 {
		transfersUsage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "list":
		return transfersList(args[1:])
	case "inspect":
		return transfersInspect(args[1:])
	case "resume":
		return transfersResume(args[1:])
	case "discard":
		return transfersDiscard(args[1:])
	case "-h", "--help", "help":
		transfersUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "sendbeam transfers: unknown command %q\n\n", args[0])
		transfersUsage(os.Stderr)
		return 2
	}
}

// transfersStore opens the store for --out (default "."), reporting honest failures.
func transfersStore(outDir string) (*clitransfer.DurableStore, error) {
	store, err := clitransfer.OpenStore(outDir)
	if err != nil {
		return nil, err
	}
	return store, nil
}

func transfersList(args []string) int {
	fs := flag.NewFlagSet("transfers list", flag.ExitOnError)
	outDir := fs.String("out", ".", "directory whose .sendbeam store to list")
	_ = fs.Parse(args)
	store, err := transfersStore(*outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sendbeam transfers list: %s\n", err)
		return 1
	}
	entries, err := store.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sendbeam transfers list: %s\n", err)
		return 1
	}
	s := newStyle(os.Stderr)
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, s.dim("No durable transfers in "+store.Root()+"."))
	} else {
		fmt.Fprintln(os.Stderr, s.dim("Durable receive state in "+store.Root()+":"))
		fmt.Fprintln(os.Stderr)
		for _, entry := range entries {
			if !entry.JournalOK {
				kind := "unreadable journal"
				if entry.Orphaned {
					kind = "orphaned partials"
				}
				fmt.Fprintf(os.Stderr, "  %s  %s\n", s.yellow(entry.TransferID), s.dim(kind+": "+entry.Err))
				fmt.Fprintf(os.Stderr, "      %s\n", s.dim("run: sendbeam transfers discard "+entry.TransferID+" --out "+*outDir))
				continue
			}
			label := entry.TransferID
			if entry.Files > 1 {
				label = fmt.Sprintf("%s (%d files)", label, entry.Files)
			}
			status := durableStatus(entry)
			fmt.Fprintf(os.Stderr, "  %s  %s committed / %s total · updated %s\n",
				s.cyan(label),
				humanBytes(entry.CommittedBytes), humanBytes(entry.TotalSize),
				formatTime(entry.UpdatedAt))
			fmt.Fprintf(os.Stderr, "      %s\n", s.dim(status+" · run: sendbeam transfers "+resumeHint(entry)))
		}
	}
	// Interrupted sends: the sender-side records of transfers whose manifest was
	// advertised but which never completed. They are local to this machine.
	fmt.Fprintln(os.Stderr)
	sender, senderErr := senderStore()
	if senderErr != nil {
		fmt.Fprintln(os.Stderr, s.yellow("Sender records unavailable: "+senderErr.Error()+"."))
		return 0
	}
	senderEntries, senderListErr := sender.List()
	if senderListErr != nil {
		fmt.Fprintln(os.Stderr, s.yellow("Sender records unavailable: "+senderListErr.Error()+"."))
		return 0
	}
	if len(senderEntries) == 0 {
		fmt.Fprintln(os.Stderr, s.dim("No interrupted sends."))
		return 0
	}
	fmt.Fprintln(os.Stderr, s.dim("Interrupted sends (re-run the same send command to resume):"))
	fmt.Fprintln(os.Stderr)
	for _, entry := range senderEntries {
		if !entry.RecordOK {
			fmt.Fprintf(os.Stderr, "  %s  %s\n", s.yellow(entry.TransferID), s.dim("unreadable record: "+entry.Err))
			fmt.Fprintf(os.Stderr, "      %s\n", s.dim("run: sendbeam transfers discard "+entry.TransferID))
			continue
		}
		fmt.Fprintf(os.Stderr, "  %s  %d file(s) · %s · updated %s\n",
			s.cyan(entry.TransferID), entry.Files, humanBytes(entry.TotalSize),
			formatTime(entry.UpdatedAt))
		status := senderStatus(entry)
		if status != "" {
			fmt.Fprintf(os.Stderr, "      %s\n", s.dim(status))
		}
		for _, p := range entry.Paths {
			fmt.Fprintf(os.Stderr, "      %s\n", s.dim(p))
		}
	}
	return 0
}

func transfersInspect(args []string) int {
	fs := flag.NewFlagSet("transfers inspect", flag.ExitOnError)
	outDir := fs.String("out", ".", "directory whose .sendbeam store to inspect")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		fmt.Fprintln(os.Stderr, "sendbeam transfers inspect: exactly one transfer id is required")
		return 2
	}
	id := positionals[0]
	store, err := transfersStore(*outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sendbeam transfers inspect: %s\n", err)
		return 1
	}
	ins, err := store.Inspect(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sendbeam transfers inspect: %s\n", err)
		fmt.Fprintf(os.Stderr, "  %s\n", newStyle(os.Stderr).dim("nothing was deleted; discard it explicitly to remove the state"))
		return 1
	}
	s := newStyle(os.Stderr)
	j := ins.Journal
	fmt.Fprintln(os.Stderr, s.bold("Transfer "+id))
	fmt.Fprintf(os.Stderr, "  %s  %s\n", s.grey("created:"), formatTime(j.CreatedAt))
	fmt.Fprintf(os.Stderr, "  %s  %s\n", s.grey("updated:"), formatTime(j.UpdatedAt))
	fmt.Fprintf(os.Stderr, "  %s  %s committed / %s total\n", s.grey("progress:"), humanBytes(ins.Committed), humanBytes(ins.Total))
	fmt.Fprintf(os.Stderr, "  %s  %s\n", s.grey("protocol:"), j.ProtocolVersion)
	fmt.Fprintf(os.Stderr, "  %s  %s\n", s.grey("manifest fingerprint:"), j.ManifestFingerprint)
	fmt.Fprintf(os.Stderr, "  %s  %s\n", s.grey("journal:"), ins.JournalPath)
	fmt.Fprintf(os.Stderr, "  %s  %s\n", s.grey("partials:"), ins.PartialDir)
	for _, f := range j.Files {
		committed := int64(f.CommittedBlocks * j.BlockSize)
		if committed > f.Size {
			committed = f.Size
		}
		fmt.Fprintf(os.Stderr, "    %s  %s / %s\n", f.Name, humanBytes(committed), humanBytes(f.Size))
	}
	if len(ins.Problems) > 0 {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, s.cross("Partial data does not back the journal's checkpoint claims:"))
		for _, problem := range ins.Problems {
			fmt.Fprintf(os.Stderr, "  %s\n", problem)
		}
		fmt.Fprintln(os.Stderr, s.dim("Resume is refused; nothing was deleted. Discard the state to start over."))
		return 1
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, s.check("Journal is self-consistent and its partial data backs every checkpoint."))
	return 0
}

// durableStatus renders the receiver-side session class for one journal (V13-PR08).
func durableStatus(entry clitransfer.DurableEntry) string {
	switch {
	case !entry.PartialOK:
		return "Partial data missing — inspect/discard"
	case !entry.HasResumeSecret:
		return "Legacy — restart required"
	default:
		return "Ready to resume"
	}
}

// resumeHint renders the management command for one journal's next step.
func resumeHint(entry clitransfer.DurableEntry) string {
	switch {
	case !entry.PartialOK:
		return "inspect " + entry.TransferID + ""
	case !entry.HasResumeSecret:
		return "discard " + entry.TransferID + ""
	default:
		return "resume " + entry.TransferID + " --code <code>"
	}
}

// senderStatus renders the sender-side session class for one record (V13-PR08).
func senderStatus(entry clitransfer.SenderEntry) string {
	if !entry.HasResumeSecret {
		return "Legacy — restart required (no resume credential; discard to send fresh)"
	}
	return "Ready to resume (re-run the same send command, then resume on the receiver)"
}

// transfersResume resumes an interrupted transfer (V13-PR08): the user pre-selected the
// interrupted journal locally, joins the sender's FRESH rendezvous with --code, and the
// two peers authenticate continuity via resume-auth before any verified progress is reused.
// Verified progress is advertised only after mutual authentication; the transfer then runs
// under a fresh key epoch with fresh counters.
func transfersResume(args []string) int {
	fs := flag.NewFlagSet("transfers resume", flag.ExitOnError)
	outDir := fs.String("out", ".", "directory whose .sendbeam store to resume from")
	code := fs.String("code", "", "fresh invite code from the sender's re-run of `sendbeam send`")
	server := fs.String("server", defaultServer, "signaling server URL")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS verification (self-signed dev certs only)")
	relayOnly := fs.Bool("relay-only", false, "force the encrypted WebSocket relay")
	var iceServer iceServerList
	fs.Var(&iceServer, "ice-server", "STUN server URL for direct-path candidates (repeatable; default stun:stun.l.google.com:19302)")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		fmt.Fprintln(os.Stderr, "sendbeam transfers resume: exactly one transfer id is required")
		return 2
	}
	if *code == "" {
		s0 := newStyle(os.Stderr)
		fmt.Fprintln(os.Stderr, "sendbeam transfers resume: --code is required — the sender re-runs "+s0.bold("sendbeam send")+" (same paths) and shares the fresh invite code")
		return 2
	}
	id := positionals[0]
	store, err := transfersStore(*outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sendbeam transfers resume: %s\n", err)
		return 1
	}
	s := newStyle(os.Stderr)
	ins, err := store.Inspect(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sendbeam transfers resume: %s\n", err)
		fmt.Fprintf(os.Stderr, "  %s\n", s.dim("nothing was deleted; discard the state explicitly to remove it"))
		return 1
	}
	if !ins.Resumable {
		fmt.Fprintln(os.Stderr, s.cross("Transfer "+id+" is not resumable:"))
		for _, problem := range ins.Problems {
			fmt.Fprintf(os.Stderr, "  %s\n", problem)
		}
		fmt.Fprintln(os.Stderr, s.dim("Nothing was deleted. Discard the state to start a fresh receive."))
		return 1
	}
	j := ins.Journal
	if j.ResumeSecret == nil {
		fmt.Fprintln(os.Stderr, s.cross("Transfer "+id+" has no resume credential (legacy pre-PR07 state); authenticated cross-session resume is unavailable."))
		fmt.Fprintf(os.Stderr, "  %s\n", s.dim("The verified partial data is kept; restart from zero explicitly with: sendbeam transfers discard "+id+" --out "+*outDir))
		return 1
	}
	// The journal is strictly validated on load (version + exact 64-hex value), so this
	// decode is a belt-and-braces re-check before the secret enters the handshake.
	secret, err := wire.DecodeResumeSecretEnvelope(&wire.ResumeSecretEnvelope{
		Version: j.ResumeSecret.Version,
		Value:   j.ResumeSecret.Value,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "sendbeam transfers resume: transfer %s has a corrupt resume credential (%v); refusing to reuse its progress — nothing was deleted\n", id, err)
		return 1
	}
	ice, err := iceServers(iceServer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sendbeam transfers resume: %s\n", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := dial(ctx, *server, *insecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n%s\n", s.cross("Failed: "+handshakeError(err)))
		return 1
	}
	defer client.Close()

	fmt.Fprintf(os.Stderr, "%s\n", s.dim("Resuming transfer "+id+" — joining the sender's fresh rendezvous "+normalizeCodeArg(*code)+" …"))
	progress := newProgress(0)
	caps := rendezvous.DefaultCaps()
	caps.Features = append(caps.Features, wire.ResumeAuthCapability)
	resumeCtx := &clitransfer.ResumeContext{
		TransferID:          j.TransferID,
		ManifestFingerprint: j.ManifestFingerprint,
		Role:                wire.RoleJoiner,
		ResumeSecret:        secret,
	}
	out, err := clitransfer.Run(ctx, client, clitransfer.Spec{
		Session: rendezvous.Options{
			Role:      rendezvous.RoleJoiner,
			Code:      normalizeCodeArg(*code),
			LocalCaps: &caps,
			OnPhase:   phasePrinter(rendezvous.RoleJoiner),
		},
		DestDir:    *outDir,
		ForceRelay: *relayOnly,
		ICEServers: ice,
		Resume:     resumeCtx,
		OnResume: func(r clitransfer.ResumeResult) {
			if r.Authenticated {
				fmt.Fprintf(os.Stderr, "%s\n", s.check(fmt.Sprintf("Authenticated with the original sender — resuming %s from %s verified; %s remains to transfer.",
					id, humanBytes(ins.Committed), humanBytes(ins.Total-ins.Committed))))
			} else if r.Attempted {
				fmt.Fprintln(os.Stderr, s.cyan("Authenticating the interrupted transfer with the sender …"))
			} else if r.Skipped {
				fmt.Fprintf(os.Stderr, "%s\n", s.yellow("The sender did not authenticate a resume; receiving a fresh transfer. Your interrupted state for "+id+" was kept."))
			}
		},
		OnTransport: transportPrinter,
		OnManifestSet: func(manifest wire.Manifest) {
			progress.setTotal(manifest.TotalSize)
			files := make([]progressFile, len(manifest.Files))
			for i, file := range manifest.Files {
				files[i] = progressFile{name: file.Name, size: file.Size}
			}
			progress.setFiles(files)
			connectPrinter(fmt.Sprintf("Receiving %s (%s) …", labelFor(manifest), humanBytes(manifest.TotalSize)))()
		},
		OnFileProgress: progress.reportFile,
		OnControls:     terminalControls(),
		OnStateChange:  progress.setState,
	})
	progress.finish()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n%s\n", s.cross("Failed: "+handshakeError(err)))
		fmt.Fprintf(os.Stderr, "%s\n", s.dim("The interrupted state for "+id+" was kept; the sender record and partial data were not deleted."))
		return 1
	}
	fmt.Println()
	if len(out.Files) == 1 {
		fmt.Println(s.check("Received " + s.bold(out.Name) + " (" + humanBytes(out.Size) + ") → " + out.Path + "."))
	} else {
		fmt.Println(s.check("Received " + s.bold(fmt.Sprintf("%d files", len(out.Files))) + " (" + humanBytes(out.Size) + ") → " + *outDir + "."))
	}
	fmt.Printf("  %s  %s\n", s.grey("SHA-256:"), out.Digest)
	return 0
}

// labelFor names the manifest's first file or file count for progress headers.
func labelFor(manifest wire.Manifest) string {
	if len(manifest.Files) == 1 {
		return manifest.Files[0].Name
	}
	return fmt.Sprintf("%d files", len(manifest.Files))
}

func transfersDiscard(args []string) int {
	fs := flag.NewFlagSet("transfers discard", flag.ExitOnError)
	outDir := fs.String("out", ".", "directory whose .sendbeam store to discard from")
	all := fs.Bool("all", false, "discard every journal and orphaned partial tree in the store")
	yes := fs.Bool("yes", false, "confirm --all without prompting")
	positionals := parseArgs(fs, args)
	store, err := transfersStore(*outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sendbeam transfers discard: %s\n", err)
		return 1
	}
	s := newStyle(os.Stderr)
	if *all {
		if !*yes {
			fmt.Fprintln(os.Stderr, "discard --all removes every journal and partial tree in "+store.Root()+".")
			fmt.Fprintln(os.Stderr, "Confirm with "+s.bold("--yes")+" (this is destructive and cannot be undone).")
			return 2
		}
		if err := store.DiscardAll(); err != nil {
			fmt.Fprintf(os.Stderr, "sendbeam transfers discard: %s\n", err)
			return 1
		}
		fmt.Fprintln(os.Stderr, s.check("Discarded all durable transfer state in "+store.Root()+"."))
		// Also drop every interrupted-send record on this machine (idempotent).
		if sender, err := senderStore(); err == nil {
			if err := sender.DiscardAll(); err != nil {
				fmt.Fprintf(os.Stderr, "sendbeam transfers discard: %s\n", err)
				return 1
			}
		}
		return 0
	}
	if len(positionals) == 0 {
		fmt.Fprintln(os.Stderr, "sendbeam transfers discard: at least one transfer id (or --all) is required")
		return 2
	}
	for _, id := range positionals {
		if err := store.Discard(id); err != nil {
			fmt.Fprintf(os.Stderr, "sendbeam transfers discard: %s\n", err)
			return 1
		}
		fmt.Fprintln(os.Stderr, s.check("Discarded "+id+"."))
	}
	// A discarded id may also have an interrupted-send record on this machine; removing it
	// is idempotent and bounded to the named id.
	if sender, err := senderStore(); err == nil {
		for _, id := range positionals {
			if err := sender.Discard(id); err != nil {
				fmt.Fprintf(os.Stderr, "sendbeam transfers discard: %s\n", err)
				return 1
			}
		}
	}
	return 0
}

func formatTime(unixMillis int64) string {
	if unixMillis <= 0 {
		return "unknown"
	}
	return time.UnixMilli(unixMillis).Format("2006-01-02 15:04:05")
}
