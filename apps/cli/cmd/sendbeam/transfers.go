package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	clitransfer "github.com/sendbeam/cli/internal/transfer"
)

// transfersUsage prints the management-command help.
func transfersUsage(w *os.File) {
	s := newStyle(w)
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam transfers list")+" [--out DIR]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam transfers inspect")+" <id> [--out DIR]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam transfers resume")+" <id> [--out DIR]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam transfers discard")+" <id>... [--out DIR] [--all] [--yes]")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, s.dim("Manage durable receive state kept under DIR/.sendbeam (default .):"))
	_, _ = fmt.Fprintln(w, "  list     show every journal, unreadable journal, and orphaned partial tree")
	_, _ = fmt.Fprintln(w, "  inspect  validate one journal against its partial data (never deletes)")
	_, _ = fmt.Fprintln(w, "  resume   verify a journal is resumable and how to resume it")
	_, _ = fmt.Fprintln(w, "  discard  explicitly delete a journal and its partials (idempotent)")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, s.dim("Discard flags:"))
	_, _ = fmt.Fprintln(w, "  --all    discard every journal and orphaned partial tree in the store")
	_, _ = fmt.Fprintln(w, "  --yes    confirm --all without prompting")
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
		return 0
	}
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
		fmt.Fprintf(os.Stderr, "  %s  %s committed / %s total · updated %s\n",
			s.cyan(label),
			humanBytes(entry.CommittedBytes), humanBytes(entry.TotalSize),
			formatTime(entry.UpdatedAt))
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

func transfersResume(args []string) int {
	fs := flag.NewFlagSet("transfers resume", flag.ExitOnError)
	outDir := fs.String("out", ".", "directory whose .sendbeam store to resume from")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		fmt.Fprintln(os.Stderr, "sendbeam transfers resume: exactly one transfer id is required")
		return 2
	}
	id := positionals[0]
	store, err := transfersStore(*outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sendbeam transfers resume: %s\n", err)
		return 1
	}
	ins, err := store.Inspect(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sendbeam transfers resume: %s\n", err)
		return 1
	}
	s := newStyle(os.Stderr)
	if !ins.Resumable {
		fmt.Fprintln(os.Stderr, s.cross("Transfer "+id+" is not resumable:"))
		for _, problem := range ins.Problems {
			fmt.Fprintf(os.Stderr, "  %s\n", problem)
		}
		fmt.Fprintln(os.Stderr, s.dim("Nothing was deleted. Discard the state to start a fresh receive."))
		return 1
	}
	fmt.Fprintln(os.Stderr, s.check(fmt.Sprintf("Transfer %s is resumable at %s committed.", id, humanBytes(ins.Committed))))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, s.dim("To resume: re-run "+s.bold("sendbeam receive <code>")+" in the same room where the sender is still connected."))
	fmt.Fprintln(os.Stderr, s.dim("The receiver detects the matching journal from the authenticated manifest and continues from its checkpoint automatically."))
	fmt.Fprintln(os.Stderr, s.dim("The invite code is never stored, so a standalone resume without the sender is not possible yet."))
	fmt.Fprintln(os.Stderr, s.dim("Cross-session authenticated resume with fresh traffic keys is a later milestone; until then every resume re-derives a fresh key from a new handshake."))
	return 0
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
	return 0
}

func formatTime(unixMillis int64) string {
	if unixMillis <= 0 {
		return "unknown"
	}
	return time.UnixMilli(unixMillis).Format("2006-01-02 15:04:05")
}
