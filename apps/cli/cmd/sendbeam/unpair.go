package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type UnpairJSONView struct {
	Status      string `json:"status"`
	DeviceID    string `json:"device_id"`
	LocalLabel  string `json:"local_label"`
	Fingerprint string `json:"fingerprint"`
	Revoked     bool   `json:"revoked"`
	Purged      bool   `json:"purged"`
}

func runUnpair(args []string) int {
	return executeUnpair(args, os.Stdin, os.Stdout, os.Stderr)
}

func executeUnpair(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("unpair", flag.ContinueOnError)
	fs.SetOutput(stderr)
	yes := fs.Bool("yes", false, "skip confirmation prompt")
	fs.BoolVar(yes, "y", false, "skip confirmation prompt (shorthand)")
	purge := fs.Bool("purge", false, "permanently delete record instead of marking revoked")
	jsonOutput := fs.Bool("json", false, "output JSON format")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	positionals := fs.Args()
	if len(positionals) < 1 {
		_, _ = fmt.Fprintln(stderr, "error: specify a device name, ID, or fingerprint to unpair")
		return 2
	}
	query := positionals[0]

	env, err := InitCLIEnvironment(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dev, err := ResolveDevice(ctx, env.TrustStore, query)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	if !*yes && !*jsonOutput {
		_, _ = fmt.Fprintf(stdout, "Unpair from device %q (%s)? [y/N]: ", dev.LocalLabel, dev.Fingerprint())
		reader := bufio.NewReader(stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))
		if input != "y" && input != "yes" {
			_, _ = fmt.Fprintln(stdout, "Operation cancelled.")
			return 0
		}
	}

	if *purge {
		if err := env.TrustStore.UnpairDevice(ctx, dev.DeviceID); err != nil {
			_, _ = fmt.Fprintf(stderr, "error deleting device from trust store: %v\n", err)
			return 1
		}
		_ = env.Secrets.DeleteSecret(dev.DeviceID)
	} else {
		if err := env.TrustStore.RevokeDevice(ctx, dev.DeviceID); err != nil {
			_, _ = fmt.Fprintf(stderr, "error revoking device in trust store: %v\n", err)
			return 1
		}
	}

	if *jsonOutput {
		view := UnpairJSONView{
			Status:      "unpaired",
			DeviceID:    dev.DeviceID,
			LocalLabel:  dev.LocalLabel,
			Fingerprint: dev.Fingerprint(),
			Revoked:     dev.Revoked,
			Purged:      *purge,
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(view); err != nil {
			_, _ = fmt.Fprintf(stderr, "error encoding JSON: %v\n", err)
			return 1
		}
		return 0
	}

	if *purge {
		_, _ = fmt.Fprintf(stdout, "Purged device %q (%s) from trusted database.\n", dev.LocalLabel, dev.Fingerprint())
	} else {
		_, _ = fmt.Fprintf(stdout, "Revoked trust for device %q (%s).\n", dev.LocalLabel, dev.Fingerprint())
	}
	return 0
}
