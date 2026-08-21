package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/sendbeam/wire"
)

type DeviceJSONView struct {
	DeviceID          string           `json:"device_id"`
	LocalLabel        string           `json:"local_label"`
	Fingerprint       string           `json:"fingerprint"`
	PublicKeyHex      string           `json:"public_key_hex"`
	PairCredentialRef string           `json:"pair_credential_ref"`
	Status            string           `json:"status"` // "active" or "revoked"
	Revoked           bool             `json:"revoked"`
	RevokedAt         *string          `json:"revoked_at,omitempty"`
	Capabilities      []string         `json:"capabilities"`
	FirstSeenAt       string           `json:"first_seen_at"`
	LastSeenAt        string           `json:"last_seen_at"`
	Policy            wire.TrustPolicy `json:"policy"`
}

func runDevices(args []string) int {
	return executeDevices(args, os.Stdout, os.Stderr)
}

func executeDevices(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("devices", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "output JSON format")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	env, err := InitCLIEnvironment(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	devices, err := env.TrustStore.ListDevices(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error listing devices: %v\n", err)
		return 1
	}

	if *jsonOutput {
		views := make([]DeviceJSONView, 0, len(devices))
		for _, dev := range devices {
			status := "active"
			var revAtStr *string
			if dev.Revoked {
				status = "revoked"
				if dev.RevokedAt != nil {
					s := dev.RevokedAt.UTC().Format(time.RFC3339)
					revAtStr = &s
				}
			}
			views = append(views, DeviceJSONView{
				DeviceID:          dev.DeviceID,
				LocalLabel:        dev.LocalLabel,
				Fingerprint:       dev.Fingerprint(),
				PublicKeyHex:      dev.PublicKey,
				PairCredentialRef: dev.PairCredentialRef,
				Status:            status,
				Revoked:           dev.Revoked,
				RevokedAt:         revAtStr,
				Capabilities:      dev.Capabilities,
				FirstSeenAt:       dev.FirstSeenAt.UTC().Format(time.RFC3339),
				LastSeenAt:        dev.LastSeenAt.UTC().Format(time.RFC3339),
				Policy:            dev.Policy,
			})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(views); err != nil {
			_, _ = fmt.Fprintf(stderr, "error encoding JSON: %v\n", err)
			return 1
		}
		return 0
	}

	if len(devices) == 0 {
		_, _ = fmt.Fprintln(stdout, "No paired devices found. Run 'sendbeam pair' to pair with a trusted device.")
		return 0
	}

	w := tabwriter.NewWriter(stdout, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(w, "LABEL\tDEVICE ID\tFINGERPRINT\tSTATUS\tAUTO-ACCEPT\tLAST SEEN")
	for _, dev := range devices {
		status := "active"
		if dev.Revoked {
			status = "revoked"
		}
		autoAccept := "no"
		if dev.Policy.AutoAccept {
			autoAccept = fmt.Sprintf("yes (%s)", dev.Policy.AutoAcceptDestDir)
		}
		lastSeen := dev.LastSeenAt.Format("2006-01-02 15:04")
		if dev.LastSeenAt.IsZero() {
			lastSeen = "never"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			dev.LocalLabel,
			dev.DeviceID[:min(14, len(dev.DeviceID))]+"...",
			dev.Fingerprint(),
			status,
			autoAccept,
			lastSeen,
		)
	}
	_ = w.Flush()
	return 0
}
