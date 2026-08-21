package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/engine/wsclient"
	"github.com/sendbeam/wire"
)

type PairJSONView struct {
	Status            string           `json:"status"`
	DeviceID          string           `json:"device_id"`
	LocalLabel        string           `json:"local_label"`
	Fingerprint       string           `json:"fingerprint"`
	PairCredentialRef string           `json:"pair_credential_ref"`
	Capabilities      []string         `json:"capabilities"`
	Policy            wire.TrustPolicy `json:"policy"`
}

// pairingPipeTransport wraps in-memory channels for testing and scripted pairing exchanges.
type pairingPipeTransport struct {
	in  <-chan []byte
	out chan<- []byte
}

func newPairingPipeTransport(in <-chan []byte, out chan<- []byte) *pairingPipeTransport {
	return &pairingPipeTransport{in: in, out: out}
}

func (t *pairingPipeTransport) SendMessage(ctx context.Context, data []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case t.out <- data:
		return nil
	}
}

func (t *pairingPipeTransport) ReceiveMessage(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case data, ok := <-t.in:
		if !ok {
			return nil, errors.New("pairing transport closed")
		}
		return data, nil
	}
}

func runPair(args []string) int {
	return executePair(args, os.Stdout, os.Stderr)
}

func executePair(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", defaultServer, "signaling server URL")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS verification (dev only)")
	customName := fs.String("name", "", "custom local display name for the paired device")
	autoAccept := fs.Bool("auto-accept", false, "enable auto-accept for transfers from this device")
	autoAcceptDest := fs.String("dest", "", "destination directory for auto-accepted transfers")
	jsonOutput := fs.Bool("json", false, "output JSON format")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *autoAccept {
		if *autoAcceptDest == "" {
			_, _ = fmt.Fprintln(stderr, "error: --dest is required when --auto-accept is enabled")
			return 2
		}
		absDest, err := filepath.Abs(*autoAcceptDest)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: invalid destination path: %v\n", err)
			return 2
		}
		*autoAcceptDest = absDest
	}

	env, err := InitCLIEnvironment(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "CLI Device"
	}
	if *customName != "" {
		hostname = *customName
	}

	coordinator := trust.NewPairingCoordinator(env.IdentityMgr, env.TrustStore)

	positionals := fs.Args()
	isJoiner := len(positionals) > 0

	var role wire.Role
	var inviteCode string

	if !isJoiner {
		role = wire.RoleOfferer
	} else {
		role = wire.RoleJoiner
		inviteCode = positionals[0]
	}

	opts := rendezvous.Options{
		Role: role,
		Code: inviteCode,
		OnCode: func(code string) {
			if !*jsonOutput {
				s := newStyleFromWriter(stdout)
				_, _ = fmt.Fprintln(stdout, s.bold("Pairing with trusted device:"))
				_, _ = fmt.Fprintf(stdout, "Invite code: %s\n", s.cyan(code))
				_, _ = fmt.Fprintln(stdout, "Waiting for peer to connect...")
			}
		},
	}

	dopts := wsclient.DialOptions{
		InsecureSkipVerify: *insecure,
	}

	res, err := wsclient.Rendezvous(ctx, *server, dopts, opts)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pairing handshake failed: %v\n", err)
		return 1
	}

	// For in-process pairing completion over established session:
	a2b := make(chan []byte, 4)
	b2a := make(chan []byte, 4)
	var transport trust.PairingTransport
	if role == wire.RoleOfferer {
		transport = newPairingPipeTransport(b2a, a2b)
	} else {
		transport = newPairingPipeTransport(a2b, b2a)
	}

	cfg := trust.PairingSessionConfig{
		DeviceName:   hostname,
		Capabilities: []string{"transfer.v1", "transfer.v2", "lan_direct"},
		MasterKey:    res.Master,
		AutoAccept:   *autoAccept,
		DestDir:      *autoAcceptDest,
	}

	var pairResult *trust.PairingResult
	if role == wire.RoleOfferer {
		pairResult, err = coordinator.InitiatePairing(ctx, transport, cfg)
	} else {
		pairResult, err = coordinator.AcceptPairing(ctx, transport, cfg)
	}

	if err != nil {
		if errors.Is(err, trust.ErrKeyConflict) {
			_, _ = fmt.Fprintln(stderr, "pairing error: device ID already exists with a different public key")
			return 1
		}
		if errors.Is(err, trust.ErrLabelConflict) {
			_, _ = fmt.Fprintf(stderr, "pairing error: a different trusted device already uses the label %q\n", *customName)
			return 1
		}
		_, _ = fmt.Fprintf(stderr, "pairing ceremony failed: %v\n", err)
		return 1
	}

	if err := env.Secrets.SetSecret(pairResult.PeerRecord.DeviceID, pairResult.KPair); err != nil {
		_, _ = fmt.Fprintf(stderr, "error persisting pair secret: %v\n", err)
		return 1
	}

	if *jsonOutput {
		view := PairJSONView{
			Status:            "paired",
			DeviceID:          pairResult.PeerRecord.DeviceID,
			LocalLabel:        pairResult.PeerRecord.LocalLabel,
			Fingerprint:       pairResult.PeerRecord.Fingerprint(),
			PairCredentialRef: pairResult.PeerRecord.PairCredentialRef,
			Capabilities:      pairResult.PeerRecord.Capabilities,
			Policy:            pairResult.PeerRecord.Policy,
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(view)
		return 0
	}

	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintln(stdout, s.bold(s.green("Successfully paired!")))
	_, _ = fmt.Fprintf(stdout, "Device Name: %s\n", pairResult.PeerRecord.LocalLabel)
	_, _ = fmt.Fprintf(stdout, "Device ID:   %s\n", pairResult.PeerRecord.DeviceID)
	_, _ = fmt.Fprintf(stdout, "Fingerprint: %s\n", pairResult.PeerRecord.Fingerprint())
	if pairResult.PeerRecord.Policy.AutoAccept {
		_, _ = fmt.Fprintf(stdout, "Auto-Accept: Enabled (saving to %s)\n", pairResult.PeerRecord.Policy.AutoAcceptDestDir)
	}
	return 0
}
