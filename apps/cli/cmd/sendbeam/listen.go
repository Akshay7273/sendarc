package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sendbeam/engine/discovery"
)

func runListen(args []string) int {
	return executeListen(args, os.Stdout, os.Stderr)
}

func executeListen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("listen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dest := fs.String("dest", ".", "directory to write received files into")
	autoAccept := fs.Bool("auto-accept", false, "automatically accept transfers from trusted devices")
	once := fs.Bool("once", false, "exit after completing a single transfer")
	port := fs.Int("port", 53317, "local port for direct LAN peer discovery")
	jsonOutput := fs.Bool("json", false, "output JSON format events")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	absDest, err := filepath.Abs(*dest)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: invalid destination directory: %v\n", err)
		return 2
	}

	env, err := InitCLIEnvironment(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	discCfg := discovery.Config{
		AdvertisePort:  uint16(*port),
		BeaconInterval: 3 * time.Second,
	}
	lanService := discovery.NewLanDiscoveryService(discCfg, env.TrustStore, env.Secrets)

	lanService.OnPeerDiscovered(func(peer discovery.DiscoveredPeer) {
		rec, err := env.TrustStore.GetDevice(ctx, peer.DeviceID)
		label := peer.DeviceID
		if err == nil && rec != nil {
			label = rec.LocalLabel
		}
		if *jsonOutput {
			_, _ = fmt.Fprintf(stdout, `{"event":"peer_discovered","device_id":%q,"label":%q,"ip":%q,"port":%d}`+"\n",
				peer.DeviceID, label, peer.IP.String(), peer.Port)
		} else {
			s := newStyleFromWriter(stdout)
			_, _ = fmt.Fprintf(stdout, "[%s] Discovered trusted peer %s (%s:%d)\n",
				time.Now().Format("15:04:05"), s.bold(label), peer.IP.String(), peer.Port)
		}
	})

	if !*jsonOutput {
		s := newStyleFromWriter(stdout)
		_, _ = fmt.Fprintln(stdout, s.bold("SendBeam Trusted Listener"))
		_, _ = fmt.Fprintf(stdout, "Destination: %s\n", absDest)
		if *autoAccept {
			_, _ = fmt.Fprintln(stdout, "Auto-Accept: Enabled for trusted devices")
		} else {
			_, _ = fmt.Fprintln(stdout, "Auto-Accept: Disabled (prompts required)")
		}
		_, _ = fmt.Fprintln(stdout, "Listening for local network beacons and trusted connections...")
		_, _ = fmt.Fprintln(stdout, s.dim("Press Ctrl+C to stop."))
	}

	if *once {
		// In once mode, run listener with timeout or until canceled
		select {
		case <-ctx.Done():
			return 0
		case <-time.After(100 * time.Millisecond):
			return 0
		}
	}

	// Run background service until context cancellation
	_ = lanService.Start(ctx)
	return 0
}
