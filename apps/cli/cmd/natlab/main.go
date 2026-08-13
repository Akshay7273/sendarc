// Command natlab runs a hermetic NAT lab for SendBeam's transport selection. It builds
// two isolated private networks, each behind a userspace NAT box (cmd/natbox) with a
// configurable mapping policy, joined by a shared public segment that hosts a signaling
// server (sendbeamd) and a STUN server (cmd/stund). For each policy pair it runs one real
// CLI transfer and reports whether the file moved over the direct WebRTC path or fell
// back to the encrypted relay, then verifies the received bytes.
//
// Hostile-network coverage (V12-PR06): any NAT policy pair, including `udp-blocked`
// (drops all outbound UDP so WebRTC cannot establish and the client must fall back to the
// relay), `netem` profiles for loss/delay/jitter/rate (with a `shift` bandwidth-upgrade
// profile), and `-cycles N` for repeated reconnect cycles. `-measure` collects per-transfer
// wall time, receiver peak RSS, and relay usage as JSON.
//
// The whole lab runs unprivileged: launch it with
//
//	unshare -Urnm natlab [flags]
//
// so the harness owns a user namespace and can create netns + veths without root on the
// host. Every stage is orchestrated through `ip` and `nsenter`, which must be on PATH.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	pubHost  = "10.0.3.100" // signaling + STUN server in the public segment
	privAIP  = "10.0.0.1"   // NAT-A private gateway
	privBIP  = "10.0.1.1"   // NAT-B private gateway
	hostFile = "payload.bin"
)

var codeRe = regexp.MustCompile(`\d+-[a-z]+-[a-z]+`)

type netns struct {
	name string
	pid  int
}

func main() {
	fileSize := flag.Int("file-size", 4*1024*1024, "payload size in bytes")
	serverBin := flag.String("server-bin", "", "path to the built sendbeamd binary (required)")
	combos := flag.String("combos",
		"full-cone/full-cone,restricted/restricted,port-restricted/port-restricted,symmetric/symmetric,full-cone/symmetric,udp-blocked/udp-blocked",
		"comma-separated NAT policy pairs (A/B); udp-blocked simulates a UDP-blocked network")
	noproxy := flag.Bool("noproxy", false, "skip NAT boxes: both peers run in the public segment over forced relay (control)")
	netem := flag.String("netem", "", "degraded-network profile applied to both bridge legs: 'loss 3%', 'delay 50ms', 'jitter 20ms', 'rate 10mbit', or 'shift 1mbit-10mbit'")
	cycles := flag.Int("cycles", 1, "repeated reconnect cycles per combo (back-to-back transfers)")
	measure := flag.Bool("measure", false, "collect per-transfer metrics (wall time, receiver peak RSS, relay usage)")
	flag.Parse()

	if os.Geteuid() != 0 {
		log.Fatal("natlab: must run as root inside a user namespace: unshare -Urnm natlab [flags]")
	}
	if *serverBin == "" {
		log.Fatal("natlab: -server-bin is required (build apps/server/cmd/sendbeamd first)")
	}

	binDir, err := os.MkdirTemp("", "natlab")
	if err != nil {
		log.Fatal(err)
	}
	binPath := func(name, pkg string) string {
		out := filepath.Join(binDir, name)
		root, err := moduleRoot()
		if err != nil {
			log.Fatalf("natlab: %v", err)
		}
		cmd := exec.Command("go", "build", "-o", out, pkg)
		cmd.Dir = root
		if outB, err := cmd.CombinedOutput(); err != nil {
			log.Fatalf("natlab: build %s: %v\n%s", pkg, err, outB)
		}
		return out
	}
	sendbeam := binPath("sendbeam", "./cmd/sendbeam")
	natbox := binPath("natbox", "./cmd/natbox")
	stund := binPath("stund", "./cmd/stund")

	src := filepath.Join(os.TempDir(), "natlab-"+hostFile)
	payload := make([]byte, *fileSize)
	if _, err := rand.New(rand.NewSource(42)).Read(payload); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(src, payload, 0o644); err != nil {
		log.Fatal(err)
	}
	dstDir := filepath.Join(os.TempDir(), fmt.Sprintf("natlab-recv-%d", os.Getpid()))
	_ = os.RemoveAll(dstDir)

	lab := &lab{
		sendbeam: sendbeam,
		natbox:   natbox,
		stund:    stund,
		server:   *serverBin,
		src:      src,
		dstDir:   dstDir,
		expect:   sha256.Sum256(payload),
		noproxy:  *noproxy,
	}
	if err := lab.setup(); err != nil {
		lab.cleanup()
		log.Fatalf("natlab: setup: %v", err)
	}
	defer lab.cleanup()
	if *netem != "" {
		if err := lab.applyNetem(*netem); err != nil {
			lab.cleanup()
			log.Fatalf("natlab: netem: %v", err)
		}
	}

	var pairs [][2]string
	for _, c := range strings.Split(*combos, ",") {
		parts := strings.SplitN(c, "/", 2)
		if len(parts) != 2 {
			log.Fatalf("natlab: bad combo %q", c)
		}
		pairs = append(pairs, [2]string{parts[0], parts[1]})
	}

	failed := false
	// A measurement is one completed transfer under a combo+cycle.
	type cycleMetric struct {
		Combo       string `json:"combo"`
		Cycle       int    `json:"cycle"`
		Transport   string `json:"transport"`
		DigestOK    bool   `json:"digestOk"`
		WallMS      int64  `json:"wallMs"`
		PathMS      int64  `json:"pathMs,omitempty"` // sender time to selected transport, -1 if not observed
		ReceiverRSS int64  `json:"receiverRSSKiB,omitempty"`
		RelayUsed   bool   `json:"relayUsed"`
	}
	var metrics []cycleMetric
	for _, pair := range pairs {
		for c := 1; c <= *cycles; c++ {
			start := time.Now()
			ok, transport, pathMs, err := lab.runTransfer(pair[0], pair[1])
			recvRSS := lab.lastRecvRSS
			wall := time.Since(start).Round(time.Millisecond)
			if err != nil {
				log.Printf("combo %s/%s cycle %d: ERROR after %v: %v", pair[0], pair[1], c, wall, err)
				failed = true
				continue
			}
			log.Printf("combo %s/%s cycle %d: %s, digest %t, path %v, %v", pair[0], pair[1], c, transport, ok, (time.Duration(pathMs) * time.Millisecond).Round(time.Millisecond), wall)
			if !ok {
				failed = true
			}
			if *measure {
				metrics = append(metrics, cycleMetric{
					Combo:       pair[0] + "/" + pair[1],
					Cycle:       c,
					Transport:   transport,
					DigestOK:    ok,
					WallMS:      wall.Milliseconds(),
					PathMS:      pathMs,
					ReceiverRSS: recvRSS,
					RelayUsed:   transport == "relay",
				})
			}
		}
	}
	if *measure && len(metrics) > 0 {
		b, _ := json.MarshalIndent(metrics, "", "  ")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "=== measurements ===")
		fmt.Fprintln(os.Stderr, string(b))
	}
	if failed {
		os.Exit(1)
	}
}

type lab struct {
	sendbeam, natbox, stund, server string
	src, dstDir                     string
	expect                          [32]byte
	noproxy                         bool

	// lastRecvRSS records the receiver process's peak RSS (KiB) after the most recent
	// transfer, for -measure memory instrumentation.
	lastRecvRSS int64

	mu    sync.Mutex
	nses  []*netns
	procs []*exec.Cmd // per-combo processes (natboxes, transfers); killed between combos
	keep  []*exec.Cmd // long-lived processes (netns holders, services); killed at cleanup
}

func (l *lab) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range append(l.procs, l.keep...) {
		_ = c.Process.Kill()
	}
	for _, n := range l.nses {
		_ = syscall.Kill(n.pid, syscall.SIGKILL)
	}
	l.procs = nil
	l.keep = nil
	l.nses = nil
}

// killCombo stops the per-combo processes and clears the list.
func (l *lab) killCombo() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.procs {
		_ = c.Process.Kill()
	}
	l.procs = nil
}

func (l *lab) spawnNetns(name string) (*netns, error) {
	cmd := exec.Command("sleep", "infinity")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawn %s: %w", name, err)
	}
	go func() { _ = cmd.Wait() }() // detached; the netns lives until cleanup
	l.mu.Lock()
	l.keep = append(l.keep, cmd)
	l.nses = append(l.nses, &netns{name: name, pid: cmd.Process.Pid})
	l.mu.Unlock()
	return &netns{name: name, pid: cmd.Process.Pid}, nil
}

// nsRun executes a command inside a netns via nsenter -t <pid> -n.
func (l *lab) nsRun(ns *netns, args ...string) error {
	full := append([]string{"-t", fmt.Sprint(ns.pid), "-n"}, args...)
	return exec.Command("nsenter", full...).Run()
}

// nsSpawn starts a long-running process inside a netns. The caller decides whether it
// belongs in l.keep (services) or l.procs (per-combo NAT boxes).
func (l *lab) nsSpawn(ns *netns, env []string, cmd string, args ...string) (*exec.Cmd, error) {
	full := append([]string{"-t", fmt.Sprint(ns.pid), "-n"}, append([]string{cmd}, args...)...)
	c := exec.Command("nsenter", full...)
	c.Env = append(os.Environ(), env...)
	c.Stdout = os.Stderr
	c.Stderr = os.Stderr
	if err := c.Start(); err != nil {
		return nil, err
	}
	return c, nil
}

func (l *lab) veth(nameA string, nsA *netns, nameB string, nsB *netns) error {
	if err := exec.Command("ip", "link", "add", nameA, "type", "veth", "peer", "name", nameB).Run(); err != nil {
		return fmt.Errorf("veth %s/%s: %w", nameA, nameB, err)
	}
	if err := exec.Command("ip", "link", "set", nameA, "netns", fmt.Sprint(nsA.pid)).Run(); err != nil {
		return err
	}
	return exec.Command("ip", "link", "set", nameB, "netns", fmt.Sprint(nsB.pid)).Run()
}

func (l *lab) setup() error {
	nsA, _ := l.spawnNetns("a")
	natA, _ := l.spawnNetns("natA")
	pub, _ := l.spawnNetns("pub")
	natB, _ := l.spawnNetns("natB")
	nsB, _ := l.spawnNetns("b")

	// Links: sender—natA, natA—pub, pub—server, natB—pub, natB—receiver.
	for _, pair := range [][2]any{
		{"a0", nsA}, {"a1", natA},
		{"pa0", natA}, {"pa1", pub},
		{"pb0", natB}, {"pb1", pub},
		{"srv0", pub}, {"srv1", pub},
		{"b0", nsB}, {"b1", natB},
	} {
		_ = pair
	}
	if err := l.veth("a0", nsA, "a1", natA); err != nil {
		return err
	}
	if err := l.veth("pa0", natA, "pa1", pub); err != nil {
		return err
	}
	if err := l.veth("pb0", natB, "pb1", pub); err != nil {
		return err
	}
	if err := l.veth("srv0", pub, "srv1", pub); err != nil {
		return err
	}
	if err := l.veth("b0", nsB, "b1", natB); err != nil {
		return err
	}

	up := func(ns *netns, ifname string) error {
		return l.nsRun(ns, "ip", "link", "set", ifname, "mtu", "9000", "up")
	}
	loopUp := func(ns *netns) error { return l.nsRun(ns, "ip", "link", "set", "lo", "up") }
	addr := func(ns *netns, ifname, ip string) error {
		return l.nsRun(ns, "ip", "addr", "add", ip, "dev", ifname)
	}
	route := func(ns *netns, gw string) error {
		return l.nsRun(ns, "ip", "route", "add", "default", "via", gw)
	}

	steps := []struct {
		ns *netns
		fn func() error
	}{
		{nsA, func() error { return loopUp(nsA) }},
		{natA, func() error { return loopUp(natA) }},
		{pub, func() error { return loopUp(pub) }},
		{natB, func() error { return loopUp(natB) }},
		{nsB, func() error { return loopUp(nsB) }},
		{nsA, func() error { return addr(nsA, "a0", "10.0.0.2/24") }},
		{nsA, func() error { return up(nsA, "a0") }},
		{nsA, func() error { return route(nsA, privAIP) }},
		{natA, func() error { return addr(natA, "a1", privAIP+"/24") }},
		{natA, func() error { return up(natA, "a1") }},
		{natA, func() error { return addr(natA, "pa0", "10.0.3.1/24") }},
		{natA, func() error { return up(natA, "pa0") }},
		{natB, func() error { return addr(natB, "b1", privBIP+"/24") }},
		{natB, func() error { return up(natB, "b1") }},
		{natB, func() error { return addr(natB, "pb0", "10.0.3.2/24") }},
		{natB, func() error { return up(natB, "pb0") }},
		{nsB, func() error { return addr(nsB, "b0", "10.0.1.2/24") }},
		{nsB, func() error { return up(nsB, "b0") }},
		{nsB, func() error { return route(nsB, privBIP) }},
	}
	for _, s := range steps {
		if err := s.fn(); err != nil {
			return fmt.Errorf("configure: %w", err)
		}
	}

	// Public segment: a bridge joining both NATs and the server host.
	for _, step := range [][]string{
		{"link", "add", "br0", "type", "bridge"},
		{"link", "set", "br0", "mtu", "9000", "up"},
		{"link", "set", "pa1", "mtu", "9000", "master", "br0"},
		{"link", "set", "pa1", "mtu", "9000", "up"},
		{"link", "set", "pb1", "mtu", "9000", "master", "br0"},
		{"link", "set", "pb1", "mtu", "9000", "up"},
		{"link", "set", "srv0", "mtu", "9000", "master", "br0"},
		{"link", "set", "srv0", "mtu", "9000", "up"},
	} {
		if err := l.nsRun(pub, append([]string{"ip"}, step...)...); err != nil {
			return fmt.Errorf("pub %v: %w", step, err)
		}
	}
	if err := addr(pub, "srv1", pubHost+"/24"); err != nil {
		return err
	}
	if err := up(pub, "srv1"); err != nil {
		return err
	}

	// NAT namespaces must not forward: only the daemons translate.
	for _, n := range []*netns{natA, natB} {
		if err := l.nsRun(n, "sysctl", "-w", "net.ipv4.ip_forward=0"); err != nil {
			return fmt.Errorf("%s ip_forward: %w", n.name, err)
		}
	}

	// Services in the public segment: signaling + STUN.
	c, err := l.nsSpawn(pub, []string{"SENDBEAM_ADDR=" + pubHost + ":8443"}, l.server)
	if err != nil {
		return fmt.Errorf("sendbeamd: %w", err)
	}
	l.mu.Lock()
	l.keep = append(l.keep, c)
	l.mu.Unlock()
	c, err = l.nsSpawn(pub, nil, l.stund, "-addr", pubHost+":3478")
	if err != nil {
		return fmt.Errorf("stund: %w", err)
	}
	l.mu.Lock()
	l.keep = append(l.keep, c)
	l.mu.Unlock()

	time.Sleep(500 * time.Millisecond)
	return nil
}

// applyNetem shapes the egress of both public bridge legs (pa1, pb1) so the
// sender→receiver downlink experiences the given profile on the direct path and
// the server→receiver relay leg. One qdisc per profile; loss and delay use netem,
// rate limits use netem's own rate control (it segments like the real bottleneck).
func (l *lab) applyNetem(spec string) error {
	var qdiscs []string
	switch {
	case strings.HasPrefix(spec, "loss "):
		qdiscs = []string{"netem loss " + strings.TrimPrefix(spec, "loss ")}
	case strings.HasPrefix(spec, "delay "):
		qdiscs = []string{"netem delay " + strings.TrimPrefix(spec, "delay ")}
	case strings.HasPrefix(spec, "jitter "):
		// Fixed delay plus variation, approximating a jittery/loaded link.
		qdiscs = []string{"netem delay " + strings.TrimPrefix(spec, "jitter ") + " " + strings.TrimPrefix(spec, "jitter ") + " distribution normal"}
	case strings.HasPrefix(spec, "rate "):
		qdiscs = []string{"netem rate " + strings.TrimPrefix(spec, "rate ")}
	case strings.HasPrefix(spec, "shift "):
		// Bandwidth shift: start at the slower rate, then re-apply the faster one shortly
		// after the transfer begins (approximates a bandwidth upgrade mid-transfer).
		parts := strings.SplitN(strings.TrimPrefix(spec, "shift "), "-", 2)
		if len(parts) != 2 {
			return fmt.Errorf("bad shift profile %q (want 'shift slow-fast')", spec)
		}
		qdiscs = []string{"netem rate " + parts[0]}
		time.AfterFunc(4*time.Second, func() {
			for _, leg := range []string{"pa1", "pb1"} {
				_ = exec.Command("nsenter", "-t", fmt.Sprint(l.nsPID("pub")), "-n", "tc", "qdisc", "replace", "dev", leg, "root", "netem", "rate", parts[1]).Run()
			}
		})
	default:
		return fmt.Errorf("unsupported netem profile %q (want 'loss 3%%', 'delay 50ms', 'jitter 20ms', 'rate 10mbit', or 'shift 1mbit-10mbit')", spec)
	}
	l.mu.Lock()
	var pub *netns
	for _, n := range l.nses {
		if n.name == "pub" {
			pub = n
		}
	}
	l.mu.Unlock()
	for _, ifname := range []string{"pa1", "pb1"} {
		for _, q := range qdiscs {
			args := append([]string{"qdisc", "add", "dev", ifname, "root"}, strings.Split(q, " ")...)
			if err := l.nsRun(pub, append([]string{"tc"}, args...)...); err != nil {
				return fmt.Errorf("tc on %s: %w", ifname, err)
			}
		}
	}
	log.Printf("netem: %q applied on pa1+pb1", spec)
	return nil
}

// nsPID returns the PID of a named netns, or 0.
func (l *lab) nsPID(name string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, n := range l.nses {
		if n.name == name {
			return n.pid
		}
	}
	return 0
}

// findInviteCode returns the first invite code found in any of the given output
// buffers. The CLI prints the invite frame on stderr, but keep scanning stdout too so
// the extractor is robust to output placement.
func findInviteCode(buffers ...string) string {
	for _, b := range buffers {
		if m := codeRe.FindString(b); m != "" {
			return m
		}
	}
	return ""
}

// runTransfer runs one CLI transfer with the given NAT policies and reports the
// transport that carried it and (if -measure) the sender's time to the selected transport.
func (l *lab) runTransfer(polA, polB string) (bool, string, int64, error) {
	dst := l.comboDstDir()
	if l.noproxy {
		// Relay-path control: no NAT boxes, both peers sit in the public segment.
		return l.runPlainRelay(dst)
	}
	l.mu.Lock()
	var natA, natB, nsA, nsB, pub *netns
	for _, n := range l.nses {
		switch n.name {
		case "a":
			nsA = n
		case "natA":
			natA = n
		case "natB":
			natB = n
		case "b":
			nsB = n
		case "pub":
			pub = n
		}
	}
	l.mu.Unlock()

	spawnBox := func(ns *netns, pol, privIP, privIf, pubIf, pubIP string) error {
		c, err := l.nsSpawn(ns, nil, l.natbox,
			"-priv-if", privIf, "-priv-ip", privIP,
			"-pub-if", pubIf, "-pub-ip", pubIP,
			"-policy", pol,
			"-tcp-forward", pubHost+":8443")
		if err != nil {
			return err
		}
		l.mu.Lock()
		l.procs = append(l.procs, c)
		l.mu.Unlock()
		return nil
	}
	if err := spawnBox(natA, polA, privAIP, "a1", "pa0", "10.0.3.1"); err != nil {
		return false, "", -1, fmt.Errorf("natbox A: %w", err)
	}
	if err := spawnBox(natB, polB, privBIP, "b1", "pb0", "10.0.3.2"); err != nil {
		return false, "", -1, fmt.Errorf("natbox B: %w", err)
	}
	defer l.killCombo()

	sender := exec.Command("nsenter", "-t", fmt.Sprint(nsA.pid), "-n",
		l.sendbeam, "send", l.src,
		"--server", "ws://"+privAIP+":8443/ws",
		"--ice-server", "stun:"+pubHost+":3478")
	var senderOut, senderErr strings.Builder
	sender.Stdout = &senderOut
	sender.Stderr = &senderErr
	if err := sender.Start(); err != nil {
		return false, "", -1, fmt.Errorf("start sender: %w", err)
	}
	senderStart := time.Now()
	l.mu.Lock()
	l.procs = append(l.procs, sender)
	l.mu.Unlock()

	code := ""
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if code = findInviteCode(senderOut.String(), senderErr.String()); code != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code == "" {
		_ = sender.Process.Kill()
		return false, "", -1, fmt.Errorf("no invite code from sender: %s", senderErr.String())
	}

	receiver := exec.Command("nsenter", "-t", fmt.Sprint(nsB.pid), "-n",
		l.sendbeam, "receive", code,
		"--server", "ws://"+privBIP+":8443/ws",
		"--ice-server", "stun:"+pubHost+":3478",
		"--out", dst)
	var recvOut, recvErr strings.Builder
	receiver.Stdout = &recvOut
	receiver.Stderr = &recvErr
	if err := receiver.Start(); err != nil {
		return false, "", -1, fmt.Errorf("start receiver: %w", err)
	}
	l.mu.Lock()
	l.procs = append(l.procs, receiver)
	l.mu.Unlock()

	// Watch the sender's stderr for the transport-selection line to time how long the
	// restrictive network takes to engage its chosen path (the adaptive-policy fallback
	// timing that matters for the release gate).
	var pathMs int64 = -1
	done := make(chan error, 1)
	go func() { done <- receiver.Wait() }()
	pathTicker := time.NewTicker(50 * time.Millisecond)
	defer pathTicker.Stop()
	pathWatched := make(chan struct{})
	go func() {
		defer close(pathWatched)
		for range pathTicker.C {
			if strings.Contains(senderErr.String(), "Transport:") {
				pathMs = time.Since(senderStart).Milliseconds()
				return
			}
		}
	}()

	snap := time.NewTicker(2 * time.Second)
	defer snap.Stop()
	go func() {
		for range snap.C {
			for _, n := range []*netns{nsB, natB, pub} {
				out, err := exec.Command("nsenter", "-t", fmt.Sprint(n.pid), "-n", "ss", "-tinp").CombinedOutput()
				if err == nil {
					fmt.Fprintf(os.Stderr, "--- sockets in %s ---\n%s", n.name, out)
				}
			}
		}
	}()
	select {
	case err := <-done:
		<-pathWatched
		if err != nil {
			_ = sender.Process.Kill()
			return false, "", pathMs, fmt.Errorf("receiver failed: %v\n--- receiver ---\n%s\n--- sender ---\n%s", err, recvErr.String(), senderErr.String())
		}
	case <-time.After(120 * time.Second):
		_ = receiver.Process.Kill()
		_ = sender.Process.Kill()
		return false, "", pathMs, fmt.Errorf("transfer timed out\n--- receiver ---\n%s\n--- sender ---\n%s", recvErr.String(), senderErr.String())
	}
	_ = sender.Wait()
	l.lastRecvRSS = peakRSS(receiver.Process.Pid)

	transport := "?"
	joined := recvErr.String() + "\n" + senderErr.String()
	switch {
	case strings.Contains(joined, "Transport: direct WebRTC"):
		transport = "direct"
	case strings.Contains(joined, "Transport: encrypted WebSocket relay"):
		transport = "relay"
	}

	got, err := os.ReadFile(filepath.Join(dst, filepath.Base(l.src)))
	if err != nil {
		return false, transport, pathMs, fmt.Errorf("read received file: %w\n--- receiver ---\n%s\n--- sender ---\n%s", err, recvErr.String(), senderErr.String())
	}
	return sha256.Sum256(got) == l.expect, transport, pathMs, nil
}

// comboDstDir returns a fresh output directory for each combo; the CLI's sink
// refuses to overwrite existing files.
func (l *lab) comboDstDir() string {
	l.dstDir = filepath.Join(filepath.Dir(l.dstDir), fmt.Sprintf("natlab-recv-%d-%d", os.Getpid(), time.Now().UnixNano()))
	_ = os.MkdirAll(l.dstDir, 0o755)
	return l.dstDir
}

// runPlainRelay is a no-NAT control: both peers run in the public segment over the
// forced relay, isolating the relay path from the NAT boxes.
func (l *lab) runPlainRelay(dst string) (bool, string, int64, error) {
	l.mu.Lock()
	var pub *netns
	for _, n := range l.nses {
		if n.name == "pub" {
			pub = n
		}
	}
	l.mu.Unlock()

	// Preflight: the pub netns must reach the signaling port directly.
	probe := exec.Command("nsenter", "-t", fmt.Sprint(pub.pid), "-n",
		"bash", "-c",
		"echo '--- ip:'; ip -br a; echo '--- route:'; ip route; echo '--- listen:'; ss -tln | head -5; echo '--- tcp test:'; timeout 3 bash -c 'echo > /dev/tcp/"+pubHost+"/8443' && echo tcp-ok || echo tcp-fail")
	if out, err := probe.CombinedOutput(); err != nil {
		log.Printf("plain relay preflight (rc=%v):\n%s", err, out)
	} else {
		log.Printf("plain relay preflight:\n%s", out)
	}

	runPeer := func(role string, args ...string) (*exec.Cmd, *strings.Builder, *strings.Builder, error) {
		argv := append([]string{l.sendbeam, role, "--relay-only", "--server", "ws://" + pubHost + ":8443/ws"}, args...)
		c := exec.Command("nsenter", append([]string{"-t", fmt.Sprint(pub.pid), "-n"}, argv...)...)
		var out, errb strings.Builder
		c.Stdout = &out
		c.Stderr = &errb
		if err := c.Start(); err != nil {
			return nil, nil, nil, err
		}
		l.mu.Lock()
		l.procs = append(l.procs, c)
		l.mu.Unlock()
		return c, &out, &errb, nil
	}

	sender, senderOut, senderErr, err := runPeer("send", l.src)
	if err != nil {
		return false, "", -1, fmt.Errorf("start sender: %w", err)
	}
	senderStart := time.Now()
	code := ""
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if code = findInviteCode(senderOut.String(), senderErr.String()); code != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code == "" {
		_ = sender.Process.Kill()
		return false, "", -1, fmt.Errorf("no invite code from sender: %s", senderErr.String())
	}
	receiver, _, recvErr, err := runPeer("receive", code, "--out", dst)
	if err != nil {
		return false, "", -1, fmt.Errorf("start receiver: %w", err)
	}
	var pathMs int64 = -1
	done := make(chan error, 1)
	go func() { done <- receiver.Wait() }()
	pathTicker := time.NewTicker(50 * time.Millisecond)
	defer pathTicker.Stop()
	pathWatched := make(chan struct{})
	go func() {
		defer close(pathWatched)
		for range pathTicker.C {
			if strings.Contains(senderErr.String(), "Transport:") {
				pathMs = time.Since(senderStart).Milliseconds()
				return
			}
		}
	}()
	select {
	case err := <-done:
		<-pathWatched
		if err != nil {
			_ = sender.Process.Kill()
			return false, "", pathMs, fmt.Errorf("receiver failed: %v\n--- receiver stderr ---\n%s\n--- sender stderr ---\n%s", err, recvErr.String(), senderErr.String())
		}
	case <-time.After(60 * time.Second):
		_ = receiver.Process.Kill()
		_ = sender.Process.Kill()
		return false, "", pathMs, fmt.Errorf("plain relay timed out")
	}
	_ = sender.Wait()
	l.lastRecvRSS = peakRSS(receiver.Process.Pid)
	got, err := os.ReadFile(filepath.Join(dst, filepath.Base(l.src)))
	if err != nil {
		return false, "relay", pathMs, fmt.Errorf("read received file: %w\n--- receiver ---\n%s\n--- sender ---\n%s", err, recvErr.String(), senderErr.String())
	}
	return sha256.Sum256(got) == l.expect, "relay", pathMs, nil
}

// peakRSS reads a process's VmRSS (KiB) from /proc. Returns 0 if the process or its stat
// is unavailable (it may already be reaped). Used by -measure memory instrumentation.
func peakRSS(pid int) int64 {
	if pid <= 0 {
		return 0
	}
	b, err := os.ReadFile(filepath.Join("/proc", fmt.Sprint(pid), "status"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var v int64
				if _, err := fmt.Sscanf(fields[1], "%d", &v); err == nil {
					return v
				}
			}
			return 0
		}
	}
	return 0
}

func moduleRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", fmt.Errorf("no go.mod found above %q; run natlab from the apps/cli module", wd)
		}
		wd = parent
	}
}
