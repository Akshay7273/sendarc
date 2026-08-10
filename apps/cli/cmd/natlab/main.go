// Command natlab runs a hermetic NAT lab for SendArc's transport selection. It builds
// two isolated private networks, each behind a userspace NAT box (cmd/natbox) with a
// configurable mapping policy, joined by a shared public segment that hosts a signaling
// server (sendarcd) and a STUN server (cmd/stund). For each policy pair it runs one real
// CLI transfer and reports whether the file moved over the direct WebRTC path or fell
// back to the encrypted relay, then verifies the received bytes.
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
	serverBin := flag.String("server-bin", "", "path to the built sendarcd binary (required)")
	combos := flag.String("combos",
		"full-cone/full-cone,restricted/restricted,port-restricted/port-restricted,symmetric/symmetric,full-cone/symmetric",
		"comma-separated NAT policy pairs (A/B)")
	noproxy := flag.Bool("noproxy", false, "skip NAT boxes: both peers run in the public segment over forced relay (control)")
	netem := flag.String("netem", "", "degraded-network profile applied to both bridge legs: 'loss 3%', 'delay 50ms', or 'rate 10mbit'")
	flag.Parse()

	if os.Geteuid() != 0 {
		log.Fatal("natlab: must run as root inside a user namespace: unshare -Urnm natlab [flags]")
	}
	if *serverBin == "" {
		log.Fatal("natlab: -server-bin is required (build apps/server/cmd/sendarcd first)")
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
	sendarc := binPath("sendarc", "./cmd/sendarc")
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
		sendarc: sendarc,
		natbox:  natbox,
		stund:   stund,
		server:  *serverBin,
		src:     src,
		dstDir:  dstDir,
		expect:  sha256.Sum256(payload),
		noproxy: *noproxy,
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
	for _, pair := range pairs {
		start := time.Now()
		ok, transport, err := lab.runTransfer(pair[0], pair[1])
		if err != nil {
			log.Printf("combo %s/%s: ERROR after %v: %v", pair[0], pair[1], time.Since(start).Round(time.Millisecond), err)
			failed = true
			continue
		}
		log.Printf("combo %s/%s: %s, digest %t, %v", pair[0], pair[1], transport, ok, time.Since(start).Round(time.Millisecond))
		if !ok {
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

type lab struct {
	sendarc, natbox, stund, server string
	src, dstDir                    string
	expect                         [32]byte
	noproxy                        bool

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
	if c, err := l.nsSpawn(pub, []string{"SENDARC_ADDR=" + pubHost + ":8443"}, l.server); err != nil {
		return fmt.Errorf("sendarcd: %w", err)
	} else {
		l.mu.Lock()
		l.keep = append(l.keep, c)
		l.mu.Unlock()
	}
	if c, err := l.nsSpawn(pub, nil, l.stund, "-addr", pubHost+":3478"); err != nil {
		return fmt.Errorf("stund: %w", err)
	} else {
		l.mu.Lock()
		l.keep = append(l.keep, c)
		l.mu.Unlock()
	}

	time.Sleep(500 * time.Millisecond)
	return nil
}

// applyNetem shapes the egress of both public bridge legs (pa1, pb1) so the
// sender→receiver downlink experiences the given profile on the direct path and
// the server→receiver relay leg. One qdisc per profile; loss and delay use netem,
// rate limits use netem's own rate control (it segments like the real bottleneck).
func (l *lab) applyNetem(spec string) error {
	var qdisc string
	switch {
	case strings.HasPrefix(spec, "loss "):
		qdisc = "netem loss " + strings.TrimPrefix(spec, "loss ")
	case strings.HasPrefix(spec, "delay "):
		qdisc = "netem delay " + strings.TrimPrefix(spec, "delay ")
	case strings.HasPrefix(spec, "rate "):
		qdisc = "netem rate " + strings.TrimPrefix(spec, "rate ")
	default:
		return fmt.Errorf("unsupported netem profile %q (want 'loss 3%%', 'delay 50ms', or 'rate 10mbit')", spec)
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
		args := append([]string{"qdisc", "add", "dev", ifname, "root"}, strings.Split(qdisc, " ")...)
		if err := l.nsRun(pub, append([]string{"tc"}, args...)...); err != nil {
			return fmt.Errorf("tc on %s: %w", ifname, err)
		}
	}
	log.Printf("netem: %q applied on pa1+pb1", qdisc)
	return nil
}

// runTransfer runs one CLI transfer with the given NAT policies and reports the
// transport that carried it.
func (l *lab) runTransfer(polA, polB string) (bool, string, error) {
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
		return false, "", fmt.Errorf("natbox A: %w", err)
	}
	if err := spawnBox(natB, polB, privBIP, "b1", "pb0", "10.0.3.2"); err != nil {
		return false, "", fmt.Errorf("natbox B: %w", err)
	}
	defer l.killCombo()

	sender := exec.Command("nsenter", "-t", fmt.Sprint(nsA.pid), "-n",
		l.sendarc, "send", l.src,
		"--server", "ws://"+privAIP+":8443/ws",
		"--ice-server", "stun:"+pubHost+":3478")
	var senderOut, senderErr strings.Builder
	sender.Stdout = &senderOut
	sender.Stderr = &senderErr
	if err := sender.Start(); err != nil {
		return false, "", fmt.Errorf("start sender: %w", err)
	}
	l.mu.Lock()
	l.procs = append(l.procs, sender)
	l.mu.Unlock()

	code := ""
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if m := codeRe.FindString(senderOut.String()); m != "" {
			code = m
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code == "" {
		_ = sender.Process.Kill()
		return false, "", fmt.Errorf("no invite code from sender: %s", senderErr.String())
	}

	receiver := exec.Command("nsenter", "-t", fmt.Sprint(nsB.pid), "-n",
		l.sendarc, "receive", code,
		"--server", "ws://"+privBIP+":8443/ws",
		"--ice-server", "stun:"+pubHost+":3478",
		"--out", dst)
	var recvOut, recvErr strings.Builder
	receiver.Stdout = &recvOut
	receiver.Stderr = &recvErr
	if err := receiver.Start(); err != nil {
		return false, "", fmt.Errorf("start receiver: %w", err)
	}
	l.mu.Lock()
	l.procs = append(l.procs, receiver)
	l.mu.Unlock()

	done := make(chan error, 1)
	go func() { done <- receiver.Wait() }()
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
		if err != nil {
			_ = sender.Process.Kill()
			return false, "", fmt.Errorf("receiver failed: %v\n--- receiver ---\n%s\n--- sender ---\n%s", err, recvErr.String(), senderErr.String())
		}
	case <-time.After(120 * time.Second):
		_ = receiver.Process.Kill()
		_ = sender.Process.Kill()
		return false, "", fmt.Errorf("transfer timed out\n--- receiver ---\n%s\n--- sender ---\n%s", recvErr.String(), senderErr.String())
	}
	_ = sender.Wait()

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
		return false, transport, fmt.Errorf("read received file: %w\n--- receiver ---\n%s\n--- sender ---\n%s", err, recvErr.String(), senderErr.String())
	}
	return sha256.Sum256(got) == l.expect, transport, nil
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
func (l *lab) runPlainRelay(dst string) (bool, string, error) {
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
		argv := append([]string{l.sendarc, role, "--relay-only", "--server", "ws://" + pubHost + ":8443/ws"}, args...)
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
		return false, "", fmt.Errorf("start sender: %w", err)
	}
	code := ""
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if m := codeRe.FindString(senderOut.String()); m != "" {
			code = m
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code == "" {
		_ = sender.Process.Kill()
		return false, "", fmt.Errorf("no invite code from sender: %s", senderErr.String())
	}
	receiver, _, recvErr, err := runPeer("receive", code, "--out", dst)
	if err != nil {
		return false, "", fmt.Errorf("start receiver: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- receiver.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			_ = sender.Process.Kill()
			return false, "", fmt.Errorf("receiver failed: %v\n--- receiver stderr ---\n%s\n--- sender stderr ---\n%s", err, recvErr.String(), senderErr.String())
		}
	case <-time.After(60 * time.Second):
		_ = receiver.Process.Kill()
		_ = sender.Process.Kill()
		return false, "", fmt.Errorf("plain relay timed out")
	}
	_ = sender.Wait()
	got, err := os.ReadFile(filepath.Join(dst, filepath.Base(l.src)))
	if err != nil {
		return false, "relay", fmt.Errorf("read received file: %w\n--- receiver ---\n%s\n--- sender ---\n%s", err, recvErr.String(), senderErr.String())
	}
	return sha256.Sum256(got) == l.expect, "relay", nil
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
