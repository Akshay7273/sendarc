// Command natbox is a userspace NAT used by the NAT lab (cmd/natlab). It sits between a
// private network segment and a public one, translating UDP 5-tuples exactly as a
// residential gateway would, with a configurable mapping policy:
//
//	full-cone       one external port per internal flow; inbound from anyone
//	restricted      one external port per internal flow; inbound from hosts we sent to
//	port-restricted one external port per internal flow; inbound from (host, port) pairs
//	                we sent to
//	symmetric       a fresh external port per destination (host, port); inbound only from
//	                that exact destination
//
// The private side is a raw AF_PACKET socket on a veth: outbound frames are parsed and
// re-encapsulated through kernel UDP sockets bound on the public interface (the mapped
// address), so no packet mangling or checksum surgery is needed. Kernel ip_forward must
// be off in this namespace — the daemon is the only forwarder. TCP (the lab's signaling
// WebSocket) is handled by a plain port-forwarding proxy to the public server.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"

	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const ethPAll = 0x0003 // ETH_P_ALL

type policy int

const (
	policyFullCone policy = iota
	policyRestricted
	policyPortRestricted
	policySymmetric
)

func parsePolicy(s string) (policy, error) {
	switch s {
	case "full-cone":
		return policyFullCone, nil
	case "restricted":
		return policyRestricted, nil
	case "port-restricted":
		return policyPortRestricted, nil
	case "symmetric":
		return policySymmetric, nil
	}
	return 0, fmt.Errorf("unknown policy %q", s)
}

// mapping is one translated UDP flow: the internal endpoint, the pinned external
// destination (symmetric only), and the set of destinations it has spoken to.
type mapping struct {
	internal netip.AddrPort
	dst      netip.AddrPort // pinned destination for symmetric; zero otherwise
	allowed  map[netip.AddrPort]struct{}
	conn     *net.UDPConn
	lastSeen time.Time
}

type natbox struct {
	policy  policy
	pubIP   netip.Addr
	privIP  netip.Addr
	privMAC [6]byte
	peerMAC [6]byte
	ifindex int
	raw     int

	mu       sync.Mutex
	mappings map[string]*mapping // key: internal string, or internal>dst for symmetric
	logged   atomic.Bool
}

func main() {
	privIf := flag.String("priv-if", "", "private-side veth interface name")
	privIP := flag.String("priv-ip", "", "private-side IP address")
	pubIf := flag.String("pub-if", "", "public-side veth interface name (for MAC resolution only)")
	pubIP := flag.String("pub-ip", "", "public-side IP address")
	pol := flag.String("policy", "full-cone", "full-cone | restricted | port-restricted | symmetric")
	proxy := flag.String("tcp-forward", "", "destination host:port for a TCP proxy bound on priv-ip:8443")
	flag.Parse()

	if *privIf == "" || *privIP == "" || *pubIf == "" || *pubIP == "" {
		log.Fatal("natbox: -priv-if, -priv-ip, -pub-if, -pub-ip are required")
	}
	p, err := parsePolicy(*pol)
	if err != nil {
		log.Fatal(err)
	}

	raw, err := openPacketSocket(*privIf)
	if err != nil {
		log.Fatalf("natbox: %v", err)
	}
	mac, err := ifaceMAC(*privIf)
	if err != nil {
		log.Fatalf("natbox: %v", err)
	}

	n := &natbox{
		policy:   p,
		pubIP:    netip.MustParseAddr(*pubIP),
		privIP:   netip.MustParseAddr(*privIP),
		privMAC:  mac,
		ifindex:  ifindex(*privIf),
		raw:      raw,
		mappings: make(map[string]*mapping),
	}

	if *proxy != "" {
		go n.tcpProxy(*proxy)
	}
	go n.sweeper()

	fmt.Fprintf(os.Stderr, "natbox: policy=%s private=%s(%s) public=%s\n", *pol, *privIf, *privIP, *pubIP)
	if err := n.serve(); err != nil {
		log.Fatalf("natbox: %v", err)
	}
}

func (n *natbox) serve() error {
	buf := make([]byte, 64*1024)
	for {
		rn, _, err := syscall.Recvfrom(n.raw, buf, 0)
		if err != nil {
			return err
		}
		n.handleFrame(buf[:rn])
	}
}

func (n *natbox) handleFrame(frame []byte) {
	if len(frame) < 14+20+8 {
		return
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 { // IPv4 only; ARP rides the kernel
		return
	}
	ip := frame[14:]
	if ip[0]>>4 != 4 || ip[9] != 17 { // UDP only; TCP rides the proxy
		return
	}
	ihl := int(ip[0]&0x0f) * 4
	if len(ip) < ihl+8 {
		return
	}
	src := netip.AddrFrom4([4]byte(ip[12:16]))
	dst := netip.AddrFrom4([4]byte(ip[16:20]))
	udp := ip[ihl:]
	if len(udp) < 8 {
		return
	}
	internal := netip.AddrPortFrom(src, binary.BigEndian.Uint16(udp[0:2]))
	ext := netip.AddrPortFrom(dst, binary.BigEndian.Uint16(udp[2:4]))

	fragOff := binary.BigEndian.Uint16(ip[6:8])
	if fragOff&0x1fff != 0 {
		// Non-initial IP fragment: WebRTC traffic is small enough to never fragment on a
		// 9 KB MTU; drop defensively.
		log.Printf("natbox: dropping non-initial fragment from %s", src)
		return
	}
	payload := udp[8:]

	n.mu.Lock()
	copy(n.peerMAC[:], frame[6:12]) // learn the peer's MAC from its own frames
	key, pin := n.key(internal, ext)
	m, ok := n.mappings[key]
	if !ok {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IP(n.pubIP.AsSlice()), Port: 0})
		if err != nil {
			log.Printf("natbox: open mapping: %v", err)
			n.mu.Unlock()
			return
		}
		m = &mapping{
			internal: internal,
			dst:      pin,
			allowed:  make(map[netip.AddrPort]struct{}),
			conn:     conn,
		}
		n.mappings[key] = m
	}
	m.lastSeen = time.Now()
	m.allowed[ext] = struct{}{}
	n.mu.Unlock()
	if !ok {
		go n.pump(m)
	}

	if _, err := m.conn.WriteTo(payload, net.UDPAddrFromAddrPort(ext)); err != nil {
		// Unroutable destinations (e.g. a peer's private host candidate reaching the
		// public segment) are a normal part of ICE; log the first few only.
		if n.logged.CompareAndSwap(false, true) {
			log.Printf("natbox: forward: %v", err)
		}
	}
}

// pump reads datagrams that arrive on a mapping's external port and delivers them to
// the internal peer, enforcing the inbound policy.
func (n *natbox) pump(m *mapping) {
	buf := make([]byte, 64*1024)
	for {
		rn, raddr, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		src := raddr.AddrPort()
		if !n.allowInbound(m, src) {
			continue
		}
		n.inject(m, src, buf[:rn])
	}
}

func (n *natbox) allowInbound(m *mapping, src netip.AddrPort) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	switch n.policy {
	case policyFullCone:
		return true
	case policyRestricted:
		for a := range m.allowed {
			if a.Addr() == src.Addr() {
				return true
			}
		}
		return false
	case policyPortRestricted:
		_, ok := m.allowed[src]
		return ok
	case policySymmetric:
		return src == m.dst
	}
	return false
}

// inject rewrites an inbound datagram back to the internal peer as an Ethernet frame on
// the private veth.
func (n *natbox) inject(m *mapping, src netip.AddrPort, payload []byte) {
	if len(payload) > 0xffff-28 {
		return
	}
	ipLen := 20 + 8 + len(payload)
	frame := make([]byte, 14+ipLen)
	copy(frame[0:6], n.peerMAC[:])
	copy(frame[6:12], n.privMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	ip[8] = 64
	ip[9] = 17
	src4 := src.Addr().As4()
	dst4 := m.internal.Addr().As4()
	copy(ip[12:16], src4[:])
	copy(ip[16:20], dst4[:])
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip[:20]))

	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:2], src.Port())
	binary.BigEndian.PutUint16(udp[2:4], m.internal.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(src4, dst4, udp))

	if err := syscall.Sendto(n.raw, frame, 0, &syscall.SockaddrLinklayer{Ifindex: n.ifindex}); err != nil {
		log.Printf("natbox: inject: %v", err)
	}
}

func (n *natbox) key(internal, dst netip.AddrPort) (string, netip.AddrPort) {
	if n.policy == policySymmetric {
		return internal.String() + ">" + dst.String(), dst
	}
	return internal.String(), netip.AddrPort{}
}

// tcpProxy forwards priv-ip:8443 to the public signaling server.
func (n *natbox) tcpProxy(dst string) {
	l, err := net.Listen("tcp", net.JoinHostPort(n.privIP.String(), "8443"))
	if err != nil {
		log.Printf("natbox: tcp proxy: %v", err)
		return
	}
	defer func() { _ = l.Close() }()
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			up, err := net.DialTimeout("tcp", dst, 5*time.Second)
			if err != nil {
				log.Printf("natbox: tcp proxy dial: %v", err)
				return
			}
			defer func() { _ = up.Close() }()
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetNoDelay(true)
			}
			if tc, ok := up.(*net.TCPConn); ok {
				_ = tc.SetNoDelay(true)
			}
			done := make(chan struct{}, 2)
			go func() {
				n, err := relayCopy(up, c)
				log.Printf("natbox: tcp proxy c->up done: %d bytes: %v", n, err)
				done <- struct{}{}
			}()
			go func() {
				n, err := relayCopy(c, up)
				log.Printf("natbox: tcp proxy up->c done: %d bytes: %v", n, err)
				done <- struct{}{}
			}()
			<-done
			log.Printf("natbox: tcp proxy closed %s <-> %s", c.RemoteAddr(), up.RemoteAddr())
		}()
	}
}

// relayCopy moves bytes between two TCP sockets without the kernel splice fast path,
// which misbehaves over the lab's 9 KB-MTU veth pairs when flow control kicks in.
func relayCopy(dst, src net.Conn) (int64, error) {
	buf := make([]byte, 64*1024)
	var total int64
	for {
		start := time.Now()
		n, err := src.Read(buf)
		if n > 0 {
			wstart := time.Now()
			if _, werr := dst.Write(buf[:n]); werr != nil {
				log.Printf("natbox: relayCopy %s->%s chunk=%d r=%v w=%v werr=%v", src.RemoteAddr(), dst.RemoteAddr(), n, time.Since(start), time.Since(wstart), werr)
				return total, werr
			}
			total += int64(n)
			log.Printf("natbox: relayCopy %s->%s chunk=%d r=%v w=%v total=%d", src.RemoteAddr(), dst.RemoteAddr(), n, time.Since(start), time.Since(wstart), total)
		}
		if err != nil {
			return total, err
		}
	}
}

// sweeper expires stale UDP mappings.
func (n *natbox) sweeper() {
	t := time.NewTicker(30 * time.Second)
	for range t.C {
		n.mu.Lock()
		for k, m := range n.mappings {
			if time.Since(m.lastSeen) > 90*time.Second {
				_ = m.conn.Close()
				delete(n.mappings, k)
			}
		}
		n.mu.Unlock()
	}
}

// --- helpers ----------------------------------------------------------------

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func openPacketSocket(ifname string) (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return 0, err
	}
	sll := &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifindex(ifname), Pkttype: syscall.PACKET_HOST}
	if err := syscall.Bind(fd, sll); err != nil {
		return 0, err
	}
	return fd, nil
}

func ifindex(ifname string) int {
	ifc, err := net.InterfaceByName(ifname)
	if err != nil {
		return 0
	}
	return ifc.Index
}

func ifaceMAC(ifname string) ([6]byte, error) {
	ifc, err := net.InterfaceByName(ifname)
	if err != nil {
		return [6]byte{}, err
	}
	var mac [6]byte
	copy(mac[:], ifc.HardwareAddr)
	return mac, nil
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func udpChecksum(src4, dst4 [4]byte, udp []byte) uint16 {
	buf := make([]byte, 12+len(udp))
	copy(buf[0:4], src4[:])
	copy(buf[4:8], dst4[:])
	buf[9] = 17
	binary.BigEndian.PutUint16(buf[10:12], uint16(len(udp)))
	copy(buf[12:], udp)
	return checksum(buf)
}
