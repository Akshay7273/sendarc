// Command stund is a minimal STUN (RFC 5389) binding-response server used by the NAT
// lab (cmd/natlab). It reports the source address it sees, exactly as a public STUN
// server would. In the lab the two NAT boxes translate requests before they reach us,
// so the reported address is the mapping's external (ip, port) — which is what makes
// the direct WebRTC path testable in a hermetic environment with no internet.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
)

const (
	stunBindingRequest  = 0x0001
	stunBindingResponse = 0x0101
	stunMagicCookie     = 0x2112a442
	stunAttrXorMapped   = 0x0020
)

func main() {
	addr := flag.String("addr", "0.0.0.0:3478", "listen address")
	flag.Parse()

	pc, err := net.ListenPacket("udp", *addr)
	if err != nil {
		log.Fatalf("stund: listen: %v", err)
	}
	defer func() { _ = pc.Close() }()
	fmt.Fprintf(os.Stderr, "stund: listening on %s\n", pc.LocalAddr())

	buf := make([]byte, 2048)
	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if resp := bindingResponse(buf[:n], raddr); resp != nil {
			if _, err := pc.WriteTo(resp, raddr); err != nil {
				log.Printf("stund: reply: %v", err)
			}
		}
	}
}

// bindingResponse answers a STUN binding request with an XOR-MAPPED-ADDRESS carrying
// the address the request was seen from. Returns nil for anything that is not a
// well-formed binding request.
func bindingResponse(req []byte, raddr net.Addr) []byte {
	if len(req) < 20 {
		return nil
	}
	typ := binary.BigEndian.Uint16(req[0:2])
	length := int(binary.BigEndian.Uint16(req[2:4]))
	if typ != stunBindingRequest || length != len(req)-20 || length > 0 {
		// Requests with attributes (e.g. FINGERPRINT) are fine; anything with a length
		// mismatch or attributes we cannot parse is still answerable for the lab.
		if typ != stunBindingRequest || length > len(req)-20 {
			return nil
		}
	}
	if binary.BigEndian.Uint32(req[4:8]) != stunMagicCookie {
		return nil
	}

	host, _, err := net.SplitHostPort(raddr.String())
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	_, portStr, err := net.SplitHostPort(raddr.String())
	if err != nil {
		return nil
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return nil
	}
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}

	// Header: type (response), length (8), cookie, transaction id.
	resp := make([]byte, 20+12)
	binary.BigEndian.PutUint16(resp[0:2], stunBindingResponse)
	binary.BigEndian.PutUint16(resp[2:4], 12)
	binary.BigEndian.PutUint32(resp[4:8], stunMagicCookie)
	copy(resp[8:20], req[8:20])

	// XOR-MAPPED-ADDRESS: reserved, family, XOR port, XOR address.
	attr := resp[20:]
	binary.BigEndian.PutUint16(attr[0:2], stunAttrXorMapped)
	binary.BigEndian.PutUint16(attr[2:4], 8)
	attr[4] = 0
	attr[5] = 0x01 // IPv4
	xorPort := port ^ (stunMagicCookie >> 16)
	binary.BigEndian.PutUint16(attr[6:8], xorPort)
	masked := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	masked ^= stunMagicCookie
	binary.BigEndian.PutUint32(attr[8:12], masked)
	return resp
}
