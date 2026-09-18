// Package proxyutil contains helper functions that are used in all other
// dnsproxy packages.
package proxyutil

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"

	"github.com/miekg/dns"
)

// LengthPrefix validates a DNS stream frame size before encoding its two-byte
// length. Callers must validate before publishing a frame or opening a stream.
func LengthPrefix(size int) (prefix [2]byte, err error) {
	if size < 0 || size > math.MaxUint16 {
		return prefix, fmt.Errorf("DNS frame length %d is outside 0..65535", size)
	}
	binary.BigEndian.PutUint16(prefix[:], uint16(size))
	return prefix, nil
}

// IPFromRR returns the IP address from rr if any.
func IPFromRR(rr dns.RR) (ip netip.Addr) {
	var data []byte
	switch rr := rr.(type) {
	case *dns.A:
		data = rr.A.To4()
	case *dns.AAAA:
		data = rr.AAAA
	default:
		return netip.Addr{}
	}

	ip, _ = netip.AddrFromSlice(data)

	return ip
}
