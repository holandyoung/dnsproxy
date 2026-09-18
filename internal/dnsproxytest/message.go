package dnsproxytest

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// OversizedMessage packs successfully but cannot fit a 16-bit DNS frame.
func OversizedMessage(t testing.TB) *dns.Msg {
	t.Helper()
	m := (&dns.Msg{}).SetQuestion("large.test.", dns.TypeTXT)
	m.Response = true
	for range 65 {
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: "large.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{strings.Repeat("x", 255), strings.Repeat("y", 255), strings.Repeat("z", 255), strings.Repeat("a", 255)},
		})
	}
	wire, err := m.Pack()
	require.NoError(t, err)
	require.Greater(t, len(wire), 65535)
	return m
}
