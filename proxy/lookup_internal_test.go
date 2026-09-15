package proxy

import (
	"context"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"net"
	"net/netip"
	"testing"

	"github.com/holandyoung/dnsproxy/upstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupNetIP(t *testing.T) {
	address := newLocalUpstreamListener(t, 0, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		response := new(dns.Msg).SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			for _, ip := range []string{"8.8.8.8", "8.8.4.4"} {
				response.Answer = append(response.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)})
			}
		}
		if r.Question[0].Qtype == dns.TypeAAAA {
			for _, ip := range []string{"2001:4860:4860::8888", "2001:4860:4860::8844"} {
				response.Answer = append(response.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP(ip)})
			}
		}
		require.NoError(testutil.PanicT{}, w.WriteMsg(response))
	}))
	dnsUpstream, err := upstream.AddressToUpstream(
		"tcp://"+address.String(),
		&upstream.Options{
			Logger:  testLogger,
			Timeout: defaultTimeout,
		},
	)
	require.NoError(t, err)

	conf := &Config{
		Logger: testLogger,
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{dnsUpstream},
		},
	}

	p, err := New(conf)
	require.NoError(t, err)

	defer dnsUpstream.Close()
	// Now let's try doing some lookups.
	addrs, err := p.LookupNetIP(context.Background(), "", "dns.google")
	require.NoError(t, err)
	require.NotEmpty(t, addrs)

	assert.Contains(t, addrs, netip.MustParseAddr("8.8.8.8"))
	assert.Contains(t, addrs, netip.MustParseAddr("8.8.4.4"))
	if len(addrs) > 2 {
		assert.Contains(t, addrs, netip.MustParseAddr("2001:4860:4860::8888"))
		assert.Contains(t, addrs, netip.MustParseAddr("2001:4860:4860::8844"))
	}
}
