package upstream_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/holandyoung/dnsproxy/dnsproxytest"
	"github.com/holandyoung/dnsproxy/internal/bootstrap"
	"github.com/holandyoung/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUpstreamResolver(t *testing.T) {
	ups := &dnsproxytest.Upstream{
		OnAddress: func() (_ string) { panic(testutil.UnexpectedCall()) },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			resp = (&dns.Msg{}).SetReply(req)
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: netip.MustParseAddr("1.2.3.4").AsSlice(),
			}}

			return resp, nil
		},
	}

	r := &upstream.UpstreamResolver{Upstream: ups}

	ipAddrs, err := r.LookupNetIP(context.Background(), "ip", "cloudflare-dns.com")
	require.NoError(t, err)

	assert.NotEmpty(t, ipAddrs)
}

func TestCachingResolver_staleness(t *testing.T) {
	ip4 := netip.MustParseAddr("1.2.3.4")
	ip6 := netip.MustParseAddr("2001:db8::1")

	const (
		smallTTL = 10 * time.Second
		largeTTL = 1000 * time.Second

		fqdn = "test.fully.qualified.name."
	)

	onExchange := func(req *dns.Msg) (resp *dns.Msg, err error) {
		resp = (&dns.Msg{}).SetReply(req)

		hdr := dns.RR_Header{
			Name:   req.Question[0].Name,
			Rrtype: req.Question[0].Qtype,
			Class:  dns.ClassINET,
		}
		var rr dns.RR
		switch q := req.Question[0]; q.Qtype {
		case dns.TypeA:
			hdr.Ttl = uint32(smallTTL.Seconds())
			rr = &dns.A{Hdr: hdr, A: ip4.AsSlice()}
		case dns.TypeAAAA:
			hdr.Ttl = uint32(largeTTL.Seconds())
			rr = &dns.AAAA{Hdr: hdr, AAAA: ip6.AsSlice()}
		default:
			require.Contains(testutil.PanicT{}, []uint16{dns.TypeA, dns.TypeAAAA}, q.Qtype)
		}
		resp.Answer = append(resp.Answer, rr)

		return resp, nil
	}

	ups := &dnsproxytest.Upstream{
		OnAddress:  func() (_ string) { panic(testutil.UnexpectedCall()) },
		OnClose:    func() (_ error) { panic(testutil.UnexpectedCall()) },
		OnExchange: onExchange,
	}

	r := upstream.NewCachingResolver(&upstream.UpstreamResolver{Upstream: ups})

	require.True(t, t.Run("resolve", func(t *testing.T) {
		testCases := []struct {
			name    string
			network bootstrap.Network
			want    []netip.Addr
		}{{
			name:    "ip4",
			network: bootstrap.NetworkIP4,
			want:    []netip.Addr{ip4},
		}, {
			name:    "ip6",
			network: bootstrap.NetworkIP6,
			want:    []netip.Addr{ip6},
		}, {
			name:    "both",
			network: bootstrap.NetworkIP,
			want:    []netip.Addr{ip4, ip6},
		}}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				if tc.name != "both" {
					t.Skip(`TODO(e.burkov):  Bootstrap now only uses "ip" network, see TODO there.`)
				}

				res, err := r.LookupNetIP(context.Background(), tc.network, fqdn)
				require.NoError(t, err)

				assert.ElementsMatch(t, tc.want, res)
			})
		}
	}))

	t.Run("staleness", func(t *testing.T) {
		now := time.Now()
		cached := r.FindCached(fqdn, now)
		require.ElementsMatch(t, []netip.Addr{ip4, ip6}, cached)

		cached = r.FindCached(fqdn, now.Add(smallTTL+time.Second))
		require.Empty(t, cached)
	})
}
