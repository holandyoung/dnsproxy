package ratelimit_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/holandyoung/dnsproxy/proxy"
	"github.com/holandyoung/dnsproxy/ratelimit"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_ZonePreservesAllowlistAndReplyAddress(t *testing.T) {
	for _, address := range []string{"[fe80::1]:12345", "[fe80::1%eth0]:12345", "[fe80::1%eth1]:12345", "[::ffff:192.0.2.1]:12345"} {
		t.Run(address, func(t *testing.T) {
			peer := netip.MustParseAddrPort(address)
			calls := 0
			middleware := ratelimit.NewMiddleware(&ratelimit.Config{
				Logger: testLogger, Ratelimit: 1, SubnetLenIPv4: 24, SubnetLenIPv6: 56,
				AllowlistAddrs: netutil.SliceSubnetSet{netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("192.0.2.0/24")},
			})
			handler := middleware.Wrap(proxy.HandlerFunc(func(_ context.Context, _ *proxy.Proxy, d *proxy.DNSContext) error {
				calls++
				require.Equal(t, peer, d.Addr, "the actual reply address must retain its zone")
				return nil
			}))
			d := &proxy.DNSContext{Addr: peer, Proto: proxy.ProtoUDP}
			require.NoError(t, handler.ServeDNS(t.Context(), nil, d), "valid request prerequisite")
			require.NoError(t, handler.ServeDNS(t.Context(), nil, d), "allowlisted peer must bypass an exhausted bucket")
			require.Equal(t, 2, calls)
		})
	}
}
