package dnsproxytest

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// DNSCryptHandler adapts a fixture function to a native DNSCrypt server.
type DNSCryptHandler func(context.Context, dnscrypt.ResponseWriter, *dns.Msg) error

func (h DNSCryptHandler) ServeDNS(ctx context.Context, w dnscrypt.ResponseWriter, r *dns.Msg) error {
	return h(ctx, w, r)
}

// StartDNSCryptServer serves UDP and TCP on the same local port with a real
// generated certificate. Its lifecycle belongs to the calling test.
func StartDNSCryptServer(tb testing.TB, rc dnscrypt.ResolverConfig, h dnscrypt.Handler) dnsstamps.ServerStamp {
	tb.Helper()
	cert, err := rc.NewCert()
	require.NoError(tb, err)
	addr := netip.AddrPortFrom(netutil.IPv4Localhost(), 0)
	for _, proto := range []dnscrypt.Proto{dnscrypt.ProtoUDP, dnscrypt.ProtoTCP} {
		srv, startErr := dnscrypt.NewServer(&dnscrypt.ServerConfig{
			Handler: h, ResolverCert: cert, Logger: slog.New(slog.DiscardHandler), ProviderName: rc.ProviderName, Addr: addr, Proto: proto,
		})
		require.NoError(tb, startErr)
		servicetest.RequireRun(tb, srv, time.Second)
		addr = netutil.NetAddrToAddrPort(srv.LocalAddr())
	}
	stamp, err := rc.CreateStamp(addr.String())
	require.NoError(tb, err)
	return stamp
}
