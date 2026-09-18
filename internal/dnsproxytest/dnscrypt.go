package dnsproxytest

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/holandyoung/dnsproxy/dnscrypt"

	"github.com/jedisct1/go-dnsstamps"
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
	var addr netip.AddrPort
	paired := false
	for range 16 {
		tcp, createErr := dnscrypt.NewServer(&dnscrypt.ServerConfig{Handler: h, ResolverCert: cert, Logger: slog.New(slog.DiscardHandler), ProviderName: rc.ProviderName, Addr: netip.AddrPortFrom(netutil.IPv4Localhost(), 0), Proto: dnscrypt.ProtoTCP})
		require.NoError(tb, createErr)
		startErr := tcp.Start(context.Background())
		require.NoError(tb, startErr)
		addr = netutil.NetAddrToAddrPort(tcp.LocalAddr())
		udp, createErr := dnscrypt.NewServer(&dnscrypt.ServerConfig{Handler: h, ResolverCert: cert, Logger: slog.New(slog.DiscardHandler), ProviderName: rc.ProviderName, Addr: addr, Proto: dnscrypt.ProtoUDP})
		require.NoError(tb, createErr)
		startErr = udp.Start(context.Background())
		if startErr != nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			closeErr := tcp.Shutdown(ctx)
			cancel()
			require.NoError(tb, closeErr)
			if errors.Is(startErr, syscall.EADDRINUSE) {
				continue
			}
			require.NoError(tb, startErr)
		}
		tb.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			require.NoError(tb, errors.Join(udp.Shutdown(ctx), tcp.Shutdown(ctx)))
		})
		paired = true
		break
	}
	require.True(tb, paired, "could not start DNSCrypt on one TCP/UDP port")
	stamp, err := rc.CreateStamp(addr.String())
	require.NoError(tb, err)
	return stamp
}
