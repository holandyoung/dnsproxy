package dnscrypt

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestServerTCPPanicReleasesConnectionBeforeShutdown(t *testing.T) {
	rc, err := GenerateResolverConfig("panic.test", nil, time.Hour)
	require.NoError(t, err)
	cert, err := rc.NewCert()
	require.NoError(t, err)
	entered := make(chan struct{})
	var panicked atomic.Bool
	s, err := NewServer(&ServerConfig{
		ProviderName: rc.ProviderName, ResolverCert: cert, Proto: ProtoTCP,
		Addr: netip.MustParseAddrPort("127.0.0.1:0"), Logger: slog.New(slog.DiscardHandler),
		Handler: HandlerFunc(func(ctx context.Context, w ResponseWriter, req *dns.Msg) error {
			if !panicked.Swap(true) {
				close(entered)
				panic("encrypted handler panic")
			}
			return w.WriteMsg(ctx, new(dns.Msg).SetReply(req))
		}),
	})
	require.NoError(t, err)
	require.NoError(t, s.Start(t.Context()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, s.Shutdown(ctx))
	})
	publicKey, err := HexDecodeKey(rc.PublicKey)
	require.NoError(t, err)
	client := NewClient(&ClientConfig{Proto: ProtoTCP, Logger: slog.New(slog.DiscardHandler)})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	info, err := client.DialStampContext(ctx, dnsstamps.ServerStamp{ServerAddrStr: s.LocalAddr().String(), ServerPk: publicKey, ProviderName: rc.ProviderName, Proto: dnsstamps.StampProtoTypeDNSCrypt})
	require.NoError(t, err)
	_, err = client.ExchangeContext(ctx, new(dns.Msg).SetQuestion("panic.test.", dns.TypeA), info, nil)
	select {
	case <-entered:
	default:
		t.Fatal("encrypted request did not reach the panic boundary")
	}
	require.True(t, errors.Is(err, io.EOF), "panic must close the actual TCP socket before the client deadline: %v", err)
	require.Eventually(t, func() bool {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return len(s.tcpConns) == 0
	}, time.Second, time.Millisecond, "completed panic worker retained its accepted connection")
	require.True(t, s.isStarted(), "test must prove cleanup before shutdown")
	response, err := client.ExchangeContext(ctx, new(dns.Msg).SetQuestion("after-panic.test.", dns.TypeA), info, nil)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Equal(t, "after-panic.test.", response.Question[0].Name)
}
