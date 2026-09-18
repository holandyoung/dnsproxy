package dnscrypt

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestListenerFailurePrecedesHandlerJoin(t *testing.T) {
	for _, proto := range []Proto{ProtoUDP, ProtoTCP} {
		t.Run(string(proto), func(t *testing.T) {
			rc, err := GenerateResolverConfig("example.org", nil, time.Hour)
			require.NoError(t, err)
			cert, err := rc.NewCert()
			require.NoError(t, err)
			failures := make(chan error, 1)
			entered, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			s, err := NewServer(&ServerConfig{
				Logger: slog.New(slog.DiscardHandler), ListenerFailures: failures,
				ProviderName: rc.ProviderName, ResolverCert: cert,
				Proto: proto, Addr: netip.MustParseAddrPort("127.0.0.1:0"),
				Handler: HandlerFunc(func(_ context.Context, _ ResponseWriter, _ *dns.Msg) error {
					close(entered)
					<-release
					return nil
				}),
			})
			require.NoError(t, err)
			require.NoError(t, s.Start(t.Context()))
			defer func() {
				unblock()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				require.NoError(t, s.Shutdown(ctx))
			}()
			stamp, err := rc.CreateStamp(s.LocalAddr().String())
			require.NoError(t, err)
			client := NewClient(&ClientConfig{Logger: slog.New(slog.DiscardHandler), Proto: proto})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			info, err := client.DialStampContext(ctx, stamp)
			require.NoError(t, err, "real certificate exchange before fault")
			exchangeDone := make(chan struct{})
			go func() {
				defer close(exchangeDone)
				_, _ = client.ExchangeContext(ctx, new(dns.Msg).SetQuestion("failure.example.", dns.TypeA), info, nil)
			}()
			defer func() { cancel(); <-exchangeDone }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("encrypted handler was not admitted")
			}
			addr := s.LocalAddr().String()
			if proto == ProtoTCP {
				err = s.tcpListener.Close()
			} else {
				err = s.udpConn.Close()
			}
			require.NoError(t, err)
			select {
			case failureErr := <-failures:
				require.ErrorContains(t, failureErr, "dnscrypt-"+string(proto)+" listener "+addr)
			case <-time.After(time.Second):
				t.Fatal("listener failure waited for retained handler")
			}
			select {
			case <-s.done:
				t.Fatal("listener falsely completed while handler still owns work")
			default:
			}
			stop, stopCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			require.ErrorIs(t, s.Shutdown(stop), context.DeadlineExceeded)
			stopCancel()
			unblock()
		})
	}
}

func TestListenerFailureNormalStopAndRestart(t *testing.T) {
	rc, err := GenerateResolverConfig("example.org", nil, time.Hour)
	require.NoError(t, err)
	cert, err := rc.NewCert()
	require.NoError(t, err)
	for _, proto := range []Proto{ProtoUDP, ProtoTCP} {
		t.Run(string(proto), func(t *testing.T) {
			failures := make(chan error, 10)
			s, serverErr := NewServer(&ServerConfig{Logger: slog.New(slog.DiscardHandler), ListenerFailures: failures,
				ProviderName: rc.ProviderName, ResolverCert: cert, Proto: proto, Addr: netip.MustParseAddrPort("127.0.0.1:0")})
			require.NoError(t, serverErr)
			for range 3 {
				require.NoError(t, s.Start(t.Context()))
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				shutdownErr := s.Shutdown(ctx)
				cancel()
				require.NoError(t, shutdownErr)
			}
			require.Empty(t, failures)
		})
	}
}
