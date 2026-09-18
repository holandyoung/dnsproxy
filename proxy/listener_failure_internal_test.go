package proxy

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/holandyoung/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Arm only after a real successful query. Fault notification must not depend
// on this diagnostic handler returning.
type failureLogBarrier struct {
	release chan struct{}
	armed   atomic.Bool
}

func (h *failureLogBarrier) Enabled(context.Context, slog.Level) bool { return true }
func (h *failureLogBarrier) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *failureLogBarrier) WithGroup(string) slog.Handler            { return h }
func (h *failureLogBarrier) Handle(context.Context, slog.Record) error {
	if h.armed.Load() {
		<-h.release
	}
	return nil
}

func TestListenerFailuresBeforeDiagnostics(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp", "tls", "https", "h3", "quic"} {
		t.Run(protocol, func(t *testing.T) {
			serverTLS, ca := newTLSConfig(t)
			roots := x509.NewCertPool()
			require.True(t, roots.AppendCertsFromPEM(ca))
			failures := make(chan error, 1)
			barrier := &failureLogBarrier{release: make(chan struct{})}
			release := sync.OnceFunc(func() { close(barrier.release) })
			defer release()
			p := mustNew(t, &Config{
				Logger: slog.New(barrier), ListenerFailures: failures,
				TLSConfig: serverTLS, RequestHandler: HandlerFunc(replyLocally),
				UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
				TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
				TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
				QUICListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
				HTTPConfig:     &HTTPConfig{ListenAddresses: []netip.AddrPort{localhostAnyPort}, HTTP3Enabled: true},
			})
			require.NoError(t, p.Start(t.Context()))
			defer func() {
				release()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				require.NoError(t, p.Shutdown(ctx))
			}()
			var addr string
			var fail func() error
			switch protocol {
			case "udp":
				addr, fail = p.udpListen[0].LocalAddr().String(), p.udpListen[0].Close
			case "tcp":
				addr, fail = p.tcpListen[0].Addr().String(), p.tcpListen[0].Close
			case "tls":
				addr, fail = p.tlsListen[0].Addr().String(), p.tlsListen[0].Close
			case "https":
				addr, fail = p.httpsListen[0].Addr().String(), p.httpsListen[0].Close
			case "h3":
				addr, fail = p.h3Listen[0].Addr().String(), p.h3Listen[0].Close
			case "quic":
				addr, fail = p.quicListen[0].Addr().String(), p.quicListen[0].Close
			}
			endpoint := protocol + "://" + addr
			if protocol == "https" || protocol == "h3" {
				endpoint += "/dns-query"
			}
			u, err := upstream.AddressToUpstream(endpoint, &upstream.Options{Logger: testLogger, RootCAs: roots, ServerName: tlsServerName, Timeout: time.Second})
			require.NoError(t, err)
			defer func(closeResource func() error) { _ = closeResource() }(u.Close)
			response, err := u.Exchange(new(dns.Msg).SetQuestion("failure.example.", dns.TypeA), nil)
			require.NoError(t, err)
			require.Equal(t, dns.RcodeSuccess, response.Rcode)
			require.Empty(t, failures)
			barrier.armed.Store(true)
			require.NoError(t, fail())
			select {
			case failureErr := <-failures:
				require.ErrorContains(t, failureErr, protocol+" listener "+addr)
			case <-time.After(time.Second):
				t.Fatal("fatal native listener failure was hidden behind diagnostics")
			}
		})
	}
}

func TestListenerNormalShutdownAndRestart(t *testing.T) {
	tlsConfig, _ := newTLSConfig(t)
	failures := make(chan error, 20)
	p := mustNew(t, &Config{Logger: testLogger, ListenerFailures: failures,
		TLSConfig: tlsConfig, RequestHandler: HandlerFunc(replyLocally),
		UDPListenAddr:  []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		QUICListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		HTTPConfig:     &HTTPConfig{ListenAddresses: []netip.AddrPort{localhostAnyPort}, HTTP3Enabled: true},
	})
	for range 3 {
		require.NoError(t, p.Start(t.Context()))
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := p.Shutdown(ctx)
		cancel()
		require.NoError(t, err)
	}
	select {
	case err := <-failures:
		t.Fatalf("normal shutdown reported a failure: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
}
