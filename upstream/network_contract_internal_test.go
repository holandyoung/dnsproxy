package upstream

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Only net.Conn is exposed, as permitted by the route API. In particular a UDP
// socket's PacketConn methods must not be required from application wrappers.
type observedRouteConn struct {
	net.Conn
	writes   chan []byte
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deadline time.Time
}

func (c *observedRouteConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	return c.Conn.SetDeadline(deadline)
}

func (c *observedRouteConn) lastDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline
}

func (c *observedRouteConn) Write(b []byte) (int, error) {
	select {
	case c.writes <- append([]byte(nil), b...):
	default:
	}
	return c.Conn.Write(b)
}

func (c *observedRouteConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

type observedRoute struct {
	routedNetwork
	opened chan *observedRouteConn
}

func (r *observedRoute) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := r.routedNetwork.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	wrapped := &observedRouteConn{Conn: conn, writes: make(chan []byte, 32), done: make(chan struct{})}
	r.opened <- wrapped
	return wrapped, nil
}

func newObservedRoute(address string) *observedRoute {
	return &observedRoute{routedNetwork: routedNetwork{address: address}, opened: make(chan *observedRouteConn, 32)}
}

func TestNetworkDialerWrappedUDPHasDatagramFraming(t *testing.T) {
	srv := startDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(r)))
	})
	t.Cleanup(func() { require.NoError(t, srv.Close()) })
	route := newObservedRoute(fmt.Sprintf("127.0.0.1:%d", srv.port))
	u, err := AddressToUpstream("udp://127.0.0.1:1", &Options{NetworkDialer: route, Timeout: time.Second, Logger: testLogger})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, u.Close()) })
	query := createTestMessage()
	query.Id = 0x4567
	response, exchangeErr := u.Exchange(query)
	conn := <-route.opened
	want, err := query.Pack()
	require.NoError(t, err)
	require.Equal(t, want, <-conn.writes, "UDP sends the exact DNS message without a TCP prefix")
	require.NoError(t, exchangeErr)
	requireResponse(t, query, response)
	select {
	case <-conn.done:
	default:
		t.Fatal("completed datagram exchange retained its route socket")
	}
}

func TestNetworkDialerHTTPVersionAllowlist(t *testing.T) {
	for _, tc := range []struct {
		name       string
		versions   []HTTPVersion
		serverH2   bool
		wantProto  int
		wantReject bool
	}{
		{"h1_to_h1", []HTTPVersion{HTTPVersion11}, false, 1, false},
		{"h1_to_h2_enabled", []HTTPVersion{HTTPVersion11}, true, 1, false},
		{"h2_to_h2", []HTTPVersion{HTTPVersion2}, true, 2, false},
		{"h2_to_h1_rejected", []HTTPVersion{HTTPVersion2}, false, 0, true},
		{"h1_h2_to_h1", []HTTPVersion{HTTPVersion11, HTTPVersion2}, false, 1, false},
		{"h1_h2_to_h2", []HTTPVersion{HTTPVersion11, HTTPVersion2}, true, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan int, 16)
			handler := createDoHHandler()
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.ProtoMajor
				handler.ServeHTTP(w, r)
			}))
			srv.EnableHTTP2 = tc.serverH2
			srv.StartTLS()
			defer srv.Close()
			roots := x509.NewCertPool()
			roots.AddCert(srv.Certificate())
			route := newObservedRoute(srv.Listener.Addr().String())
			u, err := AddressToUpstream("https://127.0.0.1:1/dns-query", &Options{
				NetworkDialer: route, RootCAs: roots, HTTPVersions: tc.versions, Timeout: time.Second, Logger: testLogger,
			})
			require.NoError(t, err)
			defer u.Close()
			for range 3 {
				query := createTestMessage()
				response, exchangeErr := u.Exchange(query)
				if tc.wantReject {
					require.Error(t, exchangeErr)
					require.Nil(t, response)
					require.Empty(t, seen, "disallowed protocol must fail before sending a DNS request")
				} else {
					require.NoError(t, exchangeErr)
					requireResponse(t, query, response)
					require.Equal(t, tc.wantProto, <-seen, "assert the actual request protocol")
				}
			}
			require.NoError(t, u.Close())
			require.NotEmpty(t, route.opened)
			for len(route.opened) != 0 {
				conn := <-route.opened
				select {
				case <-conn.done:
				case <-time.After(time.Second):
					t.Fatal("upstream close retained HTTP route socket")
				}
			}
		})
	}
}

func TestNetworkDialerDoTExchangeDeadline(t *testing.T) {
	for _, mode := range []string{"new", "pooled", "retry", "zero"} {
		t.Run(mode, func(t *testing.T) {
			release := make(chan struct{})
			var released sync.Once
			defer released.Do(func() { close(release) })
			var calls atomic.Int32
			srv := startDoTServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
				n := calls.Add(1)
				if (mode == "pooled" || mode == "retry") && n == 1 {
					require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(r)))
					return
				}
				if mode == "retry" && n == 2 {
					time.Sleep(60 * time.Millisecond)
					_ = w.Close()
					return
				}
				<-release
				// A timed-out client may already have closed its socket.
				_ = w.WriteMsg(respondToTestMessage(r))
			})
			timeout := 100 * time.Millisecond
			if mode == "zero" {
				timeout = 0
			}
			route := newObservedRoute(fmt.Sprintf("127.0.0.1:%d", srv.port))
			u, err := AddressToUpstream("tls://127.0.0.1:1", &Options{
				NetworkDialer: route, RootCAs: srv.rootCAs, Timeout: timeout, Logger: testLogger,
			})
			require.NoError(t, err)
			defer u.Close()
			if mode == "pooled" || mode == "retry" {
				checkUpstream(t, u, "tls://127.0.0.1:1")
			}
			result := make(chan error, 1)
			go func() { _, exchangeErr := u.Exchange(createTestMessage()); result <- exchangeErr }()
			if mode == "zero" {
				select {
				case err = <-result:
					t.Fatalf("zero added an exchange deadline: %v", err)
				case <-time.After(150 * time.Millisecond):
				}
				released.Do(func() { close(release) })
			}
			select {
			case err = <-result:
			case <-time.After(time.Second):
				released.Do(func() { close(release) })
				<-result
				t.Fatal("configured DoT deadline did not bound exchange")
			}
			if mode == "zero" {
				require.NoError(t, err)
				require.Len(t, route.opened, 1)
				require.True(t, (<-route.opened).lastDeadline().IsZero(), "zero must not install an implicit socket deadline")
			} else {
				require.Error(t, err)
				var netErr net.Error
				require.ErrorAs(t, err, &netErr)
				require.True(t, netErr.Timeout())
				if mode == "retry" {
					require.EqualValues(t, 3, calls.Load(), "the retry must reach the actual server")
					require.Len(t, route.opened, 2)
					original, retry := <-route.opened, <-route.opened
					require.Equal(t, original.lastDeadline(), retry.lastDeadline(), "retry must share the original socket deadline")
				}
			}
		})
	}
}

func TestNetworkDialerDoTHandshakeDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() { conn, _ := listener.Accept(); accepted <- conn }()
	route := newObservedRoute(listener.Addr().String())
	u, err := AddressToUpstream("tls://127.0.0.1:1", &Options{NetworkDialer: route, Timeout: 50 * time.Millisecond, Logger: testLogger})
	require.NoError(t, err)
	defer u.Close()
	_, err = u.Exchange(createTestMessage())
	conn := <-accepted
	require.NotNil(t, conn)
	defer conn.Close()
	require.Error(t, err)
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	require.True(t, netErr.Timeout())
	wrapped := <-route.opened
	select {
	case <-wrapped.done:
	default:
		t.Fatal("failed handshake retained actual route socket")
	}
}
