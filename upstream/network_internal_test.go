package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// A wrapper deliberately hides *net.UDPConn. Real routed/SOCKS packet sockets
// must work through net.PacketConn without native type assertions or redialing.
type routedPacket struct {
	net.PacketConn
	done chan struct{}
	once sync.Once
}

func (p *routedPacket) Close() (err error) {
	p.once.Do(func() { err = p.PacketConn.Close(); close(p.done) })
	return err
}

type routedNetwork struct {
	tcpError   error
	address    string
	packets    []*routedPacket
	streams    []net.Conn
	configured []string
	networks   []string
	mu         sync.Mutex
}

func (r *routedNetwork) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var connection net.Conn
	var err error
	if network == "tcp" && r.tcpError != nil {
		err = r.tcpError
	} else {
		connection, err = (&net.Dialer{}).DialContext(ctx, network, r.address)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.configured = append(r.configured, address)
	r.networks = append(r.networks, network)
	if err == nil {
		r.streams = append(r.streams, connection)
	}
	return connection, err
}

func TestNetworkDialerCoversUDPAndStreamProtocols(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(r)))
	})
	plain := startDNSServer(t, handler)
	t.Cleanup(func() { require.NoError(t, plain.Close()) })
	dot := startDoTServer(t, handler)
	doh := startDoHServer(t, testDoHServerOptions{})
	cases := []struct {
		name, address, target string
		roots                 *x509.CertPool
		versions              []HTTPVersion
	}{
		{"udp", "udp://127.0.0.1:1", fmt.Sprintf("127.0.0.1:%d", plain.port), nil, nil},
		{"tcp", "tcp://127.0.0.1:1", fmt.Sprintf("127.0.0.1:%d", plain.port), nil, nil},
		{"dot", "tls://127.0.0.1:1", fmt.Sprintf("127.0.0.1:%d", dot.port), dot.rootCAs, nil},
		{"doh1", "https://127.0.0.1:1/dns-query", doh.addr, doh.rootCAs, []HTTPVersion{HTTPVersion11}},
		{"doh2", "https://127.0.0.1:1/dns-query", doh.addr, doh.rootCAs, []HTTPVersion{HTTPVersion2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			route := &routedNetwork{address: tc.target}
			u, err := AddressToUpstream(tc.address, &Options{NetworkDialer: route, RootCAs: tc.roots, HTTPVersions: tc.versions, Timeout: time.Second, Logger: testLogger})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, u.Close()) })
			for range 3 {
				checkUpstream(t, u, tc.address)
			}
			route.mu.Lock()
			configured := append([]string(nil), route.configured...)
			packets := len(route.packets)
			route.mu.Unlock()
			require.NotEmpty(t, configured)
			require.Zero(t, packets)
			for _, value := range configured {
				require.Equal(t, "127.0.0.1:1", value)
			}
		})
	}
}

func TestNetworkDialerUDPTruncationReturnsTCPFailure(t *testing.T) {
	srv := startDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		require.Equal(testutil.PanicT{}, "udp", w.RemoteAddr().Network())
		response := respondToTestMessage(r)
		response.Truncated = true
		require.NoError(testutil.PanicT{}, w.WriteMsg(response))
	})
	t.Cleanup(func() { require.NoError(t, srv.Close()) })
	tcpFailure := errors.Error("configured route refused TCP")
	route := &routedNetwork{address: fmt.Sprintf("127.0.0.1:%d", srv.port), tcpError: tcpFailure}
	u, err := AddressToUpstream("127.0.0.1:1", &Options{NetworkDialer: route, Timeout: time.Second, Logger: testLogger})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, u.Close()) })
	response, err := u.Exchange(createTestMessage(), nil)
	require.ErrorIs(t, err, tcpFailure)
	require.Nil(t, response, "the failed TCP result replaces the retained truncated UDP answer")
	route.mu.Lock()
	networks := append([]string(nil), route.networks...)
	route.mu.Unlock()
	require.Equal(t, []string{"udp", "tcp"}, networks)
}

type rejectingNetwork struct{ err error }

func (r rejectingNetwork) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, r.err
}
func (r rejectingNetwork) DialPacket(context.Context, string) (net.PacketConn, net.Addr, error) {
	return nil, nil, r.err
}

func TestNetworkDialerFailureCannotFallBackToNativeDialing(t *testing.T) {
	routeFailure := errors.Error("only authorized route failed")
	for _, address := range []string{"udp://127.0.0.1:1", "tcp://127.0.0.1:1", "tls://127.0.0.1:1", "https://127.0.0.1:1/dns-query", "h3://127.0.0.1:1/dns-query", "quic://127.0.0.1:1"} {
		t.Run(address, func(t *testing.T) {
			u, err := AddressToUpstream(address, &Options{NetworkDialer: rejectingNetwork{routeFailure}, Timeout: time.Second, Logger: testLogger})
			require.NoError(t, err)
			defer func(closeResource func() error) { _ = closeResource() }(u.Close)
			response, err := u.Exchange(createTestMessage(), nil)
			require.ErrorIs(t, err, routeFailure)
			require.Nil(t, response)
		})
	}
	r, err := NewUpstreamResolver("127.0.0.1:1", &Options{NetworkDialer: rejectingNetwork{routeFailure}, Timeout: time.Second, Logger: testLogger})
	require.NoError(t, err)
	defer func(closeResource func() error) { _ = closeResource() }(r.Close)
	_, err = r.LookupNetIP(context.Background(), "ip4", "route.test")
	require.ErrorIs(t, err, routeFailure, "bootstrap construction must keep the same network owner")
}

func TestNetworkDialerKeepsStrictServerNameVerification(t *testing.T) {
	config, roots := createServerTLSConfig(t, "route.example")
	names := make(chan string, 4)
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) { names <- hello.ServerName; return nil, nil }
	srv := startDoQServer(t, config, 0)
	for _, name := range []string{"route.example", "wrong.example"} {
		t.Run(name, func(t *testing.T) {
			u, err := AddressToUpstream("quic://127.0.0.1:1", &Options{NetworkDialer: &routedNetwork{address: srv.addr}, RootCAs: roots, ServerName: name, Timeout: time.Second, Logger: testLogger})
			require.NoError(t, err)
			defer func(closeResource func() error) { _ = closeResource() }(u.Close)
			response, err := u.Exchange(createTestMessage(), nil)
			if name == "route.example" {
				require.NoError(t, err)
				require.NotNil(t, response)
			} else {
				require.ErrorContains(t, err, "certificate")
				require.Nil(t, response)
			}
			select {
			case got := <-names:
				require.Equal(t, name, got)
			case <-time.After(time.Second):
				t.Fatal("missing actual TLS SNI")
			}
		})
	}
}

func (r *routedNetwork) DialPacket(ctx context.Context, address string) (net.PacketConn, net.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	remote, err := net.ResolveUDPAddr("udp", r.address)
	if err != nil {
		return nil, nil, err
	}
	connection, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	packet := &routedPacket{PacketConn: connection, done: make(chan struct{})}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.configured = append(r.configured, address)
	r.packets = append(r.packets, packet)
	return packet, remote, nil
}

func TestNetworkDialerDoQOwnsActualPacketConnection(t *testing.T) {
	tlsConfig, roots := createServerTLSConfig(t, "127.0.0.1")
	server := startDoQServer(t, tlsConfig, 0)
	route := &routedNetwork{address: server.addr}
	address := "quic://127.0.0.1:1"
	u, err := AddressToUpstream(address, &Options{NetworkDialer: route, RootCAs: roots, Timeout: time.Second, Logger: testLogger})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, u.Close()) })
	for range 3 {
		checkUpstream(t, u, address)
	}
	route.mu.Lock()
	packets := append([]*routedPacket(nil), route.packets...)
	streams := append([]net.Conn(nil), route.streams...)
	configured := append([]string(nil), route.configured...)
	route.mu.Unlock()
	require.Len(t, packets, 1, "reuse the actual custom packet connection")
	require.Empty(t, streams, "no throwaway native UDP connection")
	require.Equal(t, []string{"127.0.0.1:1"}, configured)
	require.NoError(t, u.Close())
	select {
	case <-packets[0].done:
	case <-time.After(time.Second):
		t.Fatal("upstream did not release its packet socket")
	}
}

func TestNetworkDialerHTTP3CoversPreferenceProbeAndActualConnection(t *testing.T) {
	for _, probe := range []bool{false, true} {
		t.Run(fmt.Sprint(probe), func(t *testing.T) {
			server := startDoHServer(t, testDoHServerOptions{http3Enabled: true, delayHandshakeH2: 200 * time.Millisecond})
			route := &routedNetwork{address: server.addr}
			versions := []HTTPVersion{HTTPVersion3}
			if probe {
				versions = append(versions, HTTPVersion2)
			}
			address := "https://127.0.0.1:1/dns-query"
			u, err := AddressToUpstream(address, &Options{NetworkDialer: route, RootCAs: server.rootCAs, HTTPVersions: versions, Timeout: time.Second, Logger: testLogger})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, u.Close()) })
			for range 3 {
				checkUpstream(t, u, address)
			}
			require.True(t, isHTTP3(u.(*dnsOverHTTPS).client))
			require.NoError(t, u.Close())
			route.mu.Lock()
			packets := append([]*routedPacket(nil), route.packets...)
			configured := append([]string(nil), route.configured...)
			route.mu.Unlock()
			minimum := 1
			if probe {
				minimum = 2
			}
			require.GreaterOrEqual(t, len(packets), minimum, "probe and real HTTP/3 must both use the route")
			for _, value := range configured {
				require.Equal(t, "127.0.0.1:1", value)
			}
			for _, packet := range packets {
				select {
				case <-packet.done:
				case <-time.After(time.Second):
					t.Fatal("HTTP/3 packet socket survived upstream close")
				}
			}
		})
	}
}
