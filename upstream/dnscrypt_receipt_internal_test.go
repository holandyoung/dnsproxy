package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/holandyoung/dnsproxy/dnscrypt"
	"github.com/holandyoung/dnsproxy/internal/dnsproxytest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type dnsCryptRoute struct {
	*routedNetwork
	closing    chan struct{}
	release    <-chan struct{}
	blockClose atomic.Bool
}

// Deliberately hide the socket's concrete TCP/UDP type, as a SOCKS owner does.
func (r *dnsCryptRoute) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := r.routedNetwork.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if r.blockClose.Load() {
		return &receiptCloseConn{Conn: conn, closing: r.closing, release: r.release}, nil
	}
	return struct{ net.Conn }{conn}, nil
}

func TestDNSCryptRoutedReceiptAndTCPContinuation(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(map[bool]string{false: "udp", true: "tcp-continuation"}[tcp], func(t *testing.T) {
			rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
			require.NoError(t, err)
			stamp := dnsproxytest.StartDNSCryptServer(t, rc, dnsproxytest.DNSCryptHandler(func(ctx context.Context, w dnscrypt.ResponseWriter, req *dns.Msg) error {
				response := respondToTestMessage(req)
				if tcp {
					response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{strings.Repeat("x", 240), strings.Repeat("y", 240), strings.Repeat("z", 240)}}}
				}
				return w.WriteMsg(ctx, response)
			}))
			route := &dnsCryptRoute{routedNetwork: &routedNetwork{address: stamp.ServerAddrStr}}
			stamp.ServerAddrStr = "127.0.0.1:1"
			u, err := AddressToUpstream(stamp.String(), &Options{NetworkDialer: route, Timeout: time.Second, Logger: testLogger})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, u.Close()) })
			request := createTestMessage()
			if tcp {
				request.SetQuestion("large.example.", dns.TypeTXT)
			}
			state := NewExchangeState(time.Now().Add(time.Second))
			response, err := u.Exchange(request, state)
			require.NoError(t, err)
			require.False(t, response.Truncated)
			result, ready := state.Result()
			require.True(t, ready)
			require.NoError(t, result.Err)
			expectedWire, err := response.Pack()
			require.NoError(t, err)
			actualWire, err := result.Response.Pack()
			require.NoError(t, err)
			require.Equal(t, expectedWire, actualWire)
			require.False(t, result.ReceivedAt.IsZero())
			route.mu.Lock()
			defer route.mu.Unlock()
			want := []string{"udp", "udp"}
			if tcp {
				want = append(want, "tcp")
			}
			require.Equal(t, want, route.networks, "certificate and every encrypted phase must use the route")
			for _, target := range route.configured {
				require.Equal(t, "127.0.0.1:1", target)
			}
		})
	}
}

func TestDNSCryptReceiptBeforePhysicalClose(t *testing.T) {
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
	require.NoError(t, err)
	stamp := dnsproxytest.StartDNSCryptServer(t, rc, dnsproxytest.DNSCryptHandler(func(ctx context.Context, w dnscrypt.ResponseWriter, req *dns.Msg) error {
		return w.WriteMsg(ctx, respondToTestMessage(req))
	}))
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	route := &dnsCryptRoute{routedNetwork: &routedNetwork{address: stamp.ServerAddrStr}, closing: make(chan struct{}), release: release}
	u, err := AddressToUpstream(stamp.String(), &Options{NetworkDialer: route, Timeout: time.Second, Logger: testLogger})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, u.Close()) })
	_, err = u.Exchange(createTestMessage(), nil)
	require.NoError(t, err, "certificate and transport prerequisite")
	route.blockClose.Store(true)
	state := NewExchangeState(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { _, exchangeErr := u.Exchange(createTestMessage(), state); done <- exchangeErr }()
	select {
	case <-route.closing:
	case <-time.After(time.Second):
		t.Fatal("encrypted connection did not reach Close")
	}
	select {
	case <-done:
		t.Fatal("physical exchange returned while Close was held")
	default:
	}
	result, ready := state.Result()
	require.True(t, ready, "complete receipt must precede Close")
	require.NoError(t, result.Err)
	require.NotNil(t, result.Response)
	state.Expire()
	after, _ := state.Result()
	require.Equal(t, result, after)
	unblock()
	require.NoError(t, <-done)
}

func TestDNSCryptReceiptRejectsBadPinAndExpiredAdmission(t *testing.T) {
	for _, badPin := range []bool{false, true} {
		t.Run(map[bool]string{false: "expired-admission", true: "bad-provider-key"}[badPin], func(t *testing.T) {
			rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
			require.NoError(t, err)
			stamp := dnsproxytest.StartDNSCryptServer(t, rc, dnsproxytest.DNSCryptHandler(func(ctx context.Context, w dnscrypt.ResponseWriter, req *dns.Msg) error {
				return w.WriteMsg(ctx, respondToTestMessage(req))
			}))
			if badPin {
				stamp.ServerPk[0] ^= 1
			}
			route := &dnsCryptRoute{routedNetwork: &routedNetwork{address: stamp.ServerAddrStr}}
			u, err := AddressToUpstream(stamp.String(), &Options{NetworkDialer: route, Timeout: time.Second, Logger: testLogger})
			require.NoError(t, err)
			defer func(closeResource func() error) { _ = closeResource() }(u.Close)
			state := NewExchangeState(time.Now().Add(time.Second))
			if !badPin {
				state.Expire()
			}
			_, err = u.Exchange(createTestMessage(), state)
			if badPin {
				require.Error(t, err)
			} else {
				require.NoError(t, err, "logical expiry must not cancel physical exchange")
			}
			result, ready := state.Result()
			require.True(t, ready)
			require.Error(t, result.Err)
			require.Nil(t, result.Response)
			if !badPin {
				require.ErrorIs(t, result.Err, context.DeadlineExceeded)
			}
		})
	}
	var count atomic.Int32
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
	require.NoError(t, err)
	stamp := dnsproxytest.StartDNSCryptServer(t, rc, dnsproxytest.DNSCryptHandler(func(context.Context, dnscrypt.ResponseWriter, *dns.Msg) error { count.Add(1); return nil }))
	rejected := errors.New("certificate policy rejected")
	u, err := AddressToUpstream(stamp.String(), &Options{Timeout: time.Second, Logger: testLogger, VerifyDNSCryptCertificate: func(*dnscrypt.Certificate) error { return rejected }})
	require.NoError(t, err)
	defer func(closeResource func() error) { _ = closeResource() }(u.Close)
	_, err = u.Exchange(createTestMessage(), NewExchangeState(time.Now().Add(time.Second)))
	require.ErrorIs(t, err, rejected)
	require.Zero(t, count.Load(), "rejected certificate must not send an encrypted query")
}

func TestDNSCryptConcurrentCertificateRenewal(t *testing.T) {
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
	require.NoError(t, err)
	handler := dnsproxytest.DNSCryptHandler(func(ctx context.Context, w dnscrypt.ResponseWriter, req *dns.Msg) error {
		return w.WriteMsg(ctx, respondToTestMessage(req))
	})
	stamp := dnsproxytest.StartDNSCryptServer(t, rc, handler)
	route := &dnsCryptRoute{routedNetwork: &routedNetwork{address: stamp.ServerAddrStr}}
	var verified atomic.Int32
	u, err := AddressToUpstream(stamp.String(), &Options{NetworkDialer: route, Timeout: 3 * time.Second, Logger: testLogger, VerifyDNSCryptCertificate: func(*dnscrypt.Certificate) error {
		verified.Add(1)
		return nil
	}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, u.Close()) })
	p := u.(*dnsCrypt)
	const callers = 24
	wave := func() {
		start := make(chan struct{})
		done := make(chan error, callers)
		for i := range callers {
			go func() {
				<-start
				request := createTestMessage()
				request.Id = uint16(i + 1)
				state := NewExchangeState(time.Now().Add(3 * time.Second))
				_, queryErr := u.Exchange(request, state)
				result, ready := state.Result()
				if queryErr == nil && (!ready || result.Err != nil || result.Response == nil || result.Response.Id != request.Id) {
					queryErr = fmt.Errorf("lost per-call response: ready=%v result=%+v", ready, result)
				}
				done <- queryErr
			}()
		}
		close(start)
		for range callers {
			require.NoError(t, <-done)
		}
	}
	wave()
	require.EqualValues(t, 1, verified.Load())
	require.Len(t, route.networks, callers+1, "one certificate exchange shared by all callers")
	previous := p.currentCertificate()
	require.NotNil(t, previous)
	// Rotate the peer's real short-term key while preserving the pinned provider.
	// No exchanges remain active while changing the route and expiring our cache.
	rc.ResolverSk, rc.ResolverPk = "", ""
	rotated := dnsproxytest.StartDNSCryptServer(t, rc, handler)
	route.address = rotated.ServerAddrStr
	p.mu.Lock()
	expired := *p.resolverInfo
	cert := *expired.ResolverCert
	cert.NotAfter = uint32(time.Now().Add(-time.Hour).Unix())
	expired.ResolverCert = &cert
	p.resolverInfo = &expired
	p.mu.Unlock()
	wave()
	require.EqualValues(t, 2, verified.Load())
	require.Len(t, route.networks, 2*(callers+1))
	require.NotEqual(t, previous.ResolverCert.ResolverPk, p.currentCertificate().ResolverCert.ResolverPk)
}

type dnsCryptDialFunc func(context.Context, string, string) (net.Conn, error)

func (f dnsCryptDialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func (f dnsCryptDialFunc) DialPacket(context.Context, string) (net.PacketConn, net.Addr, error) {
	return nil, nil, errors.New("DNSCrypt must use its connected UDP owner")
}

func TestDNSCryptCloseCancelsCertificateAndEncryptedWork(t *testing.T) {
	for _, phase := range []string{"certificate", "encrypted"} {
		t.Run(phase, func(t *testing.T) {
			rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
			require.NoError(t, err)
			reached := make(chan struct{}, 1)
			notify := func() {
				select {
				case reached <- struct{}{}:
				default:
				}
			}
			stamp := dnsproxytest.StartDNSCryptServer(t, rc, dnsproxytest.DNSCryptHandler(func(context.Context, dnscrypt.ResponseWriter, *dns.Msg) error {
				notify()
				return nil
			}))
			target := stamp.ServerAddrStr
			if phase == "certificate" {
				plain := startDNSServer(t, dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) { notify() }))
				t.Cleanup(func() { require.NoError(t, plain.Close()) })
				target = fmt.Sprintf("127.0.0.1:%d", plain.port)
			}
			route := &dnsCryptRoute{routedNetwork: &routedNetwork{address: target}}
			u, err := AddressToUpstream(stamp.String(), &Options{NetworkDialer: route, Logger: testLogger})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, u.Close()) })
			const callers = 16
			done := make(chan error, callers)
			for range callers {
				go func() { _, exchangeErr := u.Exchange(createTestMessage(), nil); done <- exchangeErr }()
			}
			select {
			case <-reached:
			case <-time.After(time.Second):
				t.Fatal("physical peer did not receive the prerequisite query")
			}
			require.NoError(t, u.Close())
			deadline := time.After(time.Second)
			for range callers {
				select {
				case err = <-done:
					require.Error(t, err)
				case <-deadline:
					t.Fatal("Close did not unblock physical exchange or certificate waiter")
				}
			}
			for _, conn := range route.streams {
				_, err = conn.Write([]byte("after-close"))
				require.ErrorIs(t, err, net.ErrClosed, "exchange return must follow physical socket closure")
			}
		})
	}
}

func TestDNSCryptOneBudgetCoversCertificateAndTCP(t *testing.T) {
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
	require.NoError(t, err)
	stamp := dnsproxytest.StartDNSCryptServer(t, rc, dnsproxytest.DNSCryptHandler(func(ctx context.Context, w dnscrypt.ResponseWriter, req *dns.Msg) error {
		response := respondToTestMessage(req)
		response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{strings.Repeat("x", 240), strings.Repeat("y", 240), strings.Repeat("z", 240)}}}
		return w.WriteMsg(ctx, response)
	}))
	var deadlines []time.Time
	route := dnsCryptDialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			return nil, errors.New("missing operation deadline")
		}
		deadlines = append(deadlines, deadline)
		if network == "tcp" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	u, err := AddressToUpstream(stamp.String(), &Options{NetworkDialer: route, Logger: testLogger, Timeout: 200 * time.Millisecond})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, u.Close()) })
	state := NewExchangeState(time.Time{})
	_, err = u.Exchange(createTestMessage(), state)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Len(t, deadlines, 3, "certificate, encrypted UDP and TCP continuation must all be reached")
	require.Equal(t, deadlines[0], deadlines[1])
	require.Equal(t, deadlines[0], deadlines[2])
	result, ready := state.Result()
	require.True(t, ready)
	require.Nil(t, result.Response, "a truncated UDP response cannot survive failed TCP")
	require.ErrorIs(t, result.Err, context.DeadlineExceeded)
}

func TestDNSCryptRoutedCertificateHasNoNativeCeiling(t *testing.T) {
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
	require.NoError(t, err)
	stamp := dnsproxytest.StartDNSCryptServer(t, rc, dnsproxytest.DNSCryptHandler(func(ctx context.Context, w dnscrypt.ResponseWriter, req *dns.Msg) error {
		return w.WriteMsg(ctx, respondToTestMessage(req))
	}))
	var remaining []time.Duration
	route := dnsCryptDialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		deadline, _ := ctx.Deadline()
		remaining = append(remaining, time.Until(deadline))
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	u, err := AddressToUpstream(stamp.String(), &Options{NetworkDialer: route, Logger: testLogger, Timeout: 5 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, u.Close()) })
	_, err = u.Exchange(createTestMessage(), nil)
	require.NoError(t, err)
	require.Len(t, remaining, 2)
	require.Greater(t, remaining[0], 4*time.Second, "custom certificate dialing must not inherit a hidden two-second cap")
}

func TestDNSCryptInvalidReplyCannotPublishReceipt(t *testing.T) {
	for _, kind := range []string{"question", "id", "query-flag"} {
		t.Run(kind, func(t *testing.T) {
			rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
			require.NoError(t, err)
			stamp := dnsproxytest.StartDNSCryptServer(t, rc, dnsproxytest.DNSCryptHandler(func(ctx context.Context, w dnscrypt.ResponseWriter, req *dns.Msg) error {
				response := respondToTestMessage(req)
				switch kind {
				case "question":
					response.Question[0].Name = "other.example."
				case "id":
					response.Id++
				case "query-flag":
					response.Response = false
				}
				return w.WriteMsg(ctx, response)
			}))
			route := &dnsCryptRoute{routedNetwork: &routedNetwork{address: stamp.ServerAddrStr}}
			u, err := AddressToUpstream(stamp.String(), &Options{NetworkDialer: route, Logger: testLogger, Timeout: time.Second})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, u.Close()) })
			state := NewExchangeState(time.Time{})
			_, err = u.Exchange(createTestMessage(), state)
			require.Error(t, err)
			result, ready := state.Result()
			require.True(t, ready)
			require.Error(t, result.Err)
			require.Nil(t, result.Response)
			require.Len(t, route.networks, 2, "protocol rejection must not replay over TCP")
		})
	}
}
