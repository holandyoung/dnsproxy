package proxy_test

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/holandyoung/dnsproxy/dnsproxytest"
	"github.com/holandyoung/dnsproxy/proxy"
	"github.com/holandyoung/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO(e.burkov):  Merge those with the ones in internal tests and move to
// dnsproxytest.

const (
	// testTimeout is the common timeout for tests and contexts.
	testTimeout = 1 * time.Second

	// testCacheSize is the default size of the cache in bytes.
	testCacheSize = 64 * 1024
)

var (
	// localhostAnyPort is a localhost address with an arbitrary port.
	localhostAnyPort = netip.AddrPortFrom(netutil.IPv4Localhost(), 0)

	// testTrustedProxies is a set of trusted proxies that includes all
	// addresses used in tests.
	testTrustedProxies = netutil.SliceSubnetSet{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::0/0"),
	}
)

// assertEqualResponses compares complete wire responses except the caller ID.
// Native Copy may turn empty slices into nil without changing the DNS answer.
func assertEqualResponses(tb testing.TB, expected, actual *dns.Msg) {
	tb.Helper()

	if expected == nil {
		require.Nil(tb, actual)

		return
	}

	require.NotNil(tb, actual)

	expected, actual = expected.Copy(), actual.Copy()
	expected.Id, actual.Id = 0, 0
	expectedWire, err := expected.Pack()
	require.NoError(tb, err)
	actualWire, err := actual.Pack()
	require.NoError(tb, err)
	assert.Equal(tb, expectedWire, actualWire)
}

// TestPendingRequests uses the native scheduler barrier to prove that all
// concurrent Resolve calls have joined the pending wave before releasing it.
// Handler entry alone cannot establish that property, and real network I/O
// cannot participate in a synctest bubble.
func TestPendingRequests(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		const requests = 100
		release := make(chan struct{})
		var exchanges atomic.Int64
		u := &dnsproxytest.Upstream{
			OnExchange: func(req *dns.Msg) (*dns.Msg, error) {
				exchanges.Add(1)
				<-release
				return (&dns.Msg{}).SetReply(req), nil
			},
			OnAddress: func() string { return "" },
			OnClose:   func() error { return nil },
		}
		p := newPendingTestProxy(t, u, nil)
		contexts := make([]*proxy.DNSContext, requests)
		errs := make([]error, requests)
		var completed atomic.Int64
		for i := range requests {
			req := (&dns.Msg{}).SetQuestion("domain.example.", dns.TypeA)
			req.Id = uint16(i)
			contexts[i] = &proxy.DNSContext{Req: req, Proto: proxy.ProtoTCP, Addr: localhostAnyPort}
			go func() {
				errs[i] = p.Resolve(context.Background(), contexts[i])
				completed.Add(1)
			}()
		}
		synctest.Wait()
		assert.EqualValues(t, 1, exchanges.Load(), "concurrent wave must share one upstream exchange")
		assert.Zero(t, completed.Load(), "followers must wait for the leader result")
		close(release)
		synctest.Wait()
		require.EqualValues(t, requests, completed.Load())
		for i, dctx := range contexts {
			require.NoError(t, errs[i])
			require.NotNil(t, dctx.Res)
			assert.Equal(t, uint16(i), dctx.Res.Id)
			assertEqualResponses(t, contexts[0].Res, dctx.Res)
		}
		assert.EqualValues(t, 1, exchanges.Load())

		// Empty answers without an SOA are not cacheable. After completion a new
		// request must start a new exchange, even with the same question.
		late := &proxy.DNSContext{Req: (&dns.Msg{}).SetQuestion("domain.example.", dns.TypeA), Proto: proxy.ProtoTCP, Addr: localhostAnyPort}
		require.NoError(t, p.Resolve(context.Background(), late))
		assert.EqualValues(t, 2, exchanges.Load())
		assertEqualResponses(t, contexts[0].Res, late.Res)
	})
}

// TestPendingRequestsLateTCP preserves the real listener boundary and forces
// the interleaving that invalidated the former best-effort handler-entry test.
func TestPendingRequestsLateTCP(t *testing.T) {
	t.Parallel()
	lateEntered := make(chan struct{})
	firstReply := make(chan struct{})
	var exchanges atomic.Int64
	u := &dnsproxytest.Upstream{
		OnExchange: func(req *dns.Msg) (*dns.Msg, error) {
			exchanges.Add(1)
			select {
			case <-lateEntered:
			case <-time.After(testTimeout):
				return nil, context.DeadlineExceeded
			}
			return (&dns.Msg{}).SetReply(req), nil
		},
		OnAddress: func() string { return "" },
		OnClose:   func() error { return nil },
	}
	handler := &dnsproxytest.Handler{
		OnHandle: func(ctx context.Context, p *proxy.Proxy, d *proxy.DNSContext) error {
			if d.Req.Id == 2 {
				close(lateEntered)
				<-firstReply
			}
			return p.Resolve(ctx, d)
		},
	}
	p := newPendingTestProxy(t, u, handler)
	servicetest.RequireRun(t, p, testTimeout)
	addr := p.Addr(proxy.ProtoTCP).String()
	client := &dns.Client{Net: string(proxy.ProtoTCP), Timeout: testTimeout}
	responses := make([]*dns.Msg, 2)
	errs := make([]error, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		req := (&dns.Msg{}).SetQuestion("domain.example.", dns.TypeA)
		req.Id = 2
		responses[1], _, errs[1] = client.ExchangeContext(context.Background(), req, addr)
	}()
	req := (&dns.Msg{}).SetQuestion("domain.example.", dns.TypeA)
	req.Id = 1
	responses[0], _, errs[0] = client.ExchangeContext(context.Background(), req, addr)
	close(firstReply)
	<-done
	for _, err := range errs {
		require.NoError(t, err)
	}
	assert.EqualValues(t, 2, exchanges.Load())
	assertEqualResponses(t, responses[0], responses[1])
	require.NotNil(t, responses[0])
	require.NotNil(t, responses[1])
	assert.EqualValues(t, 1, responses[0].Id)
	assert.EqualValues(t, 2, responses[1].Id)
}

func newPendingTestProxy(t *testing.T, u upstream.Upstream, handler proxy.Handler) *proxy.Proxy {
	t.Helper()
	p, err := proxy.New(&proxy.Config{
		Logger:                 testLogger,
		UpstreamConfig:         &proxy.UpstreamConfig{Upstreams: []upstream.Upstream{u}},
		TrustedProxies:         testTrustedProxies,
		PendingRequests:        &proxy.PendingRequestsConfig{Enabled: true},
		RequestHandler:         handler,
		UDPListenAddr:          []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TCPListenAddr:          []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		CacheSizeBytes:         testCacheSize,
		CacheEnabled:           true,
		DNSSECEnabled:          true,
		EnableEDNSClientSubnet: true,
	})
	require.NoError(t, err)
	return p
}
