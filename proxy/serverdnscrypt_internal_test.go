package proxy

import (
	"net"
	"testing"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/holandyoung/dnsproxy/dnscrypt"
	"github.com/jedisct1/go-dnsstamps"
	"github.com/stretchr/testify/require"
)

func TestDNSCryptProxy(t *testing.T) {
	t.Parallel()

	// Prepare the proxy server.
	dnsProxy, rc := newTestDNSCryptProxy(t)

	servicetest.RequireRun(t, dnsProxy, testTimeout)

	// Each listener owns its ephemeral port. Shared-port fallback is exercised
	// by the upstream DNSCrypt truncation test using the paired server fixture.
	addresses := dnsProxy.Addrs(ProtoDNSCrypt)
	require.Len(t, addresses, 2)
	for i, proto := range []dnscrypt.Proto{dnscrypt.ProtoUDP, dnscrypt.ProtoTCP} {
		stamp, err := rc.CreateStamp(addresses[i].String())
		require.NoError(t, err)
		checkDNSCryptProxy(t, proto, stamp)
	}

}

// newTestDNSCryptProxy is a helper function that creates a DNSCrypt proxy and
// the corresponding resolver configuration for testing.
func newTestDNSCryptProxy(tb testing.TB) (p *Proxy, rc dnscrypt.ResolverConfig) {
	tb.Helper()

	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
	require.NoError(tb, err)

	cert, err := rc.NewCert()
	require.NoError(tb, err)

	upstreamConf := newTestUpstreamConfig(tb, defaultTimeout, testDefaultUpstreamAddr(tb))
	p = mustNew(tb, &Config{
		Logger: testLogger,
		DNSCryptUDPListenAddr: []*net.UDPAddr{{
			Port: 0, IP: net.ParseIP(listenIP),
		}},
		DNSCryptTCPListenAddr: []*net.TCPAddr{{
			Port: 0, IP: net.ParseIP(listenIP),
		}},
		UpstreamConfig:         upstreamConf,
		TrustedProxies:         defaultTrustedProxies,
		EnableEDNSClientSubnet: true,
		CacheEnabled:           true,
		CacheMinTTL:            20,
		CacheMaxTTL:            40,
		DNSCryptProviderName:   rc.ProviderName,
		DNSCryptResolverCert:   cert,
	})

	return p, rc
}

// checkDNSCryptProxy is a helper function that checks the DNSCrypt proxy by
// sending a test message and verifying the response.
func checkDNSCryptProxy(tb testing.TB, proto dnscrypt.Proto, stamp dnsstamps.ServerStamp) {
	tb.Helper()

	// Create a DNSCrypt client.
	c := dnscrypt.NewClient(&dnscrypt.ClientConfig{
		Logger: slogutil.NewDiscardLogger(),
		Proto:  proto,
	})

	ctx := testutil.ContextWithTimeout(tb, testTimeout)

	// Fetch the server certificate.
	ri, err := c.DialStampContext(ctx, stamp)
	require.NoError(tb, err)

	// Send the test message.
	msg := newTestMessage()
	reply, err := c.ExchangeContext(ctx, msg, ri, nil)
	require.NoError(tb, err)
	requireResponse(tb, msg, reply)
}
