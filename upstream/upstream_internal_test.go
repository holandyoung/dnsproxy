package upstream

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/holandyoung/dnsproxy/dnscrypt"
	"github.com/holandyoung/dnsproxy/internal/dnsproxytest"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/holandyoung/quic-go"
	"github.com/holandyoung/quic-go/qlog"
	"github.com/holandyoung/quic-go/qlogwriter"
	"github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is common timeout for tests.
const testTimeout = 2 * time.Second

// testLogger is common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

// TODO(ameshkov): Make tests here not depend on external servers.

func TestMain(m *testing.M) {
	// See https://github.com/quic-go/quic-go/issues/4228.
	errors.Check(os.Setenv("QUIC_GO_DISABLE_GSO", "1"))

	os.Exit(m.Run())
}

// TODO(a.garipov):  Refactor.
func TestUpstream_bootstrapTimeout(t *testing.T) {
	t.Parallel()

	const count = 10

	var timeout time.Duration
	if runtime.GOOS == "windows" {
		timeout = 300 * time.Millisecond
	} else {
		timeout = 100 * time.Millisecond
	}

	// Test listener that never accepts connections to emulate faulty bootstrap.
	udpListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, udpListener.Close)

	rslv, err := NewUpstreamResolver(udpListener.LocalAddr().String(), &Options{
		Logger:  testLogger,
		Timeout: timeout,
	})
	require.NoError(t, err)

	// Create an upstream that uses this faulty bootstrap.
	u, err := AddressToUpstream("tls://random-domain-name", &Options{
		Logger:    testLogger,
		Bootstrap: NewCachingResolver(rslv),
		Timeout:   timeout,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	ch := make(chan int, count)
	for idx := range count {
		go func() {
			pt := testutil.NewPanicT(t)

			t.Logf("Start %d", idx)
			req := createTestMessage()

			start := time.Now()
			_, rErr := u.Exchange(req, nil)
			elapsed := time.Since(start)

			// Require an error, since the bootstrap server cannot work.
			require.Error(pt, rErr)

			// Check that the test didn't take too much time compared to the
			// configured timeout.  The actual elapsed time may be higher than
			// the timeout due to the execution environment; 3 is an arbitrarily
			// chosen multiplier to account for that.
			require.Less(pt, elapsed, 3*timeout)

			t.Logf("Finished %d", idx)
			ch <- idx
		}()
	}

	for range count {
		select {
		case res := <-ch:
			t.Logf("Got result from %d", res)
		case <-time.After(timeout * 10):
			t.Fatalf("No response in time")
		}
	}
}

// TestUpstreams covers native protocol and stamp dispatch against local real
// servers. Public providers and their currently reachable ports are not a
// protocol conformance oracle.
func TestUpstreams(t *testing.T) {
	answer := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(r)))
	})
	plain := startDNSServer(t, answer)
	t.Cleanup(func() { require.NoError(t, plain.Close()) })
	plainAddr := fmt.Sprintf("127.0.0.1:%d", plain.port)
	dot := startDoTServer(t, answer)
	dotAddr := fmt.Sprintf("127.0.0.1:%d", dot.port)
	doh := startDoHServer(t, testDoHServerOptions{http3Enabled: true})
	quicTLS, quicRoots := createServerTLSConfig(t, "127.0.0.1")
	doq := startDoQServer(t, quicTLS, 0)
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
	require.NoError(t, err)
	crypt := dnsproxytest.StartDNSCryptServer(t, rc, dnsproxytest.DNSCryptHandler(func(ctx context.Context, w dnscrypt.ResponseWriter, r *dns.Msg) error {
		return w.WriteMsg(ctx, respondToTestMessage(r))
	}))
	var bootCalls atomic.Int32
	boot := startDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		bootCalls.Add(1)
		response := new(dns.Msg).SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1")}}
		}
		require.NoError(testutil.PanicT{}, w.WriteMsg(response))
	})
	t.Cleanup(func() { require.NoError(t, boot.Close()) })
	resolver, err := NewUpstreamResolver(fmt.Sprintf("127.0.0.1:%d", boot.port), &Options{Logger: testLogger, Timeout: time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, resolver.Close()) })
	bootstrap := NewCachingResolver(resolver)
	stamp := func(proto dnsstamps.StampProtoType, address, path string) string {
		return (&dnsstamps.ServerStamp{Proto: proto, ServerAddrStr: address, ProviderName: address, Path: path}).String()
	}
	cases := []struct {
		name     string
		address  string
		roots    *x509.CertPool
		versions []HTTPVersion
	}{
		{"plain", plainAddr, nil, nil},
		{"udp", "udp://" + plainAddr, nil, nil},
		{"tcp", "tcp://" + plainAddr, nil, nil},
		{"dot", "tls://" + dotAddr, dot.rootCAs, nil},
		{"dot_bootstrap", "tls://" + strings.Replace(dotAddr, "127.0.0.1", "resolver.test", 1), dot.rootCAs, nil},
		{"doh1", "https://" + doh.addr + "/dns-query", doh.rootCAs, []HTTPVersion{HTTPVersion11}},
		{"doh2", "https://" + doh.addr + "/dns-query", doh.rootCAs, []HTTPVersion{HTTPVersion2}},
		{"doh3", "h3://" + doh.addr + "/dns-query", doh.rootCAs, nil},
		{"doh_bootstrap", "https://" + strings.Replace(doh.addr, "127.0.0.1", "resolver.test", 1) + "/dns-query", doh.rootCAs, nil},
		{"doq", "quic://" + doq.addr, quicRoots, nil},
		{"doq_bootstrap", "quic://" + strings.Replace(doq.addr, "127.0.0.1", "resolver.test", 1), quicRoots, nil},
		{"stamp_plain", stamp(dnsstamps.StampProtoTypePlain, plainAddr, ""), nil, nil},
		{"stamp_dot", stamp(dnsstamps.StampProtoTypeTLS, dotAddr, ""), dot.rootCAs, nil},
		{"stamp_doh", stamp(dnsstamps.StampProtoTypeDoH, doh.addr, "/dns-query"), doh.rootCAs, nil},
		{"stamp_doq", stamp(dnsstamps.StampProtoTypeDoQ, doq.addr, ""), quicRoots, nil},
		{"stamp_dnscrypt", crypt.String(), nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, parseErr := AddressToUpstream(tc.address, &Options{Logger: testLogger, Timeout: time.Second, RootCAs: tc.roots, ServerName: "127.0.0.1", Bootstrap: bootstrap, HTTPVersions: tc.versions})
			require.NoError(t, parseErr)
			t.Cleanup(func() { require.NoError(t, u.Close()) })
			for range 3 {
				checkUpstream(t, u, tc.address)
			}
		})
	}
	require.Positive(t, bootCalls.Load(), "hostname cases must reach the actual local bootstrap DNS server")
}

func TestAddressToUpstream(t *testing.T) {
	cloudflareRslv, err := NewUpstreamResolver("1.1.1.1", nil)
	require.NoError(t, err)

	opt := &Options{
		Logger:    testLogger,
		Bootstrap: NewCachingResolver(cloudflareRslv),
	}

	testCases := []struct {
		addr string
		opt  *Options
		want string
	}{{
		addr: "1.1.1.1",
		opt:  nil,
		want: "1.1.1.1:53",
	}, {
		addr: "1.1.1.1:5353",
		opt:  nil,
		want: "1.1.1.1:5353",
	}, {
		addr: "one:5353",
		opt:  nil,
		want: "one:5353",
	}, {
		addr: "one.one.one.one",
		opt:  nil,
		want: "one.one.one.one:53",
	}, {
		addr: "udp://one.one.one.one",
		opt:  nil,
		want: "one.one.one.one:53",
	}, {
		addr: "tcp://one.one.one.one",
		opt:  opt,
		want: "tcp://one.one.one.one:53",
	}, {
		addr: "tls://one.one.one.one",
		opt:  opt,
		want: "tls://one.one.one.one:853",
	}, {
		addr: "https://one.one.one.one",
		opt:  opt,
		want: "https://one.one.one.one:443",
	}, {
		addr: "h3://one.one.one.one",
		opt:  opt,
		want: "https://one.one.one.one:443",
	}, {
		addr: "::ffff:1.1.1.1",
		opt:  nil,
		want: "[::ffff:1.1.1.1]:53",
	}, {
		addr: "https://[2606:4700:4700::1111]/dns-query",
		opt:  nil,
		want: "https://[2606:4700:4700::1111]:443/dns-query",
	}, {
		addr: "https://[2606:4700:4700::1111]:443/dns-query",
		opt:  nil,
		want: "https://[2606:4700:4700::1111]:443/dns-query",
	}}

	for _, tc := range testCases {
		t.Run(tc.addr, func(t *testing.T) {
			u, upsErr := AddressToUpstream(tc.addr, tc.opt)
			require.NoError(t, upsErr)
			testutil.CleanupAndRequireSuccess(t, u.Close)

			assert.Equal(t, tc.want, u.Address())
		})
	}
}

func TestAddressToUpstream_bads(t *testing.T) {
	testCases := []struct {
		addr       string
		wantErrMsg string
	}{{
		addr:       "asdf://1.1.1.1",
		wantErrMsg: "unsupported url scheme: asdf",
	}, {
		addr: "12345.1.1.1:1234567",
		wantErrMsg: `invalid port 1234567: strconv.ParseUint: parsing "1234567": ` +
			`value out of range`,
	}, {
		addr: ":1234567",
		wantErrMsg: `invalid port 1234567: strconv.ParseUint: parsing "1234567": ` +
			`value out of range`,
	}, {
		addr:       "host:",
		wantErrMsg: `invalid port : strconv.ParseUint: parsing "": invalid syntax`,
	}, {
		addr:       ":53",
		wantErrMsg: `invalid address : bad domain name "": domain name is empty`,
	}, {
		addr: "!!!",
		wantErrMsg: `invalid address !!!: bad domain name "!!!": bad top-level domain name ` +
			`label "!!!": bad top-level domain name label rune '!'`,
	}, {
		addr: "123",
		wantErrMsg: `invalid address 123: bad domain name "123": bad top-level domain name ` +
			`label "123": all octets are numeric`,
	}, {
		addr: "tcp://12345.1.1.1:1234567",
		wantErrMsg: `invalid port 1234567: strconv.ParseUint: parsing "1234567": ` +
			`value out of range`,
	}, {
		addr: "tcp://:1234567",
		wantErrMsg: `invalid port 1234567: strconv.ParseUint: parsing "1234567": ` +
			`value out of range`,
	}, {
		addr:       "tcp://host:",
		wantErrMsg: `invalid port : strconv.ParseUint: parsing "": invalid syntax`,
	}, {
		addr:       "tcp://:53",
		wantErrMsg: `invalid address : bad domain name "": domain name is empty`,
	}, {
		addr: "tcp://!!!",
		wantErrMsg: `invalid address !!!: bad domain name "!!!": bad top-level domain name ` +
			`label "!!!": bad top-level domain name label rune '!'`,
	}, {
		addr: "tcp://123",
		wantErrMsg: `invalid address 123: bad domain name "123": bad top-level domain name ` +
			`label "123": all octets are numeric`,
	}}

	for _, tc := range testCases {
		t.Run(tc.addr, func(t *testing.T) {
			_, err := AddressToUpstream(tc.addr, nil)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func localBootstrapAnswer(r *dns.Msg) *dns.Msg {
	response := new(dns.Msg).SetReply(r)
	if r.Question[0].Qtype == dns.TypeA {
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1")}}
	}
	return response
}

func localBootstrapHTTP(w http.ResponseWriter, r *http.Request) {
	wire, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
	require.NoError(testutil.PanicT{}, err)
	query := new(dns.Msg)
	require.NoError(testutil.PanicT{}, query.Unpack(wire))
	wire, err = localBootstrapAnswer(query).Pack()
	require.NoError(testutil.PanicT{}, err)
	w.Header().Set("Content-Type", "application/dns-message")
	_, err = w.Write(wire)
	require.NoError(testutil.PanicT{}, err)
}

func TestUpstreamDoTBootstrap(t *testing.T) {
	var queries atomic.Int32
	bootDoT := startDoTServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		queries.Add(1)
		require.NoError(testutil.PanicT{}, w.WriteMsg(localBootstrapAnswer(r)))
	})
	bootDoH := startDoHServer(t, testDoHServerOptions{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { queries.Add(1); localBootstrapHTTP(w, r) })})
	target := startDoTServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(r)))
	})
	for _, tc := range []struct {
		roots   *x509.CertPool
		address string
	}{
		{address: fmt.Sprintf("tls://127.0.0.1:%d", bootDoT.port), roots: bootDoT.rootCAs},
		{address: "https://" + bootDoH.addr + "/dns-query", roots: bootDoH.rootCAs},
	} {
		t.Run(tc.address, func(t *testing.T) {
			queries.Store(0)
			resolver, err := NewUpstreamResolver(tc.address, &Options{Logger: testLogger, Timeout: time.Second, RootCAs: tc.roots})
			require.NoError(t, err)
			defer func(closeResource func() error) { _ = closeResource() }(resolver.Close)
			address := fmt.Sprintf("tls://resolver.test:%d", target.port)
			u, err := AddressToUpstream(address, &Options{Logger: testLogger, Timeout: time.Second, RootCAs: target.rootCAs, ServerName: "127.0.0.1", Bootstrap: NewCachingResolver(resolver)})
			require.NoError(t, err)
			defer func(closeResource func() error) { _ = closeResource() }(u.Close)
			checkUpstream(t, u, address)
			require.Positive(t, queries.Load(), "native encrypted bootstrap must actually be used")
		})
	}
}

// TestUpstreamsInvalidBootstrap exercises the native ordered bootstrap with
// real local failed and successful servers. Bootstrap attempts have their own
// short timeout within the larger query budget.
func TestUpstreamsInvalidBootstrap(t *testing.T) {
	answer := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(r)))
	})
	dot := startDoTServer(t, answer)
	doh := startDoHServer(t, testDoHServerOptions{})
	dotName := fmt.Sprintf("resolver.test:%d", dot.port)
	dohName := strings.Replace(doh.addr, "127.0.0.1", "resolver.test", 1)
	for _, tc := range []struct {
		roots         *x509.CertPool
		name, address string
	}{
		{name: "dot", address: "tls://" + dotName, roots: dot.rootCAs},
		{name: "doh", address: "https://" + dohName + "/dns-query", roots: doh.rootCAs},
		{name: "stamp_dot", address: (&dnsstamps.ServerStamp{Proto: dnsstamps.StampProtoTypeTLS, ProviderName: dotName}).String(), roots: dot.rootCAs},
		{name: "stamp_doh", address: (&dnsstamps.ServerStamp{Proto: dnsstamps.StampProtoTypeDoH, ProviderName: dohName, Path: "/dns-query"}).String(), roots: doh.rootCAs},
	} {
		for _, badFirst := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/bad_first_%t", tc.name, badFirst), func(t *testing.T) {
				var failedCalls, goodCalls atomic.Int32
				failed := startDNSServer(t, func(dns.ResponseWriter, *dns.Msg) { failedCalls.Add(1) })
				defer func(closeResource func() error) { _ = closeResource() }(failed.Close)
				good := startDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
					goodCalls.Add(1)
					response := new(dns.Msg).SetReply(r)
					if r.Question[0].Qtype == dns.TypeA {
						response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1")}}
					}
					require.NoError(testutil.PanicT{}, w.WriteMsg(response))
				})
				defer func(closeResource func() error) { _ = closeResource() }(good.Close)
				ports := []int{failed.port, good.port}
				if !badFirst {
					ports[0], ports[1] = ports[1], ports[0]
				}
				var resolvers ConsequentResolver
				for _, port := range ports {
					resolver, err := NewUpstreamResolver(fmt.Sprintf("127.0.0.1:%d", port), &Options{Logger: testLogger, Timeout: 20 * time.Millisecond})
					require.NoError(t, err)
					defer func(closeResource func() error) { _ = closeResource() }(resolver.Close)
					resolvers = append(resolvers, NewCachingResolver(resolver))
				}
				u, err := AddressToUpstream(tc.address, &Options{Logger: testLogger, Bootstrap: resolvers, RootCAs: tc.roots, ServerName: "127.0.0.1", Timeout: time.Second})
				require.NoError(t, err)
				defer func(closeResource func() error) { _ = closeResource() }(u.Close)
				checkUpstream(t, u, tc.address)
				require.Positive(t, goodCalls.Load(), "success must use the actual native bootstrap")
				if badFirst {
					require.Positive(t, failedCalls.Load(), "first bootstrap must actually fail before continuing")
				} else {
					require.Zero(t, failedCalls.Load(), "ordered bootstrap stops at the first usable result")
				}
			})
		}
	}
	t.Run("bad_bootstrap", func(t *testing.T) {
		_, err := NewUpstreamResolver("asdfasdf", nil)
		require.Error(t, err)
	})
}

func TestAddressToUpstream_StaticResolver(t *testing.T) {
	t.Parallel()

	h := func(w dns.ResponseWriter, m *dns.Msg) {
		require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(m)))
	}
	dotSrv := startDoTServer(t, h)
	dohSrv := startDoHServer(t, testDoHServerOptions{})
	_, dohPort, err := net.SplitHostPort(dohSrv.addr)
	require.NoError(t, err)

	badResolver := &UpstreamResolver{Upstream: nil}

	dotStamp := (&dnsstamps.ServerStamp{
		ServerAddrStr: netip.AddrPortFrom(netutil.IPv4Localhost(), uint16(dotSrv.port)).String(),
		Proto:         dnsstamps.StampProtoTypeTLS,
		ProviderName:  netip.AddrPortFrom(netutil.IPv4Localhost(), uint16(dotSrv.port)).String(),
	}).String()
	dohStamp := (&dnsstamps.ServerStamp{
		ServerAddrStr: dohSrv.addr,
		Proto:         dnsstamps.StampProtoTypeDoH,
		ProviderName:  dohSrv.addr,
		Path:          "/dns-query",
	}).String()

	upstreams := []struct {
		rslv    Resolver
		name    string
		address string
	}{{
		rslv:    StaticResolver{netutil.IPv4Localhost()},
		name:    "dot",
		address: fmt.Sprintf("tls://some.dns.server:%d", dotSrv.port),
	}, {
		rslv:    StaticResolver{netutil.IPv4Localhost()},
		name:    "doh",
		address: fmt.Sprintf("https://some.dns.server:%s/dns-query", dohPort),
	}, {
		rslv:    badResolver,
		name:    "dot_stamp",
		address: dotStamp,
	}, {
		rslv:    badResolver,
		name:    "doh_stamp",
		address: dohStamp,
	}}

	for _, tc := range upstreams {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := &Options{
				Logger:             testLogger,
				Bootstrap:          tc.rslv,
				Timeout:            testTimeout,
				InsecureSkipVerify: true,
			}
			u, uErr := AddressToUpstream(tc.address, opts)
			require.NoError(t, uErr)
			testutil.CleanupAndRequireSuccess(t, u.Close)

			assert.NotPanics(t, func() {
				checkUpstream(t, u, tc.address)
			})
		})
	}
}

func TestAddPort(t *testing.T) {
	testCases := []struct {
		name string
		want string
		host string
		port uint16
	}{{
		name: "empty",
		want: ":0",
		host: "",
		port: 0,
	}, {
		name: "hostname",
		want: "example.org:53",
		host: "example.org",
		port: 53,
	}, {
		name: "ipv4",
		want: "1.2.3.4:1",
		host: "1.2.3.4",
		port: 1,
	}, {
		name: "ipv6",
		want: "[::1]:1",
		host: "::1",
		port: 1,
	}, {
		name: "ipv6_with_brackets",
		want: "[::1]:1",
		host: "[::1]",
		port: 1,
	}, {
		name: "hostname_with_port",
		want: "example.org:54",
		host: "example.org:54",
		port: 53,
	}, {
		name: "ipv4_with_port",
		want: "1.2.3.4:2",
		host: "1.2.3.4:2",
		port: 1,
	}, {
		name: "ipv6_with_brackets_and_port",
		want: "[::1]:2",
		host: "[::1]:2",
		port: 1,
	}}

	for _, tc := range testCases {
		u := &url.URL{
			Host: tc.host,
		}

		t.Run(tc.name, func(t *testing.T) {
			addPort(u, tc.port)
			assert.Equal(t, tc.want, u.Host)
		})
	}
}

// checkUpstream sends a test message to the upstream and checks the result.
func checkUpstream(tb testing.TB, u Upstream, addr string) {
	tb.Helper()

	req := createTestMessage()
	reply, err := u.Exchange(req, nil)
	require.NoErrorf(tb, err, "couldn't talk to upstream %s", addr)

	requireResponse(tb, req, reply)
}

// checkRaceCondition runs several goroutines in parallel and each of them calls
// checkUpstream several times.
func checkRaceCondition(u Upstream) {
	wg := sync.WaitGroup{}

	// The number of requests to run in every goroutine.
	reqCount := 10
	// The overall number of goroutines to run.
	goroutinesCount := 3

	makeRequests := func() {
		defer wg.Done()
		for range reqCount {
			req := createTestMessage()
			// Ignore exchange errors here, the point is to check for races.
			_, _ = u.Exchange(req, nil)
		}
	}

	wg.Add(goroutinesCount)
	for range goroutinesCount {
		go makeRequests()
	}

	wg.Wait()
}

// createTestMessage creates a *dns.Msg that we use for tests and that we then
// check with requireResponse.
func createTestMessage() (m *dns.Msg) {
	return createHostTestMessage("google-public-dns-a.google.com")
}

// respondToTestMessage crafts a *dns.Msg response to a message created by
// createTestMessage.
func respondToTestMessage(m *dns.Msg) (resp *dns.Msg) {
	resp = &dns.Msg{}
	resp.SetReply(m)
	resp.Answer = append(resp.Answer, &dns.A{
		A: net.IPv4(8, 8, 8, 8),
		Hdr: dns.RR_Header{
			Name:   "google-public-dns-a.google.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    100,
		},
	})

	return resp
}

// createHostTestMessage creates a *dns.Msg with A request for the specified
// host name.
func createHostTestMessage(host string) (req *dns.Msg) {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   dns.Fqdn(host),
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}
}

// requireResponse validates that the *dns.Msg is a valid response to the
// message created by createTestMessage.
func requireResponse(t require.TestingT, req, reply *dns.Msg) {
	require.NotNil(t, reply)
	require.Lenf(t, reply.Answer, 1, "wrong number of answers: %d", len(reply.Answer))
	require.Equal(t, req.Id, reply.Id)

	a, ok := reply.Answer[0].(*dns.A)
	require.Truef(t, ok, "wrong answer type: %v", reply.Answer[0])

	require.Equalf(t, net.IPv4(8, 8, 8, 8), a.A.To16(), "wrong answer: %v", a.A)
}

// createServerTLSConfig creates a test server TLS configuration. It returns
// a *tls.Config that can be used for both the server and the client and the
// root certificate pem-encoded.
// TODO(ameshkov): start using rootCAs in tests instead of InsecureVerify.
func createServerTLSConfig(
	tb testing.TB,
	tlsServerName string,
) (tlsConfig *tls.Config, rootCAs *x509.CertPool) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(tb, err)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(tb, err)

	notBefore := time.Now()
	notAfter := notBefore.Add(5 * 365 * time.Hour * 24)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"AdGuard Tests"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	ipAddress := net.ParseIP(tlsServerName)
	if ipAddress != nil {
		template.IPAddresses = append(template.IPAddresses, ipAddress)
	} else {
		template.DNSNames = append(template.DNSNames, tlsServerName)
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		publicKey(privateKey),
		privateKey,
	)
	require.NoError(tb, err)

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)

	cert, err := tls.X509KeyPair(certPem, keyPem)
	require.NoError(tb, err)

	rootCAs = x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(certPem)

	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   tlsServerName,
		RootCAs:      rootCAs,
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, rootCAs
}

// publicKey extracts the public key from the specified private key.
func publicKey(priv any) (pub any) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

// testTracer collects QUIC connection traces for testing.
type testTracer struct {
	tracers []*quicTracer
}

// TraceForConnection creates a tracer for a QUIC connection.
func (t *testTracer) TraceForConnection(
	_ context.Context,
	_ bool,
	_ quic.ConnectionID,
) (tracer qlogwriter.Trace) {
	newTracer := &quicTracer{recorder: &headerRecorder{}}
	t.tracers = append(t.tracers, newTracer)

	return newTracer
}

// connectionsInfo returns info for all traced connections.
func (t *testTracer) connectionsInfo() (res []*connInfo) {
	res = make([]*connInfo, 0, len(t.tracers))
	for _, tracer := range t.tracers {
		hdrs := tracer.recorder.headersWithLock()

		res = append(res, &connInfo{
			headers: hdrs,
		})
	}

	return res
}

// connInfo contains all trace event headers recorded for single connection.
type connInfo struct {
	headers []qlog.PacketHeader
}

// is0RTT returns true if the connection used 0-RTT packets.
func (c *connInfo) is0RTT() (ok bool) {
	for _, hdr := range c.headers {
		if hdr.PacketType == qlog.PacketType0RTT {
			return true
		}
	}

	return false
}

// quicTracer is an implementation of [qlogwriter.Trace] for testing.
type quicTracer struct {
	// recorder is used for recording trace events.  It must not be nil.
	recorder *headerRecorder
}

// type check
var _ qlogwriter.Trace = (*quicTracer)(nil)

// AddProducer implements the [qlogwriter.Trace] interface for *quicTracer.
func (q *quicTracer) AddProducer() (recorder qlogwriter.Recorder) {
	return q.recorder
}

// SupportsSchemas implements the [qlogwriter.Trace] interface for *quicTracer.
func (q *quicTracer) SupportsSchemas(string) (ok bool) {
	return false
}

// Recorder is an implementation of [qlogwriter.Recorder] that records
// [qlog.PacketSent] events headers.
type headerRecorder struct {
	headers []qlog.PacketHeader
	mx      sync.Mutex
}

// type check
var _ qlogwriter.Recorder = (*headerRecorder)(nil)

// RecordEvent implements the [qlogwriter.Recorder] interface for
// *headerRecorder.
func (r *headerRecorder) RecordEvent(ev qlogwriter.Event) {
	event, ok := ev.(qlog.PacketSent)
	if !ok {
		return
	}

	r.mx.Lock()
	defer r.mx.Unlock()

	r.headers = append(r.headers, event.Header)
}

// headersWithLock returns copy of recorded headers.  It is safe for concurrent
// use.
func (r *headerRecorder) headersWithLock() (res []qlog.PacketHeader) {
	r.mx.Lock()
	defer r.mx.Unlock()

	res = r.headers

	return res
}

// Close implements the [qlogwriter.Recorder] interface for
// *headerRecorder.
func (*headerRecorder) Close() (err error) {
	return nil
}

func TestNewUpstreamResolver_validity(t *testing.T) {
	t.Parallel()

	answer := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		require.NoError(testutil.PanicT{}, w.WriteMsg(localBootstrapAnswer(r)))
	})
	plain := startDNSServer(t, answer)
	t.Cleanup(func() { require.NoError(t, plain.Close()) })
	dot := startDoTServer(t, answer)
	doh := startDoHServer(t, testDoHServerOptions{handler: http.HandlerFunc(localBootstrapHTTP)})

	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
	require.NoError(t, err)
	stamp := dnsproxytest.StartDNSCryptServer(t, rc, dnsproxytest.DNSCryptHandler(func(ctx context.Context, w dnscrypt.ResponseWriter, r *dns.Msg) error {
		response := new(dns.Msg).SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: netip.MustParseAddr("192.0.2.1").AsSlice()}}
		}
		return w.WriteMsg(ctx, response)
	}))
	withTimeoutOpt := &Options{
		Logger:  testLogger,
		Timeout: 3 * time.Second,
	}

	testCases := []struct {
		name       string
		addr       string
		wantErrMsg string
	}{{
		name:       "udp",
		addr:       fmt.Sprintf("127.0.0.1:%d", plain.port),
		wantErrMsg: "",
	}, {
		name:       "dot",
		addr:       fmt.Sprintf("tls://127.0.0.1:%d", dot.port),
		wantErrMsg: "",
	}, {
		name:       "doh",
		addr:       "https://" + doh.addr + "/dns-query",
		wantErrMsg: "",
	}, {
		name:       "sdns",
		addr:       stamp.String(),
		wantErrMsg: "",
	}, {
		name:       "tcp",
		addr:       fmt.Sprintf("tcp://127.0.0.1:%d", plain.port),
		wantErrMsg: "",
	}, {
		name: "invalid_tls",
		addr: "tls://dns.adguard.com",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}, {
		name: "invalid_https",
		addr: "https://dns.adguard.com/dns-query",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}, {
		name: "invalid_tcp",
		addr: "tcp://dns.adguard.com",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}, {
		name: "invalid_no_scheme",
		addr: "dns.adguard.com",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := withTimeoutOpt.Clone()
			if tc.name == "dot" {
				opts.RootCAs = dot.rootCAs
			}
			if tc.name == "doh" {
				opts.RootCAs = doh.rootCAs
			}
			r, resolverErr := NewUpstreamResolver(tc.addr, opts)
			if tc.wantErrMsg != "" {
				assert.Equal(t, tc.wantErrMsg, resolverErr.Error())
				if nberr := (&NotBootstrapError{}); errors.As(resolverErr, &nberr) {
					assert.NotNil(t, r)
				}

				return
			}

			require.NoError(t, resolverErr)
			t.Cleanup(func() { require.NoError(t, r.Close()) })

			addrs, resolverErr := r.LookupNetIP(context.Background(), "ip", "cloudflare-dns.com")
			require.NoError(t, resolverErr)

			assert.NotEmpty(t, addrs)
		})
	}
}
