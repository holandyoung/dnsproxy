package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/holandyoung/quic-go/http3"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// A large H1 body has already left the native buffer when Write returns. The
// client must not wait for unrelated middleware work to receive its HTTP EOF.
// The reader still consumes the entire native body, not a DNS-sized prefix.
func TestHTTPSCompleteBodyBeforePostWriteObservation(t *testing.T) {
	serverTLS, caPEM := newTLSConfig(t)
	request := new(dns.Msg).SetQuestion("complete.example.", dns.TypeTXT)
	response := new(dns.Msg).SetReply(request)
	response.Compress = true
	text := make([]string, 64)
	for i := range text {
		text[i] = strings.Repeat("x", 250)
	}
	response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{
		Name: request.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60,
	}, Txt: text}}
	want, err := response.Pack()
	require.NoError(t, err)
	require.Greater(t, len(want), 8192)
	written := make(chan error, 1)
	release := make(chan struct{})
	p := mustNew(t, &Config{
		Logger: testLogger, TLSConfig: serverTLS,
		HTTPConfig: &HTTPConfig{ListenAddresses: []netip.AddrPort{localhostAnyPort}},
		RequestHandler: HandlerFunc(func(_ context.Context, _ *Proxy, d *DNSContext) error {
			d.Res = response.Copy()
			return nil
		}),
		RequestMiddleware: func(next Handler) Handler {
			return HandlerFunc(func(ctx context.Context, p *Proxy, d *DNSContext) error {
				writeErr := next.ServeDNS(ctx, p, d)
				written <- writeErr
				<-release
				return writeErr
			})
		},
	})
	servicetest.RequireRun(t, p, testTimeout)
	// This cleanup runs before the native service cleanup even on assertion failure.
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM))
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: tlsServerName, MinVersion: tls.VersionTLS12},
		TLSNextProto:    make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	wire, err := request.Pack()
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"https://"+p.Addr(ProtoHTTPS).String()+"/dns-query", bytes.NewReader(wire))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/dns-message")
	type result struct {
		err           error
		body          []byte
		status, major int
	}
	read := make(chan result, 1)
	go func() {
		r, readErr := client.Do(req)
		if readErr != nil {
			read <- result{err: readErr}
			return
		}
		body, readErr := io.ReadAll(r.Body)
		closeErr := r.Body.Close()
		if readErr == nil {
			readErr = closeErr
		}
		read <- result{body: body, err: readErr, status: r.StatusCode, major: r.ProtoMajor}
	}()
	select {
	case err = <-written:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("native DNS write did not complete")
	}
	var got result
	completedBeforeObservation := false
	select {
	case got = <-read:
		completedBeforeObservation = true
	case <-time.After(250 * time.Millisecond):
	}
	close(release)
	released = true
	if !completedBeforeObservation {
		select {
		case got = <-read:
		case <-time.After(5 * time.Second):
			t.Fatal("native HTTP body did not complete after releasing middleware")
		}
	}
	require.NoError(t, got.err)
	require.Equal(t, http.StatusOK, got.status)
	require.Equal(t, 1, got.major)
	require.Equal(t, want, got.body)
	require.True(t, completedBeforeObservation, "complete H1 body waited for post-write observation")
}

func TestHTTPSContentLengthUsesEncodedBody(t *testing.T) {
	for _, shape := range []string{"small", "compressed", "large", "refused"} {
		t.Run(shape, func(t *testing.T) {
			serverTLS, caPEM := newTLSConfig(t)
			request := new(dns.Msg).SetQuestion("length.example.", dns.TypeTXT)
			response := new(dns.Msg).SetReply(request)
			response.Compress = shape == "compressed"
			count := 1
			if shape == "compressed" || shape == "large" {
				count = 64
			}
			for range count {
				response.Answer = append(response.Answer, &dns.TXT{Hdr: dns.RR_Header{
					Name: request.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60,
				}, Txt: []string{strings.Repeat("x", 250)}})
			}
			if shape == "refused" {
				response.SetRcode(request, dns.RcodeRefused)
				response.Answer = nil
			}
			want, err := response.Pack()
			require.NoError(t, err)
			if shape == "compressed" {
				plain := response.Copy()
				plain.Compress = false
				uncompressed, packErr := plain.Pack()
				require.NoError(t, packErr)
				require.Less(t, len(want), len(uncompressed))
			}
			p := mustNew(t, &Config{
				Logger: testLogger, TLSConfig: serverTLS,
				HTTPConfig: &HTTPConfig{ListenAddresses: []netip.AddrPort{localhostAnyPort}, HTTP3Enabled: true},
				RequestHandler: HandlerFunc(func(_ context.Context, _ *Proxy, d *DNSContext) error {
					d.Res = response.Copy()
					return nil
				}),
			})
			servicetest.RequireRun(t, p, testTimeout)
			for _, major := range []int{1, 2, 3} {
				client := createTestHTTPClient(p, caPEM, major == 3)
				if transport, ok := client.Transport.(*http.Transport); ok {
					defer transport.CloseIdleConnections()
					if major == 1 {
						transport.ForceAttemptHTTP2 = false
						transport.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
						transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
					}
				} else {
					defer func() { require.NoError(t, client.Transport.(*http3.Transport).Close()) }()
				}
				wire, packErr := request.Pack()
				require.NoError(t, packErr)
				req, requestErr := http.NewRequestWithContext(t.Context(), http.MethodPost,
					"https://"+tlsServerName+"/dns-query", bytes.NewReader(wire))
				require.NoError(t, requestErr)
				req.Header.Set("Content-Type", "application/dns-message")
				r, requestErr := client.Do(req)
				require.NoError(t, requestErr)
				body, readErr := io.ReadAll(r.Body)
				require.NoError(t, r.Body.Close())
				require.NoError(t, readErr)
				require.Equal(t, http.StatusOK, r.StatusCode)
				require.Equal(t, major, r.ProtoMajor)
				if major == 1 {
					require.Equal(t, int64(len(want)), r.ContentLength)
				} else if len(want) > 8192 {
					// Preserve native large-body H2/H3 framing; the H1 fix must
					// not add a length field to these stream-terminated bodies.
					require.Equal(t, int64(-1), r.ContentLength)
				}
				require.Empty(t, r.TransferEncoding)
				require.Equal(t, want, body)
			}
		})
	}
}
