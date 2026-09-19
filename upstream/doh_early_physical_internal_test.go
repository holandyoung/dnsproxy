package upstream

import (
	"context"
	"crypto/tls"
	quic "github.com/holandyoung/quic-go"
	"github.com/miekg/dns"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestH3EarlyDialRetainsHandshakeWork(t *testing.T) {
	server := startDoHServer(t, testDoHServerOptions{http3Enabled: true})
	entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var calls atomic.Int32
	u, err := AddressToUpstream("h3://"+server.addr+"/dns-query", &Options{RootCAs: server.rootCAs, Logger: testLogger, Timeout: time.Second, HTTPVersions: []HTTPVersion{HTTPVersion3}, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.VerifiedChains) == 0 {
			t.Error("untrusted prerequisite")
		}
		if calls.Add(1) == 2 {
			if !cs.DidResume {
				t.Error("session resumption prerequisite failed")
			}
			close(entered)
			<-release
			close(exited)
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	resolver := u.(*dnsOverHTTPS)
	defer func() {
		unblock()
		if closeErr := resolver.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	request := new(dns.Msg).SetQuestion("resume.example.", dns.TypeA)
	response, err := resolver.Exchange(request, nil)
	if err != nil || response == nil {
		t.Fatal("warmup failed", err)
	}
	resolver.clientMu.Lock()
	err = resolver.closeClient(resolver.client)
	resolver.client = nil
	resolver.clientMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// Build the existing native H3 transport, then observe its actual Dial hook.
	client, _, err := resolver.getClient(new(httpWork))
	if err != nil {
		t.Fatal(err)
	}
	rt := client.Transport.(*http3Transport).baseTransport
	dial := rt.Dial
	type observed struct {
		work *httpWork
		conn *quic.Conn
	}
	early := make(chan observed, 1)
	rt.Dial = func(ctx context.Context, address string, conf *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		conn, dialErr := dial(ctx, address, conf, cfg)
		if dialErr == nil {
			scope, ok := ctx.Value(httpRequestScopeKey{}).(httpRequestScope)
			if !ok {
				t.Error("actual request scope missing")
			}
			early <- observed{scope.work, conn}
		}
		return conn, dialErr
	}
	joined := make(chan error, 1)
	go func() { _, exchangeErr := resolver.Exchange(request, nil); joined <- exchangeErr }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("resumed trusted TLS callback not entered")
	}
	var seen observed
	select {
	case seen = <-early:
	case <-time.After(time.Second):
		t.Fatal("native early dial did not return before handshake")
	}
	select {
	case <-seen.conn.HandshakeComplete():
		t.Fatal("held handshake already completed")
	default:
	}
	physical := make(chan struct{})
	go func() { seen.work.work.Wait(); close(physical) }()
	select {
	case <-physical:
		t.Error("request httpWork completed while native 0-RTT handshake callback remains live")
	case <-time.After(30 * time.Millisecond):
	}
	unblock()
	select {
	case exchangeErr := <-joined:
		if exchangeErr != nil {
			t.Fatal("resumed query after release", exchangeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("resumed query did not join")
	}
	select {
	case <-exited:
	default:
		t.Fatal("resumed TLS callback not exited")
	}
}
