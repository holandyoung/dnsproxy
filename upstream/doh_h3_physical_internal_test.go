package upstream

import (
	"crypto/tls"
	"github.com/miekg/dns"
	"sync"
	"testing"
	"time"
)

func TestH3FailureReceiptBeforeNativeTLSJoin(t *testing.T) {
	server := startDoHServer(t, testDoHServerOptions{http3Enabled: true})
	entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	resolver, err := AddressToUpstream("h3://"+server.addr+"/dns-query", &Options{RootCAs: server.rootCAs, Logger: testLogger, Timeout: 100 * time.Millisecond, HTTPVersions: []HTTPVersion{HTTPVersion3}, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.VerifiedChains) == 0 {
			t.Error("untrusted prerequisite")
		}
		close(entered)
		<-release
		close(exited)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		unblock()
		if closeErr := resolver.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	request := new(dns.Msg).SetQuestion("h3join.example.", dns.TypeA)
	state := NewExchangeState(time.Now().Add(2 * time.Second))
	joined := make(chan struct{})
	go func() { _, _ = resolver.Exchange(request, state); close(joined) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("native H3 TLS prerequisite did not enter")
	}
	select {
	case <-state.Done():
	case <-time.After(350 * time.Millisecond):
		t.Error("H3 timeout receipt is blocked by native TLS physical cleanup")
	}
	select {
	case <-joined:
		t.Error("H3 Exchange returned before TLS callback exited")
	default:
	}
	unblock()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("H3 Exchange failed to join after release")
	}
	select {
	case <-exited:
	default:
		t.Fatal("TLS callback exit missing")
	}
}
