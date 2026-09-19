package upstream

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDoHExchangeJoinsNativeTLSAfterReceipt(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if err != nil {
			t.Error(err)
			return
		}
		request := new(dns.Msg)
		if err = request.Unpack(wire); err != nil {
			t.Error(err)
			return
		}
		response := new(dns.Msg).SetReply(request)
		wire, err = response.Pack()
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, err = w.Write(wire)
		if err != nil {
			t.Error(err)
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var calls atomic.Int32
	resolver, err := AddressToUpstream(server.URL+"/dns-query", &Options{
		Logger: testLogger, RootCAs: roots, Timeout: 60 * time.Millisecond,
		HTTPVersions: []HTTPVersion{HTTPVersion2},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 {
				t.Error("native TLS prerequisite: certificate was not verified")
			}
			if calls.Add(1) == 1 {
				close(entered)
				<-release
				close(exited)
			}
			return nil
		},
	})
	require.NoError(t, err)
	defer func() { unblock(); require.NoError(t, resolver.Close()) }()
	request := new(dns.Msg).SetQuestion("physical.example.", dns.TypeA)
	state := NewExchangeState(time.Now().Add(time.Second))
	joined := make(chan struct{})
	go func() {
		_, _ = resolver.Exchange(request, state)
		close(joined)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("native trusted TLS prerequisite did not enter")
	}
	select {
	case <-state.Done():
		result, ok := state.Result()
		require.True(t, ok)
		require.Error(t, result.Err)
	case <-time.After(time.Second):
		t.Fatal("native HTTP timeout receipt waited for physical cleanup")
	}
	select {
	case <-joined:
		t.Error("Exchange returned while its native TLS callback was still running")
	case <-time.After(30 * time.Millisecond):
	}
	// Joining the first exchange must not hold the shared client's lock or
	// close a new request's connection. Its own receipt and native return work.
	response, err := resolver.Exchange(request, NewExchangeState(time.Now().Add(time.Second)))
	require.NoError(t, err)
	require.NotNil(t, response)
	unblock()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("Exchange failed to join after callback release")
	}
	select {
	case <-exited:
	default:
		t.Fatal("physical completion preceded callback exit")
	}
}
