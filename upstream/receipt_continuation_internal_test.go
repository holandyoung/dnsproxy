package upstream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestReceiptUDPContinuationRequiresNewCompleteCandidate(t *testing.T) {
	for _, mode := range []string{"TCP success", "TCP failure", "TCP late", "question retry"} {
		t.Run(mode, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			srv := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
				response := respondToTestMessage(req)
				if w.RemoteAddr().Network() == "udp" {
					if mode == "question retry" {
						response.Question[0].Name = "different.example."
					} else {
						response.Truncated = true
					}
				} else {
					close(entered)
					<-release
				}
				_ = w.WriteMsg(response)
			})
			t.Cleanup(func() { require.NoError(t, srv.Close()) })
			t.Cleanup(unblock)
			route := &routedNetwork{address: fmt.Sprintf("127.0.0.1:%d", srv.port)}
			if mode == "TCP failure" {
				route.tcpError = errors.New("TCP route rejected")
			}
			u, err := AddressToUpstream("udp://127.0.0.1:1", &Options{NetworkDialer: route, Timeout: time.Second, Logger: testLogger})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, u.Close()) })
			state := NewExchangeState(time.Now().Add(2 * time.Second))
			req := createTestMessage()
			req.Id = 0
			finished := make(chan error, 1)
			go func() { _, err := u.Exchange(req, state); finished <- err }()
			if mode != "TCP failure" {
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("TCP continuation never entered")
				}
				_, ready := state.Result()
				require.False(t, ready, "provisional UDP packet cannot publish the answer")
				if mode == "TCP late" || mode == "question retry" {
					state.Expire()
					result, ready := state.Result()
					require.True(t, ready, "rejected UDP candidate cannot keep a reservation during TCP I/O")
					require.ErrorIs(t, result.Err, context.DeadlineExceeded)
				}
			}
			tcpReleased := time.Now()
			unblock()
			select {
			case err = <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("TCP continuation did not finish")
			}
			result, ready := state.Result()
			require.True(t, ready)
			switch mode {
			case "TCP success":
				require.NoError(t, err)
				require.NoError(t, result.Err)
				require.Zero(t, result.Response.Id)
				require.False(t, result.Response.Truncated)
				require.False(t, result.ReceivedAt.Before(tcpReleased))
			case "TCP failure":
				require.ErrorIs(t, err, route.tcpError)
				require.ErrorIs(t, result.Err, route.tcpError)
				require.Nil(t, result.Response)
			default:
				require.NoError(t, err, "native request completes independently after logical expiry")
				require.ErrorIs(t, result.Err, context.DeadlineExceeded)
				require.Nil(t, result.Response)
			}
		})
	}
}

type tracedReceiptTransport struct {
	http.RoundTripper
	trace *httptrace.ClientTrace
}

func (t tracedReceiptTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.RoundTripper.RoundTrip(req.WithContext(httptrace.WithClientTrace(req.Context(), t.trace)))
}

func (t tracedReceiptTransport) CloseIdleConnections() {
	if tr, ok := t.RoundTripper.(interface{ CloseIdleConnections() }); ok {
		tr.CloseIdleConnections()
	}
}

func TestReceiptDoHBeforeNativeH2BodyClose(t *testing.T) {
	server := startDoHServer(t, testDoHServerOptions{})
	u, err := AddressToUpstream("https://"+server.addr+"/dns-query", &Options{RootCAs: server.rootCAs, HTTPVersions: []HTTPVersion{HTTPVersion2}, Timeout: 2 * time.Second, Logger: testLogger})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, u.Close()) })
	_, err = u.Exchange(createTestMessage(), nil)
	require.NoError(t, err)
	p := u.(*dnsOverHTTPS)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	tr := p.client.Transport
	p.client.Transport = tracedReceiptTransport{RoundTripper: tr, trace: &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
		if info.Err != nil {
			t.Error(info.Err)
		}
		close(entered)
		<-release
	}}}
	state := NewExchangeState(time.Now().Add(time.Second))
	finished := make(chan error, 1)
	go func() { _, err := u.Exchange(createTestMessage(), state); finished <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("native H2 send trace not reached")
	}
	select {
	case <-state.Done():
	case <-time.After(time.Second):
		t.Fatal("complete H2 body blocked on explicit body Close")
	}
	result, _ := state.Result()
	require.NoError(t, result.Err)
	require.NotEmpty(t, result.Response.Answer)
	select {
	case err := <-finished:
		t.Fatalf("native cleanup should still be waiting: %v", err)
	case <-time.After(time.Until(state.deadline)):
	}
	state.Expire()
	unblock()
	select {
	case err = <-finished:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("H2 cleanup did not exit after trace release")
	}
	after, _ := state.Result()
	require.Equal(t, result, after)
	require.True(t, result.ReceivedAt.Before(state.deadline))
}
