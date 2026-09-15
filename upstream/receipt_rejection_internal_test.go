package upstream

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

// Rejections must be exercised after successful reuse: a cold connection does
// not enter the native reconnect branch. A replay would get a valid response.
func TestReceiptDoQCachedRejectionDoesNotReplay(t *testing.T) {
	for _, mode := range []string{"empty FIN", "short prefix", "zero length", "short frame", "malformed", "extra byte", "extra frame", "wrong ID", "wrong question", "connection failure"} {
		t.Run(mode, func(t *testing.T) {
			u, calls := receiptDoQPeer(t, mode)
			_, err := u.Exchange(createTestMessage(), nil)
			require.NoError(t, err, "warm actual connection")
			require.Equal(t, int32(1), calls.Load())
			require.NotNil(t, u.(*dnsOverQUIC).conn)
			state := NewExchangeState(time.Now().Add(2 * time.Second))
			_, err = u.Exchange(createTestMessage(), state)
			result, ready := state.Result()
			require.True(t, ready)
			if mode == "connection failure" {
				require.NoError(t, err)
				require.NoError(t, result.Err)
				require.Equal(t, int32(3), calls.Load(), "one real connection failure may reconnect")
			} else {
				require.ErrorIs(t, err, errDoQProtocol)
				require.ErrorIs(t, result.Err, errDoQProtocol)
				require.Equal(t, int32(2), calls.Load(), "warmup and rejected response only")
				require.Nil(t, result.Response)
			}
		})
	}
}

func receiptDoQPeer(t *testing.T, mode string) (Upstream, *atomic.Int32) {
	t.Helper()
	tlsConfig, roots := createServerTLSConfig(t, "127.0.0.1")
	tlsConfig.NextProtos = []string{NextProtoDQ}
	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, &quic.Config{})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	var connections sync.WaitGroup
	listenerDone := make(chan struct{})
	go func() {
		defer close(listenerDone)
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				stop := context.AfterFunc(ctx, func() { _ = conn.CloseWithError(0, "") })
				defer stop()
				defer conn.CloseWithError(0, "")
				for {
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					wire, err := io.ReadAll(stream)
					if err != nil || len(wire) < 2 || int(binary.BigEndian.Uint16(wire)) != len(wire)-2 {
						return
					}
					req := new(dns.Msg)
					if err = req.Unpack(wire[2:]); err != nil {
						return
					}
					response := respondToTestMessage(req)
					bad := calls.Add(1) == 2
					if bad && mode == "connection failure" {
						_ = conn.CloseWithError(QUICCodeInternalError, "retired")
						return
					}
					if bad && mode == "wrong ID" {
						response.Id = 17
					}
					if bad && mode == "wrong question" {
						response.Question[0].Name = "different.example."
					}
					body, err := response.Pack()
					if err != nil {
						return
					}
					if bad && mode == "malformed" {
						body = body[:12]
					}
					frame := make([]byte, 2+len(body))
					binary.BigEndian.PutUint16(frame, uint16(len(body)))
					copy(frame[2:], body)
					if bad {
						switch mode {
						case "empty FIN":
							frame = nil
						case "short prefix":
							frame = frame[:1]
						case "zero length":
							frame = []byte{0, 0}
						case "short frame":
							frame = frame[:len(frame)-1]
						case "extra byte":
							frame = append(frame, 42)
						case "extra frame":
							frame = append(frame, frame...)
						}
					}
					if _, err = stream.Write(frame); err != nil {
						return
					}
					_ = stream.Close()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, listener.Close())
		select {
		case <-listenerDone:
		case <-time.After(time.Second):
			t.Fatal("QUIC accept loop did not stop")
		}
		joined := make(chan struct{})
		go func() { connections.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-time.After(time.Second):
			t.Fatal("QUIC connections did not stop")
		}
	})
	u, err := AddressToUpstream("quic://"+listener.Addr().String(), &Options{RootCAs: roots, Timeout: time.Second, Logger: testLogger})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, u.Close()) })
	return u, &calls
}

func TestReceiptDoTCachedRejectionDoesNotReplay(t *testing.T) {
	for _, mode := range []string{"wrong ID", "wrong question", "malformed", "short DNS", "connection failure"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			server := startDoTServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
				response := respondToTestMessage(req)
				bad := calls.Add(1) == 2
				if bad && mode == "connection failure" {
					_ = w.Close()
					return
				}
				if bad && mode == "wrong ID" {
					response.Id++
				}
				if bad && mode == "wrong question" {
					response.Question[0].Name = "different.example."
				}
				wire, err := response.Pack()
				if err != nil {
					t.Error(err)
					return
				}
				if bad && mode == "malformed" {
					wire = wire[:12]
				}
				if bad && mode == "short DNS" {
					wire = wire[:3]
				}
				_, _ = w.Write(wire)
			})
			u, err := AddressToUpstream(fmt.Sprintf("tls://127.0.0.1:%d", server.port), &Options{RootCAs: server.rootCAs, Timeout: time.Second, Logger: testLogger})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, u.Close()) })
			_, err = u.Exchange(createTestMessage(), nil)
			require.NoError(t, err)
			require.Equal(t, int32(1), calls.Load())
			require.Len(t, u.(*dnsOverTLS).conns, 1)
			state := NewExchangeState(time.Now().Add(2 * time.Second))
			_, err = u.Exchange(createTestMessage(), state)
			result, ready := state.Result()
			require.True(t, ready)
			if mode == "connection failure" {
				require.NoError(t, err)
				require.NoError(t, result.Err)
				require.Equal(t, int32(3), calls.Load())
			} else {
				require.ErrorIs(t, err, errDNSProtocol)
				require.ErrorIs(t, result.Err, errDNSProtocol)
				require.Equal(t, int32(2), calls.Load(), "warmup and rejected response only")
				require.Nil(t, result.Response)
			}
		})
	}
}

func TestReceiptDoHRedirectDoesNotReplay(t *testing.T) {
	for _, protocol := range []HTTPVersion{HTTPVersion11, HTTPVersion2, HTTPVersion3} {
		t.Run(string(protocol), func(t *testing.T) {
			var calls, redirects atomic.Int32
			server := startDoHServer(t, testDoHServerOptions{http3Enabled: protocol == HTTPVersion3, handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 2 {
					http.Redirect(w, r, "/redirect-target?"+r.URL.RawQuery, http.StatusFound)
					return
				}
				if r.URL.Path == "/redirect-target" {
					redirects.Add(1)
				}
				wire, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
				if err != nil {
					t.Error(err)
					return
				}
				req := new(dns.Msg)
				if err = req.Unpack(wire); err != nil {
					t.Error(err)
					return
				}
				wire, err = respondToTestMessage(req).Pack()
				if err != nil {
					t.Error(err)
					return
				}
				w.Header().Set("Content-Type", "application/dns-message")
				_, _ = w.Write(wire)
			})})
			scheme := "https://"
			if protocol == HTTPVersion3 {
				scheme = "h3://"
			}
			u, err := AddressToUpstream(scheme+server.addr+"/dns-query", &Options{RootCAs: server.rootCAs, HTTPVersions: []HTTPVersion{protocol}, Timeout: time.Second, Logger: testLogger})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, u.Close()) })
			_, err = u.Exchange(createTestMessage(), nil)
			require.NoError(t, err)
			require.Equal(t, int32(1), calls.Load())
			state := NewExchangeState(time.Now().Add(2 * time.Second))
			_, err = u.Exchange(createTestMessage(), state)
			result, ready := state.Result()
			require.True(t, ready)
			require.Error(t, err)
			require.Error(t, result.Err)
			require.Equal(t, int32(2), calls.Load())
			require.Zero(t, redirects.Load(), "redirect destination must not be visited")
		})
	}
}
