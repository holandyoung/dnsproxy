package upstream

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestReceiptDoHRequiresCompleteDNSBody(t *testing.T) {
	for _, protocol := range []HTTPVersion{HTTPVersion11, HTTPVersion2, HTTPVersion3} {
		for _, mode := range []string{"complete", "complete declared", "complete unknown", "unsolicited gzip", "short declared", "media type", "status", "oversize", "malformed", "partial at expiry"} {
			t.Run(string(protocol)+"/"+mode, func(t *testing.T) {
				partial, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				server := startDoHServer(t, testDoHServerOptions{http3Enabled: protocol == HTTPVersion3, handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					query, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
					if err != nil {
						t.Error(err)
						return
					}
					req := new(dns.Msg)
					if err = req.Unpack(query); err != nil {
						t.Error(err)
						return
					}
					body, err := respondToTestMessage(req).Pack()
					if err != nil {
						t.Error(err)
						return
					}
					w.Header().Set("Content-Type", "application/dns-message; charset=binary")
					switch mode {
					case "complete declared", "short declared":
						length := len(body)
						if mode == "short declared" {
							length++
						}
						w.Header().Set("Content-Length", strconv.Itoa(length))
					case "complete unknown":
						// Flushing headers before DATA prevents native servers
						// from inferring Content-Length from a buffered body.
						w.(http.Flusher).Flush()
					case "unsolicited gzip":
						// Native DoH transports disable compression; unsolicited
						// gzip must retain its existing rejection behavior.
						var compressed bytes.Buffer
						writer := gzip.NewWriter(&compressed)
						if _, err = writer.Write(body); err != nil {
							t.Error(err)
							return
						}
						if err = writer.Close(); err != nil {
							t.Error(err)
							return
						}
						if compressed.Len() == len(body) {
							t.Error("compressed and decoded lengths must differ")
							return
						}
						body = compressed.Bytes()
						w.Header().Set("Content-Encoding", "gzip")
						w.Header().Set("Content-Length", strconv.Itoa(len(body)))
					case "media type":
						w.Header().Set("Content-Type", "application/octet-stream")
					case "status":
						w.WriteHeader(http.StatusBadGateway)
					case "oversize":
						body = append(body, make([]byte, dns.MaxMsgSize+1-len(body))...)
					case "malformed":
						body = body[:12]
					case "partial at expiry":
						_, _ = w.Write(body[:12])
						w.(http.Flusher).Flush()
						close(partial)
						<-release
						body = body[12:]
					}
					_, _ = w.Write(body)
				})})
				t.Cleanup(unblock)
				scheme := "https://"
				if protocol == HTTPVersion3 {
					scheme = "h3://"
				}
				u, err := AddressToUpstream(scheme+server.addr+"/dns-query", &Options{RootCAs: server.rootCAs, HTTPVersions: []HTTPVersion{protocol}, Timeout: 2 * time.Second, Logger: testLogger})
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, u.Close()) })
				state := NewExchangeState(time.Now().Add(2 * time.Second))
				finished := make(chan error, 1)
				go func() { _, exchangeErr := u.Exchange(createTestMessage(), state); finished <- exchangeErr }()
				if mode == "partial at expiry" {
					select {
					case <-partial:
					case <-time.After(time.Second):
						t.Fatal("partial body prerequisite not sent")
					}
					state.Expire()
					result, ready := state.Result()
					require.True(t, ready, "a body prefix cannot retain a candidate at expiry")
					require.ErrorIs(t, result.Err, context.DeadlineExceeded)
					unblock()
				}
				select {
				case err = <-finished:
				case <-time.After(3 * time.Second):
					t.Fatal("HTTP exchange did not exit")
				}
				result, ready := state.Result()
				require.True(t, ready)
				if strings.HasPrefix(mode, "complete") {
					require.NoError(t, err)
					require.NoError(t, result.Err)
					require.NotEmpty(t, result.Response.Answer)
				} else {
					if mode == "partial at expiry" {
						require.NoError(t, err, "native operation completes after logical expiry")
					} else {
						require.Error(t, err)
					}
					require.Error(t, result.Err)
					require.Nil(t, result.Response)
					require.True(t, result.ReceivedAt.IsZero())
				}
			})
		}
	}
}

func TestReceiptDoHWarmShortBodyIsNotRetried(t *testing.T) {
	var requests atomic.Int32
	server := startDoHServer(t, testDoHServerOptions{
		http3Enabled: true,
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			query, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
			if err != nil {
				t.Error(err)
				return
			}
			req := new(dns.Msg)
			if err = req.Unpack(query); err != nil {
				t.Error(err)
				return
			}
			body, err := respondToTestMessage(req).Pack()
			if err != nil {
				t.Error(err)
				return
			}
			length := len(body)
			if requests.Add(1) == 2 {
				length++
			}
			w.Header().Set("Content-Type", "application/dns-message")
			w.Header().Set("Content-Length", strconv.Itoa(length))
			_, _ = w.Write(body)
		}),
	})
	u, err := AddressToUpstream("h3://"+server.addr+"/dns-query", &Options{
		RootCAs: server.rootCAs, HTTPVersions: []HTTPVersion{HTTPVersion3},
		Timeout: 2 * time.Second, Logger: testLogger,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, u.Close()) })
	for request := int32(1); request <= 3; request++ {
		state := NewExchangeState(time.Now().Add(2 * time.Second))
		_, err = u.Exchange(createTestMessage(), state)
		result, ready := state.Result()
		require.True(t, ready)
		require.Equal(t, request, requests.Load(), "a malformed warm response must not be retried")
		if request == 2 {
			require.Error(t, err)
			require.Error(t, result.Err)
			require.Nil(t, result.Response)
			require.True(t, result.ReceivedAt.IsZero())
		} else {
			require.NoError(t, err)
			require.NoError(t, result.Err)
			require.NotEmpty(t, result.Response.Answer)
		}
	}
}
