package upstream

import (
	"context"
	"encoding/base64"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestReceiptDoHRequiresCompleteDNSBody(t *testing.T) {
	for _, protocol := range []HTTPVersion{HTTPVersion11, HTTPVersion2, HTTPVersion3} {
		for _, mode := range []string{"complete", "media type", "status", "oversize", "malformed", "partial at expiry"} {
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
				go func() { _, err := u.Exchange(createTestMessage(), state); finished <- err }()
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
				if mode == "complete" {
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
