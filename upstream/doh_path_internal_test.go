package upstream

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDoHPreservesEscapedEndpointPath(t *testing.T) {
	for _, protocol := range []HTTPVersion{HTTPVersion11, HTTPVersion2, HTTPVersion3} {
		for _, path := range []string{"/dns-query", "/dns/query", "/dns%2Fquery", "/dns%2fquery", "/%64ns-query", "/dns%3Fquery", "/dns%23query", "/dns%252Fquery"} {
			t.Run(string(protocol)+path, func(t *testing.T) {
				observed := make(chan string, 1)
				server := startDoHServer(t, testDoHServerOptions{http3Enabled: protocol == HTTPVersion3, handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					observed <- r.RequestURI
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
					body, err := respondToTestMessage(request).Pack()
					if err != nil {
						t.Error(err)
						return
					}
					w.Header().Set("Content-Type", "application/dns-message")
					_, _ = w.Write(body)
				})})
				scheme := "https://"
				if protocol == HTTPVersion3 {
					scheme = "h3://"
				}
				resolver, err := AddressToUpstream(scheme+server.addr+path, &Options{RootCAs: server.rootCAs, HTTPVersions: []HTTPVersion{protocol}, Timeout: time.Second, Logger: testLogger})
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, resolver.Close()) })
				response, err := resolver.Exchange(createTestMessage(), nil)
				require.NoError(t, err, "actual DNS exchange must succeed before checking its endpoint")
				require.NotEmpty(t, response.Answer)
				got, _, _ := strings.Cut(<-observed, "?")
				require.Equal(t, path, got, "configured escaped path must survive native GET construction")
			})
		}
	}
}
