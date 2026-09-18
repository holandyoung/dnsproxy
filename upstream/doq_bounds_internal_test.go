package upstream

import (
	"net/url"
	"testing"

	"github.com/holandyoung/dnsproxy/internal/dnsproxytest"
	"github.com/stretchr/testify/require"
)

func TestDoQRejectsOversizedBeforeOpeningStream(t *testing.T) {
	p := &dnsOverQUIC{logger: testLogger, addr: &url.URL{Scheme: "quic", Host: "127.0.0.1:853"}}
	// A nil connection would panic at openStream; oversized input must fail
	// before invoking any QUIC operation.
	_, err := p.exchangeQUIC(dnsproxytest.OversizedMessage(t), nil, nil)
	require.ErrorContains(t, err, "DNS frame length")
}
