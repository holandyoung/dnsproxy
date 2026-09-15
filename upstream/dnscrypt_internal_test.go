package upstream

import (
	"context"
	"github.com/holandyoung/dnsproxy/internal/dnsproxytest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/holandyoung/dnsproxy/dnscrypt"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// emptyDNSCryptHandler is a [dnscrypt.Handler] that does nothing and always
// returns nil error.  It can be used in tests when the server's response is
// not important.
//
// TODO(d.kolyshev):  Move to dnscrypt.
var emptyDNSCryptHandler = dnsproxytest.DNSCryptHandler(func(
	ctx context.Context,
	w dnscrypt.ResponseWriter,
	r *dns.Msg,
) (err error) {
	return nil
})

func TestUpstreamDNSCrypt(t *testing.T) {
	t.Parallel()

	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
	require.NoError(t, err)
	stamp := dnsproxytest.StartDNSCryptServer(t, rc, dnsproxytest.DNSCryptHandler(func(ctx context.Context, w dnscrypt.ResponseWriter, r *dns.Msg) error {
		return w.WriteMsg(ctx, respondToTestMessage(r))
	}))
	address := stamp.String()
	u, err := AddressToUpstream(address, &Options{
		Logger:  testLogger,
		Timeout: 10 * time.Second,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	// Test that it responds properly
	for range 10 {
		checkUpstream(t, u, address)
	}
}

func TestDNSCrypt_Exchange_truncated(t *testing.T) {
	// Prepare the test DNSCrypt server config.
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
	require.NoError(t, err)

	var udpNum, tcpNum atomic.Uint32
	h := dnsproxytest.DNSCryptHandler(func(
		ctx context.Context,
		w dnscrypt.ResponseWriter,
		r *dns.Msg,
	) (err error) {
		if w.RemoteAddr().Network() == networkUDP {
			udpNum.Add(1)
		} else {
			tcpNum.Add(1)
		}

		res := (&dns.Msg{}).SetReply(r)
		answer := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeTXT,
				Ttl:    300,
				Class:  dns.ClassINET,
			},
		}
		res.Answer = append(res.Answer, answer)

		veryLongString := strings.Repeat("VERY LONG STRING", 7)
		for range 50 {
			answer.Txt = append(answer.Txt, veryLongString)
		}

		return w.WriteMsg(ctx, res)
	})

	srvStamp := dnsproxytest.StartDNSCryptServer(t, rc, h)
	u, err := AddressToUpstream(srvStamp.String(), &Options{
		Logger:  testLogger,
		Timeout: testTimeout,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	req := (&dns.Msg{}).SetQuestion("unit-test2.dns.adguard.com.", dns.TypeTXT)

	// Check that response is not truncated (even though it's huge).
	res, err := u.Exchange(req, nil)
	require.NoError(t, err)

	assert.False(t, res.Truncated)
	assert.Equal(t, 1, int(udpNum.Load()))
	assert.Equal(t, 1, int(tcpNum.Load()))
}

func TestDNSCrypt_Exchange_deadline(t *testing.T) {
	t.Parallel()

	// Prepare the test DNSCrypt server config
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
	require.NoError(t, err)

	srvStamp := dnsproxytest.StartDNSCryptServer(t, rc, emptyDNSCryptHandler)

	// Use a shorter timeout to speed up the test.
	u, err := AddressToUpstream(srvStamp.String(), &Options{
		Logger: testLogger,
		// TODO(f.setrakov): Use stale context when [Upstream.Exchange] will
		// accept a context.
		Timeout: 1 * time.Nanosecond,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	req := (&dns.Msg{}).SetQuestion("unit-test2.dns.adguard.com.", dns.TypeTXT)

	res, err := u.Exchange(req, nil)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	assert.Nil(t, res)
}

func TestDNSCrypt_Exchange_dialFail(t *testing.T) {
	// Prepare the test DNSCrypt server config.
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
	require.NoError(t, err)

	req := (&dns.Msg{}).SetQuestion("unit-test2.dns.adguard.com.", dns.TypeTXT)
	var u Upstream

	require.True(t, t.Run("run_and_shutdown", func(t *testing.T) {
		srvStamp := dnsproxytest.StartDNSCryptServer(t, rc, emptyDNSCryptHandler)

		// Use a shorter timeout to speed up the test.
		u, err = AddressToUpstream(srvStamp.String(), &Options{
			Logger:  testLogger,
			Timeout: 100 * time.Millisecond,
		})
		require.NoError(t, err)
	}))

	require.True(t, t.Run("dial_fail", func(t *testing.T) {
		testutil.CleanupAndRequireSuccess(t, u.Close)

		var res *dns.Msg
		res, err = u.Exchange(req, nil)
		require.Error(t, err)

		assert.Nil(t, res)
	}))

	t.Run("restart", func(t *testing.T) {
		const validationErr errors.Error = "bad cert"

		srvStamp := dnsproxytest.StartDNSCryptServer(t, rc, emptyDNSCryptHandler)

		// Use a shorter timeout to speed up the test.
		u, err = AddressToUpstream(srvStamp.String(), &Options{
			Logger:  testLogger,
			Timeout: 100 * time.Millisecond,
			VerifyDNSCryptCertificate: func(cert *dnscrypt.Certificate) (err error) {
				return validationErr
			},
		})
		require.NoError(t, err)

		var res *dns.Msg
		res, err = u.Exchange(req, nil)
		require.ErrorIs(t, err, validationErr)

		assert.Nil(t, res)
	})
}
