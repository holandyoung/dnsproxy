package dnscrypt

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCertificateProtocolTimeBounds(t *testing.T) {
	rc, err := GenerateResolverConfig("time.test", nil, time.Second)
	require.NoError(t, err)
	for _, now := range []int64{0, 1, math.MaxUint32 - 1} {
		cert, certErr := rc.newCert(time.Unix(now, 0))
		require.NoError(t, certErr)
		require.Equal(t, now, int64(cert.Serial))
		require.Equal(t, now, int64(cert.NotBefore))
		require.Equal(t, now+1, int64(cert.NotAfter))
		require.True(t, cert.verifyDate(now))
		require.True(t, cert.verifyDate(now+1))
		require.False(t, cert.verifyDate(now-1))
		require.False(t, cert.verifyDate(now+2))
	}
	for _, now := range []int64{-1, math.MaxUint32, math.MaxUint32 + 1} {
		_, err = rc.newCert(time.Unix(now, 0))
		require.Error(t, err)
	}
	rc.CertificateTTL = time.Nanosecond
	_, err = rc.newCert(time.Unix(100, 0))
	require.Error(t, err, "subsecond interval cannot encode a valid certificate")
	rc.CertificateTTL = time.Duration(math.MaxInt64)
	_, err = rc.newCert(time.Unix(100, 0))
	require.Error(t, err)
	cert := &Certificate{NotBefore: 0, NotAfter: math.MaxUint32}
	require.False(t, cert.verifyDate(-1))
	require.False(t, cert.verifyDate(math.MaxUint32+1))
}
