package fastip

import (
	"math"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/require"
)

func TestCacheWideLatencyAndTime(t *testing.T) {
	for _, latency := range []int64{0, 65535, 65536, 70000, math.MaxInt64} {
		for _, now := range []int64{-100, math.MaxUint32 - 100, math.MaxUint32 + 100} {
			ent := &cacheEntry{latencyMsec: latency}
			packed := packCacheEntry(ent, 600, now)
			require.Equal(t, ent, unpackCacheEntry(packed, now+599))
			require.Nil(t, unpackCacheEntry(packed, now+600))
		}
	}
	f := New(&Config{Logger: slogutil.NewDiscardLogger()})
	ip := netip.MustParseAddr("127.0.0.1")
	f.cacheAddSuccessful(ip, 70000)
	f.cacheAddSuccessful(ip, 65536)
	require.Equal(t, int64(65536), f.cacheFind(ip).latencyMsec)
	f.cacheAddSuccessful(ip, 65535)
	f.cacheAddSuccessful(ip, 70000)
	require.Equal(t, int64(65535), f.cacheFind(ip).latencyMsec)
	f.cacheAddSuccessful(ip, 0)
	f.cacheAddFailure(ip)
	require.Equal(t, &cacheEntry{}, f.cacheFind(ip))
}
