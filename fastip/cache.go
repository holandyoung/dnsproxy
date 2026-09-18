package fastip

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/AdguardTeam/golibs/mathutil"
)

const (
	// fastestAddrCacheTTLSec is the cache TTL for IP addresses.
	fastestAddrCacheTTLSec = 10 * 60
)

// cacheEntry represents an item that will be stored in the cache.
type cacheEntry struct {
	latencyMsec int64
	failed      bool
}

// packCacheEntry packs the cache entry and the TTL to bytes in the following
// order:
//
//   - expire   [8]byte  (signed Unix time, seconds),
//   - status   byte     (0 for ok, 1 for timed out),
//   - latency  [8]byte  (signed milliseconds).
func packCacheEntry(ent *cacheEntry, ttl uint32, now int64) (d []byte) {
	expire := now + int64(ttl)
	d = make([]byte, 8+1+8)
	// #nosec G115 -- Preserve all bits of signed Unix seconds for the inverse decoder.
	binary.BigEndian.PutUint64(d, uint64(expire))
	d[8] = mathutil.BoolToNumber[byte](ent.failed)
	// #nosec G115 -- Preserve all bits of signed milliseconds for the inverse decoder.
	binary.BigEndian.PutUint64(d[9:], uint64(ent.latencyMsec))

	return d
}

// unpackCacheEntry unpacks bytes to cache entry and checks TTL, if the record
// is expired returns nil.
func unpackCacheEntry(data []byte, now int64) (ent *cacheEntry) {
	if len(data) != 17 || data[8] > 1 {
		return nil
	}
	// #nosec G115 -- Restore the signed 64-bit bit pattern written by packCacheEntry.
	expire := int64(binary.BigEndian.Uint64(data[:8]))
	if expire <= now {
		return nil
	}

	// #nosec G115 -- Restore the signed 64-bit latency written by packCacheEntry.
	latency := int64(binary.BigEndian.Uint64(data[9:]))
	ent = &cacheEntry{failed: data[8] == 1, latencyMsec: latency}

	return ent
}

// cacheFind finds entry in the cache for the given IP address.  Returns nil if
// nothing is found or if the record is expired.
func (f *FastestAddr) cacheFind(ip netip.Addr) (ent *cacheEntry) {
	val := f.ipCache.Get(ip.AsSlice())
	if val == nil {
		return nil
	}

	return unpackCacheEntry(val, time.Now().Unix())
}

// cacheAddFailure stores unsuccessful attempt in cache.
func (f *FastestAddr) cacheAddFailure(ip netip.Addr) {
	ent := cacheEntry{
		failed: true,
	}

	f.ipCacheLock.Lock()
	defer f.ipCacheLock.Unlock()

	if f.cacheFind(ip) == nil {
		f.cacheAdd(&ent, ip, fastestAddrCacheTTLSec)
	}
}

// cacheAddSuccessful stores a successful ping result in the cache.  Replaces
// previous result if our latency is lower.
func (f *FastestAddr) cacheAddSuccessful(ip netip.Addr, latency int64) {
	ent := cacheEntry{
		latencyMsec: latency,
	}

	f.ipCacheLock.Lock()
	defer f.ipCacheLock.Unlock()

	entCached := f.cacheFind(ip)
	if entCached == nil || entCached.failed || entCached.latencyMsec > latency {
		f.cacheAdd(&ent, ip, fastestAddrCacheTTLSec)
	}
}

// cacheAdd adds a new entry to the cache.
func (f *FastestAddr) cacheAdd(ent *cacheEntry, ip netip.Addr, ttl uint32) {
	val := packCacheEntry(ent, ttl, time.Now().Unix())
	f.ipCache.Set(ip.AsSlice(), val)
}
