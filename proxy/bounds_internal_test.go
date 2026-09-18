package proxy

import (
	"bytes"
	"math"
	"net"
	"testing"

	"github.com/holandyoung/dnsproxy/internal/dnsproxytest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type frameWriteProbe struct {
	net.Conn
	buf bytes.Buffer
}

func (c *frameWriteProbe) Write(b []byte) (int, error) { return c.buf.Write(b) }

func TestTCPRejectsOversizedBeforeWrite(t *testing.T) {
	for _, size := range []int{0, 65535} {
		conn := &frameWriteProbe{}
		require.NoError(t, writePrefixed(make([]byte, size), conn))
		require.Equal(t, size+2, conn.buf.Len())
	}
	conn := &frameWriteProbe{}
	require.Error(t, writePrefixed(make([]byte, 65536), conn))
	require.Zero(t, conn.buf.Len())
	p := &Proxy{}
	require.Error(t, p.respondTCP(&DNSContext{Conn: conn, Res: dnsproxytest.OversizedMessage(t)}))
	require.Zero(t, conn.buf.Len())
}

func TestCacheRejectsInvalidWireAndPreservesLargeTTL(t *testing.T) {
	req := (&dns.Msg{}).SetQuestion("large.test.", dns.TypeTXT)
	bad := (&dns.Msg{}).SetReply(req)
	bad.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: "large.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{string(make([]byte, 256))}}}
	_, err := bad.Pack()
	require.Error(t, err, "fixture must reach Pack error")
	for _, msg := range []*dns.Msg{bad, dnsproxytest.OversizedMessage(t)} {
		c := newTestCache(t, &cacheConfig{size: 256 * 1024, withECS: true})
		// Capacity exceeds the malformed record: eviction cannot stand in for
		// rejection at the encoding/publication boundary.
		c.set(req, msg, nil, testLogger)
		require.Nil(t, c.items.Get(msgToKey(req)), "invalid wire must not be published")
		got, _, _ := c.get(req)
		require.Nil(t, got)
		c.setWithSubnet(req, msg, nil, &net.IPNet{}, testLogger)
		require.Nil(t, c.itemsWithSubnet.Get(msgToKeyWithSubnet(req, nil, 0)))
	}
	good := (&dns.Msg{}).SetReply(req)
	good.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: "large.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: math.MaxUint32 - 1}, Txt: []string{"ok"}}}
	c := newTestCache(t, nil)
	c.set(req, good, nil, testLogger)
	got, expired, _ := c.get(req)
	require.NotNil(t, got)
	require.False(t, expired)
	require.Greater(t, got.m.Answer[0].Header().Ttl, uint32(math.MaxUint32-10))
}

func TestCacheSubnetRejectsInvalidWithoutGlobalCollision(t *testing.T) {
	req := (&dns.Msg{}).SetQuestion("subnet.test.", dns.TypeA)
	for _, cidr := range []string{"192.0.2.1/0", "192.0.2.1/32", "2001:db8::1/0", "2001:db8::1/128"} {
		ip, n, err := net.ParseCIDR(cidr)
		require.NoError(t, err)
		n.IP = ip
		masked, prefix, valid := cacheSubnet(n)
		require.True(t, valid)
		require.NotEmpty(t, msgToKeyWithSubnet(req, masked, prefix))
	}
	_, prefix, valid := cacheSubnet(&net.IPNet{})
	require.True(t, valid)
	require.Zero(t, prefix)
	c := newTestCache(t, &cacheConfig{withECS: true})
	good := (&dns.Msg{}).SetReply(req)
	good.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "subnet.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
	c.setWithSubnet(req, good, nil, &net.IPNet{}, testLogger)
	globalKey := msgToKeyWithSubnet(req, nil, 0)
	globalValue := bytes.Clone(c.itemsWithSubnet.Get(globalKey))
	require.NotEmpty(t, globalValue)
	bad := good.Copy()
	bad.Answer[0].(*dns.A).A = net.IPv4(192, 0, 2, 2)
	for _, n := range []*net.IPNet{
		{IP: net.IPv4(192, 0, 2, 1), Mask: net.IPMask{255, 0, 255, 0}},
		{IP: net.IPv4(192, 0, 2, 1), Mask: net.IPMask(bytes.Repeat([]byte{255}, 32))},
		{IP: net.IPv4(192, 0, 2, 1), Mask: net.CIDRMask(64, 128)},
		{IP: net.IP{1}, Mask: net.CIDRMask(24, 32)},
	} {
		_, _, valid = cacheSubnet(n)
		require.False(t, valid)
		c.setWithSubnet(req, bad, nil, n, testLogger)
		require.Equal(t, globalValue, c.itemsWithSubnet.Get(globalKey))
		got, _, _ := c.getWithSubnet(req, n)
		require.Nil(t, got)
	}
}
