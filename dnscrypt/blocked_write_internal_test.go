package dnscrypt

import (
	"context"
	"encoding/binary"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"
)

func blockedCertificateWrite() bool {
	b := make([]byte, 4<<20)
	n := runtime.Stack(b, true)
	for _, stack := range strings.Split(string(b[:n]), "\n\n") {
		if strings.Contains(stack, "dnscrypt.writePrefixed") && strings.Contains(stack, "waitWrite") {
			return true
		}
	}
	return false
}

func TestServer_ShutdownClosesBlockedCertificateWrite(t *testing.T) {
	rc, err := GenerateResolverConfig("test.example", nil, time.Hour)
	require.NoError(t, err)
	cert, err := rc.NewCert()
	require.NoError(t, err)
	s, err := NewServer(&ServerConfig{ProviderName: rc.ProviderName, ResolverCert: cert, Proto: ProtoTCP, Addr: netip.MustParseAddrPort("127.0.0.1:0"), Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)
	require.NoError(t, s.Start(t.Context()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	c, err := net.Dial("tcp", s.LocalAddr().String())
	require.NoError(t, err)
	defer c.Close()
	tcp := c.(*net.TCPConn)
	require.NoError(t, tcp.SetReadBuffer(1024))
	require.NoError(t, tcp.SetWriteDeadline(time.Now().Add(3*time.Second)))
	// Establish native acceptance before changing only this fixture's physical
	// send buffer. A host's default autotuned send buffer is not a precondition.
	var accepted *net.TCPConn
	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		for conn := range s.tcpConns {
			accepted = conn.(*net.TCPConn)
		}
		return accepted != nil
	}, time.Second, time.Millisecond)
	require.NoError(t, accepted.SetWriteBuffer(1024))
	request := new(dns.Msg).SetQuestion(dns.Fqdn(rc.ProviderName), dns.TypeTXT)
	wire, err := request.Pack()
	require.NoError(t, err)
	frame := make([]byte, 2, len(wire)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(wire)))
	frame = append(frame, wire...)
	batch := make([]byte, 0, len(frame)*20000)
	for range 20000 {
		batch = append(batch, frame...)
	}
	_, err = tcp.Write(batch)
	require.NoError(t, err)
	require.Eventually(t, blockedCertificateWrite, 2*time.Second, 5*time.Millisecond, "must establish an actual blocked native TCP write")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_ = s.Shutdown(ctx)
	// The listener being released alone is insufficient: this peer must not be
	// needed to release a retained server write after Shutdown has returned.
	require.Eventually(t, func() bool { return !blockedCertificateWrite() }, time.Second, 5*time.Millisecond, "blocked accepted socket retained after shutdown")
	l, err := net.Listen("tcp", s.LocalAddr().String())
	require.NoError(t, err)
	require.NoError(t, l.Close())
}
