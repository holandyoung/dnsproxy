package dnscrypt

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
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
		if shutdownErr := s.Shutdown(ctx); !errors.Is(shutdownErr, ErrServerNotStarted) {
			require.NoError(t, shutdownErr)
		}
	})
	// Advertise a small receive window in the handshake itself. Reducing it
	// after Connect can leave the initial large window available to the peer.
	dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
		var setErr error
		controlErr := raw.Control(func(fd uintptr) { setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 1024) })
		return errors.Join(controlErr, setErr)
	}}
	c, err := dialer.Dial("tcp", s.LocalAddr().String())
	require.NoError(t, err)
	defer func(closeResource func() error) { _ = closeResource() }(c.Close)
	tcp := c.(*net.TCPConn)
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
	raw, err := accepted.SyscallConn()
	require.NoError(t, err)
	require.EventuallyWithT(t, func(check *assert.CollectT) {
		var info *unix.TCPInfo
		var infoErr error
		controlErr := raw.Control(func(fd uintptr) { info, infoErr = unix.GetsockoptTCPInfo(int(fd), unix.SOL_TCP, unix.TCP_INFO) })
		require.NoError(check, controlErr)
		require.NoError(check, infoErr)
		require.Zero(check, info.Snd_wnd)
		require.True(check, blockedCertificateWrite())
	}, time.Second, 5*time.Millisecond, "must establish a zero peer window and an actual blocked native TCP write")
	// This assertion measures forced shutdown, independently of the ordinary
	// write timeout. That timeout must not make a broken Shutdown look correct.
	require.NoError(t, accepted.SetWriteDeadline(time.Now().Add(10*time.Second)))
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
