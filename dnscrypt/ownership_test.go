package dnscrypt_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/holandyoung/dnsproxy/dnscrypt"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func lifecycleServer(t *testing.T) *dnscrypt.Server {
	t.Helper()
	rc, err := dnscrypt.GenerateResolverConfig(prefixedHostname, nil, time.Hour)
	require.NoError(t, err)
	cert, err := rc.NewCert()
	require.NoError(t, err)
	s, err := dnscrypt.NewServer(&dnscrypt.ServerConfig{ProviderName: rc.ProviderName, ResolverCert: cert, Proto: dnscrypt.ProtoTCP, Addr: netip.MustParseAddrPort("127.0.0.1:0"), Logger: slog.New(slog.DiscardHandler), Handler: dnscrypt.HandlerFunc(testHandler)})
	require.NoError(t, err)
	require.NoError(t, s.Start(t.Context()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		err := s.Shutdown(ctx)
		if !errors.Is(err, dnscrypt.ErrServerNotStarted) {
			require.NoError(t, err)
		}
	})
	return s
}

func certificateFrame(t *testing.T) []byte {
	m := new(dns.Msg).SetQuestion(dns.Fqdn(prefixedHostname), dns.TypeTXT)
	wire, err := m.Pack()
	require.NoError(t, err)
	framed := make([]byte, 2, len(wire)+2)
	binary.BigEndian.PutUint16(framed, uint16(len(wire)))
	return append(framed, wire...)
}

func TestServer_TCPFragmentedPrefix(t *testing.T) {
	for _, split := range []bool{false, true} {
		t.Run(map[bool]string{false: "whole", true: "split"}[split], func(t *testing.T) {
			s := lifecycleServer(t)
			c, err := net.Dial("tcp", s.LocalAddr().String())
			require.NoError(t, err)
			defer c.Close()
			require.NoError(t, c.SetDeadline(time.Now().Add(time.Second)))
			frame := certificateFrame(t)
			if split {
				_, err = c.Write(frame[:1])
				require.NoError(t, err)
				time.Sleep(20 * time.Millisecond)
				_, err = c.Write(frame[1:])
			} else {
				_, err = c.Write(frame)
			}
			require.NoError(t, err)
			r, err := (&dns.Conn{Conn: c}).ReadMsg()
			require.NoError(t, err, "TCP may split the two-byte length prefix")
			require.Len(t, r.Answer, 1)
		})
	}
}

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
	s := lifecycleServer(t)
	c, err := net.Dial("tcp", s.LocalAddr().String())
	require.NoError(t, err)
	defer c.Close()
	tcp := c.(*net.TCPConn)
	require.NoError(t, tcp.SetReadBuffer(1024))
	require.NoError(t, tcp.SetWriteDeadline(time.Now().Add(3*time.Second)))
	frame := certificateFrame(t)
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

func TestServer_ShutdownClosesEmptyAndPartialTCP(t *testing.T) {
	s := lifecycleServer(t)
	var clients []net.Conn
	for _, prefix := range [][]byte{nil, {0}, {0, 20, 0}} {
		c, err := net.Dial("tcp", s.LocalAddr().String())
		require.NoError(t, err)
		defer c.Close()
		clients = append(clients, c)
		if prefix != nil {
			_, err = c.Write(prefix)
			require.NoError(t, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, s.Shutdown(ctx))
	for _, c := range clients {
		require.NoError(t, c.SetReadDeadline(time.Now().Add(time.Second)))
		var b [1]byte
		_, err := c.Read(b[:])
		require.Error(t, err)
		if n, ok := err.(net.Error); ok {
			require.False(t, n.Timeout(), "accepted idle socket was left open")
		}
		if err == io.EOF {
			continue
		}
	}
}

func TestServer_ExpiredShutdownStillClosesAcceptedTCP(t *testing.T) {
	s := lifecycleServer(t)
	c, err := net.Dial("tcp", s.LocalAddr().String())
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.SetDeadline(time.Now().Add(time.Second)))
	_, err = c.Write(certificateFrame(t))
	require.NoError(t, err)
	r, err := (&dns.Conn{Conn: c}).ReadMsg()
	require.NoError(t, err)
	require.Len(t, r.Answer, 1, "prove this connection was accepted")
	_, err = c.Write([]byte{0})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = s.Shutdown(ctx)
	var b [1]byte
	_, err = c.Read(b[:])
	require.Error(t, err)
	if n, ok := err.(net.Error); ok {
		require.False(t, n.Timeout(), "canceled shutdown did not close the accepted connection")
	}
	join, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	require.NoError(t, s.Shutdown(join))
}

func TestServer_ImmediateShutdownAndRestart(t *testing.T) {
	for _, proto := range []dnscrypt.Proto{dnscrypt.ProtoTCP, dnscrypt.ProtoUDP} {
		t.Run(string(proto), func(t *testing.T) {
			rc, err := dnscrypt.GenerateResolverConfig(prefixedHostname, nil, time.Hour)
			require.NoError(t, err)
			cert, err := rc.NewCert()
			require.NoError(t, err)
			s, err := dnscrypt.NewServer(&dnscrypt.ServerConfig{ProviderName: rc.ProviderName, ResolverCert: cert, Proto: proto, Addr: netip.MustParseAddrPort("127.0.0.1:0"), Logger: slog.New(slog.DiscardHandler)})
			require.NoError(t, err)
			for range 40 {
				require.NoError(t, s.Start(t.Context()))
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				err = s.Shutdown(ctx)
				cancel()
				require.NoError(t, err)
			}
		})
	}
}

func TestServer_WriteBudgetBeginsAfterHandler(t *testing.T) {
	for _, proto := range []dnscrypt.Proto{dnscrypt.ProtoUDP, dnscrypt.ProtoTCP} {
		t.Run(string(proto), func(t *testing.T) {
			for _, delay := range []time.Duration{0, 2100 * time.Millisecond} {
				t.Run(delay.String(), func(t *testing.T) {
					handler := dnscrypt.HandlerFunc(func(ctx context.Context, rw dnscrypt.ResponseWriter, r *dns.Msg) error {
						select {
						case <-time.After(delay):
						case <-ctx.Done():
							return ctx.Err()
						}
						return testHandler(ctx, rw, r)
					})
					s, key, _ := newTestServer(t, handler, proto)
					client := newTestClient(&dnscrypt.ClientConfig{Proto: proto})
					stamp := newTestServerStamp(s, key)
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					info, e := client.DialStampContext(ctx, *stamp)
					require.NoError(t, e)
					before := time.Now()
					reply, e := client.ExchangeContext(ctx, new(dns.Msg).SetQuestion("test.example.", dns.TypeA), info)
					t.Logf("proto=%s processing=%s elapsed=%s err=%v", proto, delay, time.Since(before), e)
					require.NoError(t, e, "successful handler processing must not consume the actual socket write deadline")
					require.Len(t, reply.Answer, 1)
				})
			}
		})
	}
}

func TestServer_RestartWaitsForAdmittedHandler(t *testing.T) {
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	var released sync.Once
	defer released.Do(func() { close(release) })
	var calls atomic.Int32
	handler := dnscrypt.HandlerFunc(func(ctx context.Context, rw dnscrypt.ResponseWriter, r *dns.Msg) error {
		if calls.Add(1) == 1 {
			entered <- ctx
			<-release
		}
		return testHandler(ctx, rw, r)
	})
	srv, key, _ := newTestServer(t, handler, dnscrypt.ProtoTCP)
	client := newTestClient(&dnscrypt.ClientConfig{Proto: dnscrypt.ProtoTCP})
	stamp := newTestServerStamp(srv, key)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	info, e := client.DialStampContext(ctx, *stamp)
	require.NoError(t, e)
	c, e := net.Dial("tcp", srv.LocalAddr().String())
	require.NoError(t, e)
	defer c.Close()
	clientDone := make(chan error, 1)
	go func() {
		_, e := client.ExchangeConnContext(ctx, c, new(dns.Msg).SetQuestion("test.example.", dns.TypeA), info)
		clientDone <- e
	}()
	var handlerCtx context.Context
	select {
	case handlerCtx = <-entered:
	case <-ctx.Done():
		t.Fatal("handler did not admit real encrypted query")
	}
	stopped, stop := context.WithCancel(context.Background())
	stop()
	_ = srv.Shutdown(stopped)
	select {
	case <-handlerCtx.Done():
	case <-ctx.Done():
		t.Fatal("Shutdown did not cancel admitted handler")
	}
	require.Error(t, srv.Start(t.Context()), "previous held run must prevent restart")
	select {
	case e := <-clientDone:
		require.Error(t, e)
	case <-time.After(time.Second):
		t.Fatal("accepted client was not physically closed while handler remained held")
	}
	released.Do(func() { close(release) })
	join, done := context.WithTimeout(t.Context(), time.Second)
	defer done()
	require.NoError(t, srv.Shutdown(join))
	require.NoError(t, srv.Start(t.Context()))
	stamp = newTestServerStamp(srv, key)
	info, e = client.DialStampContext(ctx, *stamp)
	require.NoError(t, e)
	answer, e := client.ExchangeContext(ctx, new(dns.Msg).SetQuestion("test.example.", dns.TypeA), info)
	require.NoError(t, e)
	require.Len(t, answer.Answer, 1)
}
