package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/holandyoung/dnsproxy/dnscrypt"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// The DNSCrypt package tests both UDP/TCP loop notifications. This actual Proxy
// test also guards their common configuration bridge, without exporting a
// production fault-injection method from the DNSCrypt server.
func TestDNSCryptListenerFailureReachesProxy(t *testing.T) {
	rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, time.Hour)
	require.NoError(t, err)
	cert, err := rc.NewCert()
	require.NoError(t, err)
	failures := make(chan error, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	p := mustNew(t, &Config{
		Logger: slog.New(slog.DiscardHandler), ListenerFailures: failures,
		DNSCryptProviderName: rc.ProviderName, DNSCryptResolverCert: cert,
		DNSCryptTCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		RequestHandler: HandlerFunc(func(ctx context.Context, p *Proxy, d *DNSContext) error {
			if d.Req.Question[0].Name == "held.example." {
				close(entered)
				<-release
			}
			return replyLocally(ctx, p, d)
		}),
	})
	require.NoError(t, p.Start(t.Context()))
	defer func() {
		unblock()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, p.Shutdown(ctx))
	}()
	address := p.Addr(ProtoDNSCrypt).String()
	stamp, err := rc.CreateStamp(address)
	require.NoError(t, err)
	client := dnscrypt.NewClient(&dnscrypt.ClientConfig{Logger: testLogger, Proto: dnscrypt.ProtoTCP})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	info, err := client.DialStampContext(ctx, stamp)
	require.NoError(t, err)
	answer, err := client.ExchangeContext(ctx, new(dns.Msg).SetQuestion("ok.example.", dns.TypeA), info, nil)
	require.NoError(t, err)
	require.Equal(t, dns.RcodeSuccess, answer.Rcode)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = client.ExchangeContext(ctx, new(dns.Msg).SetQuestion("held.example.", dns.TypeA), info, nil)
	}()
	defer func() { unblock(); cancel(); <-done }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("encrypted handler was not admitted")
	}
	require.Empty(t, failures)
	interruptNativeListener(t, netip.MustParseAddrPort(address))
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err, "native listener still accepts after socket shutdown")
	select {
	case failureErr := <-failures:
		require.ErrorContains(t, failureErr, "dnscrypt-tcp listener "+address)
	case <-time.After(300 * time.Millisecond):
		t.Error("Proxy did not receive native DNSCrypt listener failure while handler retained work")
	}
	select {
	case <-release:
		t.Error("handler was released before the failure assertion")
	default:
	}
}

// Shut down only the exact loopback listener owned by this process. The fd
// stays allocated to net.Listener so normal cleanup cannot close a reused fd.
func interruptNativeListener(t *testing.T, address netip.AddrPort) {
	t.Helper()
	require.Equal(t, "127.0.0.1", address.Addr().String())
	contents, err := os.ReadFile("/proc/net/tcp")
	require.NoError(t, err)
	local, inode := fmt.Sprintf("0100007F:%04X", address.Port()), ""
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 9 && fields[1] == local && fields[3] == "0A" {
			require.Empty(t, inode, "listener inode must be unambiguous")
			inode = fields[9]
		}
	}
	require.NotEmpty(t, inode)
	entries, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	fd := -1
	for _, entry := range entries {
		target, _ := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if target == "socket:["+inode+"]" {
			require.Equal(t, -1, fd, "listener fd must be unambiguous")
			fd, err = strconv.Atoi(entry.Name())
			require.NoError(t, err)
		}
	}
	require.GreaterOrEqual(t, fd, 0, "listener must belong to this process")
	require.NoError(t, unix.Shutdown(fd, unix.SHUT_RDWR))
}
