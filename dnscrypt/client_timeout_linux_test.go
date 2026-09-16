package dnscrypt_test

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/ameshkov/dnsstamps"
	"github.com/holandyoung/dnsproxy/dnscrypt"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestClient_CertificateRetainsNativeDialTimeout(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	defer unix.Close(fd)
	require.NoError(t, unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}))
	require.NoError(t, unix.Listen(fd, 0))
	address, err := unix.Getsockname(fd)
	require.NoError(t, err)
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(address.(*unix.SockaddrInet4).Port))

	// Linux backlog zero admits one completed connection. Keep it queued
	// without Accept, and prove the next handshake cannot complete.
	held, err := net.DialTimeout("tcp4", target, time.Second)
	require.NoError(t, err)
	defer held.Close()
	check, err := net.DialTimeout("tcp4", target, 100*time.Millisecond)
	if check != nil {
		check.Close()
	}
	var timeout net.Error
	require.True(t, errors.As(err, &timeout))
	require.True(t, timeout.Timeout(), "full actual TCP accept queue prerequisite")

	ctx, cancel := context.WithTimeout(t.Context(), 3500*time.Millisecond)
	defer cancel()
	client := dnscrypt.NewClient(&dnscrypt.ClientConfig{Proto: dnscrypt.ProtoTCP})
	start := time.Now()
	_, err = client.DialStampContext(ctx, dnsstamps.ServerStamp{
		ServerAddrStr: target, ProviderName: prefixedHostname,
		Proto: dnsstamps.StampProtoTypeDNSCrypt,
	})
	elapsed := time.Since(start)
	require.Error(t, err)
	var operation *net.OpError
	require.True(t, errors.As(err, &operation))
	require.Equal(t, "dial", operation.Op, "must exercise dial, not a later DNS read")
	require.Less(t, elapsed, 2750*time.Millisecond, "certificate native default dial timeout must remain 2s")
}
