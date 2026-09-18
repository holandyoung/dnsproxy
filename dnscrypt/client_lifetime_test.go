package dnscrypt_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/holandyoung/dnsproxy/dnscrypt"
	"github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestClient_CertificateCancellationClosesRealSocket(t *testing.T) {
	for _, protocol := range []dnscrypt.Proto{dnscrypt.ProtoUDP, dnscrypt.ProtoTCP} {
		t.Run(string(protocol), func(t *testing.T) {
			var address string
			received := make(chan net.Addr, 1)
			peerDone := make(chan error, 1)
			var packet net.PacketConn
			var listener net.Listener
			if protocol == dnscrypt.ProtoUDP {
				var err error
				packet, err = net.ListenPacket("udp4", "127.0.0.1:0")
				require.NoError(t, err)
				defer func(closeResource func() error) { _ = closeResource() }(packet.Close)
				address = packet.LocalAddr().String()
				go func() {
					b := make([]byte, 4096)
					_, peer, readErr := packet.ReadFrom(b)
					if readErr == nil {
						received <- peer
					}
					peerDone <- readErr
				}()
			} else {
				var err error
				listener, err = net.Listen("tcp4", "127.0.0.1:0")
				require.NoError(t, err)
				defer func(closeResource func() error) { _ = closeResource() }(listener.Close)
				address = listener.Addr().String()
				go func() {
					c, acceptErr := listener.Accept()
					if acceptErr != nil {
						peerDone <- acceptErr
						return
					}
					defer func(closeResource func() error) { _ = closeResource() }(c.Close)
					_ = c.SetDeadline(time.Now().Add(2 * time.Second))
					_, acceptErr = (&dns.Conn{Conn: c}).ReadMsg()
					if acceptErr != nil {
						peerDone <- acceptErr
						return
					}
					received <- c.RemoteAddr()
					var b [1]byte
					_, acceptErr = c.Read(b[:])
					peerDone <- acceptErr
				}()
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			client := newTestClient(&dnscrypt.ClientConfig{Proto: protocol})
			finished := make(chan error, 1)
			go func() {
				_, err := client.DialStampContext(ctx, dnsstamps.ServerStamp{ServerAddrStr: address, ProviderName: prefixedHostname, Proto: dnsstamps.StampProtoTypeDNSCrypt})
				finished <- err
			}()
			var peer net.Addr
			select {
			case peer = <-received:
			case <-ctx.Done():
				t.Fatal("certificate request did not reach real peer")
			}
			cancel()
			select {
			case err := <-finished:
				require.Error(t, err)
			case <-time.After(300 * time.Millisecond):
				t.Fatal("canceled certificate acquisition retained socket until its deadline")
			}
			if protocol == dnscrypt.ProtoUDP {
				// The peer-observed source port is reusable only after the client
				// has physically closed its original UDP socket.
				c, err := net.ListenPacket("udp4", peer.String())
				require.NoError(t, err)
				require.NoError(t, c.Close())
				require.NoError(t, <-peerDone)
			} else {
				select {
				case err := <-peerDone:
					require.Error(t, err)
					if n, ok := err.(net.Error); ok {
						require.False(t, n.Timeout())
					}
				case <-time.After(300 * time.Millisecond):
					t.Fatal("TCP certificate peer did not observe closure")
				}
			}
		})
	}
}

func TestClient_EncryptedCancellationClosesRealSocket(t *testing.T) {
	for _, protocol := range []dnscrypt.Proto{dnscrypt.ProtoUDP, dnscrypt.ProtoTCP} {
		t.Run(string(protocol), func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			handler := dnscrypt.HandlerFunc(func(ctx context.Context, w dnscrypt.ResponseWriter, r *dns.Msg) error {
				close(entered)
				<-release
				return testHandler(ctx, w, r)
			})
			s, key, _ := newTestServer(t, handler, protocol)
			defer once.Do(func() { close(release) })
			client := newTestClient(&dnscrypt.ClientConfig{Proto: protocol})
			setup, stop := context.WithTimeout(t.Context(), time.Second)
			defer stop()
			info, err := client.DialStampContext(setup, *newTestServerStamp(s, key))
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, exchangeErr := client.ExchangeContext(ctx, new(dns.Msg).SetQuestion("test.example.", dns.TypeA), info, nil)
				done <- exchangeErr
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("encrypted request did not reach real handler")
			}
			cancel()
			select {
			case resultErr := <-done:
				require.Error(t, resultErr)
			case <-time.After(300 * time.Millisecond):
				t.Fatal("canceled encrypted exchange retained its socket")
			}
		})
	}
}
