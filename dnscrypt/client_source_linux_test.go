package dnscrypt_test

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/holandyoung/dnsproxy/dnscrypt"
	"github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestClient_LocalSourceOwnsCertificateAndEncryptedQuery(t *testing.T) {
	for _, protocol := range []dnscrypt.Proto{dnscrypt.ProtoUDP, dnscrypt.ProtoTCP} {
		t.Run(string(protocol), func(t *testing.T) {
			var local net.Addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)}
			if protocol == dnscrypt.ProtoTCP {
				local = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}
			}
			client := dnscrypt.NewClient(&dnscrypt.ClientConfig{Proto: protocol, LocalAddr: local, Logger: slog.New(slog.DiscardHandler)})
			seen := make(chan string, 1)
			control := &dns.Server{Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
				host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
				seen <- host
				_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeRefused))
			})}
			var err error
			var address string
			if protocol == dnscrypt.ProtoTCP {
				control.Listener, err = net.Listen("tcp4", "127.0.0.1:0")
				require.NoError(t, err)
				address = control.Listener.Addr().String()
			} else {
				control.PacketConn, err = net.ListenPacket("udp4", "127.0.0.1:0")
				require.NoError(t, err)
				address = control.PacketConn.LocalAddr().String()
			}
			ready, done := make(chan struct{}), make(chan struct{})
			control.NotifyStartedFunc = func() { close(ready) }
			go func() { defer close(done); _ = control.ActivateAndServe() }()
			<-ready
			defer func() { require.NoError(t, control.Shutdown()); <-done }()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			_, err = client.DialStampContext(ctx, dnsstamps.ServerStamp{ServerAddrStr: address, ProviderName: prefixedHostname, Proto: dnsstamps.StampProtoTypeDNSCrypt})
			require.Error(t, err)
			require.Equal(t, "127.0.0.2", <-seen, "certificate request must use configured local source")
			s, key, _ := newTestServer(t, dnscrypt.HandlerFunc(func(ctx context.Context, w dnscrypt.ResponseWriter, r *dns.Msg) error {
				host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
				seen <- host
				return testHandler(ctx, w, r)
			}), protocol)
			info, err := client.DialStampContext(ctx, *newTestServerStamp(s, key))
			require.NoError(t, err)
			reply, err := client.ExchangeContext(ctx, new(dns.Msg).SetQuestion("test.example.", dns.TypeA), info, nil)
			require.NoError(t, err)
			require.Len(t, reply.Answer, 1)
			require.Equal(t, "127.0.0.2", <-seen, "encrypted query must use same configured local source")
		})
	}
}
