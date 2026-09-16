package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/holandyoung/dnsproxy/dnscrypt"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func replyLocally(_ context.Context, _ *Proxy, d *DNSContext) error {
	d.Res = new(dns.Msg).SetReply(d.Req)
	return nil
}

func freeTCPAddress(t *testing.T) netip.AddrPort {
	t.Helper()
	l, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(localhostAnyPort))
	require.NoError(t, err)
	addr := l.Addr().(*net.TCPAddr).AddrPort()
	require.NoError(t, l.Close())
	return addr
}

func freeUDPAddress(t *testing.T) netip.AddrPort {
	t.Helper()
	l, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(localhostAnyPort))
	require.NoError(t, err)
	addr := l.LocalAddr().(*net.UDPAddr).AddrPort()
	require.NoError(t, l.Close())
	return addr
}

func requireTCPReleased(t *testing.T, addr netip.AddrPort) {
	t.Helper()
	l, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(addr))
	require.NoError(t, err, "failed startup retained the TCP bind")
	require.NoError(t, l.Close())
}

func TestStartFailureReleasesEveryBoundListener(t *testing.T) {
	for _, phase := range []string{"https", "dnscrypt_init", "dnscrypt_start"} {
		t.Run(phase, func(t *testing.T) {
			tcpAddr, httpsAddr, cryptAddr := freeTCPAddress(t), freeTCPAddress(t), freeUDPAddress(t)
			tlsConfig, _ := newTLSConfig(t)
			conf := &Config{
				Logger:         testLogger,
				RequestHandler: HandlerFunc(replyLocally),
				TCPListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(tcpAddr)},
				TLSConfig:      tlsConfig,
				HTTPConfig:     &HTTPConfig{ListenAddresses: []netip.AddrPort{httpsAddr}},
			}
			switch phase {
			case "https":
				conf.HTTPConfig.ListenAddresses = append(conf.HTTPConfig.ListenAddresses, httpsAddr)
			case "dnscrypt_init":
				conf.DNSCryptUDPListenAddr = []*net.UDPAddr{net.UDPAddrFromAddrPort(cryptAddr)}
			case "dnscrypt_start":
				blocker, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(localhostAnyPort))
				require.NoError(t, err)
				defer blocker.Close()
				resolver, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
				require.NoError(t, err)
				conf.DNSCryptResolverCert, err = resolver.NewCert()
				require.NoError(t, err)
				conf.DNSCryptProviderName = resolver.ProviderName
				conf.DNSCryptUDPListenAddr = []*net.UDPAddr{net.UDPAddrFromAddrPort(cryptAddr), blocker.LocalAddr().(*net.UDPAddr)}
			}
			p := mustNew(t, conf)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			require.Error(t, p.Start(ctx))
			require.False(t, p.isStarted())
			requireTCPReleased(t, tcpAddr)
			requireTCPReleased(t, httpsAddr)
			if phase == "dnscrypt_start" {
				l, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(cryptAddr))
				require.NoError(t, err, "the first DNSCrypt server survived failure of the second")
				require.NoError(t, l.Close())
			}
		})
	}
}

func TestShutdownClosesAcceptedStreamAtEveryReadBoundary(t *testing.T) {
	for _, proto := range []Proto{ProtoTCP, ProtoTLS} {
		for _, partial := range [][]byte{nil, {0}, {0, 20, 1, 2}} {
			t.Run(string(proto)+"/"+string(rune('0'+len(partial))), func(t *testing.T) {
				serverTLS, caPEM := newTLSConfig(t)
				p := mustNew(t, &Config{
					Logger: testLogger, RequestHandler: HandlerFunc(replyLocally), TLSConfig: serverTLS,
					TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
					TLSListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
				})
				startupCtx, startupCancel := context.WithCancel(context.Background())
				require.NoError(t, p.Start(startupCtx))
				startupCancel() // Startup lifetime must not cancel an accepted service.
				defer func() {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					require.NoError(t, p.Shutdown(ctx))
				}()
				roots := x509.NewCertPool()
				require.True(t, roots.AppendCertsFromPEM(caPEM))
				client := &dns.Client{Net: "tcp", Timeout: time.Second}
				if proto == ProtoTLS {
					client.Net = "tcp-tls"
					client.TLSConfig = &tls.Config{RootCAs: roots, ServerName: tlsServerName, MinVersion: tls.VersionTLS12}
				}
				conn, err := client.Dial(p.Addr(proto).String())
				require.NoError(t, err)
				defer conn.Close()
				_, _, err = client.ExchangeWithConn(newTestMessage(), conn)
				require.NoError(t, err, "a response proves that the connection was accepted")
				if len(partial) > 0 {
					_, err = conn.Conn.Write(partial)
					require.NoError(t, err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				require.NoError(t, p.Shutdown(ctx))
				require.NoError(t, conn.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
				_, err = conn.Conn.Read(make([]byte, 1))
				require.Error(t, err)
				if netErr, ok := err.(net.Error); ok {
					require.False(t, netErr.Timeout(), "Shutdown left an accepted socket waiting for its normal timeout")
				}
			})
		}
	}
}

func TestStreamAcceptsSplitLengthPrefix(t *testing.T) {
	for _, proto := range []Proto{ProtoTCP, ProtoTLS} {
		t.Run(string(proto), func(t *testing.T) {
			serverTLS, caPEM := newTLSConfig(t)
			p := mustNew(t, &Config{
				Logger: testLogger, RequestHandler: HandlerFunc(replyLocally), TLSConfig: serverTLS,
				TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
				TLSListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
			})
			require.NoError(t, p.Start(context.Background()))
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				require.NoError(t, p.Shutdown(ctx))
			}()
			roots := x509.NewCertPool()
			require.True(t, roots.AppendCertsFromPEM(caPEM))
			client := &dns.Client{Net: "tcp", Timeout: time.Second}
			if proto == ProtoTLS {
				client.Net = "tcp-tls"
				client.TLSConfig = &tls.Config{RootCAs: roots, ServerName: tlsServerName, MinVersion: tls.VersionTLS12}
			}
			conn, err := client.Dial(p.Addr(proto).String())
			require.NoError(t, err)
			defer conn.Close()
			_, _, err = client.ExchangeWithConn(newTestMessage(), conn)
			require.NoError(t, err)
			query := newTestMessage()
			body, err := query.Pack()
			require.NoError(t, err)
			wire := make([]byte, len(body)+2)
			binary.BigEndian.PutUint16(wire, uint16(len(body)))
			copy(wire[2:], body)
			_, err = conn.Conn.Write(wire[:1])
			require.NoError(t, err)
			require.NoError(t, conn.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
			_, err = conn.Conn.Read(make([]byte, 1))
			var networkError net.Error
			require.ErrorAs(t, err, &networkError, "a partial prefix must stay open until the rest arrives")
			require.True(t, networkError.Timeout())
			require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
			_, err = conn.Conn.Write(wire[1:])
			require.NoError(t, err)
			response, err := conn.ReadMsg()
			require.NoError(t, err)
			require.Equal(t, query.Id, response.Id)
			require.Equal(t, query.Question, response.Question)
		})
	}
}
