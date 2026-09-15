package proxy

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/holandyoung/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type pipelineTraceKey struct{}

type pipelineTrace struct {
	stages []string
	local  string
	err    error
	final  *dns.Msg
}

// One Proxy owns all encrypted listeners; the same entry and final-response
// hooks must cover normal resolution and native ANY refusal on each protocol.
func TestRequestPipelineAcrossEncryptedListeners(t *testing.T) {
	serverTLS, caPEM := newTLSConfig(t)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM))
	resolver, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
	require.NoError(t, err)
	cert, err := resolver.NewCert()
	require.NoError(t, err)
	observed := make(chan pipelineTrace, 1)
	p := mustNew(t, &Config{
		Logger: testLogger, TLSConfig: serverTLS, RefuseAny: true,
		TLSListenAddr:         []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		QUICListenAddr:        []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		HTTPConfig:            &HTTPConfig{ListenAddresses: []netip.AddrPort{localhostAnyPort}, HTTP3Enabled: true},
		DNSCryptUDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		DNSCryptTCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		DNSCryptProviderName:  resolver.ProviderName, DNSCryptResolverCert: cert,
		RequestHandler: HandlerFunc(replyLocally),
		RequestMiddleware: func(next Handler) Handler {
			return HandlerFunc(func(ctx context.Context, p *Proxy, d *DNSContext) error {
				trace := &pipelineTrace{stages: []string{"entry"}, local: d.LocalAddr().String()}
				err := next.ServeDNS(context.WithValue(ctx, pipelineTraceKey{}, trace), p, d)
				trace.stages = append(trace.stages, "exit")
				trace.err = err
				observed <- *trace
				return err
			})
		},
		ResponseHandler: HandlerFunc(func(ctx context.Context, _ *Proxy, d *DNSContext) error {
			trace := ctx.Value(pipelineTraceKey{}).(*pipelineTrace)
			trace.stages = append(trace.stages, "prepare")
			d.Res.RecursionAvailable = true
			return nil
		}),
	})
	servicetest.RequireRun(t, p, testTimeout)
	cases := []struct {
		name, address string
		proto         Proto
		versions      []upstream.HTTPVersion
	}{
		{"dot", "tls://" + p.Addr(ProtoTLS).String(), ProtoTLS, nil},
		{"doh1", "https://" + p.Addr(ProtoHTTPS).String() + "/dns-query", ProtoHTTPS, []upstream.HTTPVersion{upstream.HTTPVersion11}},
		{"doh2", "https://" + p.Addr(ProtoHTTPS).String() + "/dns-query", ProtoHTTPS, []upstream.HTTPVersion{upstream.HTTPVersion2}},
		{"doh3", "h3://" + p.Addr(ProtoHTTPS).String() + "/dns-query", ProtoHTTPS, nil},
		{"doq", "quic://" + p.Addr(ProtoQUIC).String(), ProtoQUIC, nil},
		{"dnscrypt_udp", p.Addrs(ProtoDNSCrypt)[0].String(), ProtoDNSCrypt, nil},
		{"dnscrypt_tcp", p.Addrs(ProtoDNSCrypt)[1].String(), ProtoDNSCrypt, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var exchange func(*dns.Msg) (*dns.Msg, error)
			if tc.proto == ProtoDNSCrypt {
				protocol := dnscrypt.ProtoUDP
				if tc.name == "dnscrypt_tcp" {
					protocol = dnscrypt.ProtoTCP
				}
				client := dnscrypt.NewClient(&dnscrypt.ClientConfig{Logger: testLogger, Proto: protocol})
				stamp, stampErr := resolver.CreateStamp(tc.address)
				require.NoError(t, stampErr)
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				info, dialErr := client.DialStampContext(ctx, stamp)
				require.NoError(t, dialErr)
				exchange = func(r *dns.Msg) (*dns.Msg, error) { return client.ExchangeContext(ctx, r, info) }
			} else {
				u, parseErr := upstream.AddressToUpstream(tc.address, &upstream.Options{RootCAs: roots, ServerName: tlsServerName, Logger: testLogger, Timeout: time.Second, HTTPVersions: tc.versions})
				require.NoError(t, parseErr)
				defer u.Close()
				exchange = func(r *dns.Msg) (*dns.Msg, error) { return u.Exchange(r, nil) }
			}
			for _, qtype := range []uint16{dns.TypeA, dns.TypeANY} {
				response, exchangeErr := exchange(new(dns.Msg).SetQuestion("pipeline.example.", qtype))
				require.NoError(t, exchangeErr)
				require.True(t, response.RecursionAvailable)
				wantCode := dns.RcodeSuccess
				if qtype == dns.TypeANY {
					wantCode = dns.RcodeNotImplemented
				}
				require.Equal(t, wantCode, response.Rcode)
				select {
				case trace := <-observed:
					require.NoError(t, trace.err)
					require.Equal(t, []string{"entry", "prepare", "exit"}, trace.stages)
					local := p.Addr(tc.proto).String()
					if tc.proto == ProtoDNSCrypt {
						local = tc.address
					}
					require.Equal(t, local, trace.local)
				case <-time.After(time.Second):
					t.Fatal("encrypted listener bypassed the pipeline")
				}
			}
		})
	}
}

// Exercise real sockets, including native early responses and the malformed
// UDP body path that historically bypassed request handling completely.
func TestRequestPipelineCoversNativeResponses(t *testing.T) {
	for _, proto := range []Proto{ProtoUDP, ProtoTCP} {
		for _, name := range []string{"normal", "large", "no_question", "any", "refuse", "drop", "response", "final_drop", "malformed"} {
			if proto == ProtoTCP && name == "malformed" {
				continue // Invalid TCP framing is a transport error, not a DNS request.
			}
			t.Run(string(proto)+"/"+name, func(t *testing.T) {
				observed := make(chan pipelineTrace, 1)
				p := mustNew(t, &Config{
					Logger:        testLogger,
					UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
					TCPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
					RefuseAny:     true,
					RequestMiddleware: func(next Handler) Handler {
						return HandlerFunc(func(ctx context.Context, p *Proxy, d *DNSContext) (err error) {
							trace := &pipelineTrace{stages: []string{"entry"}, local: d.LocalAddr().String()}
							ctx = context.WithValue(ctx, pipelineTraceKey{}, trace)
							defer func() {
								trace.stages = append(trace.stages, "exit")
								trace.err = err
								if d.Res != nil {
									trace.final = d.Res.Copy()
								}
								observed <- *trace
							}()
							if name == "drop" {
								return ErrDrop
							}
							if name == "refuse" {
								d.Res = new(dns.Msg).SetRcode(d.Req, dns.RcodeRefused)
							}
							return next.ServeDNS(ctx, p, d)
						})
					},
					RequestHandler: HandlerFunc(func(ctx context.Context, _ *Proxy, d *DNSContext) error {
						trace := ctx.Value(pipelineTraceKey{}).(*pipelineTrace)
						trace.stages = append(trace.stages, "resolve")
						d.Res = new(dns.Msg).SetReply(d.Req)
						if name == "large" {
							for range 40 {
								d.Res.Answer = append(d.Res.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: d.Req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{strings.Repeat("x", 100)}})
							}
						}
						return nil
					}),
					ResponseHandler: HandlerFunc(func(ctx context.Context, _ *Proxy, d *DNSContext) error {
						trace := ctx.Value(pipelineTraceKey{}).(*pipelineTrace)
						trace.stages = append(trace.stages, "prepare")
						if name == "final_drop" {
							return ErrDrop
						}
						d.Res.RecursionAvailable = true
						d.Res.SetEdns0(1232, false)
						if d.Proto == ProtoUDP {
							d.Res.Truncate(512)
						}
						return nil
					}),
				})
				servicetest.RequireRun(t, p, testTimeout)
				address := p.Addr(proto).String()
				query := new(dns.Msg).SetQuestion(name+".example.", dns.TypeA)
				wantCode := dns.RcodeSuccess
				switch name {
				case "no_question", "malformed":
					query.Question = nil
					wantCode = dns.RcodeFormatError
				case "any":
					query.Question[0].Qtype = dns.TypeANY
					wantCode = dns.RcodeNotImplemented
				case "refuse":
					wantCode = dns.RcodeRefused
				case "response":
					query.Response = true
				}
				var reply *dns.Msg
				var err error
				if name == "malformed" {
					wire, packErr := query.Pack()
					require.NoError(t, packErr)
					binary.BigEndian.PutUint16(wire[4:6], 1) // Claims one absent question.
					conn, dialErr := net.DialTimeout("udp", address, time.Second)
					require.NoError(t, dialErr)
					defer conn.Close()
					require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
					_, err = conn.Write(wire)
					require.NoError(t, err)
					reply, err = (&dns.Conn{Conn: conn}).ReadMsg()
				} else {
					reply, _, err = (&dns.Client{Net: string(proto), Timeout: 200 * time.Millisecond}).Exchange(query, address)
				}
				var trace pipelineTrace
				select {
				case trace = <-observed:
				case <-time.After(time.Second):
					t.Fatal("request bypassed the middleware")
				}
				require.Equal(t, address, trace.local)
				stages := []string{"entry"}
				if name == "normal" || name == "large" || name == "final_drop" {
					stages = append(stages, "resolve")
				}
				if name != "drop" && name != "response" {
					stages = append(stages, "prepare")
				}
				stages = append(stages, "exit")
				require.Equal(t, stages, trace.stages)
				if name == "drop" || name == "response" || name == "final_drop" {
					require.Error(t, err)
					require.ErrorIs(t, trace.err, ErrDrop)
					return
				}
				require.NoError(t, err)
				require.NoError(t, trace.err)
				require.Equal(t, wantCode, reply.Rcode)
				require.True(t, reply.RecursionAvailable, "final hook covers built-in responses")
				require.NotNil(t, reply.IsEdns0())
				require.EqualValues(t, 1232, reply.IsEdns0().UDPSize())
				require.Equal(t, trace.final.Truncated, reply.Truncated)
				require.Equal(t, len(trace.final.Answer), len(reply.Answer), "observer sees the final wire answer")
				if name == "large" {
					require.Equal(t, proto == ProtoUDP, reply.Truncated)
					if proto == ProtoTCP {
						require.Len(t, reply.Answer, 40)
					}
				}
			})
		}
	}
}

func TestRequestPipelineObservesUDPWriteFailure(t *testing.T) {
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(localhostAnyPort))
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	var observed error
	p := mustNew(t, &Config{
		Logger: testLogger,
		RequestHandler: HandlerFunc(func(_ context.Context, _ *Proxy, d *DNSContext) error {
			d.Res = new(dns.Msg).SetReply(d.Req)
			return nil
		}),
		RequestMiddleware: func(next Handler) Handler {
			return HandlerFunc(func(ctx context.Context, p *Proxy, d *DNSContext) error {
				observed = next.ServeDNS(ctx, p, d)
				return observed
			})
		},
	})
	query := newTestMessage()
	wire, err := query.Pack()
	require.NoError(t, err)
	p.udpHandlePacket(context.Background(), wire, localhostAnyPort.Addr(), net.UDPAddrFromAddrPort(localhostAnyPort), conn)
	require.True(t, errors.Is(observed, net.ErrClosed), "a lost write must not look successful to observation")
}

func TestRequestPipelineObservesTCPWriteFailure(t *testing.T) {
	listener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(localhostAnyPort))
	require.NoError(t, err)
	defer listener.Close()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	require.NoError(t, err)
	defer client.Close()
	server, err := listener.Accept()
	require.NoError(t, err)
	require.NoError(t, server.Close())
	var observed error
	p := mustNew(t, &Config{Logger: testLogger, RequestHandler: HandlerFunc(replyLocally), RequestMiddleware: func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, p *Proxy, d *DNSContext) error {
			observed = next.ServeDNS(ctx, p, d)
			return observed
		})
	}})
	d := p.newDNSContext(ProtoTCP, newTestMessage(), localhostAnyPort)
	d.Conn = server
	err = p.handleDNSRequest(context.Background(), d)
	require.ErrorIs(t, err, net.ErrClosed)
	require.ErrorIs(t, observed, net.ErrClosed, "a closed TCP write must not appear successful")
}
