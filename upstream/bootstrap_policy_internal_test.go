package upstream

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestBootstrapMetadataBeforeAddressExtraction(t *testing.T) {
	for _, mode := range []string{"valid", "rcode", "QR", "opcode", "qclass", "question-case", "question-name", "question-type"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			server := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
				calls.Add(1)
				response := new(dns.Msg)
				response.SetReply(req)
				response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("192.0.2.10")}}
				switch mode {
				case "rcode":
					response.Rcode = dns.RcodeServerFailure
				case "QR":
					response.Response = false
				case "opcode":
					response.Opcode = dns.OpcodeStatus
				case "qclass":
					response.Question[0].Qclass = dns.ClassCHAOS
				case "question-name":
					response.Question[0].Name = "different.example."
				case "question-type":
					response.Question[0].Qtype = dns.TypeTXT
				case "question-case":
					response.Question[0].Name = strings.ToUpper(response.Question[0].Name)
				}
				_ = w.WriteMsg(response)
			})
			t.Cleanup(func() { require.NoError(t, server.Close()) })
			resolver, err := NewUpstreamResolver(fmt.Sprintf("127.0.0.1:%d", server.port), &Options{Timeout: time.Second, Logger: testLogger})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, resolver.Close()) })
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			addresses, err := resolver.LookupNetIP(ctx, "ip4", "Bootstrap.Example.")
			require.Equal(t, int32(1), calls.Load())
			t.Logf("mode=%s addresses=%v err=%v", mode, addresses, err)
			if mode == "valid" {
				require.NoError(t, err)
				require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.10")}, addresses)
			} else {
				require.Error(t, err, "invalid bootstrap metadata must remain distinguishable from a usable answer")
			}
		})
	}
}

func TestBootstrapRequestedRRType(t *testing.T) {
	for _, family := range []string{"ip4", "ip6"} {
		t.Run(family, func(t *testing.T) {
			server := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
				response := new(dns.Msg)
				response.SetReply(req)
				response.Answer = []dns.RR{
					&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("192.0.2.10")},
					&dns.AAAA{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30}, AAAA: net.ParseIP("2001:db8::10")},
				}
				_ = w.WriteMsg(response)
			})
			t.Cleanup(func() { require.NoError(t, server.Close()) })
			resolver, err := NewUpstreamResolver(fmt.Sprintf("127.0.0.1:%d", server.port), &Options{Timeout: time.Second, Logger: testLogger})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, resolver.Close()) })
			addresses, err := resolver.LookupNetIP(context.Background(), family, "bootstrap.example")
			require.NoError(t, err)
			t.Logf("network=%s addresses=%v", family, addresses)
			wanted := "192.0.2.10"
			if family == "ip6" {
				wanted = "2001:db8::10"
			}
			require.Equal(t, []netip.Addr{netip.MustParseAddr(wanted)}, addresses, "requested RR type must exclude the other family")
		})
	}
}

func TestBootstrapCanceledBeforeAdmission(t *testing.T) {
	var calls atomic.Int32
	server := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) { calls.Add(1); _ = w.WriteMsg(respondToTestMessage(req)) })
	t.Cleanup(func() { require.NoError(t, server.Close()) })
	resolver, err := NewUpstreamResolver(fmt.Sprintf("127.0.0.1:%d", server.port), &Options{Timeout: time.Second, Logger: testLogger})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, resolver.Close()) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	addresses, err := resolver.LookupNetIP(ctx, "ip4", "bootstrap.example")
	t.Logf("canceled calls=%d addresses=%v err=%v", calls.Load(), addresses, err)
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, calls.Load())
}

func TestBootstrapQuestionAndTruncationPolicy(t *testing.T) {
	for _, mode := range []string{"wrong question", "wrong question TC", "header TC", "malformed TC", "TC TCP failure"} {
		t.Run(mode, func(t *testing.T) {
			var datagrams, streams atomic.Int32
			server := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
				response := respondToTestMessage(req)
				if w.RemoteAddr().Network() == "tcp" {
					if streams.Add(1) == 1 && mode == "TC TCP failure" {
						_ = w.Close()
						return
					}
					_ = w.WriteMsg(response)
					return
				}
				datagrams.Add(1)
				response.Question[0].Name = "different.example."
				response.Truncated = mode != "wrong question"
				if mode == "malformed TC" || mode == "header TC" {
					wire, err := response.Pack()
					if err != nil {
						t.Error(err)
						return
					}
					if mode == "malformed TC" {
						wire = wire[:13]
						decoded := new(dns.Msg)
						if decoded.Unpack(wire) == nil || !decoded.Truncated {
							t.Error("fixture must decode TC and then fail on its incomplete question")
							return
						}
					} else {
						// Native miekg deliberately accepts a header-only reply.
						wire = wire[:12]
					}
					_, _ = w.Write(wire)
					return
				}
				_ = w.WriteMsg(response)
			})
			t.Cleanup(func() { require.NoError(t, server.Close()) })
			resolver, err := NewUpstreamResolver(fmt.Sprintf("127.0.0.1:%d", server.port), &Options{Timeout: time.Second, Logger: testLogger})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, resolver.Close()) })
			addresses, err := resolver.LookupNetIP(context.Background(), "ip4", "example.org")
			require.Equal(t, int32(1), datagrams.Load())
			if mode == "wrong question TC" || mode == "header TC" {
				require.NoError(t, err)
				require.NotEmpty(t, addresses)
				require.Equal(t, int32(1), streams.Load())
			} else {
				require.Error(t, err)
				require.Empty(t, addresses)
				if mode == "TC TCP failure" {
					require.Equal(t, int32(1), streams.Load(), "a failed bootstrap TCP continuation cannot retry")
				} else {
					require.Zero(t, streams.Load(), "invalid bootstrap datagram must not cause TCP replay")
				}
			}
		})
	}
}
