package upstream

import (
	quic "github.com/holandyoung/quic-go"
	"github.com/miekg/dns"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPResetFailedGenerationNeverReturnsNilSuccess(t *testing.T) {
	var fail atomic.Bool
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready, done := make(chan struct{}), make(chan struct{})
	server := &dns.Server{PacketConn: packet, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		resp := new(dns.Msg).SetReply(m)
		if fail.Load() {
			resp.Rcode = dns.RcodeServerFailure
		} else if m.Question[0].Qtype == dns.TypeA {
			resp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.IPv4(127, 0, 0, 1)}}
		}
		_ = w.WriteMsg(resp)
	})}
	go func() { defer close(done); _ = server.ActivateAndServe() }()
	<-ready
	defer func() { _ = server.Shutdown(); <-done }()
	bootstrap, err := NewUpstreamResolver(packet.LocalAddr().String(), &Options{Timeout: time.Second, Logger: testLogger})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := bootstrap.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	u, err := AddressToUpstream("https://bootstrap.example:443/dns-query", &Options{Bootstrap: bootstrap, Logger: testLogger, HTTPVersions: []HTTPVersion{HTTPVersion2}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := u.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	p := u.(*dnsOverHTTPS)
	work := new(httpWork)
	defer work.join()
	previous, _, err := p.getClient(work)
	if err != nil || previous == nil {
		t.Fatal("real bootstrap setup failed", err)
	}
	fail.Store(true)
	if next, resetErr := p.resetClient(previous, quic.Err0RTTRejected, work); resetErr == nil || next != nil {
		t.Fatal("real failing bootstrap prerequisite did not fail", resetErr)
	}
	if p.client != nil {
		t.Fatal("first failed generation did not become empty")
	}
	next, err := p.resetClient(previous, quic.Err0RTTRejected, work)
	if err == nil && next == nil {
		t.Error("late failure returned a nil successful successor after real bootstrap failure")
	}
	fail.Store(false)
	current, err := p.resetClient(previous, quic.Err0RTTRejected, work)
	if err != nil || current == nil {
		t.Fatal("recovered bootstrap could not create successor", err)
	}
	again, err := p.resetClient(previous, quic.Err0RTTRejected, work)
	if err != nil || again != current {
		t.Fatal("late failure replaced valid successor", err)
	}
}
