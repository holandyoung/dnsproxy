package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
)

// Only String is used by the old eager message dump. The embedded interface
// makes unexpected attempts to encode/copy this fixture fail instead of masking
// a new producer-side conversion.
type countedDNSPresentation struct {
	dns.PrivateRdata
	calls *int
}

func (r countedDNSPresentation) String() string {
	*r.calls++
	return "complete private diagnostic content"
}

type diagnosticRecords struct {
	slog.Handler
	records []slog.Record
	level   slog.Level
}

func (h *diagnosticRecords) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *diagnosticRecords) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r.Clone())
	return nil
}

func TestDNSDiagnosticsDeferPresentation(t *testing.T) {
	for _, level := range []slog.Level{slog.LevelInfo, slog.LevelDebug} {
		t.Run(level.String(), func(t *testing.T) {
			calls := 0
			message := &dns.Msg{Answer: []dns.RR{&dns.PrivateRR{
				Hdr:  dns.RR_Header{Name: "diagnostic.example.", Rrtype: 65280, Class: dns.ClassINET},
				Data: countedDNSPresentation{calls: &calls},
			}}}
			handler := &diagnosticRecords{level: level}
			p := &Proxy{logger: slog.New(handler)}
			p.logDNSMessage(t.Context(), message)
			if calls != 0 {
				t.Fatalf("DNS presentation ran on the producer: %d calls", calls)
			}
			if level == slog.LevelInfo {
				if len(handler.records) != 0 {
					t.Fatal("disabled DNS diagnostics reached the handler")
				}
				return
			}
			if len(handler.records) != 1 {
				t.Fatalf("got %d records, want one complete structured message", len(handler.records))
			}
			var got *dns.Msg
			var direction string
			handler.records[0].Attrs(func(a slog.Attr) bool {
				switch a.Key {
				case "dns":
					value, ok := a.Value.Any().(DNSMessage)
					if ok {
						got = value.Msg
					}
				case "direction":
					direction = a.Value.String()
				}
				return true
			})
			if got != message || direction != "in" {
				t.Fatalf("complete borrowed message or direction lost: %p %q", got, direction)
			}
		})
	}
}

func TestDNSDiagnosticsJSONPreservesParameterIdentity(t *testing.T) {
	for _, parameter := range []dns.SVCBKeyValue{new(dns.SVCBNoDefaultAlpn), new(dns.SVCBOhttp)} {
		message := &dns.Msg{Answer: []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: "diagnostic.example.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET},
			Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"h2"}}, parameter},
		}}}}
		if _, err := message.Pack(); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		p := &Proxy{logger: slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))}
		p.logDNSMessage(t.Context(), message)
		var record struct {
			DNS string `json:"dns"`
		}
		if err := json.Unmarshal(output.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		if record.DNS != message.String() {
			t.Fatalf("complete native DNS presentation lost: %q, want %q", record.DNS, message.String())
		}
	}
}

type requestBindingAudit struct {
	bindings, udp, httpProxy, incomplete atomic.Uint64
}

func (*requestBindingAudit) Enabled(context.Context, slog.Level) bool { return true }
func (h *requestBindingAudit) WithAttrs([]slog.Attr) slog.Handler {
	h.bindings.Add(1)
	return h
}
func (h *requestBindingAudit) WithGroup(string) slog.Handler { return h }
func (h *requestBindingAudit) Handle(_ context.Context, r slog.Record) error {
	if r.Message != "handling new packet" && r.Message != "request came from proxy server" {
		return nil
	}
	fields := map[string]slog.Value{}
	r.Attrs(func(a slog.Attr) bool { fields[a.Key] = a.Value; return true })
	if r.Message == "handling new packet" {
		h.udp.Add(1)
		if fields["raddr"].Any() == nil || fields["laddr"].Any() == nil || fields[logKeyProto].Any() != ProtoUDP {
			h.incomplete.Add(1)
		}
	} else {
		h.httpProxy.Add(1)
		if fields["addr"].Any() == nil {
			h.incomplete.Add(1)
		}
	}
	return nil
}

func TestRequestDiagnosticsHavePerRecordOwnership(t *testing.T) {
	h := new(requestBindingAudit)
	p := mustNew(t, &Config{
		Logger: slog.New(h), UDPListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		HTTPConfig: &HTTPConfig{InsecureEnabled: true}, RequestHandler: HandlerFunc(replyLocally),
		TrustedProxies: defaultTrustedProxies,
	})
	servicetest.RequireRun(t, p, testTimeout)
	q := new(dns.Msg).SetQuestion("diagnostic.example.", dns.TypeA)
	r, _, err := (&dns.Client{Timeout: time.Second}).Exchange(q, p.Addr(ProtoUDP).String())
	if err != nil || r == nil || r.Rcode != dns.RcodeSuccess {
		t.Fatalf("UDP query prerequisite: %v %v", r, err)
	}
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://diagnostic.example/dns-query", bytes.NewReader(wire))
	request.RemoteAddr = "127.0.0.1:42001"
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("X-Real-IP", "192.0.2.1")
	response := httptest.NewRecorder()
	p.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("proxied HTTP prerequisite: %d %s", response.Code, response.Body.String())
	}
	if h.udp.Load() != 1 || h.httpProxy.Load() != 1 {
		t.Fatalf("request paths not both observed: udp=%d http=%d", h.udp.Load(), h.httpProxy.Load())
	}
	if h.bindings.Load() != 0 || h.incomplete.Load() != 0 {
		t.Fatalf("request diagnostics escaped per-record admission: bindings=%d incomplete=%d", h.bindings.Load(), h.incomplete.Load())
	}
}
