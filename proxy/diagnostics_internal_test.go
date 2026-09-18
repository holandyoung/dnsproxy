package proxy

import (
	"context"
	"log/slog"
	"testing"

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
					got, _ = a.Value.Any().(*dns.Msg)
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
