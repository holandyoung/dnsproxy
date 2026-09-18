package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/holandyoung/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestLookupNetIPPanicCompletesBothResults(t *testing.T) {
	for _, allPanic := range []bool{false, true} {
		t.Run(map[bool]string{false: "one_answer", true: "both_panic"}[allPanic], func(t *testing.T) {
			failure := errors.New("lookup upstream panic")
			u := &testUpstream{
				OnExchange: func(req *dns.Msg) (*dns.Msg, error) {
					if allPanic || req.Question[0].Qtype == dns.TypeAAAA {
						panic(failure)
					}
					response := new(dns.Msg).SetReply(req)
					response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IP{192, 0, 2, 1}}}
					return response, nil
				},
				OnAddress: func() string { return "panic.test" },
				OnClose:   func() error { return nil },
			}
			p, err := New(&Config{Logger: slog.New(slog.DiscardHandler), UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{u}}})
			require.NoError(t, err)
			done := make(chan struct{})
			var addrs []netip.Addr
			var lookupErr error
			go func() {
				defer close(done)
				addrs, lookupErr = p.LookupNetIP(t.Context(), "ip", "panic.test")
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("recovered lookup panic failed to deliver its result")
			}
			if allPanic {
				require.Empty(t, addrs)
				require.ErrorIs(t, lookupErr, failure)
			} else {
				require.NoError(t, lookupErr)
				require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, addrs)
			}
		})
	}
}

// Keep context's cancellation contract explicit even when there is no work.
func TestLookupNetIPCanceledDoesNotStartUpstream(t *testing.T) {
	var calls atomic.Int64
	u := &testUpstream{OnExchange: func(req *dns.Msg) (*dns.Msg, error) {
		calls.Add(1)
		return new(dns.Msg).SetReply(req), nil
	}, OnAddress: func() string { return "unused" }}
	p, err := New(&Config{Logger: slog.New(slog.DiscardHandler), UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{u}}})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = p.LookupNetIP(ctx, "ip", "canceled.test")
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, calls.Load())
}

func TestLookupNetIPCancellationDrainsWorkers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var entered, finished atomic.Int64
		u := &testUpstream{OnExchange: func(req *dns.Msg) (*dns.Msg, error) {
			entered.Add(1)
			<-release
			finished.Add(1)
			return new(dns.Msg).SetReply(req), nil
		}, OnAddress: func() string { return "owned" }}
		p, err := New(&Config{Logger: slog.New(slog.DiscardHandler), UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{u}}})
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { _, lookupErr := p.LookupNetIP(ctx, "ip", "cancel.test"); done <- lookupErr }()
		synctest.Wait()
		require.EqualValues(t, 2, entered.Load())
		cancel()
		synctest.Wait()
		select {
		case lookupErr := <-done:
			require.ErrorIs(t, lookupErr, context.Canceled)
		default:
			t.Error("canceled lookup still waits for native work")
		}
		close(release)
		synctest.Wait()
		require.EqualValues(t, 2, finished.Load())
		// synctest also requires every worker to exit; a blocked result send
		// after the caller returned is a deadlock, not a successful drain.
	})
}
