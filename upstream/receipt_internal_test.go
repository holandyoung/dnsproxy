package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestReceiptPendingValidationAndDeadline(t *testing.T) {
	for _, outcome := range []string{"valid", "invalid", "abandoned"} {
		t.Run(outcome, func(t *testing.T) {
			req := createTestMessage()
			response := respondToTestMessage(req)
			wire, err := response.Pack()
			require.NoError(t, err)
			state := NewExchangeState(time.Now().Add(time.Minute))
			require.NoError(t, state.start(req.Id))
			ticket := state.reserve(wire, req.Id, false)
			require.NotZero(t, ticket)
			state.Expire()
			_, ready := state.Result()
			require.False(t, ready, "expiry must not erase the complete candidate awaiting local validation")
			switch outcome {
			case "valid":
				state.accept(ticket, response)
			case "invalid":
				state.reject(ticket)
			case "abandoned":
				state.Abandon()
				state.accept(ticket, response)
			}
			select {
			case <-state.Done():
			default:
				t.Fatal("candidate decision was not published")
			}
			result, ready := state.Result()
			require.True(t, ready)
			if outcome == "valid" {
				require.NoError(t, result.Err)
				require.False(t, result.ReceivedAt.IsZero())
				require.Equal(t, response.Id, result.Response.Id)
				response.Id++
				require.Equal(t, req.Id, result.Response.Id, "decision owns its message")
			} else {
				require.Nil(t, result.Response)
				want := error(context.DeadlineExceeded)
				if outcome == "abandoned" {
					want = ErrExchangeAbandoned
				}
				require.ErrorIs(t, result.Err, want)
			}
			state.Expire()
			state.finish(errors.New("late cleanup error"))
			after, _ := state.Result()
			require.Equal(t, result, after, "a late timer or cleanup cannot replace the decision")
		})
	}
}

func TestReceiptRejectsProvisionalAndLateCandidates(t *testing.T) {
	req := createTestMessage()
	for _, kind := range []string{"wrong id", "truncated UDP", "query", "partial", "late", "expired before observation"} {
		t.Run(kind, func(t *testing.T) {
			response := respondToTestMessage(req)
			cutoff := time.Now().Add(time.Minute)
			if kind == "wrong id" {
				response.Id++
			}
			if kind == "truncated UDP" {
				response.Truncated = true
			}
			if kind == "query" {
				response.Response = false
			}
			if kind == "late" {
				cutoff = time.Now().Add(-time.Second)
			}
			wire, err := response.Pack()
			require.NoError(t, err)
			if kind == "partial" {
				wire = wire[:10]
			}
			state := NewExchangeState(cutoff)
			require.NoError(t, state.start(req.Id))
			if kind == "expired before observation" {
				state.Expire()
			}
			require.Zero(t, state.reserve(wire, req.Id, true))
			state.Expire()
			result, ready := state.Result()
			require.True(t, ready)
			require.ErrorIs(t, result.Err, context.DeadlineExceeded)
		})
	}
}

func TestReceiptRejectedTicketCannotCommitLaterCandidate(t *testing.T) {
	req := createTestMessage()
	response := respondToTestMessage(req)
	wire, err := response.Pack()
	require.NoError(t, err)
	state := NewExchangeState(time.Time{})
	require.NoError(t, state.start(req.Id))
	first := state.reserve(wire, req.Id, false)
	state.reject(first)
	second := state.reserve(wire, req.Id, false)
	require.Greater(t, second, first)
	state.accept(first, response)
	_, ready := state.Result()
	require.False(t, ready)
	state.accept(second, response)
	result, ready := state.Result()
	require.True(t, ready)
	require.NoError(t, result.Err)
	require.Error(t, state.start(req.Id), "an exchange state cannot be shared or reused")
}

type receiptCloseConn struct {
	net.Conn
	closing chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (c *receiptCloseConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closing) })
	<-c.release
	return err
}

type receiptCloseRoute struct {
	closing chan struct{}
	release <-chan struct{}
	address string
}

func (r *receiptCloseRoute) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, r.address)
	if err != nil {
		return nil, err
	}
	return &receiptCloseConn{Conn: c, closing: r.closing, release: r.release}, nil
}

func (r *receiptCloseRoute) DialPacket(context.Context, string) (net.PacketConn, net.Addr, error) {
	return nil, nil, errors.New("unexpected packet dial")
}

func TestReceiptPublishedBeforeRealConnectionCleanup(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp"} {
		t.Run(protocol, func(t *testing.T) {
			srv := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
				require.NoError(t, w.WriteMsg(respondToTestMessage(req)))
			})
			t.Cleanup(func() { require.NoError(t, srv.Close()) })
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			route := &receiptCloseRoute{address: fmt.Sprintf("127.0.0.1:%d", srv.port), closing: make(chan struct{}), release: release}
			u, err := AddressToUpstream(protocol+"://127.0.0.1:1", &Options{NetworkDialer: route, Timeout: time.Second, Logger: testLogger})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, u.Close()) })
			state := NewExchangeState(time.Now().Add(time.Second))
			finished := make(chan error, 1)
			go func() { _, exchangeErr := u.Exchange(createTestMessage(), state); finished <- exchangeErr }()
			select {
			case <-route.closing:
			case <-time.After(2 * time.Second):
				t.Fatal("actual connection cleanup not entered")
			}
			result, ready := state.Result()
			require.True(t, ready, "a complete answer must publish before cleanup returns")
			require.NoError(t, result.Err)
			require.NotEmpty(t, result.Response.Answer)
			require.True(t, result.ReceivedAt.Before(state.deadline))
			select {
			case resultErr := <-finished:
				t.Fatalf("cleanup prerequisite ended early: %v", resultErr)
			case <-time.After(time.Until(state.deadline)):
			}
			state.Expire()
			unblock()
			select {
			case resultErr := <-finished:
				require.NoError(t, resultErr)
			case <-time.After(time.Second):
				t.Fatal("exchange did not finish after cleanup release")
			}
			after, _ := state.Result()
			require.Equal(t, result, after)
		})
	}
}
