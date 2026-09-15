package upstream

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExchangeParallel proves first-success return without waiting for the
// other real UDP exchanges. Reserved/public addresses are not failure fixtures.
func TestExchangeParallel(t *testing.T) {
	release := make(chan struct{})
	arrived := make(chan struct{}, 2)
	finished := make(chan struct{}, 2)
	slowHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		arrived <- struct{}{}
		<-release
		require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(r)))
		finished <- struct{}{}
	})
	slow1 := startDNSServer(t, slowHandler)
	slow2 := startDNSServer(t, slowHandler)
	fast := startDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		require.NoError(testutil.PanicT{}, w.WriteMsg(respondToTestMessage(r)))
	})
	t.Cleanup(func() {
		close(release)
		for range 2 {
			select {
			case <-finished:
			case <-time.After(testTimeout):
				t.Error("slow exchange did not finish during fixture cleanup")
			}
		}
		require.NoError(t, slow1.Close())
		require.NoError(t, slow2.Close())
		require.NoError(t, fast.Close())
	})
	upstreams := []Upstream{}
	for _, server := range []*testDNSServer{slow1, slow2, fast} {
		u, err := AddressToUpstream(fmt.Sprintf("127.0.0.1:%d", server.port), &Options{Logger: testLogger, Timeout: testTimeout})
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, u.Close()) })
		upstreams = append(upstreams, u)
	}
	type result struct {
		response *dns.Msg
		winner   Upstream
		err      error
	}
	resultCh := make(chan result, 1)
	req := createTestMessage()
	go func() {
		response, winner, err := ExchangeParallel(upstreams, req)
		resultCh <- result{response, winner, err}
	}()
	select {
	case got := <-resultCh:
		require.NoError(t, got.err)
		require.Same(t, upstreams[2], got.winner)
		requireResponse(t, req, got.response)
	case <-time.After(time.Second):
		t.Fatal("parallel resolution waited for still-blocked losers")
	}
	for range 2 {
		select {
		case <-arrived:
		case <-time.After(time.Second):
			t.Fatal("parallel resolution did not start all upstreams")
		}
	}
}

func TestExchangeParallelEmpty(t *testing.T) {
	ups := []Upstream{
		&testUpstream{empty: true},
		&testUpstream{empty: true},
	}

	req := createTestMessage()
	resp, up, err := ExchangeParallel(ups, req)
	require.Error(t, err)

	assert.Nil(t, resp)
	assert.Nil(t, up)
}

// testUpstream represents a mock upstream structure.
type testUpstream struct {
	// addr is a mock A record IP address to be returned.
	addr netip.Addr

	// err is a mock error to be returned.
	err bool

	// empty indicates if a nil response is returned.
	empty bool

	// sleep is a delay before response.
	sleep time.Duration
}

// type check
var _ Upstream = (*testUpstream)(nil)

// Exchange implements the [Upstream] interface for *testUpstream.
func (u *testUpstream) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	if u.sleep != 0 {
		time.Sleep(u.sleep)
	}

	if u.empty {
		return nil, nil
	}

	if u.err {
		return nil, fmt.Errorf("upstream error")
	}

	resp = &dns.Msg{}
	resp.SetReply(req)

	if u.addr != (netip.Addr{}) {
		a := dns.A{
			A: u.addr.AsSlice(),
		}

		resp.Answer = append(resp.Answer, &a)
	}

	return resp, nil
}

// Address implements the [Upstream] interface for *testUpstream.
func (u *testUpstream) Address() (addr string) {
	return ""
}

// Close implements the [Upstream] interface for *testUpstream.
func (u *testUpstream) Close() (err error) {
	return nil
}

func TestExchangeAll(t *testing.T) {
	delayedAnsAddr := netip.MustParseAddr("1.1.1.1")
	ansAddr := netip.MustParseAddr("3.3.3.3")

	ups := []Upstream{&testUpstream{
		addr:  delayedAnsAddr,
		sleep: 100 * time.Millisecond,
	}, &testUpstream{
		err: true,
	}, &testUpstream{
		addr: ansAddr,
	}}

	req := createHostTestMessage("test.org")
	res, err := ExchangeAll(ups, req)
	require.NoError(t, err)
	require.Len(t, res, 2)

	resp := res[0].Resp
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Answer)

	ip := testutil.RequireTypeAssert[*dns.A](t, resp.Answer[0]).A
	assert.Equal(t, ansAddr.AsSlice(), []byte(ip))

	resp = res[1].Resp
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Answer)

	ip = testutil.RequireTypeAssert[*dns.A](t, resp.Answer[0]).A
	assert.Equal(t, delayedAnsAddr.AsSlice(), []byte(ip))
}
