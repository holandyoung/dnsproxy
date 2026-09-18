package bootstrap_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/holandyoung/dnsproxy/internal/bootstrap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParallelRecoveryKeepsErrorResultWhenDiagnosticsAreDisabled(t *testing.T) {
	for _, level := range []slog.Level{slog.LevelError, slog.LevelError + 1} {
		t.Run(level.String(), func(t *testing.T) {
			var output bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: level}))
			ctx := slogutil.ContextWithLogger(t.Context(), logger)
			want := errors.New("complete bootstrap panic")
			resolver := &testResolver{onLookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
				panic(want)
			}}
			addrs, err := (bootstrap.ParallelResolver{resolver, resolver}).LookupNetIP(ctx, "ip", "panic.example")
			if len(addrs) != 0 || !errors.Is(err, want) {
				t.Fatalf("recovery did not publish the native error result: %v %v", addrs, err)
			}
			if level > slog.LevelError {
				if output.Len() != 0 {
					t.Fatalf("disabled panic created output: %s", output.Bytes())
				}
				return
			}
			decoder := json.NewDecoder(&output)
			for range 2 {
				var record struct{ Panic struct{ Err, Stack string } }
				if decodeErr := decoder.Decode(&record); decodeErr != nil {
					t.Fatal(decodeErr)
				}
				if record.Panic.Err != want.Error() || !strings.Contains(record.Panic.Stack, "bootstrap.lookupAsync") {
					t.Fatalf("bootstrap panic record lost original value/stack: %+v", record)
				}
			}
			var extra any
			if decodeErr := decoder.Decode(&extra); !errors.Is(decodeErr, io.EOF) {
				t.Fatalf("panic produced extra records: %v %v", extra, decodeErr)
			}
		})
	}
}

// testResolver is the [Resolver] interface implementation for testing purposes.
//
// TODO(e.burkov):  Move to [dnsproxytest].
type testResolver struct {
	onLookupNetIP func(ctx context.Context, network, host string) (addrs []netip.Addr, err error)
}

// LookupNetIP implements the [Resolver] interface for *testResolver.
func (r *testResolver) LookupNetIP(
	ctx context.Context,
	network string,
	host string,
) (addrs []netip.Addr, err error) {
	return r.onLookupNetIP(ctx, network, host)
}

func TestLookupParallel(t *testing.T) {
	const hostname = "host.name"

	t.Run("no_resolvers", func(t *testing.T) {
		addrs, err := bootstrap.ParallelResolver(nil).LookupNetIP(context.Background(), "ip", "")
		assert.ErrorIs(t, err, bootstrap.ErrNoResolvers)
		assert.Nil(t, addrs)
	})

	pt := testutil.PanicT{}
	hostAddrs := []netip.Addr{netutil.IPv4Localhost()}

	immediate := &testResolver{
		onLookupNetIP: func(_ context.Context, network, host string) ([]netip.Addr, error) {
			require.Equal(pt, hostname, host)
			require.Equal(pt, "ip", network)

			return hostAddrs, nil
		},
	}

	t.Run("one_resolver", func(t *testing.T) {
		addrs, err := bootstrap.ParallelResolver{immediate}.LookupNetIP(
			context.Background(),
			"ip",
			hostname,
		)
		require.NoError(t, err)

		assert.Equal(t, hostAddrs, addrs)
	})

	t.Run("two_resolvers", func(t *testing.T) {
		delayCh := make(chan struct{}, 1)
		delayed := &testResolver{
			onLookupNetIP: func(_ context.Context, network, host string) ([]netip.Addr, error) {
				require.Equal(pt, hostname, host)
				require.Equal(pt, "ip", network)

				testutil.RequireReceive(pt, delayCh, testTimeout)

				return []netip.Addr{netutil.IPv6Localhost()}, nil
			},
		}

		addrs, err := bootstrap.ParallelResolver{immediate, delayed}.LookupNetIP(
			context.Background(),
			"ip",
			hostname,
		)
		require.NoError(t, err)
		testutil.RequireSend(t, delayCh, struct{}{}, testTimeout)

		assert.Equal(t, hostAddrs, addrs)
	})

	t.Run("all_errors", func(t *testing.T) {
		err := assert.AnError
		errStr := err.Error()
		wantErrMsg := strings.Join([]string{errStr, errStr, errStr}, "\n")

		r := &testResolver{
			onLookupNetIP: func(_ context.Context, network, host string) ([]netip.Addr, error) {
				return nil, assert.AnError
			},
		}

		addrs, err := bootstrap.ParallelResolver{r, r, r}.LookupNetIP(
			context.Background(),
			"ip",
			hostname,
		)
		testutil.AssertErrorMsg(t, wantErrMsg, err)
		assert.Nil(t, addrs)
	})
}
