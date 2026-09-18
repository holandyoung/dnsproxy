package proxy

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/holandyoung/dnsproxy/diagnostic"
	"github.com/holandyoung/dnsproxy/proxyutil"
	"github.com/holandyoung/dnsproxy/upstream"
	"github.com/miekg/dns"
)

// lookupResult is the complete result of one address-family lookup, including
// a recovered panic. Its caller owns exactly one channel send for every call.
type lookupResult struct {
	resp *dns.Msg
	err  error
}

// lookupIPAddr resolves one address family. Recovery completes the named result
// before the caller publishes it, so logging cannot erase a completion signal.
func (p *Proxy) lookupIPAddr(
	ctx context.Context,
	host string,
	qtype uint16,
) (result lookupResult) {
	defer func() {
		if value := recover(); value != nil {
			result = lookupResult{err: errors.FromRecovered(value)}
			if p.logger.Enabled(ctx, slog.LevelError) {
				p.logger.LogAttrs(ctx, slog.LevelError, "recovered from panic", slog.Any("panic", diagnostic.RecoveredPanic{Value: value}))
			}
		}
	}()

	req := (&dns.Msg{}).SetQuestion(host, qtype)

	// TODO(d.kolyshev): Investigate why the client address is not defined.
	d := p.newDNSContext(ProtoUDP, req, netip.AddrPort{})
	err := p.Resolve(ctx, d)
	return lookupResult{
		resp: d.Res,
		err:  err,
	}
}

// ErrEmptyHost is returned by LookupIPAddr when the host is empty and can't be
// resolved.
const ErrEmptyHost = errors.Error("host is empty")

// type check
var _ upstream.Resolver = (*Proxy)(nil)

// LookupNetIP implements the [upstream.Resolver] interface for *Proxy.  It
// resolves the specified host IP addresses by sending two DNS queries (A and
// AAAA) in parallel.  It returns both results for those two queries.
func (p *Proxy) LookupNetIP(
	ctx context.Context,
	_ string,
	host string,
) (addrs []netip.Addr, err error) {
	if host == "" {
		return nil, ErrEmptyHost
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}

	host = dns.Fqdn(host)

	// Each worker can publish even if cancellation has released the caller.
	// Native I/O remains owned by its existing upstream timeout and shutdown.
	ch := make(chan lookupResult, 2)
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		go func() { ch <- p.lookupIPAddr(ctx, host, qtype) }()
	}

	var errs []error
	for range 2 {
		var result lookupResult
		select {
		case result = <-ch:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if result.err != nil {
			errs = append(errs, result.err)

			continue
		}

		addrs = appendAnswerAddrs(addrs, result.resp.Answer)
	}

	if len(addrs) == 0 && len(errs) != 0 {
		return addrs, errors.Join(errs...)
	}

	if p.preferIPv6 {
		slices.SortStableFunc(addrs, netutil.PreferIPv6)
	} else {
		slices.SortStableFunc(addrs, netutil.PreferIPv4)
	}

	return addrs, nil
}

// appendAnswerAddrs returns addrs with addresses appended from the given ans.
func appendAnswerAddrs(addrs []netip.Addr, ans []dns.RR) (res []netip.Addr) {
	for _, ansRR := range ans {
		a := proxyutil.IPFromRR(ansRR)
		if a != (netip.Addr{}) {
			addrs = append(addrs, a)
		}
	}

	return addrs
}
