package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/optslog"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/holandyoung/quic-go"
	"github.com/miekg/dns"
)

// startListeners configures listeners and starts listening each configured
// address.  If it returns an error, all listeners should be closed manually.
func (p *Proxy) startListeners(ctx context.Context) (err error) {
	err = p.initUDPListeners(ctx)
	if err != nil {
		return err
	}

	err = p.initTCPListeners(ctx)
	if err != nil {
		return err
	}

	err = p.initTLSListeners(ctx)
	if err != nil {
		return err
	}

	err = p.initHTTPSListeners(ctx)
	if err != nil {
		return err
	}

	err = p.initQUICListeners(ctx)
	if err != nil {
		return err
	}

	return nil
}

// serveListeners starts serving the configured listeners.
func (p *Proxy) serveListeners(ctx context.Context) {
	for _, l := range p.udpListen {
		go p.udpPacketLoop(ctx, l, p.requestsSema)
	}

	for _, l := range p.tcpListen {
		go p.tcpPacketLoop(ctx, l, ProtoTCP, p.requestsSema)
	}

	for _, l := range p.tlsListen {
		go p.tcpPacketLoop(ctx, l, ProtoTLS, p.requestsSema)
	}

	for _, l := range p.httpsListen {
		srv := p.httpsServer
		go func(l net.Listener) {
			p.reportListenerFailure(ctx, "https", l.Addr(), srv.Serve(l))
		}(l)
	}

	for _, l := range p.h3Listen {
		srv := p.h3Server
		go func(l *quic.EarlyListener) {
			p.reportListenerFailure(ctx, "h3", l.Addr(), srv.ServeListener(l))
		}(l)
	}

	for _, l := range p.quicListen {
		go p.quicPacketLoop(ctx, l, p.requestsSema)
	}
}

// reportListenerFailure does not acquire the lifecycle mutex or write logs.
// Only cancellation by this listener generation makes termination intentional;
// net.ErrClosed from an independently lost socket must still reach its owner.
func (p *Proxy) reportListenerFailure(ctx context.Context, protocol string, addr net.Addr, err error) {
	if ctx.Err() != nil {
		return
	}
	if err == nil {
		err = errors.Error("listener stopped unexpectedly")
	}
	select {
	case p.listenerFailures <- fmt.Errorf("%s listener %s: %w", protocol, addr, err):
	default:
	}
}

// handleDNSRequest runs the complete pipeline and normalizes intentional drops
// for the protocol loops. Middleware observes drops before this normalization.
func (p *Proxy) handleDNSRequest(ctx context.Context, d *DNSContext) (err error) {
	err = p.requestPipeline.ServeDNS(ctx, p, d)
	if errors.Is(err, ErrDrop) {
		return nil
	}
	return err
}

func (p *Proxy) processDNSRequest(ctx context.Context, d *DNSContext) (err error) {
	p.logDNSMessage(ctx, d.Req)

	if d.Req.Response {
		p.logger.DebugContext(ctx, "dropping incoming response packet", "addr", d.Addr)

		return ErrDrop
	}

	ip := d.Addr.Addr()
	d.IsPrivateClient = p.privateNets.Contains(ip)

	// TODO(d.kolyshev):  Consider moving validation to a new middleware.
	if d.Res == nil {
		d.Res = p.validateRequest(d)
	}
	if d.Res == nil {
		err = p.requestHandler.ServeDNS(ctx, p, d)
		if errors.Is(err, ErrDrop) {
			// Don't reply to dropped clients.
			return ErrDrop
		}
	}
	if p.responseHandler != nil {
		prepareErr := p.responseHandler.ServeDNS(ctx, p, d)
		if errors.Is(prepareErr, ErrDrop) {
			return ErrDrop
		}
		err = errors.Join(err, prepareErr)
	}

	p.logDNSMessage(ctx, d.Res)
	err = errors.Join(err, p.respond(ctx, d))

	return err
}

// isForbiddenARPA returns true if dctx contains a PTR, SOA, or NS request for
// some private address and client's address is not within the private network.
// Otherwise, it sets [DNSContext.RequestedPrivateRDNS] for future use.
func (dctx *DNSContext) isForbiddenARPA(privateNets netutil.SubnetSet, l *slog.Logger) (ok bool) {
	q := dctx.Req.Question[0]
	switch q.Qtype {
	case dns.TypePTR, dns.TypeSOA, dns.TypeNS:
		// Go on.
		//
		// TODO(e.burkov):  Reconsider the list of types involved to private
		// address space.  Perhaps, use the logic for any type.  See
		// https://www.rfc-editor.org/rfc/rfc6761.html#section-6.1.
	default:
		return false
	}

	requestedPref, err := netutil.ExtractReversedAddr(q.Name)
	if err != nil {
		l.Debug("parsing reversed subnet", slogutil.KeyError, err)

		return false
	}

	if privateNets.Contains(requestedPref.Addr()) {
		dctx.RequestedPrivateRDNS = requestedPref

		return !dctx.IsPrivateClient
	}

	return false
}

// respond writes the specified response to the client (or does nothing if d.Res is empty)
func (p *Proxy) respond(ctx context.Context, d *DNSContext) error {
	// d.Conn can be nil in the case of a DoH request.
	if d.Conn != nil {
		_ = d.Conn.SetWriteDeadline(p.time.Now().Add(defaultTimeout))
	}

	var err error

	switch d.Proto {
	case ProtoUDP:
		err = p.respondUDP(d.Res, d.Conn.(*net.UDPConn), net.UDPAddrFromAddrPort(d.Addr), d.localIP)
	case ProtoTCP:
		err = p.respondTCP(d)
	case ProtoTLS:
		err = p.respondTCP(d)
	case ProtoHTTPS:
		err = p.respondHTTPS(d)
	case ProtoQUIC:
		err = p.respondQUIC(d)
	case ProtoDNSCrypt:
		err = p.respondDNSCrypt(ctx, d)
	default:
		err = fmt.Errorf("SHOULD NOT HAPPEN - unknown protocol: %s", d.Proto)
	}

	if err != nil {
		logWithNonCrit(ctx, err, "responding request", d.Proto, p.logger)
	}
	return err
}

// setMinMaxTTL sets the TTL values of all records according to the proxy
// settings.  r must not be nil.
func (p *Proxy) setMinMaxTTL(ctx context.Context, r *dns.Msg) {
	rrSets := container.KeyValues[string, []dns.RR]{{
		Key:   "answer",
		Value: r.Answer,
	}, {
		Key:   "extra",
		Value: r.Extra,
	}, {
		Key:   "ns",
		Value: r.Ns,
	}}

	for _, rrSet := range rrSets {
		for _, rr := range rrSet.Value {
			original := rr.Header().Ttl
			overridden := respectTTLOverrides(original, p.cacheMinTTL, p.cacheMaxTTL)

			if original == overridden {
				continue
			}

			optslog.Trace3(
				ctx,
				p.logger,
				"ttl overwritten",
				"section", rrSet.Key,
				"old", original,
				"new", overridden,
			)
			rr.Header().Ttl = overridden
		}
	}
}

// DNSMessage is a borrowed DNS diagnostic value. LogValue uses the native text
// representation to preserve all RR types, including parameter types encoded as
// empty Go structs. Plain encoding/json of dns.Msg loses those identities.
// Asynchronous handlers must copy Msg before returning from Handle and must not
// resolve this value until they process the owned snapshot.
type DNSMessage struct {
	Msg *dns.Msg
}

func (v DNSMessage) LogValue() slog.Value {
	if v.Msg == nil {
		return slog.AnyValue(nil)
	}
	return slog.StringValue(v.Msg.String())
}

// logDNSMessage passes the borrowed message to the logger without formatting.
// Handlers retaining the record after Handle returns must snapshot mutable
// attributes before returning, as required for any asynchronous slog handler.
func (p *Proxy) logDNSMessage(ctx context.Context, m *dns.Msg) {
	if m == nil || !p.logger.Enabled(ctx, slog.LevelDebug) {
		return
	}

	var msg string
	if m.Response {
		msg = "out"
	} else {
		msg = "in"
	}

	p.logger.DebugContext(ctx, "dns message", "direction", msg, "dns", DNSMessage{Msg: m})
}

// logWithNonCrit logs the error on the appropriate level depending on whether
// err is a critical error or not.
func logWithNonCrit(ctx context.Context, err error, msg string, proto Proto, l *slog.Logger) {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || isEPIPE(err) {
		l.DebugContext(
			ctx,
			"connection is closed",
			"proto", proto,
			"details", msg,
			slogutil.KeyError, err,
		)
	} else if netErr := net.Error(nil); errors.As(err, &netErr) && netErr.Timeout() {
		l.DebugContext(
			ctx,
			"connection timed out",
			"proto", proto,
			"details", msg,
			slogutil.KeyError, err,
		)
	} else {
		l.ErrorContext(ctx, msg, "proto", proto, slogutil.KeyError, err)
	}
}
