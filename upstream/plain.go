package upstream

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/holandyoung/dnsproxy/internal/bootstrap"
	"github.com/miekg/dns"
)

// network is the semantic type alias of the network to pass to dialing
// functions.  It's either [networkUDP] or [networkTCP].  It may also be used as
// URL scheme for plain upstreams.
type network = string

const (
	// networkUDP is the UDP network.
	networkUDP network = "udp"

	// networkTCP is the TCP network.
	networkTCP network = "tcp"
)

// plainDNS implements the [Upstream] interface for the regular DNS protocol.
type plainDNS struct {
	// addr is the DNS server URL.  Scheme is always "udp" or "tcp".
	addr *url.URL

	// logger is used for exchange logging.  It is never nil.
	logger *slog.Logger

	// getDialer either returns an initialized dial handler or creates a new
	// one.
	getDialer DialerInitializer

	// net is the network of the connections.
	net network

	// timeout is the timeout for DNS requests.
	timeout time.Duration
}

// newPlain returns the plain DNS Upstream.  addr.Scheme should be either "udp"
// or "tcp".
func newPlain(addr *url.URL, opts *Options) (u *plainDNS, err error) {
	switch addr.Scheme {
	case networkUDP, networkTCP:
		// Go on.
	default:
		return nil, fmt.Errorf("unsupported url scheme: %s", addr.Scheme)
	}

	addPort(addr, defaultPortPlain)

	return &plainDNS{
		addr:      addr,
		logger:    opts.Logger,
		getDialer: newDialerInitializer(addr, opts),
		net:       addr.Scheme,
		timeout:   opts.Timeout,
	}, nil
}

// type check
var _ Upstream = &plainDNS{}

// Address implements the [Upstream] interface for *plainDNS.
func (p *plainDNS) Address() string {
	switch p.net {
	case networkUDP:
		return p.addr.Host
	case networkTCP:
		return p.addr.String()
	default:
		panic(fmt.Sprintf("unexpected network: %s", p.net))
	}
}

// dialExchange performs a DNS exchange with the specified dial handler.
// network must be either [networkUDP] or [networkTCP].
func (p *plainDNS) dialExchange(
	network network,
	dial bootstrap.DialHandler,
	req *dns.Msg,
	state *ExchangeState,
) (resp *dns.Msg, err error) {
	addr := p.Address()

	conn := &dns.Conn{}
	upstreamReq := setRequestForNetwork(req, conn, network)
	defer func() {
		if resp != nil {
			resp.Id = req.Id
		}
	}()

	logBegin(p.logger, addr, network, upstreamReq)
	defer func() { logFinish(p.logger, addr, network, err) }()

	ctx := context.Background()
	conn.Conn, err = dial(ctx, network, "")
	if err != nil {
		return nil, fmt.Errorf("dialing %s over %s: %w", p.addr.Host, network, err)
	}
	if network == networkUDP {
		conn.Conn = connectedDatagram{conn.Conn}
	}
	defer func(c net.Conn) { err = errors.WithDeferred(err, c.Close()) }(conn.Conn)

	resp, err = p.exchangeWithConn(upstreamReq, conn, network, state)
	if isExpectedConnErr(err) {
		conn.Conn, err = dial(ctx, network, "")
		if err != nil {
			return nil, fmt.Errorf("dialing %s over %s again: %w", p.addr.Host, network, err)
		}
		if network == networkUDP {
			conn.Conn = connectedDatagram{conn.Conn}
		}
		defer func(c net.Conn) { err = errors.WithDeferred(err, c.Close()) }(conn.Conn)

		resp, err = p.exchangeWithConn(upstreamReq, conn, network, state)
	}

	if err != nil {
		return resp, fmt.Errorf("exchanging with %s over %s: %w", addr, network, err)
	}

	return resp, nil
}

// exchangeWithConn retains native miekg/dns framing, EDNS receive size and the
// default plain-DNS I/O timeout, with receipt observation before decoding.
func (p *plainDNS) exchangeWithConn(req *dns.Msg, conn *dns.Conn, network string, state *ExchangeState) (*dns.Msg, error) {
	if opt := req.IsEdns0(); opt != nil && opt.UDPSize() >= dns.MinMsgSize {
		conn.UDPSize = opt.UDPSize()
	}
	timeout := p.timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if err := conn.WriteMsg(req); err != nil {
		return nil, err
	}
	return readDNSResponse(conn, req, state, network == networkUDP)
}

// connectedDatagram preserves the explicit UDP network at the miekg/dns
// boundary. That library selects DNS framing using net.PacketConn, while a
// routed connection may expose only net.Conn. Reads and writes still use the
// original connected socket and its route owner.
type connectedDatagram struct{ net.Conn }

var _ net.PacketConn = connectedDatagram{}

func (c connectedDatagram) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.RemoteAddr(), err
}

func (c connectedDatagram) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr == nil || addr.Network() != c.RemoteAddr().Network() || addr.String() != c.RemoteAddr().String() {
		return 0, errors.Error("connected UDP destination differs from configured route")
	}
	return c.Write(b)
}

// setRequestForNetwork sets connection options in conn and overrides the
// upstream request, if necessary, depending on network.  If network is
// [networkUDP] and orig has a zero ID, req is a copy of orig with a new ID to
// increase entropy.  network must be either [networkUDP] or [networkTCP].  orig
// and conn must not be nil.
func setRequestForNetwork(orig *dns.Msg, conn *dns.Conn, network network) (req *dns.Msg) {
	req = orig
	if network != networkUDP {
		return req
	}

	conn.UDPSize = dns.MinMsgSize

	if orig.Id == 0 {
		req = orig.Copy()
		req.Id = dns.Id()
	}

	return req
}

// isExpectedConnErr returns true if the error is expected.  In this case,
// we will make a second attempt to process the request.
func isExpectedConnErr(err error) (is bool) {
	var netErr net.Error

	return err != nil && !isExchangeTimeout(err) && (errors.As(err, &netErr) || errors.Is(err, io.EOF))
}

// Exchange implements the [Upstream] interface for *plainDNS.
func (p *plainDNS) Exchange(req *dns.Msg, state *ExchangeState) (resp *dns.Msg, err error) {
	if err = state.start(req.Id); err != nil {
		return nil, err
	}
	defer func() { state.finish(err) }()
	dial, err := p.getDialer()
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return nil, err
	}

	addr := p.Address()

	resp, err = p.dialExchange(p.net, dial, req, state)
	if p.net != networkUDP {
		// The network is already TCP.
		return resp, err
	}

	if resp == nil {
		// There is likely an error with the upstream.
		return resp, err
	}

	if errors.Is(err, errQuestion) {
		// The upstream responds with malformed messages, so try TCP.
		p.logger.Debug(
			"plain response is malformed, using tcp",
			"addr", addr,
			slogutil.KeyError, err,
		)

		return p.dialExchange(networkTCP, dial, req, state)
	} else if resp.Truncated {
		// Fallback to TCP on truncated responses.
		p.logger.Debug(
			"plain response is truncated, using tcp",
			"question", &req.Question[0],
			"addr", addr,
		)

		return p.dialExchange(networkTCP, dial, req, state)
	}

	// There is either no error or the error isn't related to the received
	// message.
	return resp, err
}

// Close implements the [Upstream] interface for *plainDNS.
func (p *plainDNS) Close() (err error) {
	return nil
}
