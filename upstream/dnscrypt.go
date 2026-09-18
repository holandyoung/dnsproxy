package upstream

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/holandyoung/dnsproxy/dnscrypt"
	"github.com/miekg/dns"
)

// dnsCrypt retains one verified certificate and owns every protocol phase under
// the same exchange context. Routed certificate, UDP and TCP sockets all use the
// supplied connection owner; no direct or system-DNS fallback is introduced.
type dnsCrypt struct {
	ctx               context.Context
	resolverInfo      *dnscrypt.ResolverInfo
	refresh           chan struct{}
	client, tcpClient *dnscrypt.Client
	addr              *url.URL
	logger            *slog.Logger
	verifyCert        func(*dnscrypt.Certificate) error
	cancel            context.CancelFunc
	timeout           time.Duration
	mu                sync.RWMutex
}

func newDNSCrypt(addr *url.URL, opts *Options) *dnsCrypt {
	ctx, cancel := context.WithCancel(context.Background())
	udp := &dnscrypt.ClientConfig{Logger: opts.Logger, Proto: dnscrypt.ProtoUDP}
	if opts.NetworkDialer != nil {
		udp.DialContext = opts.NetworkDialer.DialContext
	}
	tcp := *udp
	tcp.Proto = dnscrypt.ProtoTCP
	return &dnsCrypt{
		addr: addr, logger: opts.Logger, verifyCert: opts.VerifyDNSCryptCertificate,
		timeout: opts.Timeout, ctx: ctx, cancel: cancel, refresh: make(chan struct{}, 1),
		client: dnscrypt.NewClient(udp), tcpClient: dnscrypt.NewClient(&tcp),
	}
}

var _ Upstream = (*dnsCrypt)(nil)

func (p *dnsCrypt) Address() string { return p.addr.String() }

func (p *dnsCrypt) Exchange(req *dns.Msg, state *ExchangeState) (resp *dns.Msg, err error) {
	if err = state.start(req.Id); err != nil {
		return nil, err
	}
	defer func() { state.finish(err) }()
	ctx := p.ctx
	if p.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}
	info, err := p.certificate(ctx)
	if err != nil {
		return nil, err
	}
	observer := &dnsCryptReceipt{state: state, request: req, udp: true}
	resp, err = p.client.ExchangeContext(ctx, req, info, observer)
	if err == nil && resp != nil && resp.Truncated {
		p.logger.Debug("dnscrypt received truncated, falling back to tcp", "addr", p.addr, "question", &req.Question[0])
		observer.udp = false
		resp, err = p.tcpClient.ExchangeContext(ctx, req, info, observer)
	}
	return resp, err
}

func (p *dnsCrypt) Close() error {
	p.cancel()
	return nil
}

func (p *dnsCrypt) currentCertificate() *dnscrypt.ResolverInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()
	info := p.resolverInfo
	if info != nil && info.ResolverCert.VerifyDate() {
		return info
	}
	return nil
}

func (p *dnsCrypt) certificate(ctx context.Context) (*dnscrypt.ResolverInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if info := p.currentCertificate(); info != nil {
		return info, nil
	}
	// Only the current refresher performs certificate I/O. Waiting callers keep
	// their own deadlines; a failed refresh does not poison later requests.
	select {
	case p.refresh <- struct{}{}:
		defer func() { <-p.refresh }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if info := p.currentCertificate(); info != nil {
		return info, nil
	}
	info, err := p.client.DialContext(ctx, p.Address())
	if err != nil {
		return nil, fmt.Errorf("fetching certificate info from %s: %w", p.Address(), err)
	}
	if p.verifyCert != nil {
		if err = p.verifyCert(info.ResolverCert); err != nil {
			return nil, fmt.Errorf("verifying certificate info from %s: %w", p.Address(), err)
		}
	}
	p.mu.Lock()
	p.resolverInfo = info
	p.mu.Unlock()
	return info, nil
}

// One adapter carries the existing receipt owner through the codec's read and
// decode boundary. It stores only a candidate ticket, never a second decision.
type dnsCryptReceipt struct {
	state   *ExchangeState
	request *dns.Msg
	ticket  uint64
	udp     bool
}

func (r *dnsCryptReceipt) Received() { r.ticket = r.state.reserveCandidate() }

func (r *dnsCryptReceipt) Decoded(response *dns.Msg, err error) error {
	if err == nil {
		switch {
		case response == nil || !response.Response:
			err = errDNSProtocol
		case response.Id != r.request.Id:
			err = dns.ErrId
		default:
			err = validateResponse(r.request, response)
		}
	}
	if err != nil || r.udp && response.Truncated {
		r.state.reject(r.ticket)
	} else {
		r.state.accept(r.ticket, response)
	}
	r.ticket = 0
	return err
}
