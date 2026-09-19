package upstream

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/holandyoung/dnsproxy/internal/bootstrap"
	"github.com/holandyoung/quic-go"
	"github.com/holandyoung/quic-go/http3"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// Values to configure HTTP and HTTP/2 transport.
const (
	// probeTimeout bounds an auxiliary protocol probe when query timeouts are
	// disabled. It never becomes a DoT or HTTP query deadline.
	probeTimeout = 10 * time.Second

	// transportDefaultReadIdleTimeout is the default timeout for pinging
	// idle connections in HTTP/2 transport.
	transportDefaultReadIdleTimeout = 30 * time.Second

	// transportDefaultIdleConnTimeout is the default timeout for idle
	// connections in HTTP transport.
	transportDefaultIdleConnTimeout = 5 * time.Minute

	// dohMaxConnsPerHost controls the maximum number of connections for
	// each host.  Note, that setting it to 1 may cause issues with Go's http
	// implementation, see https://github.com/AdguardTeam/dnsproxy/issues/278.
	dohMaxConnsPerHost = 2

	// dohMaxIdleConns controls the maximum number of connections being idle
	// at the same time.
	dohMaxIdleConns = 2
)

// dnsOverHTTPS is a struct that implements the Upstream interface for the
// DNS-over-HTTPS protocol.
type dnsOverHTTPS struct {
	// getDialer either returns an initialized dial handler or creates a new
	// one.
	getDialer     DialerInitializer
	networkDialer NetworkDialer

	// addr is the DNS-over-HTTPS server URL.
	addr     *url.URL
	httpHost string

	// tlsConf is the configuration of TLS.
	tlsConf *tls.Config

	// The Client's Transport typically has internal state (cached TCP
	// connections), so Clients should be reused instead of created as needed.
	// Clients are safe for concurrent use by multiple goroutines.
	client *http.Client

	// clientMu protects client publication and close admission. Native cleanup
	// never holds this lock; closeDone publishes the terminal closeErr.
	clientMu  *sync.Mutex
	closeDone chan struct{}
	closeErr  error

	// logger is used for exchange logging.  It is never nil.
	logger *slog.Logger

	// quicConf is the QUIC configuration that is used if HTTP/3 is enabled
	// for this upstream.
	quicConf *quic.Config

	// quicConfMu protects quicConf.
	quicConfMu *sync.Mutex

	// addrRedacted is the redacted string representation of addr.  It is saved
	// separately to reduce allocations during logging and error reporting.
	addrRedacted string

	// timeout is used in HTTP client and for H3 probes.
	timeout time.Duration
	closed  bool
}

// newDoH returns the DNS-over-HTTPS Upstream.
func newDoH(addr *url.URL, opts *Options) (u Upstream, err error) {
	addPort(addr, defaultPortDoH)

	var httpVersions []HTTPVersion
	if addr.Scheme == "h3" {
		addr.Scheme = "https"
		httpVersions = []HTTPVersion{HTTPVersion3}
	} else if httpVersions = opts.HTTPVersions; len(opts.HTTPVersions) == 0 {
		httpVersions = DefaultHTTPVersions
	}

	quicConf := &quic.Config{
		KeepAlivePeriod: QUICKeepAlivePeriod,
		TokenStore:      newQUICTokenStore(),
	}

	if opts.QUICTracer != nil {
		quicConf.Tracer = opts.QUICTracer.TraceForConnection
	}

	ups := &dnsOverHTTPS{
		networkDialer: opts.NetworkDialer,
		getDialer:     newDialerInitializer(addr, opts),
		addr:          addr,
		httpHost:      opts.HTTPHost,
		quicConf:      quicConf,
		quicConfMu:    &sync.Mutex{},
		tlsConf: &tls.Config{
			ServerName:   cmp.Or(opts.ServerName, addr.Hostname()),
			RootCAs:      opts.RootCAs,
			CipherSuites: opts.CipherSuites,
			// Use the default capacity for the LRU cache.  It may be useful to
			// store several caches since the user may be routed to different
			// servers in case there's load balancing on the server-side.
			ClientSessionCache: tls.NewLRUClientSessionCache(0),
			MinVersion:         tls.VersionTLS12,
			// #nosec G402 -- TLS certificate verification could be disabled by
			// configuration.
			InsecureSkipVerify:    opts.InsecureSkipVerify,
			VerifyPeerCertificate: opts.VerifyServerCertificate,
			VerifyConnection:      opts.VerifyConnection,
		},
		clientMu:     &sync.Mutex{},
		logger:       opts.Logger,
		addrRedacted: addr.Redacted(),
		timeout:      opts.Timeout,
	}
	for _, v := range httpVersions {
		ups.tlsConf.NextProtos = append(ups.tlsConf.NextProtos, string(v))
	}

	runtime.SetFinalizer(ups, (*dnsOverHTTPS).Close)

	return ups, nil
}

// type check
var _ Upstream = (*dnsOverHTTPS)(nil)

// Address implements the [Upstream] interface for *dnsOverHTTPS.  The address
// is redacted: if the original URL of this upstream contains a userinfo with a
// password, the password is replaced with "xxxxx".
func (p *dnsOverHTTPS) Address() string { return p.addrRedacted }

// Exchange implements the [Upstream] interface for *dnsOverHTTPS.
func (p *dnsOverHTTPS) Exchange(req *dns.Msg, state *ExchangeState) (resp *dns.Msg, err error) {
	if err = state.start(req.Id); err != nil {
		return nil, err
	}
	work := new(httpWork)
	defer func() { state.finish(err); work.join() }()
	// Check if there was already an active client before sending the request.
	// We'll only attempt to re-connect if there was one.
	client, isCached, err := p.getClient(work)
	if err != nil {
		return nil, fmt.Errorf("failed to init http client: %w", err)
	}

	// Make the first attempt to send the DNS query.
	resp, err = p.exchangeHTTPS(client, req, state, work)

	// Make up to 2 attempts to re-create the HTTP client and send the request
	// again.  There are several cases (mostly, with QUIC) where this workaround
	// is necessary to make HTTP client usable.  We need to make 2 attempts in
	// the case when the connection was closed (due to inactivity for example)
	// AND the server refuses to open a 0-RTT connection.
	for i := 0; isCached && p.shouldRetry(err) && i < 2; i++ {
		client, err = p.resetClient(client, err, work)
		if err != nil {
			return nil, fmt.Errorf("failed to reset http client: %w", err)
		}

		resp, err = p.exchangeHTTPS(client, req, state, work)
	}

	if err != nil {
		// No retry remains. Publish the logical failure before retiring a
		// transport that may still be joining TLS/QUIC setup or body work.
		state.finish(err)
		// If the request failed anyway, make sure we don't use this client.
		_, resErr := p.resetClient(client, err, work)

		return nil, errors.WithDeferred(err, resErr)
	}

	return resp, err
}

// Close implements the Upstream interface for *dnsOverHTTPS.
func (p *dnsOverHTTPS) Close() (err error) {
	p.clientMu.Lock()
	if p.closed {
		done := p.closeDone
		p.clientMu.Unlock()
		<-done
		return p.closeErr
	}
	p.closed = true
	p.closeDone = make(chan struct{})
	client := p.client
	p.client = nil
	runtime.SetFinalizer(p, nil)
	p.clientMu.Unlock()
	if client != nil {
		err = p.closeClient(client)
	}
	p.closeErr = err
	close(p.closeDone)
	return err
}

// closeClient cleans up resources used by client if necessary.  Note that this
// should be done for HTTP/3, as it can lead to resource leaks due to keep-alive
// connections, and for HTTP/2 due to idle connections.
func (p *dnsOverHTTPS) closeClient(client *http.Client) (err error) {
	if isHTTP3(client) {
		return client.Transport.(io.Closer).Close()
	}
	client.CloseIdleConnections()

	return nil
}

// exchangeHTTPS logs the request and its result and calls exchangeHTTPSClient.
// client and req must not be nil.
func (p *dnsOverHTTPS) exchangeHTTPS(client *http.Client, req *dns.Msg, state *ExchangeState, work *httpWork) (resp *dns.Msg, err error) {
	n := networkTCP
	if isHTTP3(client) {
		n = networkUDP
	}

	logBegin(p.logger, p.addrRedacted, n, req)
	defer func() { logFinish(p.logger, p.addrRedacted, n, err) }()

	buf, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing message: %w", err)
	}

	// In order to maximize HTTP cache friendliness, DoH clients using media
	// formats that include the ID field from the DNS message header, such as
	// "application/dns-message", SHOULD use a DNS ID of 0 in every DNS request.
	//
	// See https://www.rfc-editor.org/rfc/rfc8484.html.
	binary.BigEndian.PutUint16(buf, 0)

	resp, err = p.exchangeHTTPSClient(client, req, buf, state, work)
	if err != nil {
		return nil, fmt.Errorf("exchanging: %w", err)
	}

	return resp, nil
}

// exchangeHTTPSClient sends the DNS query to a DoH resolver using the specified
// http.Client instance.  buf is the packed DNS message that will be sent to the
// resolver.  client must not be nil.
func (p *dnsOverHTTPS) exchangeHTTPSClient(
	client *http.Client,
	req *dns.Msg,
	buf []byte,
	state *ExchangeState,
	work *httpWork,
) (resp *dns.Msg, err error) {
	// It appears, that GET requests are more memory-efficient with Golang
	// implementation of HTTP/2.
	method := http.MethodGet
	if isHTTP3(client) {
		// If we're using HTTP/3, use http3.MethodGet0RTT to force using 0-RTT.
		method = http3.MethodGet0RTT
	}

	q := url.Values{
		"dns": []string{base64.RawURLEncoding.EncodeToString(buf)},
	}

	u := url.URL{
		Scheme:   p.addr.Scheme,
		User:     p.addr.User,
		Host:     p.addr.Host,
		Path:     p.addr.Path,
		RawPath:  p.addr.RawPath,
		RawQuery: q.Encode(),
	}

	requestCtx := context.Background()
	var cancel context.CancelFunc
	if p.timeout > 0 {
		requestCtx, cancel = context.WithTimeout(requestCtx, p.timeout)
	} else {
		requestCtx, cancel = context.WithCancel(requestCtx)
	}
	defer cancel()
	requestCtx = context.WithValue(requestCtx, httpRequestScopeKey{}, httpRequestScope{requestCtx, work})
	httpReq, err := http.NewRequestWithContext(requestCtx, method, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating http request to %s: %w", p.addrRedacted, err)
	}
	if p.httpHost != "" {
		httpReq.Host = p.httpHost
	}

	// Prevent the client from sending User-Agent header, see
	// https://github.com/AdguardTeam/dnsproxy/issues/211.
	httpReq.Header.Set(httphdr.UserAgent, "")
	httpReq.Header.Set(httphdr.Accept, "application/dns-message")

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", p.addrRedacted, err)
	}
	defer slogutil.CloseAndLog(httpReq.Context(), p.logger, httpResp.Body, slog.LevelDebug)

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"expected status %d, got %d from %s",
			http.StatusOK,
			httpResp.StatusCode,
			p.addrRedacted,
		)
	}
	media, _, mediaErr := mime.ParseMediaType(httpResp.Header.Get(httphdr.ContentType))
	if mediaErr != nil || !strings.EqualFold(media, "application/dns-message") {
		return nil, fmt.Errorf("invalid DNS response content type from %s", p.addrRedacted)
	}
	if httpResp.ContentLength > dns.MaxMsgSize {
		return nil, fmt.Errorf("DNS response body too large from %s", p.addrRedacted)
	}
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, dns.MaxMsgSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", p.addrRedacted, err)
	}
	if len(body) == 0 || len(body) > dns.MaxMsgSize {
		return nil, fmt.Errorf("invalid DNS response body length from %s", p.addrRedacted)
	}
	if httpResp.ContentLength >= 0 && int64(len(body)) != httpResp.ContentLength {
		return nil, fmt.Errorf(
			"DNS response body length from %s: got %d, declared %d",
			p.addrRedacted,
			len(body),
			httpResp.ContentLength,
		)
	}
	ticket := state.reserve(body, 0, false)
	defer func() {
		if err != nil {
			state.reject(ticket)
		}
	}()

	resp = &dns.Msg{}
	err = resp.Unpack(body)
	if err != nil {
		return nil, fmt.Errorf(
			"unpacking response from %s: body is %s: %w",
			p.addrRedacted,
			body,
			err,
		)
	}
	if resp.Id != 0 {
		return nil, fmt.Errorf("unexpected non-zero id in response: %d", resp.Id)
	}
	resp.Id = req.Id
	if err = validateResponse(req, resp); err != nil {
		return nil, fmt.Errorf("validating response: %w", err)
	}
	state.accept(ticket, resp)

	return resp, nil
}

// shouldRetry checks what error we have received and returns true if we should
// re-create the HTTP client and retry the request.
func (p *dnsOverHTTPS) shouldRetry(err error) (ok bool) {
	if err == nil {
		return false
	}

	if isExchangeTimeout(err) {
		return false
	}

	var qAppErr *quic.ApplicationError
	if errors.As(err, &qAppErr) {
		// Error code 0 is often returned when the server has been restarted,
		// and we try to use the same connection on the client-side.
		// http3.ErrCodeNoError may be used by an HTTP/3 server when closing
		// an idle connection.  These connections are not immediately closed
		// by the HTTP client so this case should be handled.
		if qAppErr.ErrorCode == 0 ||
			qAppErr.ErrorCode == quic.ApplicationErrorCode(http3.ErrCodeNoError) {
			return true
		}
	}

	var resetErr *quic.StatelessResetError
	if errors.As(err, &resetErr) {
		// A stateless reset is sent when a server receives a QUIC packet that
		// it doesn't know how to decrypt.  For instance, it may happen when
		// the server was recently rebooted.  We should reconnect and try again
		// in this case.
		return true
	}

	var qTransportError *quic.TransportError
	if errors.As(err, &qTransportError) && qTransportError.ErrorCode == quic.NoError {
		// A transport error with the NO_ERROR error code could be sent by the
		// server when it considers that it's time to close the connection.
		// For example, Google DNS eventually closes an active connection with
		// the NO_ERROR code and "Connection max age expired" message:
		// https://github.com/AdguardTeam/dnsproxy/issues/283
		return true
	}

	if errors.Is(err, quic.Err0RTTRejected) {
		// This error happens when we try to establish a 0-RTT connection with
		// a token the server is no more aware of.  This can be reproduced by
		// restarting the QUIC server (it will clear its tokens cache).  The
		// next connection attempt will return this error until the client's
		// tokens cache is purged.
		return true
	}

	return false
}

// resetClient triggers re-creation of the *http.Client that is used by this
// upstream.  This method accepts the error that caused resetting client as
// depending on the error we may also reset the QUIC config.
func (p *dnsOverHTTPS) resetClient(failed *http.Client, resetErr error, work *httpWork) (client *http.Client, err error) {
	p.clientMu.Lock()
	if p.closed {
		p.clientMu.Unlock()
		return nil, net.ErrClosed
	}
	if p.client != nil && p.client != failed {
		// A different exchange has already replaced this failed generation.
		// A late failure must never close its successor's healthy connection.
		client = p.client
		p.clientMu.Unlock()
		return client, nil
	}

	if errors.Is(resetErr, quic.Err0RTTRejected) {
		// Reset the TokenStore only if 0-RTT was rejected.
		p.resetQUICConfig()
	}

	oldClient := p.client
	p.logger.Debug("recreating the http client", slogutil.KeyError, resetErr)
	p.client, err = p.createClient(work)
	client = p.client
	p.clientMu.Unlock()
	// Physical retirement cannot hold the shared client's publication lock.
	if oldClient != nil {
		closeErr := p.closeClient(oldClient)
		if closeErr != nil {
			p.logger.Warn("failed to close the old http client", slogutil.KeyError, closeErr)
		}
	}

	return client, err
}

// getQUICConfig returns the QUIC config in a thread-safe manner.  Note, that
// this method returns a pointer, it is forbidden to change its properties.
func (p *dnsOverHTTPS) getQUICConfig() (c *quic.Config) {
	p.quicConfMu.Lock()
	defer p.quicConfMu.Unlock()

	return p.quicConf
}

// resetQUICConfig Re-create the token store to make sure we're not trying to
// use invalid for 0-RTT.
func (p *dnsOverHTTPS) resetQUICConfig() {
	p.quicConfMu.Lock()
	defer p.quicConfMu.Unlock()

	p.quicConf = p.quicConf.Clone()
	p.quicConf.TokenStore = newQUICTokenStore()
}

// getClient gets or lazily initializes an HTTP client (and transport) that will
// be used for this DoH resolver.
func (p *dnsOverHTTPS) getClient(work *httpWork) (c *http.Client, isCached bool, err error) {
	startTime := time.Now()

	p.clientMu.Lock()
	defer p.clientMu.Unlock()
	if p.closed {
		return nil, false, net.ErrClosed
	}

	if p.client != nil {
		return p.client, true, nil
	}

	// Timeout can be exceeded while waiting for the lock. This happens quite
	// often on mobile devices.
	elapsed := time.Since(startTime)
	if p.timeout > 0 && elapsed > p.timeout {
		return nil, false, fmt.Errorf("timeout exceeded: %s", elapsed)
	}

	p.logger.Debug("creating a new http client")
	p.client, err = p.createClient(work)

	return p.client, false, err
}

// createClient creates a new *http.Client instance.  The HTTP protocol version
// will depend on whether HTTP3 is allowed and provided by this upstream.  Note,
// that we'll attempt to establish a QUIC connection when creating the client in
// order to check whether HTTP3 is supported.
func (p *dnsOverHTTPS) createClient(work *httpWork) (*http.Client, error) {
	transport, err := p.createTransport(work)
	if err != nil {
		return nil, fmt.Errorf("initializing http transport: %w", err)
	}

	client := &http.Client{
		Transport: transport,
		// A redirect is a non-200 DNS response, not permission to send the
		// query to another endpoint. Apply this to every HTTP transport.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		// The request context is the sole timeout owner, also carried through
		// native transports that detach their dial context. Zero stays off.
		Jar: nil,
	}

	p.client = client

	return p.client, nil
}

// createTransport initializes an HTTP transport that will be used specifically
// for this DoH resolver.  This HTTP transport ensures that the HTTP requests
// will be sent exactly to the IP address got from the bootstrap resolver. Note,
// that this function will first attempt to establish a QUIC connection (if
// HTTP3 is enabled in the upstream options).  If this attempt is successful,
// it returns an HTTP3 transport, otherwise it returns the H1/H2 transport.
func (p *dnsOverHTTPS) createTransport(work *httpWork) (t http.RoundTripper, err error) {
	dialContext, err := p.getDialer()
	if err != nil {
		return nil, fmt.Errorf("bootstrapping %s: %w", p.addrRedacted, err)
	}

	// First, we attempt to create an HTTP3 transport.  If the probe QUIC
	// connection is established successfully, we'll be using HTTP3 for this
	// upstream.
	tlsConf := p.tlsConf.Clone()
	transportH3, err := p.createTransportH3(tlsConf, dialContext, work)
	if err == nil {
		p.logger.Debug("using http/3 for this upstream, quic was faster")

		return transportH3, nil
	}

	p.logger.Debug("got error, switching to http/2 for this upstream", slogutil.KeyError, err)

	if !p.supportsHTTP() {
		return nil, errors.Error("HTTP1/1 and HTTP2 are not supported by this upstream")
	}

	allowH1 := slices.Contains(p.tlsConf.NextProtos, string(HTTPVersion11))
	allowH2 := slices.Contains(p.tlsConf.NextProtos, string(HTTPVersion2))
	protocols := &http.Protocols{}
	protocols.SetHTTP1(allowH1)
	protocols.SetHTTP2(allowH2)
	tlsConf.NextProtos = nil
	if allowH2 {
		tlsConf.NextProtos = append(tlsConf.NextProtos, string(HTTPVersion2))
	}
	if allowH1 {
		tlsConf.NextProtos = append(tlsConf.NextProtos, string(HTTPVersion11))
	}

	transport := &http.Transport{
		Protocols:          protocols,
		TLSClientConfig:    tlsConf,
		DisableCompression: true,
		DialContext:        dialContext,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			ctx, finish, dialErr := beginHTTPDial(ctx)
			if dialErr != nil {
				return nil, dialErr
			}
			defer finish()
			conn, dialErr := tlsDial(ctx, dialContext, tlsConf.Clone())
			if dialErr != nil {
				return nil, dialErr
			}
			if !allowH1 && conn.ConnectionState().NegotiatedProtocol != string(HTTPVersion2) {
				return nil, errors.WithDeferred(errors.Error("upstream did not negotiate required HTTP/2"), conn.Close())
			}
			// HTTP owns request deadlines and pooled connection reuse.
			if dialErr = conn.SetDeadline(time.Time{}); dialErr != nil {
				return nil, errors.WithDeferred(dialErr, conn.Close())
			}
			return conn, nil
		},
		IdleConnTimeout: transportDefaultIdleConnTimeout,
		MaxConnsPerHost: dohMaxConnsPerHost,
		MaxIdleConns:    dohMaxIdleConns,
		// Since we have a custom DialContext, we need to use this field to make
		// golang http.Client attempt to use HTTP/2. Otherwise, it would only be
		// used when negotiated on the TLS level.
		ForceAttemptHTTP2: allowH2,
	}

	// Explicitly configure transport to use HTTP/2.
	//
	// See https://github.com/AdguardTeam/dnsproxy/issues/11.
	if allowH2 {
		var transportH2 *http2.Transport
		transportH2, err = http2.ConfigureTransports(transport)
		if err != nil {
			return nil, err
		}
		// Enable HTTP/2 pings on idle connections.
		transportH2.ReadIdleTimeout = transportDefaultReadIdleTimeout
	}

	return transport, nil
}

// http3Transport is a wrapper over [*http3.Transport] that tries to optimize
// its behavior.  The main thing that it does is trying to force use a single
// connection to a host instead of creating a new one all the time.  It also
// helps mitigate race issues with quic-go.
type http3Transport struct {
	baseTransport *http3.Transport

	closed bool
	mu     sync.RWMutex
}

// type check
var _ http.RoundTripper = (*http3Transport)(nil)

// RoundTrip implements the http.RoundTripper interface for *http3Transport.
func (h *http3Transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.closed {
		return nil, net.ErrClosed
	}

	// Try to use cached connection to the target host if it's available.
	resp, err = h.baseTransport.RoundTripOpt(req, http3.RoundTripOpt{OnlyCachedConn: true})

	if errors.Is(err, http3.ErrNoCachedConn) {
		// If there are no cached connection, trigger creating a new one.
		resp, err = h.baseTransport.RoundTrip(req)
	}

	return resp, err
}

// type check
var _ io.Closer = (*http3Transport)(nil)

// Close implements the io.Closer interface for *http3Transport.
func (h *http3Transport) Close() (err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.closed = true

	return h.baseTransport.Close()
}

// createTransportH3 tries to create an HTTP/3 transport for this upstream.  We
// should be able to fall back to H1/H2 in case if HTTP/3 is unavailable or if
// it is too slow.  In order to do that, this method will run two probes in
// parallel (one for TLS, the other one for QUIC) and if QUIC is faster it will
// create the [*http3.Transport] instance.
func (p *dnsOverHTTPS) createTransportH3(
	tlsConfig *tls.Config,
	dialContext bootstrap.DialHandler,
	work *httpWork,
) (roundTripper http.RoundTripper, err error) {
	if !p.supportsH3() {
		return nil, errors.Error("HTTP3 support is not enabled")
	}

	addr, err := p.probeH3(tlsConfig, dialContext, work)
	if err != nil {
		return nil, err
	}

	rt := &http3.Transport{
		Dial: func(
			ctx context.Context,

			// Ignore the address and always connect to the one that we got
			// from the bootstrapper.
			_ string,
			tlsCfg *tls.Config,
			cfg *quic.Config,
		) (c *quic.Conn, err error) {
			ctx, finish, dialErr := beginHTTPDial(ctx)
			if dialErr != nil {
				return nil, dialErr
			}
			c, err = dialQUIC(ctx, p.networkDialer, addr, tlsCfg, cfg)
			if err != nil {
				finish()
				return nil, err
			}
			// DialEarly must return promptly for 0-RTT, but that is not
			// handshake completion. Transfer this same work reference to the
			// physical connection's completion signals. Native dial ctx is
			// canceled on return and cannot establish physical completion.
			select {
			case <-c.HandshakeComplete():
				finish()
			case <-c.Context().Done():
				finish()
			default:
				go func(connection *quic.Conn) {
					select {
					case <-connection.HandshakeComplete():
					case <-connection.Context().Done():
					}
					finish()
				}(c)
			}
			return c, nil
		},
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
		QUICConfig:         p.getQUICConfig(),
	}

	return &http3Transport{baseTransport: rt}, nil
}

// probeH3 runs a test to check whether QUIC is faster than TLS for this
// upstream.  If the test is successful it will return the address that we
// should use to establish the QUIC connections.
func (p *dnsOverHTTPS) probeH3(
	tlsConfig *tls.Config,
	dialContext bootstrap.DialHandler,
	work *httpWork,
) (addr string, err error) {
	// We're using bootstrapped address instead of what's passed to the function
	// it does not create an actual connection, but it helps us determine
	// what IP is actually reachable (when there are v4/v6 addresses).
	if p.networkDialer != nil {
		addr = p.addr.Host
	} else {
		rawConn, dialErr := dialContext(context.Background(), "udp", "")
		if dialErr != nil {
			return "", fmt.Errorf("failed to dial: %w", dialErr)
		}
		// Native bootstrap selects an address; custom routes dial the real
		// packet connection once in dialQUIC, without a disposable UDP probe.
		_ = rawConn.Close()
		udpConn, ok := rawConn.(*net.UDPConn)
		if !ok {
			return "", fmt.Errorf("not a UDP connection to %s", p.addrRedacted)
		}
		addr = udpConn.RemoteAddr().String()
	}

	// Avoid spending time on probing if this upstream only supports HTTP/3.
	if p.supportsH3() && !p.supportsHTTP() {
		return addr, nil
	}

	// Use a new *tls.Config with empty session cache for probe connections.
	// Surprisingly, this is really important since otherwise it invalidates
	// the existing cache.
	// TODO(ameshkov): figure out why the sessions cache invalidates here.
	probeTLSCfg := tlsConfig.Clone()
	probeTLSCfg.ClientSessionCache = nil

	// Do not expose probe connections to the callbacks that are passed to
	// the bootstrap options to avoid side-effects.
	// TODO(ameshkov): consider exposing, somehow mark that this is a probe.
	probeTLSCfg.VerifyPeerCertificate = nil
	probeTLSCfg.VerifyConnection = nil

	// Run probeQUIC and probeTLS in parallel and see which one is faster.
	chQUIC := make(chan error, 1)
	chTLS := make(chan error, 1)
	// Exchange is still admitting work here. Register before either child
	// starts; selecting the faster protocol is not physical completion.
	work.work.Add(2)
	go func(address string) { defer work.work.Done(); p.probeQUIC(address, probeTLSCfg, chQUIC) }(addr)
	go func() { defer work.work.Done(); p.probeTLS(dialContext, probeTLSCfg, chTLS) }()

	select {
	case quicErr := <-chQUIC:
		if quicErr != nil {
			// QUIC failed, return error since HTTP3 was not preferred.
			return "", quicErr
		}

		// Return immediately, QUIC was faster.
		return addr, quicErr
	case tlsErr := <-chTLS:
		if tlsErr != nil {
			// Return immediately, TLS failed.
			p.logger.Debug("probing tls", slogutil.KeyError, tlsErr)

			return addr, nil
		}

		return "", errors.Error("TLS was faster than QUIC, prefer it")
	}
}

// probeQUIC attempts to establish a QUIC connection to the specified address.
// We run probeQUIC and probeTLS in parallel and see which one is faster.
func (p *dnsOverHTTPS) probeQUIC(addr string, tlsConfig *tls.Config, ch chan error) {
	startTime := time.Now()

	t := p.timeout
	if t == 0 {
		t = probeTimeout
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(t))
	defer cancel()

	conn, err := dialQUIC(ctx, p.networkDialer, addr, tlsConfig, p.getQUICConfig())
	if err != nil {
		ch <- fmt.Errorf("opening quic connection to %s: %w", p.addrRedacted, err)
		return
	}

	// Ignore the error since there's no way we can use it for anything useful.
	_ = conn.CloseWithError(QUICCodeNoError, "")

	ch <- nil

	elapsed := time.Since(startTime)
	p.logger.Debug("quic connection established", "elapsed", elapsed)
}

// probeTLS attempts to establish a TLS connection to the specified address. We
// run probeQUIC and probeTLS in parallel and see which one is faster.
func (p *dnsOverHTTPS) probeTLS(dialContext bootstrap.DialHandler, tlsConfig *tls.Config, ch chan error) {
	startTime := time.Now()

	t := p.timeout
	if t == 0 {
		t = probeTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()
	conn, err := tlsDial(ctx, dialContext, tlsConfig)
	if err != nil {
		ch <- fmt.Errorf("opening TLS connection: %w", err)
		return
	}
	if !slices.Contains(p.tlsConf.NextProtos, string(HTTPVersion11)) &&
		conn.ConnectionState().NegotiatedProtocol != string(HTTPVersion2) {
		_ = conn.Close()
		ch <- errors.Error("TLS probe did not negotiate required HTTP/2")
		return
	}

	// Ignore the error since there's no way we can use it for anything useful.
	_ = conn.Close()

	ch <- nil

	elapsed := time.Since(startTime)
	p.logger.Debug("tls connection established", "elapsed", elapsed)
}

// supportsH3 returns true if HTTP/3 is supported by this upstream.
func (p *dnsOverHTTPS) supportsH3() (ok bool) {
	return slices.Contains(p.tlsConf.NextProtos, string(HTTPVersion3))
}

// supportsHTTP returns true if HTTP/1.1 or HTTP2 is supported by this upstream.
func (p *dnsOverHTTPS) supportsHTTP() (ok bool) {
	for _, v := range p.tlsConf.NextProtos {
		if v == string(HTTPVersion11) || v == string(HTTPVersion2) {
			return true
		}
	}

	return false
}

// isHTTP3 checks if the *http.Client is an HTTP/3 client.
func isHTTP3(client *http.Client) (ok bool) {
	_, ok = client.Transport.(*http3Transport)

	return ok
}
