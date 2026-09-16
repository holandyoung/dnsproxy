package dnscrypt

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/miekg/dns"
)

// defaultReadTimeout is the default read timeout for all reads.
const defaultReadTimeout = 2 * time.Second

// defaultTCPIdleTimeout is the timeout used for TCP connections after the first
// read.  For the first read [defaultReadTimeout] is used.
const defaultTCPIdleTimeout = 8 * time.Second

// defaultUDPSize is the default size of the UDP read buffer.  The release notes
// for dnscrypt-proxy version 1.1.0-RC1 claim that this size was chosen as the
// maximum one "for compatibility with some scary network setups", and making it
// smaller seems to break things for some people.
//
// See also: https://github.com/AdguardTeam/AdGuardDNS/issues/188.
const defaultUDPSize = 1252

// ServerConfig is the configuration structure for [Server].
type ServerConfig struct {
	// Handler to invoke.  If nil, the [DefaultHandler] is used.
	Handler Handler

	// ResolverCert contains resolver certificate.  It must not be nil.
	ResolverCert *Certificate

	// Logger is a logger instance for Server.  If not set, slog.Default() will
	// be used.
	Logger *slog.Logger

	// ListenerFailures receives fatal listener errors before logging or joining
	// admitted handlers. Sending never blocks; callers should provide a buffered
	// channel and act on the first failure. Only the caller may close the channel,
	// after all serving runs have stopped. Nil disables reporting.
	ListenerFailures chan<- error

	// ProviderName is a DNSCrypt provider name.
	ProviderName string

	// Addr is the address for server to listen.  It must not be empty.
	Addr netip.AddrPort

	// Proto defines protocol for serving.  It must be one of the following:
	//
	//	- [ProtoTCP]
	//	- [ProtoUDP]
	Proto Proto

	// UDPSize is the default buffer size to use to read incoming UDP messages.
	// If not set it defaults to [defaultUDPSize].
	UDPSize uint
}

// type check
var _ validate.Interface = (*ServerConfig)(nil)

// Validate implements the [validate.Interface] for *ServerConfig.
func (c *ServerConfig) Validate() (err error) {
	errs := []error{
		validate.NotEmpty("ProviderName", c.ProviderName),
		validate.NotEmpty("Addr", c.Addr),
		validate.NotNil("ResolverCert", c.ResolverCert),
		c.Proto.Validate(),
	}

	if c.ResolverCert != nil {
		errs = validate.Append(errs, "ResolverCert", c.ResolverCert)
	}

	return errors.Join(errs...)
}

// Server is a DNSCrypt server implementation.
type Server struct {
	handler          Handler
	resolverCert     *Certificate
	logger           *slog.Logger
	listenerFailures chan<- error
	// done closes only after the serving loop and its admitted handlers exit.
	done        chan struct{}
	cancel      context.CancelFunc
	udpConn     *net.UDPConn
	tcpListener net.Listener
	// tcpConns tracks active connections.
	//
	// TODO(f.setrakov): Consider using syncutil.Map.
	tcpConns     map[net.Conn]struct{}
	addr         netip.AddrPort
	providerName string
	proto        Proto
	udpSize      uint
	// mu protects concurrent access to listeners, connections and run state.
	mu sync.RWMutex
	// started indicates whether the server is processing queries.
	started bool
}

// NewServer returns properly initialized *Server.  conf must be non-nil and
// valid.
func NewServer(conf *ServerConfig) (s *Server, err error) {
	err = conf.Validate()
	if err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &Server{
		listenerFailures: conf.ListenerFailures,
		handler:          cmp.Or(conf.Handler, defaultDNSCryptHandler),
		resolverCert:     conf.ResolverCert,
		providerName:     conf.ProviderName,
		addr:             conf.Addr,
		logger:           cmp.Or(conf.Logger, slog.Default()),
		udpSize:          cmp.Or(conf.UDPSize, defaultUDPSize),
		proto:            conf.Proto,
		tcpConns:         map[net.Conn]struct{}{},
	}, nil
}

// LocalAddr returns the local network address for the given protocol, if known.
func (s *Server) LocalAddr() (addr net.Addr) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch s.proto {
	case ProtoTCP:
		if s.tcpListener != nil {
			return s.tcpListener.Addr()
		}
	case ProtoUDP:
		if s.udpConn != nil {
			return s.udpConn.LocalAddr()
		}
	default:
		panic(fmt.Errorf(
			"proto: %w: %q, supported: %q",
			errors.ErrBadEnumValue,
			s.proto,
			[]Proto{ProtoTCP, ProtoUDP},
		))
	}

	return nil
}

// type check
var _ service.Interface = (*Server)(nil)

// Start implements the [service.Interface] for *Server.  It does not block
// calling goroutine.
func (s *Server) Start(ctx context.Context) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err = ctx.Err(); err != nil {
		return err
	}
	if s.started {
		return ErrServerAlreadyStarted
	}
	if s.done != nil {
		select {
		case <-s.done:
		default:
			return errors.Error("previous DNSCrypt run is still closing")
		}
	}
	switch s.proto {
	case ProtoTCP:
		s.tcpListener, err = net.ListenTCP(string(ProtoTCP), net.TCPAddrFromAddrPort(s.addr))
	case ProtoUDP:
		s.udpConn, err = net.ListenUDP(string(ProtoUDP), net.UDPAddrFromAddrPort(s.addr))
		if err == nil {
			err = setUDPSocketOptions(s.udpConn)
		}
	default:
		return errors.Error("invalid DNSCrypt protocol")
	}
	if err != nil {
		s.closeListeners(ctx)
		return fmt.Errorf("binding DNSCrypt %s: %w", s.proto, err)
	}
	ctx, s.cancel = context.WithCancel(context.WithoutCancel(ctx))
	s.started = true
	s.done = make(chan struct{})
	done := s.done
	// The single serving owner is registered before Start returns. Its local
	// worker group is joined before done, so Shutdown never races a later Add.
	go func() {
		defer close(done)
		defer slogutil.RecoverAndLog(ctx, s.logger)
		var serveErr error
		if s.proto == ProtoTCP {
			serveErr = s.serveTCP(ctx)
		} else {
			serveErr = s.serveUDP(ctx)
		}
		if serveErr != nil {
			s.logger.WarnContext(ctx, "DNSCrypt listener failed", slogutil.KeyError, serveErr)
		}
	}()
	return nil
}

// reportListenerFailure runs before waiting for handlers, since the owner must
// be able to start bounded cleanup even if a handler never returns.
func (s *Server) reportListenerFailure(ctx context.Context, addr net.Addr, err error) {
	if ctx.Err() != nil {
		return
	}
	if err == nil {
		err = errors.Error("listener stopped unexpectedly")
	}
	select {
	case s.listenerFailures <- fmt.Errorf("dnscrypt-%s listener %s: %w", s.proto, addr, err):
	default:
	}
}

// closeListeners closes server active network listeners.
func (s *Server) closeListeners(ctx context.Context) {
	if s.tcpListener != nil {
		err := s.tcpListener.Close()
		if err != nil {
			s.logger.WarnContext(ctx, "closing tcp listener", slogutil.KeyError, err)
		}
	}

	if s.udpConn != nil {
		err := s.udpConn.Close()
		if err != nil {
			s.logger.WarnContext(ctx, "closing udp connection", slogutil.KeyError, err)
		}
	}
}

// Shutdown stops admission, cancels handler contexts and closes all physical
// sockets before waiting. A canceled caller still initiates complete cleanup;
// another call can join the same run. No deadline is extended for slow clients.
func (s *Server) Shutdown(ctx context.Context) (err error) {
	s.mu.Lock()
	if s.done == nil {
		s.mu.Unlock()
		return ErrServerNotStarted
	}
	if s.started {
		s.started = false
		s.cancel()
		s.closeListeners(ctx)
		for conn := range s.tcpConns {
			_ = conn.Close()
		}
	}
	done := s.done
	s.mu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// isStarted returns true if the server is processing queries right now.
func (s *Server) isStarted() (ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	started := s.started

	return started
}

// serveDNS serves a DNS response.  rw and r must not be nil.
func (s *Server) serveDNS(ctx context.Context, rw ResponseWriter, r *dns.Msg) (err error) {
	if r == nil || len(r.Question) != 1 || r.Response {
		return ErrInvalidQuery
	}

	s.logger.DebugContext(ctx, "handling a DNS query", "question", r.Question[0].Name)
	err = s.handler.ServeDNS(ctx, rw, r)
	if err == nil {
		return nil
	}

	s.logger.DebugContext(ctx, "error while handling a DNS query", slogutil.KeyError, err)

	reply := &dns.Msg{}
	reply.SetRcode(r, dns.RcodeServerFailure)
	err = rw.WriteMsg(ctx, reply)
	if err != nil {
		return fmt.Errorf("writing message: %w", err)
	}

	return nil
}

// encrypt encrypts DNSCrypt response.  m must not be nil.
func (s *Server) encrypt(m *dns.Msg, q *encryptedQuery) (encrypted []byte, err error) {
	r := &encryptedResponse{
		esVersion: q.esVersion,
		nonce:     q.nonce,
	}
	packet, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing dns message: %w", err)
	}

	sharedKey, err := computeSharedKey(q.esVersion, &s.resolverCert.ResolverSk, &q.clientPk)
	if err != nil {
		return nil, fmt.Errorf("computing shared key: %w", err)
	}

	return r.encrypt(packet, sharedKey)
}

// decrypt decrypts the incoming message and returns a DNS message to process.
func (s *Server) decrypt(b []byte) (msg *dns.Msg, query *encryptedQuery, err error) {
	query = &encryptedQuery{
		esVersion:   s.resolverCert.ESVersion,
		clientMagic: s.resolverCert.ClientMagic,
	}
	decrypted, err := query.decrypt(b, s.resolverCert.ResolverSk)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting query: %w", err)
	}

	msg = &dns.Msg{}
	err = msg.Unpack(decrypted)
	if err != nil {
		return nil, nil, fmt.Errorf("unpacking dns message: %w", err)
	}

	return msg, query, nil
}

// handleHandshake handles a TXT request that requests certificate data.
func (s *Server) handleHandshake(b []byte, certTxt string) (res []byte, err error) {
	m := &dns.Msg{}
	err = m.Unpack(b)
	if err != nil {
		return nil, fmt.Errorf("unpacking dns message: %w", err)
	}

	if len(m.Question) != 1 || m.Response {
		return nil, ErrInvalidQuery
	}

	q := m.Question[0]
	providerName := dns.Fqdn(s.providerName)

	qName := strings.ToLower(q.Name)
	if q.Qtype != dns.TypeTXT || qName != providerName {
		return nil, ErrInvalidQuery
	}

	reply := &dns.Msg{}
	reply.SetReply(m)
	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeTXT,
			Ttl:    60,
			Class:  dns.ClassINET,
		},
		Txt: []string{
			certTxt,
		},
	}
	reply.Answer = append(reply.Answer, txt)

	// These bits are important for the old dnscrypt-proxy versions.
	reply.Authoritative = true
	reply.RecursionAvailable = true

	return reply.Pack()
}

// getCertTXT serializes the cert TXT record that are to be sent to the client.
func (s *Server) getCertTXT() (cert string) {
	// Ignore the error as it is always nil.
	certBuf, _ := s.resolverCert.MarshalBinary()

	return packTxtString(certBuf)
}
