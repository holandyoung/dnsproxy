package dnscrypt

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/holandyoung/dnsproxy/internal/netutil"
	"github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
)

// ResolverInfo contains DNSCrypt resolver information necessary for
// decryption/encryption.
type ResolverInfo struct {
	// ResolverCert contains certificate info (obtained with the first
	// unencrypted DNS request).
	ResolverCert *Certificate

	// ServerAddress is the server IP address.
	ServerAddress string

	// ProviderName is the provider name.
	ProviderName string

	// ServerPublicKey is the resolver public key (this key is used to
	// validate cert signature).
	ServerPublicKey ed25519.PublicKey

	// SharedKey is the shared key that is to be used to encrypt/decrypt
	// messages.
	SharedKey [KeySize]byte

	// SecretKey is the client short-term secret key.
	SecretKey [KeySize]byte

	// PublicKey is the client short-term public key.
	PublicKey [KeySize]byte
}

// ClientConfig is the configuration structure for [Client].
type ClientConfig struct {
	// LocalAddr is the optional local source for certificate and encrypted
	// exchanges. Its concrete type must match Proto. Nil uses native selection.
	LocalAddr net.Addr

	// Logger is a logger instance for Client.  If not set, slog.Default()
	// will be used.
	Logger *slog.Logger

	// DialContext owns all certificate and encrypted connections when set.
	// It replaces native dialing, including the native certificate dial ceiling;
	// the supplied context owns the complete operation budget. LocalAddr applies
	// only to native dialing. The caller owns shutdown of its routed connections.
	DialContext func(context.Context, string, string) (net.Conn, error)

	// Proto is the base network protocol.
	Proto Proto

	// UDPSize is the maximum size of a DNS response (or query) this client
	// can send or receive.  If not set, we use [dns.MinMsgSize] by default.
	UDPSize int
}

// Client is a DNSCrypt resolver client.
type Client struct {
	logger             *slog.Logger
	dialContext        func(context.Context, string, string) (net.Conn, error)
	proto              Proto
	certificateTimeout time.Duration
	udpSize            int
}

// NewClient returns properly initialized *Client.  c must be non-nil and valid.
func NewClient(conf *ClientConfig) (c *Client) {
	dial := conf.DialContext
	var certificateTimeout time.Duration
	if dial == nil {
		dial = (&net.Dialer{LocalAddr: conf.LocalAddr}).DialContext
		certificateTimeout = 2 * time.Second
	}
	return &Client{
		logger:             cmp.Or(conf.Logger, slog.Default()),
		dialContext:        dial,
		certificateTimeout: certificateTimeout,
		proto:              conf.Proto,
		udpSize:            cmp.Or(conf.UDPSize, dns.MinMsgSize),
	}
}

// ResponseObserver belongs to one encrypted exchange. Received is called after
// the complete ciphertext is read, before bounded decryption and DNS decoding.
// Decoded always follows it, even on failure, before connection cleanup. Both
// methods must be bounded and must not perform I/O. Certificate replies do not
// enter this boundary. A rejected candidate cannot cover another read or retry.
type ResponseObserver interface {
	Received()
	Decoded(*dns.Msg, error) error
}

// DialContext fetches and validates DNSCrypt certificate from the given server.
// Data received during this call is then used for DNS requests
// encryption/decryption.  stampStr is an sdns:// address which is parsed using
// go-dnsstamps package.
func (c *Client) DialContext(ctx context.Context, stampStr string) (info *ResolverInfo, err error) {
	stamp, err := dnsstamps.NewServerStampFromString(stampStr)
	if err != nil {
		return nil, fmt.Errorf("creating server stamp: %w", err)
	}

	if stamp.Proto != dnsstamps.StampProtoTypeDNSCrypt {
		return nil, ErrInvalidDNSStamp
	}

	return c.DialStampContext(ctx, stamp)
}

// DialStampContext fetches and validates DNSCrypt certificate from the given
// server.  Data received during this call is then used for DNS requests
// encryption/decryption.
func (c *Client) DialStampContext(
	ctx context.Context,
	stamp dnsstamps.ServerStamp,
) (info *ResolverInfo, err error) {
	info = &ResolverInfo{}
	info.SecretKey, info.PublicKey = generateRandomKeyPair()

	info.ServerPublicKey = stamp.ServerPk
	info.ServerAddress = stamp.ServerAddrStr
	info.ProviderName = stamp.ProviderName

	cert, err := c.fetchCert(ctx, stamp)
	if err != nil {
		return nil, fmt.Errorf("fetching cert: %w", err)
	}

	info.ResolverCert = cert
	sharedKey, err := computeSharedKey(cert.ESVersion, &info.SecretKey, &cert.ResolverPk)
	if err != nil {
		return nil, fmt.Errorf("computing shared key: %w", err)
	}

	info.SharedKey = sharedKey

	return info, nil
}

// ExchangeContext performs a synchronous DNS query to the specified DNSCrypt
// server and returns a DNS response.  This method creates a new network
// connection for every call so avoid using it for TCP.  DNSCrypt cert needs to
// be fetched and validated prior to this call using the
// [Client.DialStampContext] method.  m and info must not be nil.
func (c *Client) ExchangeContext(
	ctx context.Context,
	m *dns.Msg,
	info *ResolverInfo,
	observer ResponseObserver,
) (resp *dns.Msg, err error) {
	proto := ProtoUDP
	if c.proto == ProtoTCP {
		proto = ProtoTCP
	}

	conn, err := c.dialContext(ctx, string(proto), info.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("dialing: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, conn.Close()) }()

	resp, err = c.ExchangeConnContext(ctx, conn, m, info, observer)
	if err != nil {
		return nil, fmt.Errorf("exchanging: %w", err)
	}

	return resp, nil
}

// ExchangeConnContext performs a synchronous DNS query to the specified
// DNSCrypt server and returns a DNS response.  DNSCrypt server information
// needs to be fetched and validated prior to this call using the
// [Client.DialStampContext] method.  conn, m, and info must not be nil.
func (c *Client) ExchangeConnContext(
	ctx context.Context,
	conn net.Conn,
	m *dns.Msg,
	info *ResolverInfo,
	observer ResponseObserver,
) (resp *dns.Msg, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	// Cancellation owns the actual in-flight socket, including a context with
	// no deadline. A canceled connection cannot be reused for another exchange.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	query, clientNonce, err := c.encrypt(m, info)
	if err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}

	err = c.writeQuery(ctx, conn, query)
	if err != nil {
		return nil, fmt.Errorf("writing query: %w", err)
	}

	b, err := c.readResponse(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if observer != nil {
		observer.Received()
	}
	resp, err = c.decrypt(b, clientNonce, info)
	if observer != nil {
		observed := observer.Decoded(resp, err)
		if err == nil {
			err = observed
		}
	}
	if err != nil {
		return nil, fmt.Errorf("decrypting response: %w", err)
	}

	return resp, nil
}

// writeQuery writes query to the network connection.  Depending on the
// protocol we may write a 2-byte prefix or not.  conn must not be nil.
func (c *Client) writeQuery(ctx context.Context, conn net.Conn, query []byte) (err error) {
	deadline, ok := ctx.Deadline()
	if ok {
		_ = conn.SetWriteDeadline(deadline)
	}

	if c.proto == ProtoTCP {
		err = writePrefixed(query, conn)
		if err != nil {
			return fmt.Errorf("writing to tcp connection: %w", err)
		}
	} else {
		_, err = conn.Write(query)
		if err != nil {
			return fmt.Errorf("writing to connection: %w", err)
		}
	}

	return nil
}

// readResponse reads response from the network connection depending on the
// protocol, we may read a 2-byte prefix or not.  conn must not be nil.
func (c *Client) readResponse(ctx context.Context, conn net.Conn) (resp []byte, err error) {
	deadline, ok := ctx.Deadline()
	if ok {
		_ = conn.SetReadDeadline(deadline)
	}

	if c.proto != ProtoTCP {
		resp = make([]byte, c.udpSize)
		var n int
		n, err = conn.Read(resp)
		if err != nil {
			return nil, err
		}

		return resp[:n], nil
	}

	// If we got here, this is a TCP connection so we should read a 2-byte
	// prefix first.
	return readPrefixed(conn)
}

// encrypt encrypts a DNS message using shared key from the resolver info.  m
// and info must not be nil.
func (c *Client) encrypt(
	m *dns.Msg,
	info *ResolverInfo,
) (msg []byte, clientNonce nonce, err error) {
	q := &encryptedQuery{
		esVersion:   info.ResolverCert.ESVersion,
		clientMagic: info.ResolverCert.ClientMagic,
		clientPk:    info.PublicKey,
	}
	query, err := m.Pack()
	if err != nil {
		return nil, nonce{}, fmt.Errorf("packing dns message: %w", err)
	}

	msg, clientNonce, err = q.encrypt(query, info.SharedKey)
	if err != nil {
		return nil, nonce{}, fmt.Errorf("encrypting message: %w", err)
	}

	if len(msg) > c.maxQuerySize() {
		return nil, nonce{}, ErrQueryTooLarge
	}

	return msg, clientNonce, nil
}

// decrypt decrypts a DNS message using a shared key from the resolver info.
// info must not be nil.
func (c *Client) decrypt(
	b []byte,
	clientNonce nonce,
	info *ResolverInfo,
) (msg *dns.Msg, err error) {
	dr := &encryptedResponse{
		esVersion: info.ResolverCert.ESVersion,
	}

	response, err := dr.decrypt(b, info.SharedKey, clientNonce)
	if err != nil {
		return nil, fmt.Errorf("decrypting server response: %w", err)
	}

	msg = &dns.Msg{}
	err = msg.Unpack(response)
	if err != nil {
		return nil, fmt.Errorf("unpacking dns message: %w", err)
	}

	return msg, nil
}

// fetchCert loads DNSCrypt cert from the specified server.
func (c *Client) fetchCert(
	ctx context.Context,
	stamp dnsstamps.ServerStamp,
) (cert *Certificate, err error) {
	providerName := stamp.ProviderName
	if !strings.HasSuffix(providerName, ".") {
		providerName = providerName + "."
	}

	query := &dns.Msg{}
	query.SetQuestion(providerName, dns.TypeTXT)
	dialCtx := ctx
	if c.certificateTimeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, c.certificateTimeout)
		defer cancel()
	}
	proto := ProtoUDP
	if c.proto == ProtoTCP {
		proto = ProtoTCP
	}
	socket, err := c.dialContext(dialCtx, string(proto), stamp.ServerAddrStr)
	if err != nil {
		return nil, fmt.Errorf("dialing certificate server: %w", err)
	}
	if proto == ProtoUDP {
		socket = netutil.ConnectedDatagram{Conn: socket}
	}
	conn := &dns.Conn{Conn: socket, UDPSize: uint16(defaultUDPSize)}
	defer func(closeResource func() error) { _ = closeResource() }(conn.Close)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if c.certificateTimeout > 0 {
		native := time.Now().Add(c.certificateTimeout)
		if deadline.IsZero() || native.Before(deadline) {
			deadline = native
		}
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err = conn.WriteMsg(query); err != nil {
		return nil, fmt.Errorf("sending certificate query: %w", err)
	}
	var r *dns.Msg
	for {
		r, err = conn.ReadMsg()
		if err != nil || r.Id == query.Id {
			break
		}
		if proto == ProtoTCP {
			err = dns.ErrId
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("sending dns query: %w", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, ErrFailedToFetchCert
	}

	cert = c.parseAnswer(ctx, r.Answer, stamp.ServerPk, stamp.ProviderName)
	if cert == nil {
		return nil, fmt.Errorf("no valid txt records for provider %q", providerName)
	}

	return cert, nil
}

// parseAnswer parses DNS TXT records and returns the certificate with the
// highest priority.
func (c *Client) parseAnswer(
	ctx context.Context,
	answer []dns.RR,
	serverPk ed25519.PublicKey,
	providerName string,
) (cert *Certificate) {
	for _, rr := range answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}

		certStr := strings.Join(txt.Txt, "")

		currentCert := &Certificate{}
		err := currentCert.UnmarshalBinary(unpackTxtString(certStr))
		if err != nil {
			c.logger.DebugContext(
				ctx,
				"failed to parse certificate",
				"provider_name", providerName,
				slogutil.KeyError, err,
			)

			continue
		}

		err = verifyCert(currentCert, serverPk)
		if err != nil {
			c.logger.DebugContext(
				ctx,
				"failed to verify certificate",
				"provider_name", providerName,
				slogutil.KeyError, err,
			)

			continue
		}

		if cert == nil || c.certHasHigherPriority(ctx, cert, currentCert, providerName) {
			cert = currentCert
		}
	}

	return cert
}

// certHasHigherPriority returns true if current has higher priority than prev.
// A higher serial number is preferred, or a higher ESVersion if the serial
// numbers are the same.  prev and current must not be nil.
func (c *Client) certHasHigherPriority(
	ctx context.Context,
	prev *Certificate,
	current *Certificate,
	providerName string,
) (hasHigherPriority bool) {
	if prev.Serial > current.Serial {
		c.logger.DebugContext(
			ctx,
			"cert superseded by a previous certificate",
			"provider", providerName,
			"cert_serial", current.Serial,
		)

		return false
	}

	if prev.Serial < current.Serial {
		return true
	}

	if current.ESVersion <= prev.ESVersion {
		c.logger.DebugContext(
			ctx,
			"keeping the current cert es version",
			"provider", providerName,
		)

		return false
	}

	c.logger.DebugContext(
		ctx,
		"upgrading the construction",
		"provider", providerName,
		"es_version", prev.ESVersion,
		"new_es_version", current.ESVersion,
	)

	return true
}

// verifyCert verifies the date and signature of the certificate.  cert must not
// be nil.
//
// TODO(f.setrakov): Consider validating the date separately and use
// [Certificate.Validate].
func verifyCert(cert *Certificate, serverPk ed25519.PublicKey) (err error) {
	if !cert.VerifyDate() {
		return ErrInvalidDate
	}

	if !cert.VerifySignature(serverPk) {
		return ErrInvalidCertSignature
	}

	return nil
}

// maxQuerySize returns the maximum query size for the client.
func (c *Client) maxQuerySize() (size int) {
	if c.proto == ProtoTCP {
		return dns.MaxMsgSize
	}

	return c.udpSize
}
