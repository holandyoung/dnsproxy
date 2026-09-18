package upstream

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/holandyoung/quic-go"
)

// dialQUIC is the single connection boundary for DoQ, HTTP/3, and HTTP/3
// preference probes. A custom route never reaches DialAddrEarly.
func dialQUIC(ctx context.Context, dialer NetworkDialer, address string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
	if dialer == nil {
		return quic.DialAddrEarly(ctx, address, tlsConfig, config)
	}
	packet, destination, err := dialer.DialPacket(ctx, address)
	if err != nil {
		return nil, err
	}
	if packet == nil || destination == nil {
		if packet != nil {
			_ = packet.Close()
		}
		return nil, fmt.Errorf("network dialer returned an incomplete packet connection")
	}
	connection, err := quic.DialEarly(ctx, packet, destination, tlsConfig, config)
	if err != nil {
		_ = packet.Close()
		return nil, err
	}
	context.AfterFunc(connection.Context(), func() { _ = packet.Close() })
	return connection, nil
}
