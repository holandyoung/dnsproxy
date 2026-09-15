package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// A complete DNS frame rejected by the codec or protocol is not a failed
// connection. Retrying it could turn the rejected answer into success.
var errDNSProtocol = errors.New("invalid DNS response")

// A timeout ends this exchange. Rebuilding a retained transport may help a
// later query, but must not grant this query another request after its timeout.
func isExchangeTimeout(err error) bool {
	var netErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout()
}

// readDNSResponse uses the native DNS connection's datagram/stream framing and
// exposes the complete-frame boundary before Unpack.  These upstreams do not
// configure TSIG keys: native WriteMsg rejects signed requests, and unsolicited
// signed replies retain the native missing-secret error.
func readDNSResponse(conn *dns.Conn, req *dns.Msg, state *ExchangeState, udp, checkQuestion bool) (*dns.Msg, error) {
	for {
		wire, err := conn.ReadMsgHeader(nil)
		if err != nil {
			if errors.Is(err, dns.ErrShortRead) {
				return nil, fmt.Errorf("%w: %w", errDNSProtocol, err)
			}
			return nil, err
		}
		ticket := state.reserve(wire, req.Id, udp)
		response := new(dns.Msg)
		err = response.Unpack(wire)
		if err == nil && response.IsTsig() != nil {
			err = dns.TsigVerifyWithProvider(wire, unconfiguredTSIG{}, "", false)
		}
		if err != nil {
			state.reject(ticket)
			return response, fmt.Errorf("%w: %w", errDNSProtocol, err)
		}
		if response.Id != req.Id {
			state.reject(ticket)
			if udp {
				continue
			}
			return response, fmt.Errorf("%w: %w", errDNSProtocol, dns.ErrId)
		}
		if checkQuestion {
			if err = validateResponse(req, response); err != nil {
				state.reject(ticket)
				return response, fmt.Errorf("%w: %w", errDNSProtocol, err)
			}
		}
		state.accept(ticket, response)
		return response, nil
	}
}

// No upstream option installs TSIG keys.  Use native signature-buffer and
// record checks while retaining the same missing-key result as dns.Conn.
type unconfiguredTSIG struct{}

func (unconfiguredTSIG) Generate([]byte, *dns.TSIG) ([]byte, error) { return nil, dns.ErrSecret }
func (unconfiguredTSIG) Verify([]byte, *dns.TSIG) error             { return dns.ErrSecret }
