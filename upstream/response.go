package upstream

import "github.com/miekg/dns"

// readDNSResponse uses the native DNS connection's datagram/stream framing and
// exposes the complete-frame boundary before Unpack.  These upstreams do not
// configure TSIG keys: native WriteMsg rejects signed requests, and unsolicited
// signed replies retain the native missing-secret error.
func readDNSResponse(conn *dns.Conn, req *dns.Msg, state *ExchangeState, udp bool) (*dns.Msg, error) {
	for {
		wire, err := conn.ReadMsgHeader(nil)
		if err != nil {
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
			return response, err
		}
		if response.Id != req.Id {
			state.reject(ticket)
			if udp {
				continue
			}
			return response, dns.ErrId
		}
		if err = validateResponse(req, response); err != nil {
			state.reject(ticket)
			return response, err
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
