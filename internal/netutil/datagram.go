package netutil

import (
	"errors"
	"net"
)

// ConnectedDatagram preserves explicit UDP framing at the miekg/dns boundary
// when a routed connection exposes only net.Conn. It retains the route owner.
type ConnectedDatagram struct{ net.Conn }

var _ net.PacketConn = ConnectedDatagram{}

func (c ConnectedDatagram) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.RemoteAddr(), err
}

func (c ConnectedDatagram) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr == nil || addr.Network() != c.RemoteAddr().Network() || addr.String() != c.RemoteAddr().String() {
		return 0, errors.New("connected UDP destination differs from configured route")
	}
	return c.Write(b)
}
