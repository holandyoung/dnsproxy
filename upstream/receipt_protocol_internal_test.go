package upstream

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestReceiptAcrossConcurrentNativeProtocols(t *testing.T) {
	plain := startDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) { _ = w.WriteMsg(respondToTestMessage(r)) })
	t.Cleanup(func() { require.NoError(t, plain.Close()) })
	dot := startDoTServer(t, func(w dns.ResponseWriter, r *dns.Msg) { _ = w.WriteMsg(respondToTestMessage(r)) })
	doh := startDoHServer(t, testDoHServerOptions{http3Enabled: true})
	tlsConfig, roots := createServerTLSConfig(t, "127.0.0.1")
	doq := startDoQServer(t, tlsConfig, 0)
	for _, tc := range []struct {
		name, address string
		roots         *x509.CertPool
		versions      []HTTPVersion
	}{
		{"udp", fmt.Sprintf("udp://127.0.0.1:%d", plain.port), nil, nil},
		{"tcp", fmt.Sprintf("tcp://127.0.0.1:%d", plain.port), nil, nil},
		{"dot", fmt.Sprintf("tls://127.0.0.1:%d", dot.port), dot.rootCAs, nil},
		{"doh1", "https://" + doh.addr + "/dns-query", doh.rootCAs, []HTTPVersion{HTTPVersion11}},
		{"doh2", "https://" + doh.addr + "/dns-query", doh.rootCAs, []HTTPVersion{HTTPVersion2}},
		{"doh3", "h3://" + doh.addr + "/dns-query", doh.rootCAs, nil},
		{"doq", "quic://" + doq.addr, roots, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, err := AddressToUpstream(tc.address, &Options{RootCAs: tc.roots, HTTPVersions: tc.versions, Timeout: 2 * time.Second, Logger: testLogger})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, u.Close()) })
			// The second wave exercises cached connections and multiplexing.
			for wave := range 2 {
				done := make(chan error, 12)
				for index := range 12 {
					go func() {
						req := createHostTestMessage(fmt.Sprintf("receipt-%d-%d.example", wave, index))
						req.Id = uint16(wave*12 + index)
						original := req.Copy()
						started := time.Now()
						state := NewExchangeState(started.Add(3 * time.Second))
						response, err := u.Exchange(req, state)
						if err == nil {
							result, ready := state.Result()
							if !ready || result.Err != nil || result.Response == nil || result.ReceivedAt.Before(started) || result.ReceivedAt.After(time.Now()) {
								err = fmt.Errorf("invalid receipt: ready=%v result=%+v", ready, result)
							} else if result.Response.Id != original.Id || result.Response.Question[0] != original.Question[0] || response.Id != original.Id || req.Id != original.Id {
								err = fmt.Errorf("receipt or request crossed calls: request=%v result=%v", original, result.Response)
							}
						}
						done <- err
					}()
				}
				for range 12 {
					require.NoError(t, <-done)
				}
			}
		})
	}
}

func TestReceiptDoQRequiresCompleteFrameAndFIN(t *testing.T) {
	for _, mode := range []string{"complete", "delayed FIN", "missing FIN", "extra byte", "wrong ID"} {
		t.Run(mode, func(t *testing.T) {
			tlsConfig, roots := createServerTLSConfig(t, "127.0.0.1")
			tlsConfig.NextProtos = []string{NextProtoDQ}
			listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, &quic.Config{})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, listener.Close()) })
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			t.Cleanup(cancel)
			sent, fin, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			serverDone := make(chan error, 1)
			go func() {
				serverDone <- func() error {
					conn, err := listener.Accept(ctx)
					if err != nil {
						return err
					}
					defer conn.CloseWithError(0, "")
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						return err
					}
					wire, err := io.ReadAll(stream)
					if err != nil {
						return err
					}
					if len(wire) < 2 || int(binary.BigEndian.Uint16(wire)) != len(wire)-2 {
						return fmt.Errorf("invalid request framing")
					}
					req := new(dns.Msg)
					if err = req.Unpack(wire[2:]); err != nil {
						return err
					}
					if req.Id != 0 {
						return fmt.Errorf("nonzero DoQ wire ID")
					}
					response := respondToTestMessage(req)
					if mode == "wrong ID" {
						response.Id = 9
					}
					body, err := response.Pack()
					if err != nil {
						return err
					}
					frame := make([]byte, 2+len(body))
					binary.BigEndian.PutUint16(frame, uint16(len(body)))
					copy(frame[2:], body)
					if mode == "extra byte" {
						frame = append(frame, 0x42)
					}
					if _, err = stream.Write(frame); err != nil {
						return err
					}
					close(sent)
					if mode == "delayed FIN" {
						select {
						case <-fin:
						case <-ctx.Done():
							return ctx.Err()
						}
					}
					if mode != "missing FIN" {
						_ = stream.Close()
					}
					select {
					case <-release:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				}()
			}()
			defer func() {
				close(release)
				select {
				case err := <-serverDone:
					require.NoError(t, err)
				case <-ctx.Done():
					t.Error("DoQ peer did not join")
				}
			}()
			u, err := AddressToUpstream("quic://"+listener.Addr().String(), &Options{RootCAs: roots, Timeout: time.Second, Logger: testLogger})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, u.Close()) })
			state := NewExchangeState(time.Now().Add(2 * time.Second))
			finished := make(chan error, 1)
			go func() { _, err := u.Exchange(createTestMessage(), state); finished <- err }()
			select {
			case <-sent:
			case <-ctx.Done():
				t.Fatal("DoQ response frame not sent")
			}
			finAllowed := time.Time{}
			if mode == "delayed FIN" {
				select {
				case <-state.Done():
					t.Fatal("candidate published before FIN")
				case <-time.After(30 * time.Millisecond):
				}
				finAllowed = time.Now()
				close(fin)
			}
			select {
			case err = <-finished:
			case <-ctx.Done():
				t.Fatal("DoQ exchange did not finish")
			}
			result, ready := state.Result()
			require.True(t, ready)
			if mode == "complete" || mode == "delayed FIN" {
				require.NoError(t, err)
				require.NoError(t, result.Err)
				require.NotEmpty(t, result.Response.Answer)
				require.False(t, result.ReceivedAt.Before(finAllowed))
			} else {
				require.Error(t, err)
				require.Error(t, result.Err)
				require.Nil(t, result.Response)
				require.True(t, result.ReceivedAt.IsZero())
			}
		})
	}
}
