# HyperCacheDNS integration fork

This module is `github.com/holandyoung/dnsproxy`, based on AdGuard's dnsproxy
v0.84.2, commit `096ff91186cbc334ede2e3c40f02a6ad6cf71dbb`. Upstream authorship
and the Apache 2.0 license remain intact. HyperCacheDNS consumes an immutable
fork revision directly; it does not replace the upstream module at build time.

## Required semantics and deviations

| Boundary | Reason for the change | Evidence |
| --- | --- | --- |
| `upstream.Options.NetworkDialer` | The application owns bootstrap, routes, SOCKS associations and physical shutdown. Native QUIC discarded a UDP connection and redialed directly, bypassing packet wrappers. One `dialQUIC` now covers DoQ, HTTP/3 and probes with the actual `net.PacketConn`. Routing errors never authorize another route. | `TestNetworkDialerDoQOwnsActualPacketConnection`, `TestNetworkDialerHTTP3CoversPreferenceProbeAndActualConnection` |
| `upstream.Options.ServerName` | Verification name/SNI must remain independent of the physical destination. All encrypted upstreams use the same option; certificate verification stays enabled. | `TestNetworkDialerKeepsStrictServerNameVerification`, `TestRequestPipelineAcrossEncryptedListeners` |
| `NewUpstreamResolver` | Bootstrap must retain ordinary upstream network and TLS policy. The old partial option copy lost these properties. | `TestNetworkDialerFailureCannotFallBackToNativeDialing`, `TestUpstreams` |
| `RequestMiddleware` and `ResponseHandler` | ACL, health handling, per-listener response shaping and observation must cover every parsed request, including native early responses and malformed-body UDP FORMERR. The wrapper sees final errors and intentional drops before normalization. | `TestRequestPipelineCoversNativeResponses`, `TestRequestPipelineObservesUDPWriteFailure` |
| Custom handler without `UpstreamConfig` | An application-owned resolver must not create a dummy upstream configuration or transfer the same upstream ownership twice. A default handler still requires upstreams. | Real pipeline tests use only a custom handler |
| Listener lifecycle | Failed starts must release bound HTTP/TCP/DNSCrypt listeners. Shutdown cancels the serving generation, closes accepted TCP/TLS/QUIC sockets and unblocks semaphore waits. Cancellation of a successful startup context does not terminate the service. | `TestStartFailureReleasesEveryBoundListener`, `TestShutdownClosesAcceptedStreamAtEveryReadBoundary` |
| TCP framing | A stream read may return only one prefix byte. Read the complete two-byte length before decoding; preserve ordinary TCP/TLS segmentation. | `TestStreamAcceptsSplitLengthPrefix` |
| UDP framing through connection owners | miekg/dns selects datagram framing by `net.PacketConn`, but routed connections only promise `net.Conn`. The explicit UDP boundary preserves datagram identity using the same connected socket, including retries. | `TestNetworkDialerWrappedUDPHasDatagramFraming` verifies exact outgoing wire bytes and closure |
| HTTP version allowlist | H2-only must reject H1 before sending the DNS request; H1-only must use H1 even when the server also supports H2. Apply protocol selection to the actual connection and H3 preference probes. | `TestNetworkDialerHTTPVersionAllowlist` checks real request protocol, negative negotiation and socket closure |
| DoT exchange deadline | Dialing, handshake, pooled I/O and retry use one deadline; application-owned bootstrap receives that deadline through NetworkDialer. Zero adds no query deadline. Remove the implicit ten-second DoT limit. | `TestNetworkDialerDoTExchangeDeadline`, `TestNetworkDialerDoTHandshakeDeadline` |
| Final stream write errors | A closed TCP socket must reach the final observer just like a failed UDP write. | `TestRequestPipelineObservesTCPWriteFailure` |
| Native failure results | UDP truncation retains dnsproxy's native TCP retry result. No retained-UDP-answer fallback is added. | `TestNetworkDialerUDPTruncationReturnsTCPFailure`, `TestUpstream_plainDNS_fallbackToTCP` |

DNSCrypt listeners remain supported. A DNSCrypt upstream with a custom dialer
is explicitly rejected: its native client cannot use that connection owner.
HyperCacheDNS does not expose DNSCrypt upstreams.

Hooks start after DNS framing/decryption succeeds. TLS handshake failures,
unreadable DNS headers and malformed HTTP/TCP framing remain transport errors.
A UDP message with a usable header and invalid body passes through both hooks.

The application owns cache, refresh, route/group budgets, logging and joining
its workers. `Proxy.Shutdown` cannot promise completion of an arbitrary custom
handler that ignores cancellation. Closing connections and joining workers
are separate assertions.

## Verification and delivery

`go.mod` owns the Go version. `sh scripts/check.sh` is the same local, PR and
master gate: formatting, module integrity, vet, the full shuffled/repeated race
suite and vulnerability scanning. Protocol conformance uses real local servers
and certificates, without assumptions about public providers or reserved IPs.
No failed assertion is converted into a skip.
Inherited live-provider tests now use local native DNS/TLS/HTTP/DNSCrypt
servers. Success and failure are controlled by those servers; reserved IP
ranges are not treated as an unreachable-network oracle. Shared TCP/UDP
fixtures reserve both port spaces and retry only address-in-use collisions,
closing the first listener before retrying. Address-parser tests may still
contain public address strings without making network requests.
The inherited caching-resolver suite still skips its `ip4`/`ip6` staleness
subcases: native cache keys do not distinguish those lookup networks. The
application-owned bootstrap path bypasses that native caching resolver. These
skipped cases are not coverage of selective-family native bootstrap.

Auxiliary H3 preference probes retain a ten-second bound when query timeouts
are disabled; this only limits protocol probing, not the query deadline.
Native bootstrap resolvers retain their own wait/timeout behavior: elapsed
bootstrap time consumes the DoT budget, but a Resolver that ignores its context
cannot be forcibly interrupted. HyperCacheDNS owns bootstrap in NetworkDialer;
it must verify that its actual work respects the supplied deadline. Native
ordered-bootstrap tests use short individual bootstrap budgets within the
query budget and prove both failure-then-success and first-success termination.

Use a task branch, independent review of the exact commit, green local and PR
checks, a PR to `master`, and CI verification of the resulting master commit.
Upstream mirroring, private AdGuard automation, image publication and releases
are not part of this fork's CI.
