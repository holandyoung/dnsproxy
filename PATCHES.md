# HyperCacheDNS integration fork

This module is `github.com/holandyoung/dnsproxy`, based on AdGuard's dnsproxy
v0.84.2, commit `096ff91186cbc334ede2e3c40f02a6ad6cf71dbb`. Upstream authorship
and the Apache 2.0 license remain intact. HyperCacheDNS consumes an immutable
fork revision directly; it does not replace the upstream module at build time.

## Required semantics and deviations

Bootstrap preserves the application's stricter existing answer policy before
`UpstreamResolver` reduces a DNS message to addresses: QR, opcode, ID, the exact
question including class/case, and NOERROR must match; only records of the
requested A/AAAA type are extracted. A plain upstream created specifically by
`NewUpstreamResolver` delegates question policy to that boundary. It retries TCP
for a successfully decoded TC response, but not for an invalid question alone
or a partially decoded malformed TC frame. A failed UDP/TCP bootstrap exchange
also does not retry the same server internally; the application advances its
ordered server list. Business upstream question-to-TCP
behavior is unchanged. The factory fixes this private policy before publishing
the instance; no alternate Exchange interface or public compatibility option is
introduced. `LookupNetIP` rejects an already canceled context. In-flight native
lookups still require application-scoped NetworkDialer ownership and timeout;
this change does not claim that the native lookup wait itself observes context.
Evidence: `TestBootstrapMetadataBeforeAddressExtraction`,
`TestBootstrapQuestionAndTruncationPolicy`, `TestBootstrapRequestedRRType`, and
`TestBootstrapCanceledBeforeAdmission`.

Complete protocol rejections never authorize a hidden query replay. Native
DoT/DoQ reconnect only for connection failures on a retained connection; DNS
codec/question/ID errors and DoQ invalid framing/FIN are final. DoH clients
reject redirects before visiting the destination on H1, H2 and H3. These
deviations preserve HyperCacheDNS's established rejection policy. Evidence:
`TestReceiptDoQCachedRejectionDoesNotReplay`,
`TestReceiptDoTCachedRejectionDoesNotReplay`, and
`TestReceiptDoHRedirectDoesNotReplay` warm actual connections before the bad
response and count application queries; real connection-failure controls still
recover. TCP and encrypted-protocol TC policy remains an application decision.

An exchange timeout is also final: UDP/TCP, DoQ, and DoH no longer explicitly
retry timeout errors. Actual warm missing-FIN and HTTP partial-body tests plus
plain unanswered queries assert no extra request after the native timeout.
This does not redefine every native phase as one physical wall-clock budget:
bootstrap and the H3 preference probe retain the limits described below, while
the application owns its member/group acceptance cutoff through ExchangeState.

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
| Complete-message receipt | Cache TTL and logical member cutoffs use the complete response observation, before decoding and cleanup. A returned timestamp alone cannot preserve a timely answer when native Close blocks. The single `Exchange(req, state)` signature carries an invocation-local decision owner; old callers explicitly pass nil. | `TestReceiptPublishedBeforeRealConnectionCleanup`, `TestReceiptDoHBeforeNativeH2BodyClose`, `TestReceiptAcrossConcurrentNativeProtocols` |
| DoQ completion and response ID | Require one complete frame followed by FIN and reject extra bytes or nonzero wire ID before restoring the caller's ID. The prior frame-only reader accepted incomplete transactions. The original request is no longer mutated. | `TestReceiptDoQRequiresCompleteFrameAndFIN`; [RFC 9250 sections 4.2 and 4.3](https://www.rfc-editor.org/rfc/rfc9250.html#section-4.2) |
| DoH response boundary | Validate HTTP status, DNS media type and complete bounded body before candidate admission. A prefix, response headers or a body exceeding 65535 bytes is not a complete DNS response. | Native H1/H2/H3 receipt tests and strict response-body tests |

DNSCrypt listeners remain supported. A DNSCrypt upstream with a custom dialer
is explicitly rejected: its native client cannot use that connection owner.
HyperCacheDNS does not expose DNSCrypt upstreams.
Non-nil receipt state is also explicitly rejected for DNSCrypt upstreams: its
client does not expose a complete-message boundary. DNSCrypt listeners and
ordinary synchronous upstream exchanges remain supported.

## Logical receipt and physical completion

`ExchangeState` is constructed per invocation. `Done` and `Result` expose its
immutable response, receipt and error independently of `Exchange` return.
`Expire` seals admission of new candidates; an already observed complete
candidate may finish only bounded local decoding and validation. `Abandon`
discards a losing invocation immediately. Neither cancels or joins the native
network operation; the application still owns tracking and draining its workers
and physical resources. A later cleanup error is returned by `Exchange`, and
does not replace an already accepted response.

Receipt observation and expiry serialize on one short state lock. The clock is
read there immediately after complete native read and before decoding. This is
a software observation boundary, not a guarantee about physical packet arrival
during arbitrary scheduler pauses. There is no hidden validation grace timer.
Validation is bounded by DNS message size, not by a promise that a paused
goroutine runs immediately at the wall-clock deadline. Tests cover both expiry
before observation and completion of a reserved candidate after sealing.

Wrong-ID UDP packets and truncated UDP replies cannot reserve a final answer.
A rejected question releases its reservation before TCP continuation. A TCP
reply supplies a new receipt; TCP failure or logical expiry cannot restore the
provisional UDP result. Each state belongs to one call, including concurrent
calls through shared TLS/HTTP/QUIC connections. Reusing a state is an error.

The common plain/TLS reader uses miekg/dns `Conn.WriteMsg`, `ReadMsgHeader`,
`Msg.Unpack` and native TSIG verification, with no duplicate application DNS
framing stack. The small plain exchange boundary retains native EDNS receive
size, UDP ID filtering and the inherited two-second I/O default when its native
timeout is zero. DoT retains its separately documented zero-timeout behavior.
Miekg/dns is BSD-3-Clause; its pinned module and license remain unchanged.

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

DoH request construction preserves the configured URL's escaped path. Dropping
`RawPath` changed endpoints such as `/dns%2Fquery` into `/dns/query`. Actual
HTTP/1.1, HTTP/2 and HTTP/3 exchanges cover encoded separators, literal escaped
characters, question marks, fragments and percent signs before comparing the
request path. The native GET query parameter and response validation are unchanged.

Use a task branch, independent review of the exact commit, green local and PR
checks, a PR to `master`, and CI verification of the resulting master commit.
Upstream mirroring, private AdGuard automation, image publication and releases
are not part of this fork's CI.
# DNSCrypt transport ownership

The `dnscrypt/` package adopts AdguardTeam/dnscrypt v0.0.2 at
`2eb01a7a527fbf26aeba502d8e2a4c0ae39997bd`. See its
[adaptation record](dnscrypt/ADAPTATION.md) for the copied source boundary,
original Unlicense, exact changes, rejected wrapper approach and real TCP
counterexamples. All client, proxy, command and test imports use that package;
the previous external dependency is removed. Shutdown closes accepted sockets
before joining work, including certificate-handshake writers outside middleware.
