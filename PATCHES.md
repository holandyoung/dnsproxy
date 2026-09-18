# HyperCacheDNS integration fork

This module is `github.com/holandyoung/dnsproxy`, based on AdGuard's dnsproxy
v0.84.2, commit `096ff91186cbc334ede2e3c40f02a6ad6cf71dbb`. Upstream authorship
and the Apache 2.0 license remain intact. HyperCacheDNS consumes an immutable
fork revision directly; it does not replace the upstream module at build time.

## Required semantics and deviations

DNS message diagnostics use one structured debug record with direction and the
complete borrowed `diagnostic.DNSMessage` value; the former eager `String`/per-line dump is retired.
The Enabled check precedes all message processing, including at info level.
The synchronous handler consumes the message during Handle. An asynchronous
handler must recognize this typed value before resolving LogValuer, reserve
capacity and take its own immutable Msg snapshot before Handle returns, then
format/write it in its worker; Record.Clone alone does not copy
Any payloads. This is a log format change, not a DNS wire or query policy change.
TestDNSDiagnosticsDeferPresentation detects producer-side text generation and
requires the entire message to reach an enabled handler. Disabled logging never
evaluates the RR presentation. Application queue/byte limits, drops, metrics
and shutdown remain the application's ownership and acceptance boundary.
DNSMessage.LogValue retains the complete native DNS text: directly passing
dns.Msg to encoding/json loses empty-struct SVCB parameter identities.
TestDNSDiagnosticsJSONPreservesParameterIdentity covers real packable HTTPS
records with distinct no-default-alpn and ohttp values through standard slog JSON.
Per-request UDP peer/local/protocol and HTTP proxy attributes are submitted on
each record, not retained through dynamic WithAttrs handlers. Static logger
prefixes remain construction-time metadata. TestRequestDiagnosticsHavePerRecordOwnership
first completes a real UDP exchange and a native proxied HTTP handler request,
then verifies that both diagnostic paths retain their attributes without
creating child handlers that lack a capacity-admission/release lifetime.

The shared `diagnostic` package also owns `RecoveredPanic` and the directly
deferred recover helper used by proxy and DNSCrypt. It replaces the eager
golibs stack/per-line presentation at those same recovery boundaries, preserving
recovery, return and cleanup behavior even when ERROR output is disabled. One
structured record carries the complete value and native current-goroutine stack.
Standard synchronous slog handlers resolve it directly. Retaining handlers must
reserve capacity before snapshot/capture and must capture the stack while still
in the recovering goroutine. Formatting it later would capture a worker stack.
No logger queue or application-specific budget is added here; application
acceptance owns bounds and loss decisions. `proxy.DNSMessage` is removed without
an alias; both values have one shared package independent of protocol servers.
The bootstrap parallel resolver retains its channel-result recovery boundary and
the native FromRecovered conversion needed by callers; only its diagnostic value
uses the same shared package. Disabled logging cannot suppress that error result.

The inherited pending-request test released its upstream when handlers entered,
before every request had actually joined the pending wave. A forced late Resolve
reproduces its false single-exchange assertion and recovered-panic/EOF failure.
The replacement uses Go's native [testing/synctest](https://go.dev/pkg/testing/synctest/)
barrier through the real Resolve path: all 100 calls must block, share exactly one
exchange and preserve caller IDs; an uncached later call must start a new exchange.
A separate real TCP test forces that late arrival and verifies both replies.
No pending-request production behavior, time budget or gate is weakened.

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

DNSCrypt certificate acquisition, encrypted UDP and TCP continuation use the
same optional NetworkDialer and one exchange deadline. Concurrent calls share
one verified, valid certificate; expired certificates are fetched again under
the same provider public key and verification callback. Waiting for a refresher
is cancelable and Close cancels every exchange. A complete ciphertext reserves
the existing invocation-local ExchangeState before bounded authentication and
decoding; bad authentication, ID, question or UDP truncation releases it before
any continuation. A final answer publishes before physical Close. The adopted
client changes its sole exchange signature to carry an optional per-call
ResponseObserver; no legacy overload or second receipt owner remains.
Evidence: TestDNSCryptRoutedReceiptAndTCPContinuation,
TestDNSCryptConcurrentCertificateRenewal, TestDNSCryptReceiptBeforePhysicalClose,
TestDNSCryptCloseCancelsCertificateAndEncryptedWork,
TestDNSCryptOneBudgetCoversCertificateAndTCP,
TestDNSCryptRoutedCertificateHasNoNativeCeiling and
TestDNSCryptInvalidReplyCannotPublishReceipt.

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

`go.mod` owns the Go version and native tool versions. `sh scripts/check.sh`
(`make check`) is the single local, hook, PR and master gate: gofmt, module
integrity, vet and staticcheck across Darwin/FreeBSD/Linux/OpenBSD/Windows,
nilness, ineffassign, unparam, fieldalignment, strict shadow, errcheck, gosec,
ShellCheck, JSON/YAML validation, the full shuffled/repeated race suite and
vulnerability scanning. ShellCheck and jq are explicit CI prerequisites.
The old duplicate dispatchers, Make targets and their unsupported POSIX-shell
pipefail options are retired together. Go's `work` and `tool` patterns are
native supported features; they were not private tooling. The old lint script
contained valid semantic checks, which remain in the single gate. Staticcheck
is updated to v0.8.1 because the older analyzer panics on Go 1.27 syntax.
Fork style follows gofmt and semantic analyzers: inherited filename bans,
standard-library import bans, arbitrary complexity thresholds, spelling and
alternate source/Markdown formatters are retired, not treated as evidence of
correctness. No vulnerability or semantic rule is disabled globally.
Protocol conformance uses real local servers
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

## Stamp codec and HTTP authority

The sole stamp codec is jedisct1/go-dnsstamps at
6579dc73e4a24adff7def08165a50d81609f4759 (MIT). It replaces the
ameshkov v1.0.3 codec across client, server, upstream and test callers; no
compatibility adapter remains. The former codec injected obsolete TLS/QUIC
IP ports (843/784) and rejected standardized optional bootstrap fields. The
maintained codec validates physical IP and provider port separately. Unsupported
relay/oblivious protocols remain rejected by the native upstream factory.

Options.HTTPHost carries HTTP Host/:authority independently of URL dial target
and TLS ServerName. Empty preserves native URL authority. This is needed when a
stamp pins a physical IP but addresses a virtual HTTP service; it does not
disable TLS verification. TestDoHHTTPAuthorityIsIndependentOfDialAndTLS covers
actual H1, H2 and H3 exchanges and option cloning. HyperCacheDNS's compiler owns
stamp pin admission and its egress TLS verification callback; merely decoding a
stamp in the generic upstream parser does not establish pin enforcement.

## Frame, cache and certificate representation boundaries

The QUIC dependency uses the temporary `github.com/holandyoung/quic-go` module
for synchronized peer-parameter publication and 0-RTT/datagram generation
ownership. `go.mod` alone owns its immutable pin. The application must consume
the same module and revision, without production replace directives or a second
official QUIC module. Follow the [fork maintenance and exit rules](https://github.com/holandyoung/quic-go/blob/hcdns/PATCHES.md):
inspect official releases and actual source before each product release or
dependency update; once equivalent official behavior passes the original
race/0-RTT/consumer regressions, switch both consumers back and retire the patches.

`proxyutil.LengthPrefix` is the sole checked 16-bit frame encoder; the unchecked
`AddPrefix` API is removed. TCP retains scatter/gather writes without copying
the complete payload. DoQ rejects oversized packed requests before opening a
stream. DNSCrypt retains ErrQueryTooLarge for that rejection. Cache publication
checks both DNS Pack errors and the encoded length instead of storing corrupt
records. Legal frame bytes and complete-message/FIN receipt rules are unchanged.

The optional native caches use signed 64-bit Unix expiration seconds, and
fastip uses signed 64-bit milliseconds and boolean failure state. Large values
no longer wrap into expired or faster entries. Their private in-memory format
has no compatibility reader or disk migration. Fixed byte budgets are unchanged:
fastip payloads grow from 7 to 17 bytes, DNS cache headers from 6 to 10 bytes,
so these optional caches fit fewer entries in the same budget. Existing TTL
admission rules are unchanged. Subnet validation owns family/prefix bounds for
both caching and pending-request keys; invalid masks cannot alias a global
entry. Nil-mask global entries and valid IPv4/IPv6 prefixes remain supported.

Certificate generation observes one clock instant and rejects validity periods
outside the DNSCrypt unsigned 32-bit seconds domain. Verification widens wire
timestamps rather than narrowing the host clock; endpoints remain inclusive.
The protocol's secretbox construction is retained. Poly1305's deprecation and
two proven 32-byte XOR bounds have precise local analyzer explanations, with
independent libsodium 1.0.18 vectors (0/1/31/32/33/63/64/65 bytes), alias tests
and every-byte tamper rejection. It must not be replaced with RFC 8439 AEAD.
See [the DNSCrypt protocol](https://dnscrypt.info/protocol/) and
[libsodium's native construction](https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/crypto_secretbox/xchacha20poly1305/secretbox_xchacha20poly1305.c).

Evidence: TestLengthPrefixBounds, TestTCPRejectsOversizedBeforeWrite,
TestDoQRejectsOversizedBeforeOpeningStream,
TestCacheRejectsInvalidWireAndPreservesLargeTTL, TestCacheWideLatencyAndTime,
TestCacheSubnetRejectsInvalidWithoutGlobalCollision,
TestCertificateProtocolTimeBounds and TestLibsodiumSecretboxVectors. These
targeted checks do not replace full-gate or application performance acceptance.
