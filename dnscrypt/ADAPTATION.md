# DNSCrypt source ownership

This directory adopts the library from
[`AdguardTeam/dnscrypt` v0.0.2](https://github.com/AdguardTeam/dnscrypt/tree/2eb01a7a527fbf26aeba502d8e2a4c0ae39997bd)
(commit `2eb01a7a527fbf26aeba502d8e2a4c0ae39997bd`, 2026-07-02).
Its original Unlicense is preserved in [LICENSE](LICENSE).

The copied boundary is the root library's Go files and tests, `testdata`,
`internal/xsecretbox`, and `internal/dnscrypttest`. Relative paths are unchanged
under this directory. Module imports now use
`github.com/holandyoung/dnsproxy/dnscrypt`. The source repository's command,
forwarder, build scripts and tool dependencies are not product consumers and
are not adopted. The generator's exported library API and configuration file
format remain native. No cryptographic algorithm is changed.

All dnsproxy client and server imports use this owner. The original module
dependency is removed; no replace directive or compatibility facade remains.
Update this source deliberately when updating the native DNS foundation.

## Why the adoption is necessary

The upstream release and its current master are the same commit. Two actual
TCP tests falsified its suitability for the approved lifecycle:

- A valid certificate query's two-byte length prefix, split across TCP writes,
  returned EOF. Reading the prefix once ignored valid short reads.
- A client that writes certificate queries without reading filled the server's
  send buffer. Shutdown closed the listening port but only changed accepted
  sockets' read deadlines; a blocked write and its socket remained until the
  client disconnected. Certificate exchanges happen before proxy middleware.

Fixing a wrapper around Shutdown would only bound the wait and retain the
resource. Adopting this mature implementation into the existing integration
fork keeps the protocol and its physical ownership together without creating
a second external fork or reimplementing DNSCrypt cryptography.

## Local changes

- `dns.go`: read the full TCP prefix, reject oversized outgoing frames before
  narrowing their length. Remove the impossible uint16 > 65535 read check.
- `server.go`, `servertcp.go`, `serverudp.go`: one serving run owns its context,
  listeners, accepted sockets and completion channel. Register that run before
  Start returns; join admitted work before publishing completion. Stop cancels
  handlers and closes physical sockets even with an expired caller context.
  Restart is rejected until the previous run actually exits. Repeated Shutdown
  calls join that same run. UDP socket setup occurs before successful startup.
- `servertcp.go`: reject connections accepted concurrently with shutdown and
  bound certificate and encrypted-response writes using the native first-read
  timeout, starting immediately before the physical write. Handler execution
  does not consume that deadline. Slow peers cannot pin the connection indefinitely.
- `ownership_test.go`, `blocked_write_internal_test.go`: actual whole/split TCP frames, observed blocked writes,
  empty and partial TCP, expired-context closure, immediate shutdown/restart,
  slow successful encrypted handlers, and restart blocked until an admitted
  handler actually exits.

Before the repair, the intact-frame control passed while the split frame and
retained-writer assertions failed. The blocked-write fixture sets its accepted
TCP socket send buffer explicitly before asserting an actual blocked write, so
the precondition does not depend on the host's TCP autotuning limits. The original upstream protocol, certificate,
client, crypto and UDP truncation tests remain part of the fork's full race gate.
No new support for DNSCrypt receipt admission is implied: the product's six
upstream protocols use the separate native receipt contract.
