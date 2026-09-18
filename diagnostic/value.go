// Package diagnostic exposes borrowed values to synchronous slog handlers.
// Applications that retain records own admission, snapshots and output lifetime.
package diagnostic

import (
	"context"
	"log/slog"
	"runtime/debug"

	"github.com/miekg/dns"
)

// DNSMessage is a borrowed DNS diagnostic value. LogValue uses the native text
// representation to preserve all RR types, including parameter types encoded as
// empty Go structs. Plain encoding/json of dns.Msg loses those identities.
// Asynchronous handlers must copy Msg before returning from Handle and must not
// resolve this value until they process the owned snapshot.
type DNSMessage struct {
	Msg *dns.Msg
}

func (v DNSMessage) LogValue() slog.Value {
	if v.Msg == nil {
		return slog.AnyValue(nil)
	}

	return slog.StringValue(v.Msg.String())
}

// RecoveredPanic carries the complete borrowed panic value. A synchronous
// handler resolves it in the recovering goroutine. An asynchronous handler must
// recognize this type before resolving LogValuer, reserve its capacity, freeze
// Value and capture runtime.Stack(buf, false) before Handle returns. Resolving
// it later in a worker would record the wrong goroutine's stack.
type RecoveredPanic struct {
	Value any
}

func (v RecoveredPanic) LogValue() slog.Value {
	key := "value"
	if _, ok := v.Value.(error); ok {
		key = "err"
	}

	return slog.GroupValue(slog.Any(key, v.Value), slog.String("stack", string(debug.Stack())))
}

// RecoverAndLog must be directly deferred at the existing recovery boundary.
// Recovery happens even when ERROR diagnostics are disabled. Stack capture and
// value presentation belong to the enabled handler, never to the producer.
func RecoverAndLog(ctx context.Context, logger *slog.Logger) {
	value := recover()
	if value == nil || !logger.Enabled(ctx, slog.LevelError) {
		return
	}

	logger.LogAttrs(ctx, slog.LevelError, "recovered from panic", slog.Any("panic", RecoveredPanic{Value: value}))
}
