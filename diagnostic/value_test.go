package diagnostic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

type countedError struct{ calls int }

func (e *countedError) Error() string {
	e.calls++

	return "complete panic value"
}

type borrowedHandler struct {
	slog.Handler
	value   any
	records int
	enabled bool
}

func (h *borrowedHandler) Enabled(context.Context, slog.Level) bool { return h.enabled }

func (h *borrowedHandler) Handle(_ context.Context, record slog.Record) error {
	h.records++
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key == "panic" {
			h.value = attr.Value.Any()
		}

		return true
	})

	return nil
}

func panicOriginFixture(logger *slog.Logger, value any, cleanup *int) {
	defer func() { *cleanup++ }()
	defer RecoverAndLog(context.Background(), logger)

	panicValueFixture(value)
}

func panicValueFixture(value any) { panic(value) }

func panicBoundsFixture(index int) {
	values := []string{"one"}
	_ = values[index]
}

func TestRecoveryPrecedesLoggingAndEnabledPrecedesCapture(t *testing.T) {
	value := &countedError{}
	handler := &borrowedHandler{}
	logger := slog.New(handler)
	cleanups := 0
	allocations := testing.AllocsPerRun(100, func() {
		panicOriginFixture(logger, value, &cleanups)
	})
	if allocations != 0 || cleanups != 101 || handler.records != 0 || value.calls != 0 {
		t.Fatalf("disabled recovery: allocations=%v cleanups=%d records=%d presentations=%d", allocations, cleanups, handler.records, value.calls)
	}

	handler.enabled = true
	panicOriginFixture(logger, value, &cleanups)
	borrowed, ok := handler.value.(RecoveredPanic)
	if !ok || borrowed.Value != value || handler.records != 1 || value.calls != 0 || cleanups != 102 {
		t.Fatalf("enabled producer did not deliver one complete borrowed value: %+v calls=%d cleanups=%d", handler, value.calls, cleanups)
	}
}

func TestSynchronousPanicContainsValueAndOriginStack(t *testing.T) {
	for _, value := range []any{errors.New("complete error"), "complete string", 42} {
		var output bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&output, nil))
		cleanups := 0
		panicOriginFixture(logger, value, &cleanups)
		var record struct {
			Panic struct {
				Value      any
				Err, Stack string
			}
		}
		if err := json.Unmarshal(output.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		if cleanups != 1 || !strings.Contains(record.Panic.Stack, "panicOriginFixture") || !strings.Contains(record.Panic.Stack, "goroutine ") {
			t.Fatalf("origin stack or cleanup lost: %s", output.Bytes())
		}
		switch x := value.(type) {
		case error:
			if record.Panic.Err != x.Error() {
				t.Fatalf("error value changed: %s", output.Bytes())
			}
		case string:
			if record.Panic.Value != x {
				t.Fatalf("string value changed: %s", output.Bytes())
			}
		case int:
			if record.Panic.Value != float64(x) {
				t.Fatalf("numeric value changed: %s", output.Bytes())
			}
		}
	}
}

func TestNormalReturnDoesNotCreatePanicDiagnostic(t *testing.T) {
	handler := &borrowedHandler{enabled: true}
	func() {
		defer RecoverAndLog(t.Context(), slog.New(handler))
	}()
	if handler.records != 0 {
		t.Fatalf("normal return produced %d records", handler.records)
	}
}

func TestNativeRuntimePanicsRemainComplete(t *testing.T) {
	t.Setenv("GODEBUG", "panicnil=0")
	for _, trigger := range []func(){
		func() { var value any = 1; _ = value.(string) },
		func() { panicBoundsFixture(len(t.Name())) },
		func() { panicValueFixture(nil) },
	} {
		var output bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&output, nil))
		func() {
			defer RecoverAndLog(t.Context(), logger)
			trigger()
		}()
		var record struct {
			Panic struct{ Err, Stack string }
		}
		if err := json.Unmarshal(output.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		if record.Panic.Err == "" || !strings.Contains(record.Panic.Stack, "TestNativeRuntimePanicsRemainComplete") {
			t.Fatalf("runtime panic information lost: %s", output.Bytes())
		}
	}
}
