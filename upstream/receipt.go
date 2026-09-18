package upstream

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ErrExchangeAbandoned means another logical operation owns the answer.  It
// does not cancel the upstream's network operation or physical cleanup.
var ErrExchangeAbandoned = errors.New("exchange abandoned")

// ExchangeResult is a decision made before physical connection cleanup.  A
// successful Response is immutable and ReceivedAt is its complete-message
// observation time, before DNS decoding.  It is not a kernel arrival timestamp.
type ExchangeResult struct {
	Response   *dns.Msg
	ReceivedAt time.Time
	Err        error
}

// ExchangeState belongs to exactly one Exchange call.  A group may expire or
// abandon it without canceling the native operation.  It never calls user code
// or waits for I/O.  Construct it with NewExchangeState; do not copy it.
type ExchangeState struct {
	result   ExchangeResult
	deadline time.Time
	received time.Time
	done     chan struct{}
	ticket   uint64
	mu       sync.Mutex
	original uint16
	started  bool
	reserved bool
	sealed   bool
	finished bool
}

// NewExchangeState creates a decision owner with a logical cutoff.  A zero
// cutoff leaves admission open until Expire or Abandon is called.  Native
// network timeouts remain independent of this cutoff.
func NewExchangeState(cutoff time.Time) *ExchangeState {
	return &ExchangeState{deadline: cutoff, done: make(chan struct{})}
}

// Done closes when a decision is available, independently of Exchange return.
func (s *ExchangeState) Done() <-chan struct{} { return s.done }

// Result returns the immutable decision and whether it is available.
func (s *ExchangeState) Result() (ExchangeResult, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.result, s.finished
}

// Expire seals admission of new candidates.  An already observed complete
// candidate may finish bounded, local decoding/validation.  It may not hold
// admission across another read, a retry or Close.  No grace timer is added.
func (s *ExchangeState) Expire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sealed = true
	if !s.reserved {
		s.completeLocked(ExchangeResult{Err: context.DeadlineExceeded})
	}
}

// Abandon discards this call immediately, including any candidate currently
// being decoded.  A late response cannot publish another decision.
func (s *ExchangeState) Abandon() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completeLocked(ExchangeResult{Err: ErrExchangeAbandoned})
}

func (s *ExchangeState) start(id uint16) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("exchange state reused")
	}
	s.started, s.original = true, id
	return nil
}

// reserve observes a complete possible final response.  UDP TC and wrong-ID
// packets cannot reserve: the TCP continuation must supply a fresh candidate.
// Observation and the timer use the same lock, so a delayed publisher cannot
// resurrect an already finalized timeout with a previously captured timestamp.
func (s *ExchangeState) reserve(wire []byte, id uint16, udp bool) uint64 {
	if s == nil || len(wire) < 12 || binary.BigEndian.Uint16(wire) != id ||
		wire[2]&0x80 == 0 || (udp && wire[2]&0x02 != 0) {
		return 0
	}
	return s.reserveCandidate()
}

// reserveCandidate also admits complete encrypted frames whose DNS header is
// unavailable until bounded local decryption. Failed authentication, wrong ID,
// invalid questions and UDP truncation release that candidate before any retry.
func (s *ExchangeState) reserveCandidate() uint64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished || s.sealed || s.reserved {
		return 0
	}
	now := time.Now()
	if !s.deadline.IsZero() && now.After(s.deadline) {
		s.completeLocked(ExchangeResult{Err: context.DeadlineExceeded})
		return 0
	}
	s.ticket++
	s.reserved, s.received = true, now
	return s.ticket
}

func (s *ExchangeState) reject(ticket uint64) {
	if s == nil || ticket == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished || !s.reserved || ticket != s.ticket {
		return
	}
	s.reserved = false
	if s.sealed || (!s.deadline.IsZero() && time.Now().After(s.deadline)) {
		s.completeLocked(ExchangeResult{Err: context.DeadlineExceeded})
	}
}

func (s *ExchangeState) accept(ticket uint64, response *dns.Msg) {
	if s == nil || ticket == 0 {
		return
	}
	// The protocol may restore the wire ID or return its message to a caller
	// after publication; the decision owns its independent immutable copy.
	response = response.Copy()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.finished && s.reserved && ticket == s.ticket {
		response.Id = s.original
		s.completeLocked(ExchangeResult{Response: response, ReceivedAt: s.received})
	}
}

func (s *ExchangeState) finish(err error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		err = ErrNoReply
	}
	s.completeLocked(ExchangeResult{Err: err})
}

func (s *ExchangeState) completeLocked(result ExchangeResult) {
	if !s.finished {
		s.result, s.finished, s.reserved = result, true, false
		close(s.done)
	}
}
