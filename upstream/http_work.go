package upstream

import (
	"context"
	"net"
	"sync"
)

// httpWork belongs to one Exchange, not its reusable transport. net/http can
// finish RoundTrip while a dial still runs, and can start a queued dial even
// later. Sealing admission and joining admitted children share one mutex.
type httpWork struct {
	work   sync.WaitGroup
	mu     sync.Mutex
	sealed bool
}

func (w *httpWork) begin() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.sealed {
		return false
	}
	w.work.Add(1)
	return true
}

func (w *httpWork) join() {
	w.mu.Lock()
	w.sealed = true
	w.mu.Unlock()
	w.work.Wait()
}

type httpRequestScopeKey struct{}

type httpRequestScope struct {
	request context.Context
	work    *httpWork
}

// beginHTTPDial restores the original request deadline/cancellation that native
// net/http deliberately removes from its dial context, while still observing
// native cancellation. It accounts the whole TLS/QUIC setup, not only TCP/UDP.
func beginHTTPDial(native context.Context) (ctx context.Context, finish func(), err error) {
	scope, ok := native.Value(httpRequestScopeKey{}).(httpRequestScope)
	if !ok || !scope.work.begin() {
		return nil, nil, net.ErrClosed
	}
	ctx, cancel := context.WithCancel(scope.request)
	stop := context.AfterFunc(native, cancel)
	finish = func() { stop(); cancel(); scope.work.work.Done() }
	if err = ctx.Err(); err != nil {
		finish()
		return nil, nil, err
	}
	return ctx, finish, nil
}
