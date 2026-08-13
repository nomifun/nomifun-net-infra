package console

import (
	"bytes"
	"context"
	"net/http"
	"sync"
	"testing"
	"time"
)

// streamRecorder 是一个支持 Flush 的 ResponseWriter，用于测试 SSE。
//
// httptest.ResponseRecorder 虽然实现了 Flush，但它的 Body 不是并发安全的 ——
// SSE 测试里一个 goroutine 在写、测试主体在读，必须加锁，否则 -race 会报告。
type streamRecorder struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	header http.Header
	code   int
}

func newStreamRecorder() *streamRecorder {
	return &streamRecorder{header: make(http.Header), code: http.StatusOK}
}

func (r *streamRecorder) Header() http.Header { return r.header }

func (r *streamRecorder) Write(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.Write(b)
}

func (r *streamRecorder) WriteHeader(code int) { r.code = code }

// Flush 让 http.NewResponseController 能找到 flush 能力。
func (r *streamRecorder) Flush() {}

func (r *streamRecorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}

func contextWithTimeout(t *testing.T, d time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), d)
}
