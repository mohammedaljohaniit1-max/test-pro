package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/engine"
)

func alert(i int) *engine.Alert {
	return &engine.Alert{ID: "a" + string(rune('0'+i%10)), Rule: "r", Key: "k", Severity: "high", EventTime: 1, DetectedAt: 2, Fields: map[string]any{"i": i}}
}

func TestWebhookSuccessAndSignature(t *testing.T) {
	var got atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts := r.Header.Get("X-Tempora-Timestamp")
		if r.Header.Get("X-Tempora-Signature") != "sha256="+Sign("s3cret", ts, body) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var m map[string]any
		if json.Unmarshal(body, &m) != nil || m["rule"] != "r" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		got.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	wh, _ := NewWebhook(WebhookOptions{URL: srv.URL, Secret: "s3cret"})
	if err := wh.Deliver(context.Background(), alert(1)); err != nil {
		t.Fatal(err)
	}
	if got.Load() != 1 {
		t.Fatal("not delivered")
	}
}

func TestWebhookRetriesTransientFailures(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	wh, _ := NewWebhook(WebhookOptions{URL: srv.URL, MaxRetries: 4, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond})
	if err := wh.Deliver(context.Background(), alert(1)); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestWebhookDoesNotRetry4xx(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	wh, _ := NewWebhook(WebhookOptions{URL: srv.URL, MaxRetries: 5, BaseDelay: time.Millisecond})
	if err := wh.Deliver(context.Background(), alert(1)); err == nil {
		t.Fatal("expected error")
	}
	if calls.Load() != 1 {
		t.Fatalf("4xx retried: %d calls", calls.Load())
	}
}

func TestWebhookCircuitBreaker(t *testing.T) {
	var calls atomic.Int32
	var healthy atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		if healthy.Load() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	wh, _ := NewWebhook(WebhookOptions{URL: srv.URL, MaxRetries: 0, FailThreshold: 3, Cooldown: 50 * time.Millisecond})
	for i := 0; i < 3; i++ {
		_ = wh.Deliver(context.Background(), alert(i))
	}
	if wh.State() != "open" {
		t.Fatalf("state=%s", wh.State())
	}
	before := calls.Load()
	if err := wh.Deliver(context.Background(), alert(9)); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected open circuit, got %v", err)
	}
	if calls.Load() != before {
		t.Fatal("open circuit still called endpoint")
	}
	time.Sleep(60 * time.Millisecond)
	healthy.Store(true)
	if err := wh.Deliver(context.Background(), alert(10)); err != nil {
		t.Fatalf("half-open probe failed: %v", err)
	}
	if wh.State() != "closed" {
		t.Fatalf("state after recovery=%s", wh.State())
	}
}

func TestHubRecentAndSubscribe(t *testing.T) {
	h := NewHub(3)
	ch, cancel := h.Subscribe(10)
	for i := 0; i < 5; i++ {
		a := alert(i)
		if i == 4 {
			a.Rule = "other"
		}
		_ = h.Deliver(context.Background(), a)
	}
	rec := h.Recent(0, "", "")
	if len(rec) != 3 || rec[0].Fields["i"] != 4 || rec[2].Fields["i"] != 2 {
		t.Fatalf("recent: %d", len(rec))
	}
	if f := h.Recent(10, "other", ""); len(f) != 1 {
		t.Fatal("rule filter")
	}
	for i := 0; i < 5; i++ {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("subscriber missed alerts")
		}
	}
	cancel()
	cancel() // idempotent
	if h.Subscribers() != 0 {
		t.Fatal("subscriber not removed")
	}
	_, c2 := h.Subscribe(1)
	_ = h.Close()
	c2() // cancel after close must not panic
}

type slowSink struct {
	mu    sync.Mutex
	n     int
	block chan struct{}
}

func (s *slowSink) Name() string { return "slow" }
func (s *slowSink) Deliver(context.Context, *engine.Alert) error {
	<-s.block
	s.mu.Lock()
	s.n++
	s.mu.Unlock()
	return nil
}
func (s *slowSink) Close() error { return nil }

type countSink struct{ n atomic.Int64 }

func (c *countSink) Name() string                                 { return "count" }
func (c *countSink) Deliver(context.Context, *engine.Alert) error { c.n.Add(1); return nil }
func (c *countSink) Close() error                                 { return nil }

// TestDispatcherIsolatesSlowSinks: a sink that blocks forever must not stall
// the dispatcher or starve other sinks; its overflow is dropped and counted.
func TestDispatcherIsolatesSlowSinks(t *testing.T) {
	fast := &countSink{}
	slow := &slowSink{block: make(chan struct{})}
	const n, q = 200, 64
	d := NewDispatcher(slog.New(slog.NewTextHandler(io.Discard, nil)), q, fast, slow)
	ch := make(chan *engine.Alert)
	done := make(chan struct{})
	go func() { d.Run(context.Background(), ch); close(done) }()
	sent := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			ch <- alert(i)
			if i%16 == 0 {
				time.Sleep(time.Millisecond) // let the fast worker keep pace
			}
		}
		close(sent)
	}()
	select {
	case <-sent:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatcher stalled behind a blocked sink")
	}
	deadline := time.Now().Add(2 * time.Second)
	for fast.n.Load()+int64(d.Stats()[0].Dropped) < n && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(slow.block)
	close(ch)
	<-done
	st := d.Stats()
	if st[0].Delivered+st[0].Dropped != n || st[0].Delivered < n/2 {
		t.Fatalf("fast sink starved: %+v", st[0])
	}
	if st[1].Dropped == 0 || st[1].Delivered+st[1].Dropped != n {
		t.Fatalf("slow sink accounting: %+v", st[1])
	}
	if d.Total() != n {
		t.Fatal("total")
	}
}

func TestJSONLinesFormat(t *testing.T) {
	var buf bytes.Buffer
	s := NewJSONLines("buf", &buf)
	for i := 0; i < 3; i++ {
		if err := s.Deliver(context.Background(), alert(i)); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Close()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines=%d", len(lines))
	}
	for _, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil || m["rule"] != "r" {
			t.Fatalf("invalid JSON line %q", line)
		}
	}
}
