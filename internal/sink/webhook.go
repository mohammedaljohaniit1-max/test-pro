package sink

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/engine"
)

// ErrCircuitOpen is returned while the webhook circuit breaker is open.
var ErrCircuitOpen = errors.New("sink: webhook circuit open")

// WebhookOptions configure a webhook sink.
type WebhookOptions struct {
	URL        string
	Secret     string // optional HMAC-SHA256 signing key
	Timeout    time.Duration
	MaxRetries int
	BaseDelay  time.Duration
	MaxDelay   time.Duration
	// Breaker: open after FailThreshold consecutive failed deliveries, stay
	// open for Cooldown, then allow a single half-open probe.
	FailThreshold int
	Cooldown      time.Duration
	Client        *http.Client
}

// Webhook POSTs alerts as JSON with exponential backoff + full jitter retries
// and a consecutive-failure circuit breaker.
//
// Headers: Content-Type: application/json, X-Tempora-Rule, X-Tempora-Alert-Id,
// X-Tempora-Timestamp and, when a secret is configured,
// X-Tempora-Signature: sha256=hex(HMAC(secret, timestamp + "." + body)).
type Webhook struct {
	opts WebhookOptions

	mu          sync.Mutex
	consecutive int
	openUntil   time.Time
	halfOpen    bool
}

// NewWebhook validates options and constructs the sink.
func NewWebhook(o WebhookOptions) (*Webhook, error) {
	if o.URL == "" {
		return nil, errors.New("sink: webhook url required")
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.MaxRetries < 0 {
		o.MaxRetries = 0
	}
	if o.BaseDelay <= 0 {
		o.BaseDelay = 200 * time.Millisecond
	}
	if o.MaxDelay <= 0 {
		o.MaxDelay = 10 * time.Second
	}
	if o.FailThreshold <= 0 {
		o.FailThreshold = 5
	}
	if o.Cooldown <= 0 {
		o.Cooldown = 30 * time.Second
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: o.Timeout}
	}
	return &Webhook{opts: o}, nil
}

// Name implements Sink.
func (w *Webhook) Name() string { return "webhook:" + w.opts.URL }

func (w *Webhook) allow(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.consecutive < w.opts.FailThreshold {
		return true
	}
	if now.Before(w.openUntil) {
		return false
	}
	if w.halfOpen {
		return false // a probe is already in flight
	}
	w.halfOpen = true
	return true
}

func (w *Webhook) record(ok bool, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.halfOpen = false
	if ok {
		w.consecutive = 0
		return
	}
	w.consecutive++
	if w.consecutive >= w.opts.FailThreshold {
		w.openUntil = now.Add(w.opts.Cooldown)
	}
}

// State returns "closed", "open" or "half-open".
func (w *Webhook) State() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case w.consecutive < w.opts.FailThreshold:
		return "closed"
	case w.halfOpen || !time.Now().Before(w.openUntil):
		return "half-open"
	}
	return "open"
}

// Deliver implements Sink.
func (w *Webhook) Deliver(ctx context.Context, a *engine.Alert) error {
	if !w.allow(time.Now()) {
		return ErrCircuitOpen
	}
	body, err := json.Marshal(a)
	if err != nil {
		w.record(true, time.Now()) // not the endpoint's fault
		return err
	}
	var lastErr error
	for attempt := 0; attempt <= w.opts.MaxRetries; attempt++ {
		if attempt > 0 {
			d := w.backoff(attempt)
			t := time.NewTimer(d)
			select {
			case <-ctx.Done():
				t.Stop()
				w.record(false, time.Now())
				return ctx.Err()
			case <-t.C:
			}
		}
		retry, err := w.post(ctx, a, body)
		if err == nil {
			w.record(true, time.Now())
			return nil
		}
		lastErr = err
		if !retry {
			break
		}
	}
	w.record(false, time.Now())
	return lastErr
}

// backoff: exponential with full jitter, capped.
func (w *Webhook) backoff(attempt int) time.Duration {
	d := w.opts.BaseDelay << uint(attempt-1)
	if d <= 0 || d > w.opts.MaxDelay {
		d = w.opts.MaxDelay
	}
	return time.Duration(rand.Int64N(int64(d)) + 1)
}

func (w *Webhook) post(ctx context.Context, a *engine.Alert, body []byte) (retry bool, err error) {
	rctx, cancel := context.WithTimeout(ctx, w.opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, w.opts.URL, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tempora-webhook/1")
	req.Header.Set("X-Tempora-Rule", a.Rule)
	req.Header.Set("X-Tempora-Alert-Id", a.ID)
	req.Header.Set("X-Tempora-Timestamp", ts)
	if w.opts.Secret != "" {
		req.Header.Set("X-Tempora-Signature", "sha256="+Sign(w.opts.Secret, ts, body))
	}
	resp, err := w.opts.Client.Do(req)
	if err != nil {
		return ctx.Err() == nil, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return true, fmt.Errorf("sink: webhook status %d", resp.StatusCode)
	default:
		return false, fmt.Errorf("sink: webhook status %d (not retried)", resp.StatusCode)
	}
}

// Sign computes the webhook signature hex(HMAC-SHA256(secret, ts + "." + body)).
func Sign(secret, ts string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts))
	m.Write([]byte{'.'})
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// Close implements Sink.
func (w *Webhook) Close() error { return nil }
