package sink

import (
	"context"
	"sync"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/engine"
)

// Hub retains the most recent alerts in a ring buffer (for the query API) and
// broadcasts new alerts to live subscribers (for Server-Sent Events). Slow
// subscribers lose alerts rather than slowing the hub.
type Hub struct {
	mu      sync.RWMutex
	ring    []*engine.Alert
	next    int
	full    bool
	subs    map[chan *engine.Alert]struct{}
	dropped uint64
}

// NewHub creates a hub retaining capacity alerts.
func NewHub(capacity int) *Hub {
	if capacity <= 0 {
		capacity = 1000
	}
	return &Hub{ring: make([]*engine.Alert, capacity), subs: make(map[chan *engine.Alert]struct{})}
}

// Name implements Sink.
func (h *Hub) Name() string { return "hub" }

// Deliver implements Sink.
func (h *Hub) Deliver(_ context.Context, a *engine.Alert) error {
	h.mu.Lock()
	h.ring[h.next] = a
	h.next = (h.next + 1) % len(h.ring)
	if h.next == 0 {
		h.full = true
	}
	for ch := range h.subs {
		select {
		case ch <- a:
		default:
			h.dropped++
		}
	}
	h.mu.Unlock()
	return nil
}

// Recent returns up to limit most recent alerts, newest first, optionally
// filtered by rule name and/or key.
func (h *Hub) Recent(limit int, rule, key string) []*engine.Alert {
	h.mu.RLock()
	defer h.mu.RUnlock()
	n := h.next
	if h.full {
		n = len(h.ring)
	}
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]*engine.Alert, 0, limit)
	for i := 1; i <= n && len(out) < limit; i++ {
		a := h.ring[(h.next-i+len(h.ring))%len(h.ring)]
		if a == nil {
			continue
		}
		if rule != "" && a.Rule != rule {
			continue
		}
		if key != "" && a.Key != key {
			continue
		}
		out = append(out, a)
	}
	return out
}

// Subscribe registers a live subscriber. The returned cancel func must be
// called to release it.
func (h *Hub) Subscribe(buffer int) (<-chan *engine.Alert, func()) {
	if buffer <= 0 {
		buffer = 256
	}
	ch := make(chan *engine.Alert, buffer)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			if _, ok := h.subs[ch]; ok {
				delete(h.subs, ch)
				close(ch)
			}
			h.mu.Unlock()
		})
	}
}

// Subscribers returns the live subscriber count.
func (h *Hub) Subscribers() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs)
}

// Close implements Sink: disconnects all subscribers.
func (h *Hub) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		delete(h.subs, ch)
		close(ch)
	}
	return nil
}
