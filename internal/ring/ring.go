// Package ring implements a bounded, lock-free multi-producer / multi-consumer
// queue (Dmitry Vyukov's sequence-cell algorithm) with an optional parking
// "doorbell" so that idle consumers do not spin.
//
// Every cell carries a sequence number. A producer claims position p by CAS on
// the tail when cell[p & mask].seq == p, writes the value, then publishes it
// by storing seq = p+1. A consumer claims position p when seq == p+1, reads the
// value, then releases the cell to the next lap with seq = p+cap. Producers
// and consumers therefore never touch the same cache line except on the
// actual hand-off cell, and there are no locks on the hot path.
package ring

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"time"
)

const cacheLine = 64

// ErrClosed is returned by blocking operations after Close.
var ErrClosed = errors.New("ring: closed")

type cell[T any] struct {
	seq atomic.Uint64
	val T
}

// Ring is a bounded MPMC queue. The zero value is not usable; use New.
type Ring[T any] struct {
	_      [cacheLine]byte
	tail   atomic.Uint64 // next position to enqueue
	_      [cacheLine - 8]byte
	head   atomic.Uint64 // next position to dequeue
	_      [cacheLine - 8]byte
	mask   uint64
	cells  []cell[T]
	closed atomic.Bool
	// bell wakes a parked consumer. Capacity 1 coalesces wake-ups.
	bell chan struct{}
	// parked is non-zero while a consumer is (about to be) parked; producers
	// only pay for a channel send when someone is actually waiting.
	parked atomic.Int32
	// space wakes producers blocked on a full ring.
	space        chan struct{}
	spaceWaiters atomic.Int32
}

// New creates a ring whose capacity is size rounded up to a power of two
// (minimum 2).
func New[T any](size int) *Ring[T] {
	if size < 2 {
		size = 2
	}
	c := uint64(1)
	for c < uint64(size) {
		c <<= 1
	}
	r := &Ring[T]{
		mask:  c - 1,
		cells: make([]cell[T], c),
		bell:  make(chan struct{}, 1),
		space: make(chan struct{}, 1),
	}
	for i := range r.cells {
		r.cells[i].seq.Store(uint64(i))
	}
	return r
}

// Cap returns the ring capacity.
func (r *Ring[T]) Cap() int { return int(r.mask + 1) }

// Len returns an approximate number of queued items.
func (r *Ring[T]) Len() int {
	t, h := r.tail.Load(), r.head.Load()
	if t < h {
		return 0
	}
	return int(t - h)
}

// TryPush enqueues v without blocking. It returns false if the ring is full
// or closed.
func (r *Ring[T]) TryPush(v T) bool {
	if r.closed.Load() {
		return false
	}
	pos := r.tail.Load()
	for {
		c := &r.cells[pos&r.mask]
		seq := c.seq.Load()
		switch diff := int64(seq) - int64(pos); {
		case diff == 0:
			if r.tail.CompareAndSwap(pos, pos+1) {
				c.val = v
				c.seq.Store(pos + 1)
				r.ring()
				return true
			}
			pos = r.tail.Load()
		case diff < 0:
			return false // full
		default:
			pos = r.tail.Load()
		}
	}
}

// Push enqueues v, blocking while the ring is full until ctx is done or the
// ring is closed. Waiting uses a bounded spin, then yields, then parks.
func (r *Ring[T]) Push(ctx context.Context, v T) error {
	for spins := 0; ; spins++ {
		if r.closed.Load() {
			return ErrClosed
		}
		if r.TryPush(v) {
			return nil
		}
		switch {
		case spins < 32:
			// busy spin: the consumer is usually microseconds away.
		case spins < 64:
			runtime.Gosched()
		default:
			r.spaceWaiters.Add(1)
			// Re-check after announcing ourselves to avoid a lost wake-up.
			if r.TryPush(v) {
				r.spaceWaiters.Add(-1)
				return nil
			}
			t := time.NewTimer(time.Millisecond)
			select {
			case <-r.space:
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				r.spaceWaiters.Add(-1)
				return ctx.Err()
			}
			t.Stop()
			r.spaceWaiters.Add(-1)
		}
	}
}

// TryPop dequeues one item without blocking.
func (r *Ring[T]) TryPop() (v T, ok bool) {
	pos := r.head.Load()
	for {
		c := &r.cells[pos&r.mask]
		seq := c.seq.Load()
		switch diff := int64(seq) - int64(pos+1); {
		case diff == 0:
			if r.head.CompareAndSwap(pos, pos+1) {
				v = c.val
				var zero T
				c.val = zero // release references for the GC
				c.seq.Store(pos + r.mask + 1)
				r.signalSpace()
				return v, true
			}
			pos = r.head.Load()
		case diff < 0:
			return v, false // empty
		default:
			pos = r.head.Load()
		}
	}
}

// PopBatch drains up to len(dst) items into dst without blocking and returns
// the number written. Batching amortises the doorbell and space signalling.
func (r *Ring[T]) PopBatch(dst []T) int {
	n := 0
	var zero T
	for n < len(dst) {
		pos := r.head.Load()
		c := &r.cells[pos&r.mask]
		seq := c.seq.Load()
		diff := int64(seq) - int64(pos+1)
		if diff < 0 {
			break
		}
		if diff > 0 || !r.head.CompareAndSwap(pos, pos+1) {
			continue
		}
		dst[n] = c.val
		c.val = zero
		c.seq.Store(pos + r.mask + 1)
		n++
	}
	if n > 0 {
		r.signalSpace()
	}
	return n
}

// Wait parks the caller until an item may be available, the timeout elapses,
// or the ring is closed. It returns false only if the ring is closed and
// empty.
func (r *Ring[T]) Wait(timeout time.Duration) bool {
	if r.Len() > 0 {
		return true
	}
	r.parked.Add(1)
	defer r.parked.Add(-1)
	if r.Len() > 0 {
		return true
	}
	if r.closed.Load() {
		return false
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-r.bell:
	case <-t.C:
	}
	return !(r.closed.Load() && r.Len() == 0)
}

// Close marks the ring closed. Pending items can still be drained.
func (r *Ring[T]) Close() {
	if r.closed.CompareAndSwap(false, true) {
		select {
		case r.bell <- struct{}{}:
		default:
		}
		select {
		case r.space <- struct{}{}:
		default:
		}
	}
}

// Closed reports whether Close has been called.
func (r *Ring[T]) Closed() bool { return r.closed.Load() }

func (r *Ring[T]) ring() {
	if r.parked.Load() > 0 {
		select {
		case r.bell <- struct{}{}:
		default:
		}
	}
}

func (r *Ring[T]) signalSpace() {
	if r.spaceWaiters.Load() > 0 {
		select {
		case r.space <- struct{}{}:
		default:
		}
	}
}
