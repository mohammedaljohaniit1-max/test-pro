// Package pq provides allocation-conscious priority queues used by the shard
// event loop:
//
//   - Heap: a generic 4-ary min-heap (used as the out-of-order reorder buffer).
//   - Timers: an indexed 4-ary min-heap of deadlines with O(log n) cancel and
//     reschedule, used for window expiry and absence (negation) deadlines.
//
// A 4-ary layout halves tree depth relative to a binary heap and keeps
// siblings in the same cache line, which measurably helps sift-down on the
// hot path.
package pq

// Heap is a 4-ary min-heap ordered by less. Not safe for concurrent use.
type Heap[T any] struct {
	items []T
	less  func(a, b T) bool
}

// NewHeap creates a heap with the given ordering.
func NewHeap[T any](less func(a, b T) bool, capacity int) *Heap[T] {
	return &Heap[T]{items: make([]T, 0, capacity), less: less}
}

// Len returns the number of items.
func (h *Heap[T]) Len() int { return len(h.items) }

// Peek returns the minimum without removing it.
func (h *Heap[T]) Peek() (T, bool) {
	if len(h.items) == 0 {
		var zero T
		return zero, false
	}
	return h.items[0], true
}

// Push inserts v.
func (h *Heap[T]) Push(v T) {
	h.items = append(h.items, v)
	h.up(len(h.items) - 1)
}

// Pop removes and returns the minimum.
func (h *Heap[T]) Pop() (T, bool) {
	var zero T
	n := len(h.items)
	if n == 0 {
		return zero, false
	}
	top := h.items[0]
	last := n - 1
	h.items[0] = h.items[last]
	h.items[last] = zero
	h.items = h.items[:last]
	if last > 0 {
		h.down(0)
	}
	return top, true
}

func (h *Heap[T]) up(i int) {
	it := h.items
	v := it[i]
	for i > 0 {
		p := (i - 1) >> 2
		if !h.less(v, it[p]) {
			break
		}
		it[i] = it[p]
		i = p
	}
	it[i] = v
}

func (h *Heap[T]) down(i int) {
	it := h.items
	n := len(it)
	v := it[i]
	for {
		c := i<<2 + 1
		if c >= n {
			break
		}
		m := c
		end := c + 4
		if end > n {
			end = n
		}
		for j := c + 1; j < end; j++ {
			if h.less(it[j], it[m]) {
				m = j
			}
		}
		if !h.less(it[m], v) {
			break
		}
		it[i] = it[m]
		i = m
	}
	it[i] = v
}
