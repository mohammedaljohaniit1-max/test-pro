package pq

// TimerID identifies a scheduled timer. The zero value is never issued.
type TimerID uint64

// Timer is a scheduled deadline with an opaque payload.
type Timer[P any] struct {
	ID       TimerID
	Deadline int64
	Payload  P
}

type timerSlot[P any] struct {
	t   Timer[P]
	seq uint64 // FIFO tie-break for equal deadlines
}

// Timers is an indexed 4-ary min-heap of deadlines. Each timer's heap
// position is tracked in a map so that Cancel and Reset run in O(log n)
// without tombstones. Not safe for concurrent use: it is owned by exactly one
// shard goroutine.
type Timers[P any] struct {
	heap   []timerSlot[P]
	index  map[TimerID]int
	nextID TimerID
	seq    uint64
}

// NewTimers creates an empty timer heap.
func NewTimers[P any]() *Timers[P] {
	return &Timers[P]{index: make(map[TimerID]int)}
}

// Len returns the number of pending timers.
func (t *Timers[P]) Len() int { return len(t.heap) }

// Schedule adds a timer and returns its id.
func (t *Timers[P]) Schedule(deadline int64, payload P) TimerID {
	t.nextID++
	t.seq++
	id := t.nextID
	t.heap = append(t.heap, timerSlot[P]{t: Timer[P]{ID: id, Deadline: deadline, Payload: payload}, seq: t.seq})
	i := len(t.heap) - 1
	t.index[id] = i
	t.up(i)
	return id
}

// Cancel removes a pending timer. It reports whether the timer existed.
func (t *Timers[P]) Cancel(id TimerID) bool {
	i, ok := t.index[id]
	if !ok {
		return false
	}
	t.removeAt(i)
	return true
}

// Reset moves an existing timer to a new deadline.
func (t *Timers[P]) Reset(id TimerID, deadline int64) bool {
	i, ok := t.index[id]
	if !ok {
		return false
	}
	old := t.heap[i].t.Deadline
	t.heap[i].t.Deadline = deadline
	t.seq++
	t.heap[i].seq = t.seq
	if deadline < old {
		t.up(i)
	} else {
		t.down(i)
	}
	return true
}

// Next returns the earliest deadline.
func (t *Timers[P]) Next() (int64, bool) {
	if len(t.heap) == 0 {
		return 0, false
	}
	return t.heap[0].t.Deadline, true
}

// PopMin removes and returns the earliest timer.
func (t *Timers[P]) PopMin() (Timer[P], bool) {
	if len(t.heap) == 0 {
		var zero Timer[P]
		return zero, false
	}
	tm := t.heap[0].t
	t.removeAt(0)
	return tm, true
}

// PopExpired removes and returns (via fn) every timer whose deadline is <= now,
// in deadline order. fn may schedule new timers; those are also fired if they
// are already expired.
func (t *Timers[P]) PopExpired(now int64, fn func(Timer[P])) int {
	n := 0
	for len(t.heap) > 0 && t.heap[0].t.Deadline <= now {
		tm := t.heap[0].t
		t.removeAt(0)
		fn(tm)
		n++
	}
	return n
}

func (t *Timers[P]) removeAt(i int) {
	last := len(t.heap) - 1
	delete(t.index, t.heap[i].t.ID)
	if i != last {
		t.heap[i] = t.heap[last]
		t.index[t.heap[i].t.ID] = i
	}
	var zero timerSlot[P]
	t.heap[last] = zero
	t.heap = t.heap[:last]
	if i < len(t.heap) {
		t.down(i)
		t.up(i)
	}
}

func (t *Timers[P]) less(a, b *timerSlot[P]) bool {
	if a.t.Deadline != b.t.Deadline {
		return a.t.Deadline < b.t.Deadline
	}
	return a.seq < b.seq
}

func (t *Timers[P]) swap(i, j int) {
	t.heap[i], t.heap[j] = t.heap[j], t.heap[i]
	t.index[t.heap[i].t.ID] = i
	t.index[t.heap[j].t.ID] = j
}

func (t *Timers[P]) up(i int) {
	for i > 0 {
		p := (i - 1) >> 2
		if !t.less(&t.heap[i], &t.heap[p]) {
			return
		}
		t.swap(i, p)
		i = p
	}
}

func (t *Timers[P]) down(i int) {
	n := len(t.heap)
	for {
		c := i<<2 + 1
		if c >= n {
			return
		}
		m := c
		end := c + 4
		if end > n {
			end = n
		}
		for j := c + 1; j < end; j++ {
			if t.less(&t.heap[j], &t.heap[m]) {
				m = j
			}
		}
		if !t.less(&t.heap[m], &t.heap[i]) {
			return
		}
		t.swap(i, m)
		i = m
	}
}
