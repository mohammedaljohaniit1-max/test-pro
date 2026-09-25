package pq

import (
	"math/rand/v2"
	"sort"
	"testing"
)

func TestHeapSorts(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 1))
	h := NewHeap(func(a, b int) bool { return a < b }, 0)
	var ref []int
	for i := 0; i < 10000; i++ {
		v := r.IntN(1000)
		h.Push(v)
		ref = append(ref, v)
		if r.IntN(3) == 0 {
			sort.Ints(ref)
			got, _ := h.Pop()
			if got != ref[0] {
				t.Fatalf("pop %d want %d", got, ref[0])
			}
			ref = ref[1:]
		}
	}
	sort.Ints(ref)
	for _, want := range ref {
		got, ok := h.Pop()
		if !ok || got != want {
			t.Fatalf("drain got %d want %d", got, want)
		}
	}
	if _, ok := h.Pop(); ok {
		t.Fatal("pop from empty heap")
	}
}

func TestTimersOrderCancelReset(t *testing.T) {
	r := rand.New(rand.NewPCG(2, 2))
	tm := NewTimers[int]()
	live := map[TimerID]int64{}
	for i := 0; i < 5000; i++ {
		switch op := r.IntN(10); {
		case op < 6:
			d := r.Int64N(100000)
			live[tm.Schedule(d, i)] = d
		case op < 8 && len(live) > 0:
			for id := range live {
				if !tm.Cancel(id) {
					t.Fatal("cancel of live timer failed")
				}
				delete(live, id)
				break
			}
		case len(live) > 0:
			for id := range live {
				d := r.Int64N(100000)
				if !tm.Reset(id, d) {
					t.Fatal("reset of live timer failed")
				}
				live[id] = d
				break
			}
		}
		if tm.Len() != len(live) {
			t.Fatalf("len %d want %d", tm.Len(), len(live))
		}
	}
	var last int64 = -1
	n := tm.PopExpired(1<<62, func(x Timer[int]) {
		if x.Deadline < last {
			t.Fatalf("out of order: %d after %d", x.Deadline, last)
		}
		if live[x.ID] != x.Deadline {
			t.Fatalf("timer %d deadline %d want %d", x.ID, x.Deadline, live[x.ID])
		}
		delete(live, x.ID)
		last = x.Deadline
	})
	if len(live) != 0 || tm.Len() != 0 || n == 0 {
		t.Fatalf("not fully drained: %d left", len(live))
	}
	if tm.Cancel(12345) {
		t.Fatal("cancel of unknown id succeeded")
	}
}

func TestTimersFIFOForEqualDeadlines(t *testing.T) {
	tm := NewTimers[int]()
	for i := 0; i < 100; i++ {
		tm.Schedule(10, i)
	}
	want := 0
	tm.PopExpired(10, func(x Timer[int]) {
		if x.Payload != want {
			t.Fatalf("got %d want %d", x.Payload, want)
		}
		want++
	})
}

func TestPopExpiredBoundary(t *testing.T) {
	tm := NewTimers[string]()
	tm.Schedule(5, "a")
	tm.Schedule(10, "b")
	var got []string
	tm.PopExpired(9, func(x Timer[string]) { got = append(got, x.Payload) })
	if len(got) != 1 || got[0] != "a" {
		t.Fatalf("got %v", got)
	}
	if d, ok := tm.Next(); !ok || d != 10 {
		t.Fatal("next deadline wrong")
	}
	if x, ok := tm.PopMin(); !ok || x.Payload != "b" {
		t.Fatal("popmin wrong")
	}
}

func BenchmarkTimersScheduleCancel(b *testing.B) {
	tm := NewTimers[int]()
	ids := make([]TimerID, 1024)
	for i := range ids {
		ids[i] = tm.Schedule(int64(i), i)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		j := i & 1023
		tm.Cancel(ids[j])
		ids[j] = tm.Schedule(int64(i), i)
	}
}
