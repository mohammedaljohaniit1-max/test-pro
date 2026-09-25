package ring

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCapacityRounding(t *testing.T) {
	for in, want := range map[int]int{0: 2, 1: 2, 2: 2, 3: 4, 1000: 1024, 1024: 1024} {
		if got := New[int](in).Cap(); got != want {
			t.Errorf("New(%d).Cap()=%d want %d", in, got, want)
		}
	}
}

func TestFIFOAndFull(t *testing.T) {
	r := New[int](4)
	for i := 0; i < 4; i++ {
		if !r.TryPush(i) {
			t.Fatalf("push %d failed", i)
		}
	}
	if r.TryPush(99) {
		t.Fatal("push into full ring succeeded")
	}
	for i := 0; i < 4; i++ {
		v, ok := r.TryPop()
		if !ok || v != i {
			t.Fatalf("pop %d: got %d %v", i, v, ok)
		}
	}
	if _, ok := r.TryPop(); ok {
		t.Fatal("pop from empty ring succeeded")
	}
	// Wrap-around across many laps.
	for lap := 0; lap < 1000; lap++ {
		if !r.TryPush(lap) {
			t.Fatal("push after wrap failed")
		}
		if v, _ := r.TryPop(); v != lap {
			t.Fatalf("lap %d got %d", lap, v)
		}
	}
}

func TestPopBatch(t *testing.T) {
	r := New[int](16)
	for i := 0; i < 10; i++ {
		r.TryPush(i)
	}
	buf := make([]int, 4)
	got := []int{}
	for {
		n := r.PopBatch(buf)
		if n == 0 {
			break
		}
		got = append(got, buf[:n]...)
	}
	for i, v := range got {
		if v != i {
			t.Fatalf("batch order broken: %v", got)
		}
	}
	if len(got) != 10 {
		t.Fatalf("got %d items", len(got))
	}
}

// TestMPMCStress checks that under heavy contention every item is delivered
// exactly once and per-producer FIFO order is preserved.
func TestMPMCStress(t *testing.T) {
	const producers, consumers, per = 4, 4, 50000
	r := New[uint64](256)
	var wg sync.WaitGroup
	ctx := context.Background()
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(p uint64) {
			defer wg.Done()
			for i := uint64(0); i < per; i++ {
				if err := r.Push(ctx, p<<32|i); err != nil {
					t.Error(err)
					return
				}
			}
		}(uint64(p))
	}
	seen := make([][]uint64, consumers)
	var total atomic.Int64
	var cwg sync.WaitGroup
	for c := 0; c < consumers; c++ {
		cwg.Add(1)
		go func(c int) {
			defer cwg.Done()
			buf := make([]uint64, 32)
			for total.Load() < producers*per {
				n := r.PopBatch(buf)
				if n == 0 {
					r.Wait(time.Millisecond)
					continue
				}
				seen[c] = append(seen[c], buf[:n]...)
				total.Add(int64(n))
			}
		}(c)
	}
	wg.Wait()
	cwg.Wait()
	count := make(map[uint64]int)
	for c := range seen {
		last := map[uint64]int64{}
		for _, v := range seen[c] {
			count[v]++
			p, i := v>>32, int64(v&0xffffffff)
			if prev, ok := last[p]; ok && i <= prev {
				t.Fatalf("consumer %d saw producer %d out of order: %d after %d", c, p, i, prev)
			}
			last[p] = i
		}
	}
	if len(count) != producers*per {
		t.Fatalf("delivered %d distinct items, want %d", len(count), producers*per)
	}
	for v, n := range count {
		if n != 1 {
			t.Fatalf("item %x delivered %d times", v, n)
		}
	}
}

func TestPushBlocksUntilSpaceOrCancel(t *testing.T) {
	r := New[int](2)
	r.TryPush(1)
	r.TryPush(2)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := r.Push(ctx, 3); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Push(context.Background(), 4) }()
	time.Sleep(10 * time.Millisecond)
	r.TryPop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked push not released after pop")
	}
}

func TestCloseSemantics(t *testing.T) {
	r := New[int](4)
	r.TryPush(1)
	r.Close()
	if r.TryPush(2) {
		t.Fatal("push after close succeeded")
	}
	if err := r.Push(context.Background(), 2); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
	if v, ok := r.TryPop(); !ok || v != 1 {
		t.Fatal("pending item lost after close")
	}
	if r.Wait(time.Second) {
		t.Fatal("Wait on closed+empty ring should return false immediately")
	}
}

func TestWaitWakesOnPush(t *testing.T) {
	r := New[int](4)
	start := time.Now()
	go func() {
		time.Sleep(5 * time.Millisecond)
		r.TryPush(1)
	}()
	if !r.Wait(2 * time.Second) {
		t.Fatal("wait returned false")
	}
	if time.Since(start) > time.Second {
		t.Fatal("wait was not woken by push")
	}
}

func BenchmarkPushPopSPSC(b *testing.B) {
	r := New[int](1024)
	done := make(chan struct{})
	go func() {
		buf := make([]int, 64)
		got := 0
		for got < b.N {
			n := r.PopBatch(buf)
			if n == 0 {
				r.Wait(time.Millisecond)
			}
			got += n
		}
		close(done)
	}()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.Push(ctx, i)
	}
	<-done
}

func BenchmarkPushPopMPMC(b *testing.B) {
	r := New[int](4096)
	var stop atomic.Bool
	go func() {
		buf := make([]int, 64)
		for !stop.Load() {
			if r.PopBatch(buf) == 0 {
				r.Wait(time.Millisecond)
			}
		}
	}()
	ctx := context.Background()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = r.Push(ctx, 1)
		}
	})
	stop.Store(true)
}
