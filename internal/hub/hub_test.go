package hub

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/netmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/procmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/sysmon"
)

type fakeProcs struct{}

func (fakeProcs) List() ([]procmon.RawProcess, error) {
	return []procmon.RawProcess{{PID: 10, Name: "a.exe", Threads: 3}, {PID: 11, Name: "b.exe", Threads: 2}}, nil
}
func (fakeProcs) Details(p *procmon.RawProcess) { p.Access = true }

type fakePlat struct{}

func (fakePlat) CPUTimes() (sysmon.CPUTimes, error) { return sysmon.CPUTimes{}, nil }
func (fakePlat) Memory() (uint64, uint64, uint64, uint64, error) {
	return 8 << 30, 4 << 30, 0, 0, nil
}
func (fakePlat) Disks() ([]model.DiskUsage, error) { return nil, nil }
func (fakePlat) Uptime() time.Duration             { return time.Hour }
func (fakePlat) Info() (string, string)            { return "h", "w" }
func (fakePlat) Cores() int                        { return 4 }

type fakeEvents struct {
	mu    sync.Mutex
	calls []uint64
	next  uint64
}

func (f *fakeEvents) Query(ch string, since time.Time, max, lvl int, after uint64) ([]model.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, after)
	f.next++
	return []model.Event{{Channel: ch, RecordID: after + 1, Time: time.Now(), Level: 2, LevelStr: "error", Provider: "p"}}, nil
}

func newHub(t *testing.T) (*Hub, *fakeEvents) {
	conns := []model.Connection{{Proto: "TCP", LocalAddr: "0.0.0.0", LocalPort: 80, State: "LISTEN", PID: 10}}
	pm := procmon.New(fakeProcs{}, 2)
	tr := netmon.NewTracker(func() ([]model.Connection, error) { return conns, nil }, pm.Resolve)
	fe := &fakeEvents{}
	h := New(Config{MetricsEvery: 10 * time.Millisecond, NetEvery: 10 * time.Millisecond, EventsEvery: 10 * time.Millisecond, Channels: []string{"System"}},
		slog.New(slog.NewTextHandler(io.Discard, nil)), sysmon.New(fakePlat{}, 10), pm, tr, fe)
	return h, fe
}

func TestRunBroadcastsAndSnapshot(t *testing.T) {
	h, fe := newHub(t)
	sub := h.Subscribe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.Run(ctx); close(done) }()
	seen := map[string]bool{}
	deadline := time.After(3 * time.Second)
	for !(seen["metrics"] && seen["processes"] && seen["netstats"] && seen["netdiff"] && seen["events"]) {
		select {
		case b := <-sub.C:
			var m struct{ Type string }
			json.Unmarshal(b, &m)
			seen[m.Type] = true
		case <-deadline:
			t.Fatalf("missing message types: %v", seen)
		}
	}
	// Concurrent snapshots while collectors run (exercised under -race).
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				s := h.Snapshot()
				_ = s.Connections
				h.Connections()
			}
		}()
	}
	wg.Wait()
	// Sockets observed before the first process sample carry a placeholder
	// name; it must converge to the real name on a later poll.
	deadline = time.After(3 * time.Second)
	for h.Connections()[0].ProcessName != "a.exe" {
		select {
		case <-deadline:
			t.Fatalf("process name never resolved: %+v", h.Connections()[0])
		case <-time.After(5 * time.Millisecond):
		}
	}
	deadline = time.After(3 * time.Second)
	for {
		fe.mu.Lock()
		n := len(fe.calls)
		fe.mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("event collector did not poll twice")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
	s := h.Snapshot()
	if len(s.Connections) != 1 || s.Connections[0].ProcessName != "a.exe" || s.Metrics.Processes != 2 || s.Metrics.Threads != 5 {
		t.Fatalf("snapshot %+v", s)
	}
	fe.mu.Lock()
	calls := append([]uint64(nil), fe.calls...)
	fe.mu.Unlock()
	if len(calls) < 2 || calls[0] != 0 || calls[1] != 1 {
		t.Fatalf("event polling must be incremental by record id: %v", calls)
	}
	evs, _ := h.Events()
	if len(evs) < 2 || evs[0].RecordID < evs[1].RecordID {
		t.Fatalf("events not accumulated newest-first: %+v", evs)
	}
}

func TestSlowSubscriberIsDropped(t *testing.T) {
	h, _ := newHub(t)
	slow := h.Subscribe()
	fast := h.Subscribe()
	for i := 0; i < 100; i++ {
		h.Broadcast("x", i)
		select {
		case <-fast.C:
		default:
		}
	}
	select {
	case <-slow.Done():
	default:
		t.Fatal("slow subscriber not dropped")
	}
	if h.Subscribers() != 1 || h.Dropped() != 1 {
		t.Fatalf("subs=%d dropped=%d", h.Subscribers(), h.Dropped())
	}
	h.Unsubscribe(slow) // idempotent
}
