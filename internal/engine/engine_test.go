package engine

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/rules"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()

func at(d time.Duration) int64 { return t0 + int64(d) }

func ev(ts time.Duration, typ, key string, kv ...any) *event.Event {
	e := &event.Event{Time: at(ts), Type: typ, Key: key}
	for i := 0; i+1 < len(kv); i += 2 {
		name := kv[i].(string)
		switch v := kv[i+1].(type) {
		case int:
			e.Set(name, event.Int(int64(v)))
		case float64:
			e.Set(name, event.Float(v))
		case string:
			e.Set(name, event.Str(v))
		case bool:
			e.Set(name, event.Bool(v))
		}
	}
	return e
}

// harness runs an engine and collects alerts.
type harness struct {
	t      *testing.T
	eng    *Engine
	mu     sync.Mutex
	alerts []*Alert
	done   chan struct{}
}

func newHarness(t *testing.T, cfg Config, src string) *harness {
	t.Helper()
	rs, err := rules.Compile(src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	h := &harness{t: t, eng: New(cfg, rs), done: make(chan struct{})}
	go func() {
		defer close(h.done)
		for a := range h.eng.Alerts() {
			h.mu.Lock()
			h.alerts = append(h.alerts, a)
			h.mu.Unlock()
		}
	}()
	t.Cleanup(h.close)
	return h
}

func (h *harness) close() {
	select {
	case <-h.done:
		return
	default:
	}
	h.eng.Close()
	<-h.done
}

func (h *harness) send(evs ...*event.Event) {
	h.t.Helper()
	for _, e := range evs {
		if err := e.Normalize(); err != nil {
			h.t.Fatal(err)
		}
		if err := h.eng.Submit(context.Background(), e); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *harness) advance(d time.Duration) {
	h.t.Helper()
	if err := h.eng.Advance(context.Background(), at(d)); err != nil {
		h.t.Fatal(err)
	}
}

// flush waits until the alert collector has consumed every alert emitted so
// far (alerts are emitted synchronously by shards before Advance returns).
func (h *harness) got() []*Alert {
	h.t.Helper()
	if err := h.eng.Sync(context.Background()); err != nil {
		h.t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		want := h.eng.Totals().Alerts - h.eng.Totals().Muted
		h.mu.Lock()
		n := uint64(len(h.alerts))
		out := append([]*Alert(nil), h.alerts...)
		h.mu.Unlock()
		if n >= want || time.Now().After(deadline) {
			sort.Slice(out, func(i, j int) bool {
				if out[i].EventTime != out[j].EventTime {
					return out[i].EventTime < out[j].EventTime
				}
				return out[i].Key < out[j].Key
			})
			return out
		}
		time.Sleep(time.Millisecond)
	}
}

func (h *harness) expect(n int) []*Alert {
	h.t.Helper()
	a := h.got()
	if len(a) != n {
		for _, x := range a {
			h.t.Logf("alert: rule=%s key=%s t=%v fields=%v", x.Rule, x.Key, time.Duration(x.EventTime-t0), x.Fields)
		}
		h.t.Fatalf("got %d alerts, want %d", len(a), n)
	}
	return a
}

const bruteRule = `
rule brute {
  within 1m
  sequence {
    fail: auth.failure[3:]
    !reset: auth.reset
    ok: auth.success where user == fail.user
  }
  emit { user = ok.user, failures = count(fail) }
}`

func TestSequenceBasicMatch(t *testing.T) {
	h := newHarness(t, Config{Shards: 2}, bruteRule)
	h.send(
		ev(1*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(2*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(3*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(4*time.Second, "auth.success", "ip1", "user", "root"),
	)
	a := h.expect(1)
	if a[0].Key != "ip1" || a[0].Fields["user"] != "root" || a[0].Fields["failures"] != int64(3) {
		t.Fatalf("alert: %+v", a[0].Fields)
	}
	if a[0].EventTime != at(4*time.Second) || len(a[0].Evidence) != 4 {
		t.Fatalf("event time / evidence: %v %d", a[0].EventTime, len(a[0].Evidence))
	}
	if a[0].Fields["duration_ms"] != 3000.0 {
		t.Fatalf("duration: %v", a[0].Fields["duration_ms"])
	}
}

func TestSequenceNotEnoughFailures(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, bruteRule)
	h.send(
		ev(1*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(2*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(3*time.Second, "auth.success", "ip1", "user", "root"),
	)
	h.expect(0)
}

func TestSequenceKeyIsolation(t *testing.T) {
	h := newHarness(t, Config{Shards: 4}, bruteRule)
	h.send(
		ev(1*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(2*time.Second, "auth.failure", "ip2", "user", "root"),
		ev(3*time.Second, "auth.failure", "ip3", "user", "root"),
		ev(4*time.Second, "auth.success", "ip1", "user", "root"),
	)
	h.expect(0)
}

func TestSequenceNegationKills(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, bruteRule)
	h.send(
		ev(1*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(2*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(3*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(4*time.Second, "auth.reset", "ip1"),
		ev(5*time.Second, "auth.success", "ip1", "user", "root"),
	)
	h.expect(0)
	// A fresh sequence after the reset must still be detected.
	h.send(
		ev(6*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(7*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(8*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(9*time.Second, "auth.success", "ip1", "user", "root"),
	)
	h.expect(1)
}

func TestSequenceCrossStepPredicate(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, bruteRule)
	h.send(
		ev(1*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(2*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(3*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(4*time.Second, "auth.success", "ip1", "user", "alice"), // different user
	)
	h.expect(0)
}

func TestSequenceWithinWindowExpiry(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, bruteRule)
	h.send(
		ev(0, "auth.failure", "ip1", "user", "root"),
		ev(10*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(20*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(61*time.Second, "auth.success", "ip1", "user", "root"), // 61s after first
	)
	// Sliding semantics: after the first failure expires the run slides to
	// start at 10s, which leaves 2 failures < 3: no match.
	h.expect(0)
}

func TestSequenceSlidingWindowKeepsRecentFailures(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, bruteRule)
	h.send(
		ev(0, "auth.failure", "ip1", "user", "root"),
		ev(30*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(40*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(50*time.Second, "auth.failure", "ip1", "user", "root"),
		ev(75*time.Second, "auth.success", "ip1", "user", "root"),
	)
	// Failures at 30,40,50 are within 1m of 75? The run start slides to 30s
	// after the 0s failure expires (deadline 60s); 75-30=45s <= 1m.
	a := h.expect(1)
	if a[0].Fields["failures"] != int64(3) {
		t.Fatalf("failures=%v", a[0].Fields["failures"])
	}
	if a[0].Fields["duration_ms"] != 45000.0 {
		t.Fatalf("duration=%v", a[0].Fields["duration_ms"])
	}
}

func TestSequenceBoundedQuantifierSlides(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, `
rule burst {
  within 10s
  sequence { x: tick[3:3]  y: done }
  emit { n = count(x), last = x.n }
}`)
	for i := 0; i < 6; i++ {
		h.send(ev(time.Duration(i)*time.Second, "tick", "k", "n", i))
	}
	h.send(ev(7*time.Second, "done", "k"))
	a := h.expect(1)
	if a[0].Fields["n"] != int64(3) || a[0].Fields["last"] != int64(5) {
		t.Fatalf("fields %v", a[0].Fields)
	}
	if a[0].Fields["duration_ms"] != 4000.0 { // earliest retained tick is t=3s
		t.Fatalf("duration %v", a[0].Fields["duration_ms"])
	}
}

func TestSequenceThreeSteps(t *testing.T) {
	h := newHarness(t, Config{Shards: 2}, `
rule chain {
  within 30s
  sequence {
    req: http.request where starts_with(path, "/admin")
    proc: process.start where parent == "nginx"
    conn: net.connect where not cidr(dst, "10.0.0.0/8")
  }
  emit { path = req.path, dst = conn.dst }
}`)
	h.send(
		ev(1*time.Second, "http.request", "host", "path", "/admin/x"),
		ev(2*time.Second, "net.connect", "host", "dst", "8.8.8.8"), // out of order step: ignored
		ev(3*time.Second, "process.start", "host", "parent", "nginx"),
		ev(4*time.Second, "net.connect", "host", "dst", "10.1.1.1"), // internal: skip
		ev(5*time.Second, "net.connect", "host", "dst", "1.1.1.1"),
	)
	a := h.expect(1)
	if a[0].Fields["path"] != "/admin/x" || a[0].Fields["dst"] != "1.1.1.1" {
		t.Fatalf("fields %v", a[0].Fields)
	}
}

func TestSequenceMultipleOverlappingRuns(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, `
rule ab { within 10s sequence { a: A  b: B } emit { id = a.id } }`)
	h.send(
		ev(1*time.Second, "A", "k", "id", 1),
		ev(2*time.Second, "A", "k", "id", 2),
		ev(3*time.Second, "B", "k"),
	)
	// Skip-till-next-match with independent runs per start: both A's pair
	// with the B.
	a := h.expect(2)
	ids := []any{a[0].Fields["id"], a[1].Fields["id"]}
	if !(ids[0] == int64(1) && ids[1] == int64(2)) && !(ids[0] == int64(2) && ids[1] == int64(1)) {
		t.Fatalf("ids %v", ids)
	}
}

func TestMaxRunsEvictsOldest(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, `
rule ab { within 1m max_runs 2 sequence { a: A  b: B } emit { id = a.id } }`)
	h.send(
		ev(1*time.Second, "A", "k", "id", 1),
		ev(2*time.Second, "A", "k", "id", 2),
		ev(3*time.Second, "A", "k", "id", 3),
		ev(4*time.Second, "B", "k"),
	)
	a := h.expect(2)
	for _, x := range a {
		if x.Fields["id"] == int64(1) {
			t.Fatal("oldest run should have been evicted")
		}
	}
	if h.eng.Totals().RunEvicts != 1 {
		t.Fatalf("run evictions = %d", h.eng.Totals().RunEvicts)
	}
}

const absenceRule = `
rule missing_hb {
  within 30s
  sequence { start: service.start  !hb: service.heartbeat }
  emit { version = start.version }
}`

func TestAbsenceFiresAtDeadline(t *testing.T) {
	h := newHarness(t, Config{Shards: 2}, absenceRule)
	h.send(ev(0, "service.start", "svc-a", "version", "1.0"))
	h.advance(29 * time.Second)
	h.expect(0)
	h.advance(31 * time.Second)
	a := h.expect(1)
	if a[0].Kind != "absence" || a[0].EventTime != at(30*time.Second) || a[0].Fields["version"] != "1.0" {
		t.Fatalf("absence alert: kind=%s t=%v f=%v", a[0].Kind, a[0].EventTime, a[0].Fields)
	}
}

func TestAbsenceCancelledByEvent(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, absenceRule)
	h.send(
		ev(0, "service.start", "svc-a"),
		ev(10*time.Second, "service.heartbeat", "svc-a"),
		ev(10*time.Second, "service.start", "svc-b"),
	)
	h.advance(5 * time.Minute)
	a := h.expect(1)
	if a[0].Key != "svc-b" {
		t.Fatalf("wrong key %s", a[0].Key)
	}
}

func TestAbsenceHeartbeatExactlyAtDeadline(t *testing.T) {
	// Events at time t are processed before timers with deadline >= t, so a
	// heartbeat exactly at the deadline still cancels the absence.
	h := newHarness(t, Config{Shards: 1}, absenceRule)
	h.send(ev(0, "service.start", "svc"), ev(30*time.Second, "service.heartbeat", "svc"))
	h.advance(time.Hour)
	h.expect(0)
}

func TestIdleAdvanceFiresAbsenceWithoutTraffic(t *testing.T) {
	rs, _ := rules.Compile(`rule m { within 50ms sequence { s: start  !h: hb } }`)
	e := New(Config{Shards: 1, IdleAdvance: 20 * time.Millisecond}, rs)
	defer e.Close()
	s := &event.Event{Time: time.Now().UnixNano(), Type: "start", Key: "k"}
	if err := e.Submit(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-e.Alerts():
		if a.Rule != "m" {
			t.Fatalf("unexpected alert %s", a.Rule)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("absence alert not produced by idle watermark advance")
	}
}

func TestOutOfOrderWithinLatenessIsReordered(t *testing.T) {
	h := newHarness(t, Config{Shards: 1, AllowedLateness: 5 * time.Second}, bruteRule)
	// Delivered out of order but within 5s lateness: must match as if ordered.
	h.send(
		ev(3*time.Second, "auth.failure", "ip", "user", "u"),
		ev(1*time.Second, "auth.failure", "ip", "user", "u"),
		ev(5*time.Second, "auth.success", "ip", "user", "u"),
		ev(2*time.Second, "auth.failure", "ip", "user", "u"),
	)
	h.advance(time.Minute)
	a := h.expect(1)
	if a[0].Fields["failures"] != int64(3) {
		t.Fatalf("failures %v", a[0].Fields["failures"])
	}
	if h.eng.Totals().Late != 0 {
		t.Fatal("no events should be late")
	}
}

func TestLateEventsDropped(t *testing.T) {
	h := newHarness(t, Config{Shards: 1, AllowedLateness: time.Second}, bruteRule)
	h.send(ev(10*time.Second, "x", "k"))
	h.send(ev(5*time.Second, "auth.failure", "k", "user", "u")) // 5s behind max, lateness 1s
	h.got()
	if late := h.eng.Totals().Late; late != 1 {
		t.Fatalf("late=%d want 1", late)
	}
}

func TestZeroLatenessDropsRegressions(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, bruteRule)
	h.send(ev(10*time.Second, "x", "k"), ev(10*time.Second, "x", "k"), ev(9*time.Second, "x", "k"))
	h.got()
	if late := h.eng.Totals().Late; late != 1 {
		t.Fatalf("late=%d want 1 (equal timestamps are not late)", late)
	}
}

func TestSuppression(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, `
rule a { within 1s suppress 10s sequence { x: X } }`)
	for i := 0; i < 5; i++ {
		h.send(ev(time.Duration(i)*time.Second, "X", "k"))
	}
	h.send(ev(11*time.Second, "X", "k"))
	h.send(ev(1*time.Second+11*time.Second, "X", "other")) // different key not suppressed
	h.expect(3)
	if s := h.eng.Totals().Suppressed; s != 4 {
		t.Fatalf("suppressed=%d want 4", s)
	}
}

func TestSingleStepQuantifierCrashLoop(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, `
rule crash { within 5m sequence { r: service.start[3:] } emit { n = count(r) } }`)
	h.send(
		ev(0, "service.start", "svc"),
		ev(time.Minute, "service.start", "svc"),
		ev(2*time.Minute, "service.start", "svc"),
	)
	a := h.expect(1)
	if a[0].Fields["n"] != int64(3) {
		t.Fatalf("n=%v", a[0].Fields["n"])
	}
}

const latencyRule = `
rule slow {
  aggregate over 10s step 1s
  from http.request
  having count() >= 10 and p99(latency) > 500
  emit { p99 = p99(latency), n = count(), mx = max(latency), avg = avg(latency), rps = rate() }
}`

func TestAggregateThreshold(t *testing.T) {
	h := newHarness(t, Config{Shards: 2}, latencyRule)
	for i := 0; i < 20; i++ {
		h.send(ev(time.Duration(i)*100*time.Millisecond, "http.request", "svc", "latency", 50.0))
	}
	h.expect(0)
	for i := 0; i < 5; i++ {
		h.send(ev(2*time.Second+time.Duration(i)*10*time.Millisecond, "http.request", "svc", "latency", 2000.0))
	}
	// With 21 samples the p99 rank int(0.99*20)=19 still lands on a 50ms
	// sample; the 22nd sample (second spike) is the first to breach.
	a := h.expect(1) // subsequent matches suppressed for one window
	f := a[0].Fields
	if f["n"] != int64(22) || f["mx"] != 2000.0 {
		t.Fatalf("fields %v", f)
	}
	p99 := f["p99"].(float64)
	if p99 < 1980 || p99 > 2020 {
		t.Fatalf("p99=%v", p99)
	}
	if a[0].WindowEnd-a[0].WindowStart != int64(10*time.Second) {
		t.Fatalf("window span %v", time.Duration(a[0].WindowEnd-a[0].WindowStart))
	}
	if h.eng.Totals().Suppressed != 3 {
		t.Fatalf("suppressed=%d", h.eng.Totals().Suppressed)
	}
}

func TestAggregateSlidingExpiry(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, `
rule many { aggregate over 5s step 1s from X having count() >= 5 emit { n = count() } }`)
	// 4 events in [0,1s), then 1 event at 5.5s: the first pane has slid out,
	// so the window [1s,6s) contains only 1 event.
	for i := 0; i < 4; i++ {
		h.send(ev(time.Duration(i)*100*time.Millisecond, "X", "k"))
	}
	h.send(ev(5500*time.Millisecond, "X", "k"))
	h.expect(0)
	// 4 more in the same window -> 5.
	for i := 0; i < 4; i++ {
		h.send(ev(5600*time.Millisecond+time.Duration(i)*time.Millisecond, "X", "k"))
	}
	a := h.expect(1)
	if a[0].Fields["n"] != int64(5) {
		t.Fatalf("n=%v", a[0].Fields["n"])
	}
}

func TestAggregateGroupByAndWhere(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, `
rule errs {
  aggregate over 1m step 10s
  from http.request
  where method == "GET"
  by path
  having count() >= 3 and sum(if(status >= 500, 1, 0)) / count() >= 0.5
  emit { path = group, n = count() }
}`)
	for i := 0; i < 4; i++ {
		h.send(ev(time.Duration(i)*time.Second, "http.request", "svc", "method", "GET", "path", "/a", "status", 500))
		h.send(ev(time.Duration(i)*time.Second, "http.request", "svc", "method", "GET", "path", "/b", "status", 200))
		h.send(ev(time.Duration(i)*time.Second, "http.request", "svc", "method", "POST", "path", "/c", "status", 500))
	}
	a := h.expect(1)
	if a[0].Group != "/a" || a[0].Fields["path"] != "/a" || a[0].Fields["n"] != int64(3) {
		t.Fatalf("alert %+v %v", a[0].Group, a[0].Fields)
	}
}

func TestAggregateDistinct(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, `
rule scan { aggregate over 10s step 1s from net.flow having distinct(port) >= 20 emit { d = distinct(port) } }`)
	for p := 0; p < 19; p++ {
		h.send(ev(time.Duration(p)*10*time.Millisecond, "net.flow", "ip", "port", 1000+p))
		h.send(ev(time.Duration(p)*10*time.Millisecond, "net.flow", "ip", "port", 1000+p)) // dup
	}
	h.expect(0)
	h.send(ev(time.Second, "net.flow", "ip", "port", 5000))
	a := h.expect(1)
	if d := a[0].Fields["d"].(int64); d < 19 || d > 21 {
		t.Fatalf("distinct=%d", d)
	}
}

func TestAggregateGroupReclaimed(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, latencyRule)
	h.send(ev(0, "http.request", "svc", "latency", 1.0))
	h.got()
	if h.eng.Totals().Groups != 1 {
		t.Fatal("group not created")
	}
	h.advance(12 * time.Second)
	h.got()
	if g := h.eng.Totals().Groups; g != 0 {
		t.Fatalf("idle group not reclaimed: %d", g)
	}
	if tm := h.eng.Totals().Timers; tm != 0 {
		t.Fatalf("timer leak: %d", tm)
	}
}

func TestKeyTTLAndLRU(t *testing.T) {
	h := newHarness(t, Config{Shards: 1, KeyTTL: time.Minute, MaxKeysPerShard: 100}, bruteRule)
	for i := 0; i < 250; i++ {
		h.send(ev(time.Duration(i)*time.Millisecond, "auth.failure", fmt.Sprintf("k%d", i), "user", "u"))
	}
	h.got()
	tot := h.eng.Totals()
	if tot.Keys != 100 || tot.KeyEvicts != 150 {
		t.Fatalf("keys=%d evicts=%d", tot.Keys, tot.KeyEvicts)
	}
	h.advance(10 * time.Minute)
	h.got()
	tot = h.eng.Totals()
	if tot.Keys != 0 || tot.Runs != 0 || tot.Timers != 0 {
		t.Fatalf("state not reclaimed: keys=%d runs=%d timers=%d", tot.Keys, tot.Runs, tot.Timers)
	}
}

func TestIrrelevantEventsAllocateNoState(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, bruteRule)
	for i := 0; i < 1000; i++ {
		h.send(ev(time.Duration(i)*time.Millisecond, "http.request", fmt.Sprintf("k%d", i)))
		// auth.success is relevant but cannot start a run.
		h.send(ev(time.Duration(i)*time.Millisecond, "auth.success", fmt.Sprintf("k%d", i), "user", "x"))
	}
	h.got()
	if k := h.eng.Totals().Keys; k != 0 {
		t.Fatalf("keys=%d; irrelevant/non-starting events must not create state", k)
	}
}

func TestHotReloadPreservesUnchangedRules(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, bruteRule+`
rule other { within 1m sequence { a: Z  b: Y } }`)
	h.send(
		ev(1*time.Second, "auth.failure", "ip", "user", "u"),
		ev(2*time.Second, "auth.failure", "ip", "user", "u"),
		ev(3*time.Second, "auth.failure", "ip", "user", "u"),
		ev(3*time.Second, "Z", "ip"),
	)
	h.got()
	// Reload: brute unchanged, "other" modified (its state must be dropped),
	// and a new rule added.
	rs, err := rules.Compile(`rule added { within 1s sequence { q: Q } }
rule other { within 2m sequence { a: Z  b: Y } }
` + bruteRule)
	if err != nil {
		t.Fatal(err)
	}
	h.eng.SetRules(rs)
	h.send(ev(4*time.Second, "auth.success", "ip", "user", "u"), ev(5*time.Second, "Y", "ip"), ev(6*time.Second, "Q", "ip"))
	a := h.expect(2)
	rulesSeen := map[string]bool{}
	for _, x := range a {
		rulesSeen[x.Rule] = true
	}
	if !rulesSeen["brute"] || !rulesSeen["added"] || rulesSeen["other"] {
		t.Fatalf("rules fired: %v", rulesSeen)
	}
	if v := h.eng.Totals().RuleVersion; v != 2 {
		t.Fatalf("rule version %d", v)
	}
}

func TestMutedReplayRebuildsStateSilently(t *testing.T) {
	h := newHarness(t, Config{Shards: 1}, bruteRule)
	h.eng.SetMuted(true)
	h.send(
		ev(1*time.Second, "auth.failure", "ip", "user", "u"),
		ev(2*time.Second, "auth.failure", "ip", "user", "u"),
		ev(3*time.Second, "auth.failure", "ip", "user", "u"),
		ev(4*time.Second, "auth.success", "ip", "user", "u"),
		ev(5*time.Second, "auth.failure", "ip2", "user", "u"),
		ev(6*time.Second, "auth.failure", "ip2", "user", "u"),
		ev(7*time.Second, "auth.failure", "ip2", "user", "u"),
	)
	h.got()
	h.eng.SetMuted(false)
	if m := h.eng.Totals().Muted; m != 1 {
		t.Fatalf("muted=%d", m)
	}
	// The state for ip2 survived "replay": one live event completes it.
	h.send(ev(8*time.Second, "auth.success", "ip2", "user", "u"))
	a := h.expect(1)
	if a[0].Key != "ip2" {
		t.Fatal("wrong key")
	}
}

func TestBackpressureDropOnFull(t *testing.T) {
	rs, _ := rules.Compile(bruteRule)
	e := New(Config{Shards: 1, RingSize: 2, DropOnFull: true}, rs)
	defer e.Close()
	var rejected int
	for i := 0; i < 10000; i++ {
		err := e.Submit(context.Background(), &event.Event{Time: at(time.Duration(i)), Type: "x", Key: "k"})
		if err == ErrBackpressure {
			rejected++
		}
	}
	if rejected == 0 {
		t.Fatal("expected some backpressure rejections with a tiny ring")
	}
	if e.Totals().Rejected != uint64(rejected) {
		t.Fatal("rejected counter mismatch")
	}
}

func TestSubmitAfterClose(t *testing.T) {
	rs, _ := rules.Compile(bruteRule)
	e := New(Config{Shards: 1}, rs)
	e.Close()
	e.Close() // idempotent
	if err := e.Submit(context.Background(), &event.Event{Time: 1, Type: "x"}); err != ErrClosed {
		t.Fatalf("got %v", err)
	}
	if _, ok := <-e.Alerts(); ok {
		t.Fatal("alerts channel should be closed")
	}
}

// TestDeterminismUnderReordering: delivering the same event multiset in
// different arrival orders (within the lateness bound) must produce identical
// alerts. This is the core event-time correctness property.
func TestDeterminismUnderReordering(t *testing.T) {
	src := bruteRule + absenceRule + latencyRule
	base := make([]*event.Event, 0, 4000)
	r := rand.New(rand.NewPCG(7, 7))
	for i := 0; i < 4000; i++ {
		ts := time.Duration(i) * 20 * time.Millisecond
		key := fmt.Sprintf("k%d", r.IntN(20))
		switch r.IntN(6) {
		case 0, 1:
			base = append(base, ev(ts, "auth.failure", key, "user", "u"))
		case 2:
			base = append(base, ev(ts, "auth.success", key, "user", "u"))
		case 3:
			base = append(base, ev(ts, "service.start", key))
		case 4:
			base = append(base, ev(ts, "service.heartbeat", key))
		default:
			base = append(base, ev(ts, "http.request", key, "latency", r.Float64()*1000))
		}
	}
	run := func(order []*event.Event) []string {
		h := newHarness(t, Config{Shards: 3, AllowedLateness: 2 * time.Second}, src)
		for _, e := range order {
			h.send(e.Clone())
		}
		h.advance(time.Hour)
		if late := h.eng.Totals().Late; late != 0 {
			t.Fatalf("%d events dropped as late; disorder exceeds lateness", late)
		}
		var sig []string
		for _, a := range h.got() {
			sig = append(sig, fmt.Sprintf("%s|%s|%d|%v", a.Rule, a.Key, a.EventTime, a.Fields["failures"]))
		}
		h.close()
		sort.Strings(sig)
		return sig
	}
	want := run(base)
	if len(want) == 0 {
		t.Fatal("scenario produced no alerts; test is vacuous")
	}
	for trial := 0; trial < 3; trial++ {
		// Bounded disorder: order by event time plus a random delay in
		// [0, 1s), strictly below the 2s allowed lateness.
		type keyed struct {
			e     *event.Event
			order int64
		}
		ks := make([]keyed, len(base))
		for i, e := range base {
			ks[i] = keyed{e, e.Time + r.Int64N(int64(time.Second))}
		}
		sort.Slice(ks, func(i, j int) bool { return ks[i].order < ks[j].order })
		shuffled := make([]*event.Event, len(ks))
		for i := range ks {
			shuffled[i] = ks[i].e
		}
		got := run(shuffled)
		if len(got) != len(want) {
			t.Fatalf("trial %d: %d alerts vs %d", trial, len(got), len(want))
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("trial %d: alert %d differs:\n got %s\nwant %s", trial, i, got[i], want[i])
			}
		}
	}
}

func TestConcurrentProducers(t *testing.T) {
	h := newHarness(t, Config{Shards: 4, AllowedLateness: time.Minute}, bruteRule)
	const producers, keys = 8, 200
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for k := p; k < keys; k += producers {
				key := fmt.Sprintf("ip-%d", k)
				for i := 0; i < 5; i++ {
					e := ev(time.Duration(i)*time.Second, "auth.failure", key, "user", "u")
					_ = e.Normalize()
					_ = h.eng.Submit(context.Background(), e)
				}
				e := ev(6*time.Second, "auth.success", key, "user", "u")
				_ = e.Normalize()
				_ = h.eng.Submit(context.Background(), e)
			}
		}(p)
	}
	wg.Wait()
	h.advance(time.Hour)
	// Suppression is off, and skip-till-next-match with a sliding stage-0 run
	// means exactly one run per key absorbs all failures -> one alert per key.
	a := h.expect(keys)
	seen := map[string]bool{}
	for _, x := range a {
		if seen[x.Key] {
			t.Fatalf("duplicate alert for %s", x.Key)
		}
		seen[x.Key] = true
	}
}
