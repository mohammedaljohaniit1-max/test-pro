package loadgen

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/engine"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/rules"
)

func TestDeterministic(t *testing.T) {
	a := New(Options{Seed: 5, Keys: 100, InjectPct: 0.01})
	b := New(Options{Seed: 5, Keys: 100, InjectPct: 0.01})
	for i := 0; i < 5000; i++ {
		x, y := a.Next(), b.Next()
		if x.Time != y.Time || x.Type != y.Type || x.Key != y.Key || len(x.Attrs) != len(y.Attrs) {
			t.Fatalf("diverged at %d", i)
		}
	}
}

func TestBoundedDisorderAndValidity(t *testing.T) {
	jitter := 100 * time.Millisecond
	g := New(Options{Seed: 1, Keys: 1000, Jitter: jitter, InjectPct: 0.02})
	var maxSeen int64
	for i := 0; i < 50000; i++ {
		e := g.Next()
		if err := e.Normalize(); err != nil {
			t.Fatalf("invalid event: %v", err)
		}
		if e.Time > maxSeen {
			maxSeen = e.Time
		}
		if maxSeen-e.Time > int64(jitter) {
			t.Fatalf("disorder %v exceeds jitter", time.Duration(maxSeen-e.Time))
		}
	}
	if len(g.Injected()) == 0 {
		t.Fatal("no scenarios injected")
	}
}

// TestDetectionRecall: every injected scenario must be detected by the
// bundled rule pack (recall = 1.0) and background keys must never trip the
// security rules.
func TestDetectionRecall(t *testing.T) {
	rs, err := rules.CompileFiles("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	eng := engine.New(engine.Config{Shards: 2, AllowedLateness: 500 * time.Millisecond}, rs)
	got := map[string]map[string]bool{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for a := range eng.Alerts() {
			if got[a.Rule] == nil {
				got[a.Rule] = map[string]bool{}
			}
			got[a.Rule][a.Key] = true
		}
	}()
	g := New(Options{Seed: 11, Keys: 20000, Jitter: 200 * time.Millisecond, InjectPct: 0.004})
	ctx := context.Background()
	batch := make([]*event.Event, 0, 256)
	for i := 0; i < 200000; i++ {
		batch = append(batch, g.Next())
		if len(batch) == cap(batch) {
			if _, err := eng.SubmitBatch(ctx, batch); err != nil {
				t.Fatal(err)
			}
			batch = batch[:0]
		}
	}
	batch = append(batch, g.Drain()...)
	if _, err := eng.SubmitBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if err := eng.Advance(ctx, g.Now()+int64(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	late := eng.Totals().Late
	eng.Close()
	<-done
	if late != 0 {
		t.Fatalf("%d late events", late)
	}
	inj := g.Injected()
	want := map[string]int{
		"brute_force_then_success": inj[ScenarioBruteForce],
		"latency_slo_breach":       inj[ScenarioLatencySpike],
		"port_scan":                inj[ScenarioPortScan],
		"missing_heartbeat":        inj[ScenarioHeartbeatGap],
	}
	for rule, n := range want {
		if n == 0 {
			t.Fatalf("scenario for %s never injected; test vacuous", rule)
		}
		if len(got[rule]) != n {
			t.Errorf("%s: detected %d distinct keys, injected %d", rule, len(got[rule]), n)
		}
	}
	for _, rule := range []string{"brute_force_then_success", "port_scan"} {
		for key := range got[rule] {
			if strings.HasPrefix(key, "10.") {
				t.Errorf("%s: false positive on background key %s", rule, key)
			}
		}
	}
}
