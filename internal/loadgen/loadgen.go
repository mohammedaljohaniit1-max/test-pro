// Package loadgen produces deterministic synthetic telemetry mixing benign
// background traffic with injected attack / fault scenarios whose expected
// detections are known. It backs the benchmark tool, integration tests and
// demo mode.
package loadgen

import (
	"fmt"
	"math"
	"math/rand/v2"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/pq"
)

// Scenario identifies an injected pattern.
type Scenario int

// Scenarios matching the bundled rules in rules/.
const (
	ScenarioBruteForce   Scenario = iota // N auth failures then success from one IP
	ScenarioLatencySpike                 // p99 latency surge on one service
	ScenarioPortScan                     // many distinct ports from one IP
	ScenarioHeartbeatGap                 // service starts and never heartbeats
)

// Options configure a generator.
type Options struct {
	Seed      uint64
	Keys      int           // distinct background keys (IPs / hosts)
	Start     time.Time     // event-time origin
	Rate      float64       // events per second of event time
	Jitter    time.Duration // max out-of-order displacement
	InjectPct float64       // fraction of events that belong to scenarios (0..1)
}

// Generator is not safe for concurrent use; create one per goroutine.
type Generator struct {
	o        Options
	rnd      *rand.Rand
	step     int64
	now      int64
	pending  *pq.Heap[*event.Event] // scenario events, released in time order
	injected map[Scenario]int
	keys     []string
	services []string
	users    []string
	paths    []string
}

// New creates a generator.
func New(o Options) *Generator {
	if o.Keys <= 0 {
		o.Keys = 10000
	}
	if o.Rate <= 0 {
		o.Rate = 50000
	}
	if o.Start.IsZero() {
		o.Start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	g := &Generator{
		o:        o,
		rnd:      rand.New(rand.NewPCG(o.Seed, o.Seed^0x9e3779b97f4a7c15)),
		step:     int64(float64(time.Second) / o.Rate),
		now:      o.Start.UnixNano(),
		injected: map[Scenario]int{},
		pending:  pq.NewHeap(func(a, b *event.Event) bool { return a.Time < b.Time }, 1024),
	}
	if g.step < 1 {
		g.step = 1
	}
	g.keys = make([]string, o.Keys)
	for i := range g.keys {
		g.keys[i] = fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255)
	}
	for i := 0; i < 32; i++ {
		g.services = append(g.services, fmt.Sprintf("svc-%02d", i))
	}
	g.users = []string{"alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "root", "admin"}
	g.paths = []string{"/", "/login", "/api/v1/orders", "/api/v1/users", "/static/app.js", "/healthz", "/api/v1/search"}
	return g
}

// Injected returns how many instances of each scenario were generated.
func (g *Generator) Injected() map[Scenario]int {
	out := make(map[Scenario]int, len(g.injected))
	for k, v := range g.injected {
		out[k] = v
	}
	return out
}

// Now returns the generator's current event-time clock.
func (g *Generator) Now() int64 { return g.now }

func (g *Generator) jitter() int64 {
	if g.o.Jitter <= 0 {
		return 0
	}
	return g.rnd.Int64N(int64(g.o.Jitter))
}

// Next returns the next event. Scenario events are interleaved with the
// background stream at their own timestamps (never ahead of the generator
// clock), so the stream's disorder is bounded by Jitter.
func (g *Generator) Next() *event.Event {
	if top, ok := g.pending.Peek(); ok && top.Time <= g.now {
		g.pending.Pop()
		return top
	}
	g.now += g.step
	if g.o.InjectPct > 0 && g.rnd.Float64() < g.o.InjectPct/8 {
		g.inject(Scenario(g.rnd.IntN(4)))
	}
	return g.background()
}

// Pending returns the number of scenario events not yet emitted.
func (g *Generator) Pending() int { return g.pending.Len() }

// Drain returns all remaining scenario events in time order, advancing the
// clock past them (used to finish a finite run with every scenario complete).
func (g *Generator) Drain() []*event.Event {
	out := make([]*event.Event, 0, g.pending.Len())
	for g.pending.Len() > 0 {
		ev, _ := g.pending.Pop()
		if ev.Time > g.now {
			g.now = ev.Time
		}
		out = append(out, ev)
	}
	return out
}

// Fill writes len(dst) events.
func (g *Generator) Fill(dst []*event.Event) {
	for i := range dst {
		dst[i] = g.Next()
	}
}

func (g *Generator) background() *event.Event {
	ts := g.now - g.jitter()
	key := g.keys[g.rnd.IntN(len(g.keys))]
	switch r := g.rnd.IntN(100); {
	case r < 55:
		svc := g.services[g.rnd.IntN(len(g.services))]
		lat := math.Exp(g.rnd.NormFloat64()*0.5 + 3.5) // median ~33ms
		status := int64(200)
		if g.rnd.IntN(100) < 2 {
			status = 500
		}
		return mk(ts, "http.request", svc, "edge", []event.Attr{
			{Name: "client_ip", Val: event.Str(key)},
			{Name: "latency_ms", Val: event.Float(lat)},
			{Name: "method", Val: event.Str("GET")},
			{Name: "path", Val: event.Str(g.paths[g.rnd.IntN(len(g.paths))])},
			{Name: "status", Val: event.Int(status)},
		})
	case r < 75:
		ok := g.rnd.IntN(50) != 0 // 2% background failure rate
		typ := "auth.success"
		if !ok {
			typ = "auth.failure"
		}
		return mk(ts, typ, key, "sshd", []event.Attr{
			{Name: "method", Val: event.Str("password")},
			{Name: "user", Val: event.Str(g.users[g.rnd.IntN(len(g.users))])},
		})
	case r < 95:
		return mk(ts, "net.flow", key, "netflow", []event.Attr{
			{Name: "bytes", Val: event.Int(g.rnd.Int64N(1 << 16))},
			{Name: "dst_port", Val: event.Int([]int64{22, 80, 443, 8080, 5432}[g.rnd.IntN(5)])},
			{Name: "proto", Val: event.Str("tcp")},
		})
	default:
		svc := g.services[g.rnd.IntN(len(g.services))]
		return mk(ts, "service.heartbeat", svc, "agent", []event.Attr{
			{Name: "cpu", Val: event.Float(g.rnd.Float64())},
		})
	}
}

func mk(ts int64, typ, key, src string, attrs []event.Attr) *event.Event {
	return &event.Event{Time: ts, Type: typ, Key: key, Source: src, Attrs: attrs}
}

// inject queues one scenario instance. Scenario keys use reserved ranges
// (2001:db8::/32 documentation IPv6 prefix, "atk-svc-*") so they never collide with
// background keys and expected detections are exact.
func (g *Generator) inject(s Scenario) {
	g.injected[s]++
	id := g.injected[s]
	t := g.now
	switch s {
	case ScenarioBruteForce:
		ip := fmt.Sprintf("2001:db8:1::%x", id)
		for i := 0; i < 6; i++ {
			t += int64(200 * time.Millisecond)
			g.pending.Push(mk(t, "auth.failure", ip, "sshd", []event.Attr{
				{Name: "method", Val: event.Str("password")},
				{Name: "user", Val: event.Str("root")},
			}))
		}
		t += int64(500 * time.Millisecond)
		g.pending.Push(mk(t, "auth.success", ip, "sshd", []event.Attr{
			{Name: "method", Val: event.Str("password")},
			{Name: "user", Val: event.Str("root")},
		}))
	case ScenarioLatencySpike:
		svc := fmt.Sprintf("atk-svc-%d", id)
		for i := 0; i < 60; i++ {
			t += int64(50 * time.Millisecond)
			g.pending.Push(mk(t, "http.request", svc, "edge", []event.Attr{
				{Name: "latency_ms", Val: event.Float(1500 + g.rnd.Float64()*500)},
				{Name: "path", Val: event.Str("/api/v1/orders")},
				{Name: "status", Val: event.Int(200)},
			}))
		}
	case ScenarioPortScan:
		ip := fmt.Sprintf("2001:db8:2::%x", id)
		for p := 0; p < 40; p++ {
			t += int64(20 * time.Millisecond)
			g.pending.Push(mk(t, "net.flow", ip, "netflow", []event.Attr{
				{Name: "bytes", Val: event.Int(60)},
				{Name: "dst_port", Val: event.Int(int64(1000 + p))},
				{Name: "proto", Val: event.Str("tcp")},
			}))
		}
	case ScenarioHeartbeatGap:
		svc := fmt.Sprintf("atk-svc-hb-%d", id)
		g.pending.Push(mk(t, "service.start", svc, "agent", []event.Attr{
			{Name: "version", Val: event.Str("1.4.2")},
		}))
	}
}
