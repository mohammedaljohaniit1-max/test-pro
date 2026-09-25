// Command tempora-bench measures end-to-end engine throughput and latency
// in-process (no network), or drives a running server over TCP.
//
//	tempora-bench -events 2000000 -producers 4 -rules rules
//	tempora-bench -target 127.0.0.1:9090 -rate 50000 -duration 30s
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/engine"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/loadgen"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/rules"
)

func main() {
	var (
		n         = flag.Int("events", 1_000_000, "events per run (in-process mode)")
		producers = flag.Int("producers", runtime.GOMAXPROCS(0), "concurrent producer goroutines")
		shards    = flag.Int("shards", 0, "engine shards (0 = GOMAXPROCS)")
		keys      = flag.Int("keys", 50_000, "distinct background keys")
		rulesPath = flag.String("rules", "rules", "rules file/dir")
		lateness  = flag.Duration("lateness", 500*time.Millisecond, "allowed lateness")
		jitter    = flag.Duration("jitter", 200*time.Millisecond, "event-time jitter (out-of-order)")
		inject    = flag.Float64("inject", 0.001, "scenario injection fraction")
		batch     = flag.Int("batch", 256, "submit batch size")
		target    = flag.String("target", "", "TCP address of a running tempora (network mode)")
		rate      = flag.Int("rate", 0, "network mode: events/s (0 = unlimited)")
		duration  = flag.Duration("duration", 10*time.Second, "network mode: run time")
		asJSON    = flag.Bool("json", false, "emit machine-readable JSON result")
		cpuprof   = flag.String("cpuprofile", "", "write a CPU profile of the measured phase")
		memprof   = flag.String("memprofile", "", "write a heap profile after the run")
	)
	flag.Parse()
	cpuProfile, memProfile = *cpuprof, *memprof
	if *target != "" {
		if err := network(*target, *rate, *duration, *keys, *inject, *jitter, *producers); err != nil {
			fmt.Fprintln(os.Stderr, "bench:", err)
			os.Exit(1)
		}
		return
	}
	res, err := inProcess(*n, *producers, *shards, *keys, *rulesPath, *lateness, *jitter, *inject, *batch)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(1)
	}
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(res)
		return
	}
	res.print()
}

var cpuProfile, memProfile string

// Result is a benchmark summary.
type Result struct {
	Events         int               `json:"events"`
	Producers      int               `json:"producers"`
	Shards         int               `json:"shards"`
	Rules          int               `json:"rules"`
	GOMAXPROCS     int               `json:"gomaxprocs"`
	Seconds        float64           `json:"seconds"`
	EventsPerSec   float64           `json:"events_per_sec"`
	Alerts         uint64            `json:"alerts"`
	AlertsByRule   map[string]uint64 `json:"alerts_by_rule"`
	Injected       map[string]int    `json:"injected"`
	Late           uint64            `json:"late"`
	EvalP50us      float64           `json:"eval_p50_us"`
	EvalP99us      float64           `json:"eval_p99_us"`
	EvalP999us     float64           `json:"eval_p999_us"`
	AlertP50us     float64           `json:"alert_p50_us"`
	AlertP99us     float64           `json:"alert_p99_us"`
	HeapInuseMiB   float64           `json:"heap_inuse_mib"`
	PeakHeapMiB    float64           `json:"peak_heap_mib"`
	BytesPerKey    float64           `json:"bytes_per_key"`
	GCCycles       uint32            `json:"gc_cycles"`
	GCPauseTotalMs float64           `json:"gc_pause_total_ms"`
	AllocsPerEvent float64           `json:"allocs_per_event"`
	Totals         engine.ShardStats `json:"totals"`
}

var scenarioNames = map[loadgen.Scenario]string{
	loadgen.ScenarioBruteForce: "brute_force", loadgen.ScenarioLatencySpike: "latency_spike",
	loadgen.ScenarioPortScan: "port_scan", loadgen.ScenarioHeartbeatGap: "heartbeat_gap",
}

func inProcess(n, producers, shards, keys int, rulesPath string, lateness, jitter time.Duration, inject float64, batch int) (*Result, error) {
	rs, err := rules.CompileFiles(rulesPath)
	if err != nil {
		return nil, err
	}
	if producers < 1 {
		producers = 1
	}
	eng := engine.New(engine.Config{Shards: shards, AllowedLateness: lateness}, rs)
	// Pre-generate a single event-time-ordered stream (bounded jitter) so
	// generation cost is excluded from the measurement, then partition it by
	// shard so that each producer owns a disjoint set of shards. This mirrors
	// partition-aligned producers (e.g. Kafka partitions): every shard sees a
	// single ordered stream, and disorder is bounded by the jitter rather
	// than by goroutine scheduling skew between producers.
	g := loadgen.New(loadgen.Options{Seed: 42, Keys: keys, Rate: 100_000, Jitter: jitter, InjectPct: inject})
	all := make([]*event.Event, n)
	g.Fill(all)
	all = append(all, g.Drain()...)
	endTS := g.Now()
	injected := map[string]int{}
	for sc, c := range g.Injected() {
		injected[scenarioNames[sc]] += c
	}
	streams := make([][]*event.Event, producers)
	for _, ev := range all {
		p := eng.ShardFor(ev.Key) % producers
		streams[p] = append(streams[p], ev)
	}
	total := len(all)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	var drained atomic.Uint64
	var wgA sync.WaitGroup
	wgA.Add(1)
	go func() {
		defer wgA.Done()
		for range eng.Alerts() {
			drained.Add(1)
		}
	}()
	var peak atomic.Uint64
	stopMem := make(chan struct{})
	go func() {
		t := time.NewTicker(50 * time.Millisecond)
		defer t.Stop()
		var ms runtime.MemStats
		for {
			select {
			case <-stopMem:
				return
			case <-t.C:
				runtime.ReadMemStats(&ms)
				if ms.HeapInuse > peak.Load() {
					peak.Store(ms.HeapInuse)
				}
			}
		}
	}()

	ctx := context.Background()
	if cpuProfile != "" {
		f, err := os.Create(cpuProfile)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			return nil, err
		}
	}
	start := time.Now()
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(evs []*event.Event) {
			defer wg.Done()
			for i := 0; i < len(evs); i += batch {
				j := i + batch
				if j > len(evs) {
					j = len(evs)
				}
				if _, err := eng.SubmitBatch(ctx, evs[i:j]); err != nil {
					fmt.Fprintln(os.Stderr, "submit:", err)
					return
				}
			}
		}(streams[p])
	}
	wg.Wait()
	// Advance event time past the longest rule horizon so absence rules and
	// open windows resolve, then barrier.
	if err := eng.Advance(ctx, endTS+int64(10*time.Minute)); err != nil {
		return nil, err
	}
	elapsed := time.Since(start)
	if cpuProfile != "" {
		pprof.StopCPUProfile()
	}
	if memProfile != "" {
		f, err := os.Create(memProfile)
		if err != nil {
			return nil, err
		}
		_ = pprof.WriteHeapProfile(f)
		f.Close()
	}

	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	close(stopMem)
	tot := eng.Totals()
	m := eng.Metrics()
	res := &Result{
		Events: total, Producers: producers, Shards: eng.Config().Shards, Rules: len(rs.Rules),
		GOMAXPROCS: runtime.GOMAXPROCS(0), Seconds: elapsed.Seconds(),
		EventsPerSec: float64(total) / elapsed.Seconds(),
		Injected:     injected, Late: tot.Late,
		EvalP50us: m.EvalLatency.Quantile(0.5) * 1e6, EvalP99us: m.EvalLatency.Quantile(0.99) * 1e6,
		EvalP999us: m.EvalLatency.Quantile(0.999) * 1e6,
		AlertP50us: m.AlertLatency.Quantile(0.5) * 1e6, AlertP99us: m.AlertLatency.Quantile(0.99) * 1e6,
		HeapInuseMiB:   float64(after.HeapInuse) / (1 << 20),
		PeakHeapMiB:    float64(peak.Load()) / (1 << 20),
		GCCycles:       after.NumGC - before.NumGC,
		GCPauseTotalMs: float64(after.PauseTotalNs-before.PauseTotalNs) / 1e6,
		AllocsPerEvent: float64(after.Mallocs-before.Mallocs) / float64(total),
		Totals:         tot,
	}
	if tot.Keys > 0 {
		// Retained heap attributable to engine state, net of the
		// pre-generated input which is still live.
		res.BytesPerKey = float64(int64(after.HeapInuse)-int64(before.HeapInuse)) / float64(tot.Keys)
	}
	eng.Close()
	wgA.Wait()
	res.Alerts = tot.Alerts
	res.AlertsByRule = eng.RuleMatches()
	runtime.KeepAlive(streams)
	return res, nil
}

func (r *Result) print() {
	fmt.Printf("Tempora in-process benchmark\n")
	fmt.Printf("  events            %d (producers=%d shards=%d rules=%d GOMAXPROCS=%d)\n", r.Events, r.Producers, r.Shards, r.Rules, r.GOMAXPROCS)
	fmt.Printf("  elapsed           %.3fs\n", r.Seconds)
	fmt.Printf("  throughput        %.0f events/s\n", r.EventsPerSec)
	fmt.Printf("  eval latency      p50=%.2fus p99=%.2fus p99.9=%.2fus (sampled, per event)\n", r.EvalP50us, r.EvalP99us, r.EvalP999us)
	fmt.Printf("  ingest->alert     p50=%.1fus p99=%.1fus\n", r.AlertP50us, r.AlertP99us)
	fmt.Printf("  alerts            %d %v\n", r.Alerts, r.AlertsByRule)
	fmt.Printf("  injected          %v\n", r.Injected)
	fmt.Printf("  late dropped      %d\n", r.Late)
	fmt.Printf("  state             keys=%d runs=%d groups=%d timers=%d\n", r.Totals.Keys, r.Totals.Runs, r.Totals.Groups, r.Totals.Timers)
	fmt.Printf("  memory            heap_inuse=%.1fMiB peak=%.1fMiB ~%.0f B/key\n", r.HeapInuseMiB, r.PeakHeapMiB, r.BytesPerKey)
	fmt.Printf("  gc                cycles=%d pause_total=%.2fms allocs/event=%.2f\n", r.GCCycles, r.GCPauseTotalMs, r.AllocsPerEvent)
}

func network(addr string, rate int, d time.Duration, keys int, inject float64, jitter time.Duration, conns int) error {
	if conns < 1 {
		conns = 1
	}
	var sent atomic.Uint64
	deadline := time.Now().Add(d)
	var wg sync.WaitGroup
	errc := make(chan error, conns)
	for c := 0; c < conns; c++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				errc <- err
				return
			}
			defer conn.Close()
			w := bufio.NewWriterSize(conn, 256<<10)
			g := loadgen.New(loadgen.Options{Seed: uint64(id + 1), Keys: keys, Start: time.Now(), Rate: 100_000, Jitter: jitter, InjectPct: inject})
			perConn := 0
			if rate > 0 {
				perConn = rate / conns
				if perConn < 1 {
					perConn = 1
				}
			}
			tickStart := time.Now()
			var local int
			buf := make([]byte, 0, 512)
			for time.Now().Before(deadline) {
				ev := g.Next()
				buf = appendWire(buf[:0], ev)
				if _, err := w.Write(buf); err != nil {
					errc <- err
					return
				}
				local++
				sent.Add(1)
				if perConn > 0 && local%100 == 0 {
					want := time.Duration(float64(local) / float64(perConn) * float64(time.Second))
					if ahead := want - time.Since(tickStart); ahead > 0 {
						_ = w.Flush()
						time.Sleep(ahead)
					}
				}
			}
			if err := w.Flush(); err != nil {
				errc <- err
			}
		}(c)
	}
	start := time.Now()
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		var last uint64
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				cur := sent.Load()
				fmt.Printf("  sent %d events (%d/s)\n", cur, cur-last)
				last = cur
			}
		}
	}()
	wg.Wait()
	close(stop)
	select {
	case err := <-errc:
		return err
	default:
	}
	el := time.Since(start)
	fmt.Printf("network mode: sent %d events in %.2fs (%.0f events/s)\n", sent.Load(), el.Seconds(), float64(sent.Load())/el.Seconds())
	return nil
}

func appendWire(dst []byte, ev *event.Event) []byte {
	m := map[string]any{
		"type": ev.Type, "key": ev.Key, "source": ev.Source, "ts": ev.Time,
	}
	attrs := make(map[string]any, len(ev.Attrs))
	for _, a := range ev.Attrs {
		attrs[a.Name] = a.Val.Interface()
	}
	m["attrs"] = attrs
	b, _ := json.Marshal(m)
	dst = append(dst, b...)
	return append(dst, '\n')
}
