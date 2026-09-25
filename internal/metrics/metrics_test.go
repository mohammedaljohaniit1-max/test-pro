package metrics

import (
	"math"
	"strings"
	"sync"
	"testing"
)

func TestCountersGaugesConcurrent(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("req_total", "Requests.", "code", "200")
	g := r.Gauge("inflight", "In flight.")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10000; j++ {
				c.Inc()
				g.Add(1)
				g.Add(-1)
			}
		}()
	}
	wg.Wait()
	if c.Load() != 80000 || g.Load() != 0 {
		t.Fatalf("counter=%d gauge=%d", c.Load(), g.Load())
	}
	if r.Counter("req_total", "Requests.", "code", "200") != c {
		t.Fatal("same labels must return the same series")
	}
}

func TestHistogramQuantiles(t *testing.T) {
	h := NewHistogram(ExponentialBuckets(1, 2, 16))
	for i := 1; i <= 1000; i++ {
		h.Observe(float64(i))
	}
	if h.Count() != 1000 || h.Sum() != 500500 {
		t.Fatalf("count=%d sum=%v", h.Count(), h.Sum())
	}
	p50 := h.Quantile(0.5)
	if p50 < 400 || p50 > 600 {
		t.Fatalf("p50=%v", p50)
	}
	if !math.IsNaN(NewHistogram([]float64{1}).Quantile(0.5)) {
		t.Fatal("empty histogram quantile should be NaN")
	}
}

func TestPrometheusExposition(t *testing.T) {
	r := NewRegistry()
	r.Counter("a_total", "A counter.", "path", `/x"y`).Add(3)
	r.Gauge("b", "B gauge.").Set(-2)
	h := r.Histogram("lat_seconds", "Latency.", []float64{0.1, 1}, "op", "read")
	h.Observe(0.05)
	h.Observe(0.5)
	h.Observe(5)
	r.GaugeFunc("f", "Func.", func() float64 { return 1.5 })
	var sb strings.Builder
	if err := r.WritePrometheus(&sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{
		"# TYPE a_total counter",
		`a_total{path="/x\"y"} 3`,
		"# TYPE b gauge\nb -2",
		`lat_seconds_bucket{op="read",le="0.1"} 1`,
		`lat_seconds_bucket{op="read",le="1"} 2`,
		`lat_seconds_bucket{op="read",le="+Inf"} 3`,
		`lat_seconds_count{op="read"} 3`,
		"f 1.5",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// Families are sorted by name for stable scrapes.
	if strings.Index(out, "a_total") > strings.Index(out, "lat_seconds") {
		t.Fatal("families not sorted")
	}
}

func TestTypeConflictPanics(t *testing.T) {
	r := NewRegistry()
	r.Counter("x", "x")
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on type conflict")
		}
	}()
	r.Gauge("x", "x")
}

func BenchmarkHistogramObserve(b *testing.B) {
	h := NewHistogram(ExponentialBuckets(1e-6, 2, 20))
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		v := 1e-5
		for pb.Next() {
			h.Observe(v)
		}
	})
}
