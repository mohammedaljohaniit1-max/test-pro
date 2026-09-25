// Package metrics is a small, dependency-free, lock-free metrics registry
// that renders the Prometheus text exposition format (v0.0.4).
//
// Hot-path operations (Counter.Add, Gauge.Set, Histogram.Observe) are single
// atomic instructions on padded words; registration and rendering take a
// mutex but are off the hot path.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Counter is a monotonically increasing uint64.
type Counter struct {
	v atomic.Uint64
	_ [56]byte
}

// Inc adds one.
func (c *Counter) Inc() { c.v.Add(1) }

// Add adds n.
func (c *Counter) Add(n uint64) { c.v.Add(n) }

// Load returns the current value.
func (c *Counter) Load() uint64 { return c.v.Load() }

// Gauge is an int64 that can go up and down.
type Gauge struct {
	v atomic.Int64
	_ [56]byte
}

// Set stores v.
func (g *Gauge) Set(v int64) { g.v.Store(v) }

// Add adds d (may be negative).
func (g *Gauge) Add(d int64) { g.v.Add(d) }

// Load returns the current value.
func (g *Gauge) Load() int64 { return g.v.Load() }

// Histogram is a fixed-bucket cumulative histogram of float64 observations.
type Histogram struct {
	bounds  []float64
	counts  []atomic.Uint64 // len(bounds)+1, last is +Inf
	sumBits atomic.Uint64
	count   atomic.Uint64
}

// NewHistogram creates a histogram with strictly increasing upper bounds.
func NewHistogram(bounds []float64) *Histogram {
	b := append([]float64(nil), bounds...)
	sort.Float64s(b)
	return &Histogram{bounds: b, counts: make([]atomic.Uint64, len(b)+1)}
}

// ExponentialBuckets returns count bounds starting at start, each factor
// times the previous.
func ExponentialBuckets(start, factor float64, count int) []float64 {
	out := make([]float64, count)
	v := start
	for i := range out {
		out[i] = v
		v *= factor
	}
	return out
}

// Observe records v.
func (h *Histogram) Observe(v float64) {
	// Linear scan beats binary search for the ~20 buckets used here.
	i := 0
	for i < len(h.bounds) && v > h.bounds[i] {
		i++
	}
	h.counts[i].Add(1)
	h.count.Add(1)
	for {
		old := h.sumBits.Load()
		nv := math.Float64bits(math.Float64frombits(old) + v)
		if h.sumBits.CompareAndSwap(old, nv) {
			return
		}
	}
}

// Count returns the number of observations.
func (h *Histogram) Count() uint64 { return h.count.Load() }

// Sum returns the sum of observations.
func (h *Histogram) Sum() float64 { return math.Float64frombits(h.sumBits.Load()) }

// Quantile estimates the q-quantile by linear interpolation inside buckets.
func (h *Histogram) Quantile(q float64) float64 {
	total := h.count.Load()
	if total == 0 {
		return math.NaN()
	}
	rank := q * float64(total)
	var acc float64
	lower := 0.0
	for i := range h.counts {
		c := float64(h.counts[i].Load())
		if acc+c >= rank {
			upper := math.Inf(1)
			if i < len(h.bounds) {
				upper = h.bounds[i]
			} else {
				return lower
			}
			if c == 0 {
				return upper
			}
			return lower + (upper-lower)*(rank-acc)/c
		}
		acc += c
		if i < len(h.bounds) {
			lower = h.bounds[i]
		}
	}
	return lower
}

type kind int

const (
	kindCounter kind = iota
	kindGauge
	kindHistogram
	kindGaugeFunc
	kindCounterFunc
)

type series struct {
	labels string // pre-rendered {a="b"}
	c      *Counter
	g      *Gauge
	h      *Histogram
	fn     func() float64
}

type family struct {
	name, help string
	kind       kind
	series     []*series
	byLabels   map[string]*series
}

// Registry holds metric families.
type Registry struct {
	mu       sync.Mutex
	families map[string]*family
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry { return &Registry{families: make(map[string]*family)} }

// Labels is an ordered list of name/value pairs.
type Labels []string

func renderLabels(l Labels) string {
	if len(l) == 0 {
		return ""
	}
	if len(l)%2 != 0 {
		panic("metrics: labels must be name/value pairs")
	}
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < len(l); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(l[i])
		b.WriteString(`="`)
		b.WriteString(escape(l[i+1]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func escape(s string) string {
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

func (r *Registry) get(name, help string, k kind, labels Labels) *series {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.families[name]
	if !ok {
		f = &family{name: name, help: help, kind: k, byLabels: make(map[string]*series)}
		r.families[name] = f
	} else if f.kind != k {
		panic(fmt.Sprintf("metrics: %s re-registered with a different type", name))
	}
	ls := renderLabels(labels)
	if s, ok := f.byLabels[ls]; ok {
		return s
	}
	s := &series{labels: ls}
	f.byLabels[ls] = s
	f.series = append(f.series, s)
	return s
}

// Counter returns (creating if needed) the counter for name+labels.
func (r *Registry) Counter(name, help string, labels ...string) *Counter {
	s := r.get(name, help, kindCounter, labels)
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.c == nil {
		s.c = &Counter{}
	}
	return s.c
}

// Gauge returns (creating if needed) the gauge for name+labels.
func (r *Registry) Gauge(name, help string, labels ...string) *Gauge {
	s := r.get(name, help, kindGauge, labels)
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.g == nil {
		s.g = &Gauge{}
	}
	return s.g
}

// Histogram returns (creating if needed) the histogram for name+labels.
func (r *Registry) Histogram(name, help string, bounds []float64, labels ...string) *Histogram {
	s := r.get(name, help, kindHistogram, labels)
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.h == nil {
		s.h = NewHistogram(bounds)
	}
	return s.h
}

// GaugeFunc registers a gauge sampled at scrape time.
func (r *Registry) GaugeFunc(name, help string, fn func() float64, labels ...string) {
	s := r.get(name, help, kindGaugeFunc, labels)
	r.mu.Lock()
	s.fn = fn
	r.mu.Unlock()
}

// CounterFunc registers a counter sampled at scrape time.
func (r *Registry) CounterFunc(name, help string, fn func() float64, labels ...string) {
	s := r.get(name, help, kindCounterFunc, labels)
	r.mu.Lock()
	s.fn = fn
	r.mu.Unlock()
}

func fmtFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// WritePrometheus renders all families in text exposition format.
func (r *Registry) WritePrometheus(w io.Writer) error {
	r.mu.Lock()
	names := make([]string, 0, len(r.families))
	for n := range r.families {
		names = append(names, n)
	}
	sort.Strings(names)
	fams := make([]*family, len(names))
	for i, n := range names {
		f := r.families[n]
		cp := *f
		cp.series = append([]*series(nil), f.series...)
		fams[i] = &cp
	}
	r.mu.Unlock()

	var b strings.Builder
	for _, f := range fams {
		typ := "counter"
		switch f.kind {
		case kindGauge, kindGaugeFunc:
			typ = "gauge"
		case kindHistogram:
			typ = "histogram"
		}
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", f.name, f.help, f.name, typ)
		for _, s := range f.series {
			switch f.kind {
			case kindCounter:
				fmt.Fprintf(&b, "%s%s %d\n", f.name, s.labels, s.c.Load())
			case kindGauge:
				fmt.Fprintf(&b, "%s%s %d\n", f.name, s.labels, s.g.Load())
			case kindGaugeFunc, kindCounterFunc:
				fmt.Fprintf(&b, "%s%s %s\n", f.name, s.labels, fmtFloat(s.fn()))
			case kindHistogram:
				writeHistogram(&b, f.name, s.labels, s.h)
			}
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writeHistogram(b *strings.Builder, name, labels string, h *Histogram) {
	inner := ""
	if labels != "" {
		inner = labels[1:len(labels)-1] + ","
	}
	var acc uint64
	for i := range h.counts {
		acc += h.counts[i].Load()
		le := "+Inf"
		if i < len(h.bounds) {
			le = fmtFloat(h.bounds[i])
		}
		fmt.Fprintf(b, "%s_bucket{%sle=\"%s\"} %d\n", name, inner, le, acc)
	}
	fmt.Fprintf(b, "%s_sum%s %s\n", name, labels, fmtFloat(h.Sum()))
	fmt.Fprintf(b, "%s_count%s %d\n", name, labels, acc)
}
