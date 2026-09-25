package sketch

import (
	"math"
	"math/rand/v2"
	"sort"
	"strconv"
	"testing"
)

func TestHashDistribution(t *testing.T) {
	const buckets, n = 64, 64000
	var counts [buckets]int
	for i := 0; i < n; i++ {
		counts[Hash64("key-"+strconv.Itoa(i))%buckets]++
	}
	exp := float64(n) / buckets
	var chi float64
	for _, c := range counts {
		d := float64(c) - exp
		chi += d * d / exp
	}
	// 63 dof: p=0.001 critical value ~103.4.
	if chi > 103 {
		t.Fatalf("hash distribution chi^2=%.1f too high", chi)
	}
	if Hash64("") == Hash64("\x00") || Hash64("abc") == Hash64("abd") {
		t.Fatal("trivial collisions")
	}
}

func TestHLLAccuracy(t *testing.T) {
	for _, n := range []int{10, 100, 1000, 10000, 200000} {
		h := MustHLL(12)
		for i := 0; i < n; i++ {
			h.AddString("item-" + strconv.Itoa(i))
			h.AddString("item-" + strconv.Itoa(i)) // duplicates must not count
		}
		est := float64(h.Estimate())
		rel := math.Abs(est-float64(n)) / float64(n)
		// 1.04/sqrt(4096) = 1.6% std error; allow ~4 sigma.
		if rel > 0.065 {
			t.Errorf("n=%d estimate=%.0f relerr=%.3f", n, est, rel)
		}
	}
}

func TestHLLMerge(t *testing.T) {
	a, b, all := MustHLL(10), MustHLL(10), MustHLL(10)
	for i := 0; i < 5000; i++ {
		s := strconv.Itoa(i)
		if i%2 == 0 {
			a.AddString(s)
		} else {
			b.AddString(s)
		}
		all.AddString(s)
	}
	if err := a.Merge(b); err != nil {
		t.Fatal(err)
	}
	if a.Estimate() != all.Estimate() {
		t.Fatalf("merge not equivalent: %d vs %d", a.Estimate(), all.Estimate())
	}
	if err := a.Merge(MustHLL(11)); err == nil {
		t.Fatal("precision mismatch accepted")
	}
	if _, err := NewHLL(3); err == nil {
		t.Fatal("invalid precision accepted")
	}
}

func exactQuantile(sorted []float64, q float64) float64 {
	return sorted[int(q*float64(len(sorted)-1))]
}

func TestDDSketchRelativeError(t *testing.T) {
	r := rand.New(rand.NewPCG(9, 9))
	dists := map[string]func() float64{
		"lognormal": func() float64 { return math.Exp(r.NormFloat64()*1.5 + 3) },
		"uniform":   func() float64 { return r.Float64() * 1000 },
		"pareto":    func() float64 { return 1 / math.Pow(1-r.Float64(), 1/1.2) },
		"mixed":     func() float64 { return r.NormFloat64() * 100 },
	}
	const alpha = 0.01
	for name, gen := range dists {
		s := MustDDSketch(alpha, 2048)
		vals := make([]float64, 50000)
		for i := range vals {
			vals[i] = gen()
			s.Add(vals[i])
		}
		sort.Float64s(vals)
		for _, q := range []float64{0.01, 0.25, 0.5, 0.9, 0.99, 0.999} {
			want := exactQuantile(vals, q)
			got := s.Quantile(q)
			if want == 0 {
				continue
			}
			if rel := math.Abs(got-want) / math.Abs(want); rel > alpha*1.01+1e-9 {
				t.Errorf("%s q=%.3f got %.4f want %.4f relerr %.4f", name, q, got, want, rel)
			}
		}
		if s.Count() != uint64(len(vals)) || s.Min() != vals[0] || s.Max() != vals[len(vals)-1] {
			t.Errorf("%s: count/min/max mismatch", name)
		}
	}
}

func TestDDSketchMergeEquivalence(t *testing.T) {
	r := rand.New(rand.NewPCG(10, 10))
	whole := MustDDSketch(0.01, 512)
	parts := make([]*DDSketch, 8)
	for i := range parts {
		parts[i] = MustDDSketch(0.01, 512)
	}
	for i := 0; i < 40000; i++ {
		v := math.Exp(r.NormFloat64()*2 + float64(i%8))
		whole.Add(v)
		parts[i%8].Add(v)
	}
	merged := MustDDSketch(0.01, 512)
	for _, p := range parts {
		if err := merged.Merge(p); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []float64{0.1, 0.5, 0.9, 0.99} {
		if a, b := whole.Quantile(q), merged.Quantile(q); math.Abs(a-b)/a > 1e-9 {
			t.Errorf("q=%v whole=%v merged=%v", q, a, b)
		}
	}
	// Reset + reuse keeps correctness.
	merged.Reset()
	if merged.Count() != 0 || !math.IsNaN(merged.Quantile(0.5)) {
		t.Fatal("reset failed")
	}
	merged.Add(42)
	if merged.Quantile(0.5) != 42 {
		t.Fatal("single value quantile should clamp to exact value")
	}
}

func TestDDSketchCollapseKeepsHighQuantiles(t *testing.T) {
	s := MustDDSketch(0.01, 64) // tiny bucket budget forces collapsing
	var vals []float64
	for i := 0; i < 20000; i++ {
		v := math.Pow(10, float64(i%12)-3) * (1 + float64(i%7)/10)
		vals = append(vals, v)
		s.Add(v)
	}
	if s.Buckets() > 64 {
		t.Fatalf("bucket budget exceeded: %d", s.Buckets())
	}
	sort.Float64s(vals)
	want := exactQuantile(vals, 0.99)
	if got := s.Quantile(0.99); math.Abs(got-want)/want > 0.0101 {
		t.Fatalf("p99 degraded by collapsing: got %v want %v", got, want)
	}
	// Merge path also respects the budget.
	o := MustDDSketch(0.01, 64)
	o.Add(1e-6)
	o.Add(1e9)
	if err := s.Merge(o); err != nil {
		t.Fatal(err)
	}
	if s.Buckets() > 64 {
		t.Fatalf("merge exceeded bucket budget: %d", s.Buckets())
	}
	if s.Max() != 1e9 || s.Quantile(1) != 1e9 {
		t.Fatal("max lost in merge")
	}
}

func TestDDSketchEdgeCases(t *testing.T) {
	s := MustDDSketch(0.02, 128)
	if !math.IsNaN(s.Quantile(0.5)) || !math.IsNaN(s.Min()) {
		t.Fatal("empty sketch should return NaN")
	}
	s.Add(math.NaN())
	s.Add(math.Inf(1))
	if s.Count() != 0 {
		t.Fatal("NaN/Inf must be ignored")
	}
	s.Add(0)
	s.Add(-5)
	s.Add(5)
	if s.Quantile(0.5) != 0 {
		t.Fatalf("median of {-5,0,5} = %v", s.Quantile(0.5))
	}
	if q := s.Quantile(0); q != -5 {
		t.Fatalf("q0=%v", q)
	}
	if _, err := NewDDSketch(0, 100); err == nil {
		t.Fatal("alpha=0 accepted")
	}
	if _, err := NewDDSketch(0.01, 4); err == nil {
		t.Fatal("tiny bucket budget accepted")
	}
}

func BenchmarkDDSketchAdd(b *testing.B) {
	s := MustDDSketch(0.01, 512)
	r := rand.New(rand.NewPCG(1, 1))
	vals := make([]float64, 4096)
	for i := range vals {
		vals[i] = math.Exp(r.NormFloat64() + 3)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.Add(vals[i&4095])
	}
}

func BenchmarkDDSketchMerge(b *testing.B) {
	r := rand.New(rand.NewPCG(1, 1))
	src := MustDDSketch(0.01, 512)
	for i := 0; i < 1000; i++ {
		src.Add(math.Exp(r.NormFloat64()*2 + 3))
	}
	dst := MustDDSketch(0.01, 512)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dst.Reset()
		_ = dst.Merge(src)
	}
}

func BenchmarkHLLAdd(b *testing.B) {
	h := MustHLL(10)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.AddHash(HashUint64(uint64(i)))
	}
}
