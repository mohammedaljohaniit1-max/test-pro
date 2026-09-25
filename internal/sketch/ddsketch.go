package sketch

import (
	"fmt"
	"math"
)

// DDSketch is a relative-error quantile sketch (Masson et al., VLDB 2019).
// Positive values x are mapped to bucket ceil(log_gamma(x)); every quantile
// estimate is within relative error alpha of the true value. Values <= 0 (or
// below minIndexable) are counted in a dedicated zero bucket; negative values
// are tracked in a mirrored store.
//
// Buckets are stored in a dense, offset-indexed slice. When the number of
// buckets would exceed maxBuckets, the lowest buckets are collapsed into one,
// preserving accuracy for the high quantiles that alerting cares about.
type DDSketch struct {
	alpha      float64
	gamma      float64
	logGamma   float64
	maxBuckets int

	pos   store
	neg   store
	zero  uint64
	count uint64
	sum   float64
	min   float64
	max   float64
}

const minIndexable = 1e-9

type store struct {
	counts []uint64
	offset int // bucket index of counts[0]
	total  uint64
}

// NewDDSketch creates a sketch with relative accuracy alpha in (0,1) and at
// most maxBuckets buckets per sign.
func NewDDSketch(alpha float64, maxBuckets int) (*DDSketch, error) {
	if !(alpha > 0 && alpha < 1) {
		return nil, fmt.Errorf("sketch: ddsketch alpha %v must be in (0,1)", alpha)
	}
	if maxBuckets < 16 {
		return nil, fmt.Errorf("sketch: ddsketch maxBuckets %d must be >= 16", maxBuckets)
	}
	g := (1 + alpha) / (1 - alpha)
	return &DDSketch{
		alpha: alpha, gamma: g, logGamma: math.Log(g), maxBuckets: maxBuckets,
		min: math.Inf(1), max: math.Inf(-1),
	}, nil
}

// MustDDSketch panics on invalid parameters.
func MustDDSketch(alpha float64, maxBuckets int) *DDSketch {
	s, err := NewDDSketch(alpha, maxBuckets)
	if err != nil {
		panic(err)
	}
	return s
}

func (s *DDSketch) index(x float64) int {
	return int(math.Ceil(math.Log(x) / s.logGamma))
}

func (s *DDSketch) value(idx int) float64 {
	// Midpoint of bucket (gamma^(i-1), gamma^i] in relative terms.
	return 2 * math.Pow(s.gamma, float64(idx)) / (1 + s.gamma)
}

// Add inserts a value. NaN and infinities are ignored.
func (s *DDSketch) Add(x float64) {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return
	}
	s.count++
	s.sum += x
	if x < s.min {
		s.min = x
	}
	if x > s.max {
		s.max = x
	}
	switch {
	case x > minIndexable:
		s.pos.add(s.index(x), 1, s.maxBuckets)
	case x < -minIndexable:
		s.neg.add(s.index(-x), 1, s.maxBuckets)
	default:
		s.zero++
	}
}

func (st *store) add(idx int, n uint64, maxBuckets int) {
	st.total += n
	if len(st.counts) == 0 {
		st.counts = make([]uint64, 1, 8)
		st.offset = idx
		st.counts[0] = n
		return
	}
	if idx < st.offset {
		grow := st.offset - idx
		if len(st.counts)+grow > maxBuckets {
			// Collapse: anything below the lowest retained bucket lands there.
			keepLow := st.offset + len(st.counts) - maxBuckets
			if idx < keepLow || grow > maxBuckets {
				st.counts[0] += n
				return
			}
		}
		nc := make([]uint64, len(st.counts)+grow, (len(st.counts)+grow)*5/4+1)
		copy(nc[grow:], st.counts)
		st.counts = nc
		st.offset = idx
		st.counts[0] += n
		return
	}
	pos := idx - st.offset
	if pos >= len(st.counts) {
		need := pos + 1
		if need > maxBuckets {
			// Collapse the lowest buckets to make room at the top.
			shift := need - maxBuckets
			if shift >= len(st.counts) {
				var sum uint64
				for _, c := range st.counts {
					sum += c
				}
				clear(st.counts)
				st.counts = st.counts[:1]
				st.counts[0] = sum
				st.offset = idx - maxBuckets + 1
				pos = idx - st.offset
				need = pos + 1
			} else {
				var sum uint64
				for _, c := range st.counts[:shift+1] {
					sum += c
				}
				copy(st.counts, st.counts[shift:])
				st.counts = st.counts[:len(st.counts)-shift]
				st.counts[0] = sum
				st.offset += shift
				pos = idx - st.offset
				need = pos + 1
			}
		}
		for len(st.counts) < need {
			st.counts = append(st.counts, 0)
		}
	}
	st.counts[pos] += n
}

// mergeFrom adds every bucket of o into st in a single pass: the index range
// is widened once (collapsing the lowest buckets if it would exceed
// maxBuckets) and the counts are then summed densely. This is O(len(st) +
// len(o)) with no per-bucket branching on the growth path, versus
// O(len(o) * grow) for repeated add().
func (st *store) mergeFrom(o *store, maxBuckets int) {
	if o.total == 0 {
		return
	}
	if len(st.counts) == 0 {
		st.counts = append(st.counts[:0], o.counts...)
		st.offset, st.total = o.offset, o.total
		if len(st.counts) > maxBuckets {
			st.reshape(st.offset+len(st.counts)-maxBuckets, st.offset+len(st.counts))
		}
		return
	}
	lo, hi := st.offset, st.offset+len(st.counts)
	if o.offset < lo {
		lo = o.offset
	}
	if e := o.offset + len(o.counts); e > hi {
		hi = e
	}
	if hi-lo > maxBuckets {
		lo = hi - maxBuckets
	}
	st.reshape(lo, hi)
	src := o.counts
	dst := st.counts
	i := 0
	for ; i < len(src) && o.offset+i < lo; i++ {
		dst[0] += src[i] // collapsed into the lowest retained bucket
	}
	base := o.offset + i - lo
	src = src[i:]
	dst = dst[base : base+len(src)]
	for j, c := range src {
		dst[j] += c
	}
	st.total += o.total
}

// reshape re-bases the dense store onto bucket range [lo, hi), folding any
// buckets below lo into the new lowest bucket. Reuses capacity when possible.
func (st *store) reshape(lo, hi int) {
	n := hi - lo
	old := st.counts
	var below uint64
	start := 0
	if st.offset < lo {
		k := lo - st.offset
		if k > len(old) {
			k = len(old)
		}
		for _, c := range old[:k] {
			below += c
		}
		start = k
	}
	kept := old[start:]
	pos := st.offset + start - lo
	if pos < 0 {
		pos = 0
	}
	var buf []uint64
	if cap(old) >= n {
		buf = old[:n]
		copy(buf[pos:], kept) // memmove: overlap-safe
		clear(buf[:pos])
		clear(buf[pos+len(kept):])
	} else {
		buf = make([]uint64, n, n+n/4)
		copy(buf[pos:], kept)
	}
	buf[0] += below
	st.counts, st.offset = buf, lo
}

// Merge folds o into s. Both sketches must share alpha.
func (s *DDSketch) Merge(o *DDSketch) error {
	if o.alpha != s.alpha {
		return fmt.Errorf("sketch: ddsketch alpha mismatch %v != %v", s.alpha, o.alpha)
	}
	if o.count == 0 {
		return nil
	}
	s.pos.mergeFrom(&o.pos, s.maxBuckets)
	s.neg.mergeFrom(&o.neg, s.maxBuckets)
	s.zero += o.zero
	s.count += o.count
	s.sum += o.sum
	if o.min < s.min {
		s.min = o.min
	}
	if o.max > s.max {
		s.max = o.max
	}
	return nil
}

// Reset clears the sketch, retaining bucket memory.
func (s *DDSketch) Reset() {
	s.pos.counts = s.pos.counts[:0]
	s.pos.total = 0
	s.neg.counts = s.neg.counts[:0]
	s.neg.total = 0
	s.zero, s.count, s.sum = 0, 0, 0
	s.min, s.max = math.Inf(1), math.Inf(-1)
}

// Count returns the number of values inserted.
func (s *DDSketch) Count() uint64 { return s.count }

// Sum returns the exact sum of values inserted.
func (s *DDSketch) Sum() float64 { return s.sum }

// Min returns the exact minimum (NaN if empty).
func (s *DDSketch) Min() float64 {
	if s.count == 0 {
		return math.NaN()
	}
	return s.min
}

// Max returns the exact maximum (NaN if empty).
func (s *DDSketch) Max() float64 {
	if s.count == 0 {
		return math.NaN()
	}
	return s.max
}

// Quantile returns the estimated q-quantile, q in [0,1]. NaN if empty.
func (s *DDSketch) Quantile(q float64) float64 {
	if s.count == 0 || q < 0 || q > 1 || math.IsNaN(q) {
		return math.NaN()
	}
	if q == 0 {
		return s.min
	}
	if q == 1 {
		return s.max
	}
	rank := uint64(q * float64(s.count-1))
	var v float64
	switch {
	case rank < s.neg.total:
		// Negative store is walked from the largest magnitude down.
		var acc uint64
		for i := len(s.neg.counts) - 1; i >= 0; i-- {
			acc += s.neg.counts[i]
			if acc > rank {
				v = -s.value(s.neg.offset + i)
				break
			}
		}
	case rank < s.neg.total+s.zero:
		v = 0
	default:
		r := rank - s.neg.total - s.zero
		var acc uint64
		for i, c := range s.pos.counts {
			acc += c
			if acc > r {
				v = s.value(s.pos.offset + i)
				break
			}
		}
	}
	// Clamp to the exact observed range.
	if v < s.min {
		v = s.min
	}
	if v > s.max {
		v = s.max
	}
	return v
}

// Buckets returns the number of allocated buckets (memory proxy).
func (s *DDSketch) Buckets() int { return len(s.pos.counts) + len(s.neg.counts) }
