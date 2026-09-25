package sketch

import (
	"fmt"
	"math"
	"math/bits"
)

// HLL is a dense HyperLogLog sketch with 2^p single-byte registers.
// With p=12 it uses 4 KiB and has a standard error of ~1.63%.
type HLL struct {
	p    uint8
	regs []uint8
}

// NewHLL creates a sketch with precision p in [4, 16].
func NewHLL(p uint8) (*HLL, error) {
	if p < 4 || p > 16 {
		return nil, fmt.Errorf("sketch: hll precision %d out of range [4,16]", p)
	}
	return &HLL{p: p, regs: make([]uint8, 1<<p)}, nil
}

// MustHLL is NewHLL that panics on invalid precision (for constants).
func MustHLL(p uint8) *HLL {
	h, err := NewHLL(p)
	if err != nil {
		panic(err)
	}
	return h
}

// Precision returns p.
func (h *HLL) Precision() uint8 { return h.p }

// AddHash inserts a pre-hashed 64-bit value.
func (h *HLL) AddHash(x uint64) {
	idx := x >> (64 - h.p)
	w := x<<h.p | 1<<(h.p-1) // guard bit bounds rank
	rank := uint8(bits.LeadingZeros64(w)) + 1
	if rank > h.regs[idx] {
		h.regs[idx] = rank
	}
}

// AddString inserts a string.
func (h *HLL) AddString(s string) { h.AddHash(Hash64(s)) }

// Merge folds o into h. Both sketches must share a precision.
func (h *HLL) Merge(o *HLL) error {
	if o.p != h.p {
		return fmt.Errorf("sketch: hll precision mismatch %d != %d", h.p, o.p)
	}
	for i, r := range o.regs {
		if r > h.regs[i] {
			h.regs[i] = r
		}
	}
	return nil
}

// Reset clears all registers.
func (h *HLL) Reset() { clear(h.regs) }

// Estimate returns the estimated cardinality.
func (h *HLL) Estimate() uint64 {
	m := float64(len(h.regs))
	var sum float64
	zeros := 0
	for _, r := range h.regs {
		sum += 1 / float64(uint64(1)<<r)
		if r == 0 {
			zeros++
		}
	}
	var alpha float64
	switch len(h.regs) {
	case 16:
		alpha = 0.673
	case 32:
		alpha = 0.697
	case 64:
		alpha = 0.709
	default:
		alpha = 0.7213 / (1 + 1.079/m)
	}
	est := alpha * m * m / sum
	if est <= 2.5*m && zeros > 0 {
		// Linear counting is far more accurate in the small range.
		est = m * math.Log(m/float64(zeros))
	}
	return uint64(est + 0.5)
}

// SizeBytes returns the memory held by the registers.
func (h *HLL) SizeBytes() int { return len(h.regs) }
