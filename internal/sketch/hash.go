// Package sketch contains fixed-memory probabilistic summaries used by the
// windowed aggregation engine:
//
//   - HLL: HyperLogLog cardinality estimator (dense registers, bias-corrected
//     with linear counting for small ranges). Mergeable.
//   - DDSketch: relative-error quantile sketch with logarithmic buckets.
//     Mergeable, bounded bucket count with lowest-bucket collapsing.
package sketch

import "math/bits"

// Hash64 is a fast, well-distributed, allocation-free 64-bit string hash
// (wyhash-style multiply-mix over 8-byte lanes). It is not cryptographic; it
// is used for sketch registers and shard routing.
func Hash64(s string) uint64 {
	const (
		p0 = 0xa0761d6478bd642f
		p1 = 0xe7037ed1a0b428db
		p2 = 0x8ebc6af09c88c6e3
	)
	h := uint64(len(s)) * p0
	i := 0
	for ; i+8 <= len(s); i += 8 {
		v := uint64(s[i]) | uint64(s[i+1])<<8 | uint64(s[i+2])<<16 | uint64(s[i+3])<<24 |
			uint64(s[i+4])<<32 | uint64(s[i+5])<<40 | uint64(s[i+6])<<48 | uint64(s[i+7])<<56
		h = mix(h^v, p1)
	}
	var tail uint64
	for j := 0; i < len(s); i, j = i+1, j+8 {
		tail |= uint64(s[i]) << j
	}
	h = mix(h^tail, p2)
	return fmix(h)
}

// HashUint64 hashes an integer.
func HashUint64(v uint64) uint64 { return fmix(v ^ 0x9e3779b97f4a7c15) }

func mix(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	return hi ^ lo
}

// fmix is the MurmurHash3 64-bit finaliser (full avalanche).
func fmix(k uint64) uint64 {
	k ^= k >> 33
	k *= 0xff51afd7ed558ccd
	k ^= k >> 33
	k *= 0xc4ceb9fe1a85ec53
	k ^= k >> 33
	return k
}
