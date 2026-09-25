// Package event defines the canonical telemetry event model shared by every
// stage of the pipeline: ingestion, journaling, routing and evaluation.
//
// Events are immutable once they have been admitted by the engine. This
// invariant is what allows shard goroutines to share *Event pointers between
// NFA runs, reorder buffers and alerts without copying or locking.
package event

import (
	"math"
	"strconv"
)

// Kind is the dynamic type tag of a Value.
type Kind uint8

// Supported value kinds.
const (
	KindNull Kind = iota
	KindBool
	KindInt
	KindFloat
	KindString
)

func (k Kind) String() string {
	switch k {
	case KindNull:
		return "null"
	case KindBool:
		return "bool"
	case KindInt:
		return "int"
	case KindFloat:
		return "float"
	case KindString:
		return "string"
	default:
		return "kind(" + strconv.Itoa(int(k)) + ")"
	}
}

// Value is a compact tagged union (32 bytes on 64-bit platforms). Numeric and
// boolean payloads share the same 64-bit word to keep the struct small and
// cache friendly.
type Value struct {
	S string
	N uint64
	K Kind
}

// Null is the zero Value.
var Null = Value{}

// Int constructs an integer value.
func Int(i int64) Value { return Value{K: KindInt, N: uint64(i)} }

// Float constructs a floating point value.
func Float(f float64) Value { return Value{K: KindFloat, N: math.Float64bits(f)} }

// Str constructs a string value.
func Str(s string) Value { return Value{K: KindString, S: s} }

// Bool constructs a boolean value.
func Bool(b bool) Value {
	if b {
		return Value{K: KindBool, N: 1}
	}
	return Value{K: KindBool}
}

// IsNull reports whether v is null.
func (v Value) IsNull() bool { return v.K == KindNull }

// IsNumeric reports whether v is an int or float.
func (v Value) IsNumeric() bool { return v.K == KindInt || v.K == KindFloat }

// AsInt returns the integer payload (floats are truncated).
func (v Value) AsInt() int64 {
	switch v.K {
	case KindInt:
		return int64(v.N)
	case KindFloat:
		return int64(math.Float64frombits(v.N))
	case KindBool:
		return int64(v.N)
	}
	return 0
}

// AsFloat returns the numeric payload as float64.
func (v Value) AsFloat() float64 {
	switch v.K {
	case KindInt:
		return float64(int64(v.N))
	case KindFloat:
		return math.Float64frombits(v.N)
	case KindBool:
		return float64(v.N)
	}
	return 0
}

// AsBool returns the truthiness of v: null, false, 0 and "" are falsy.
func (v Value) AsBool() bool {
	switch v.K {
	case KindBool, KindInt:
		return v.N != 0
	case KindFloat:
		f := math.Float64frombits(v.N)
		return f != 0 && !math.IsNaN(f)
	case KindString:
		return v.S != ""
	}
	return false
}

// AsString returns the string payload, or a formatted representation for
// non-string kinds.
func (v Value) AsString() string {
	switch v.K {
	case KindString:
		return v.S
	case KindInt:
		return strconv.FormatInt(int64(v.N), 10)
	case KindFloat:
		return strconv.FormatFloat(math.Float64frombits(v.N), 'g', -1, 64)
	case KindBool:
		if v.N != 0 {
			return "true"
		}
		return "false"
	}
	return ""
}

// Interface converts v to a plain Go value suitable for JSON encoding.
func (v Value) Interface() any {
	switch v.K {
	case KindString:
		return v.S
	case KindInt:
		return int64(v.N)
	case KindFloat:
		f := math.Float64frombits(v.N)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil
		}
		return f
	case KindBool:
		return v.N != 0
	}
	return nil
}

// Equal implements SQL-like equality with numeric promotion. Null equals only
// null.
func (v Value) Equal(o Value) bool {
	if v.IsNumeric() && o.IsNumeric() {
		if v.K == KindInt && o.K == KindInt {
			return v.N == o.N
		}
		return v.AsFloat() == o.AsFloat()
	}
	if v.K != o.K {
		return false
	}
	switch v.K {
	case KindNull:
		return true
	case KindString:
		return v.S == o.S
	default:
		return v.N == o.N
	}
}

// Compare orders two values. ok is false when the values are not comparable
// (different non-numeric kinds, or either side null).
func (v Value) Compare(o Value) (c int, ok bool) {
	if v.IsNumeric() && o.IsNumeric() {
		if v.K == KindInt && o.K == KindInt {
			a, b := int64(v.N), int64(o.N)
			switch {
			case a < b:
				return -1, true
			case a > b:
				return 1, true
			}
			return 0, true
		}
		a, b := v.AsFloat(), o.AsFloat()
		switch {
		case a < b:
			return -1, true
		case a > b:
			return 1, true
		case a == b:
			return 0, true
		}
		return 0, false // NaN
	}
	if v.K != o.K || v.K == KindNull {
		return 0, false
	}
	switch v.K {
	case KindString:
		switch {
		case v.S < o.S:
			return -1, true
		case v.S > o.S:
			return 1, true
		}
		return 0, true
	case KindBool:
		return int(v.N) - int(o.N), true
	}
	return 0, false
}

func (v Value) String() string {
	if v.K == KindString {
		return strconv.Quote(v.S)
	}
	if v.K == KindNull {
		return "null"
	}
	return v.AsString()
}
