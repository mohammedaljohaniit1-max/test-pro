package event

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// Limits enforced on admission. They bound the worst-case memory footprint of
// a single event and protect the engine from hostile producers.
const (
	MaxAttrs       = 64
	MaxNameLen     = 128
	MaxStringLen   = 4096
	MaxTypeLen     = 128
	MaxKeyLen      = 512
	MaxEncodedSize = 64 << 10
)

// Validation errors.
var (
	ErrMissingType  = errors.New("event: missing type")
	ErrTypeTooLong  = errors.New("event: type too long")
	ErrKeyTooLong   = errors.New("event: key too long")
	ErrTooManyAttrs = errors.New("event: too many attributes")
	ErrAttrName     = errors.New("event: invalid attribute name")
	ErrAttrTooLong  = errors.New("event: attribute string too long")
	ErrDuplicate    = errors.New("event: duplicate attribute")
	ErrMissingTime  = errors.New("event: missing timestamp")
)

// Attr is a single named attribute.
type Attr struct {
	Name string
	Val  Value
}

// Event is one telemetry record. Attrs is kept sorted by Name so that lookups
// are a binary search and encoding is canonical.
type Event struct {
	// Seq is a monotonically increasing sequence number assigned at admission.
	Seq uint64
	// Time is the event time in Unix nanoseconds.
	Time int64
	// Type classifies the event (e.g. "auth.failure").
	Type string
	// Key is the partition key: all events sharing a key are processed by the
	// same shard in event-time order. Rules correlate events within a key.
	Key string
	// Source identifies the producer.
	Source string
	// Attrs holds the payload, sorted by name.
	Attrs []Attr
	// Ingested is the wall-clock admission time in Unix nanoseconds. It is
	// process-local (not journaled) and used for end-to-end latency metrics.
	Ingested int64
}

// Reserved pseudo-attribute names resolvable through Get.
const (
	FieldType   = "type"
	FieldKey    = "key"
	FieldSource = "source"
	FieldTime   = "ts"
)

// Get resolves an attribute or a reserved pseudo-field.
func (e *Event) Get(name string) Value {
	if e == nil {
		return Null
	}
	switch name {
	case FieldType:
		return Str(e.Type)
	case FieldKey:
		return Str(e.Key)
	case FieldSource:
		return Str(e.Source)
	case FieldTime:
		return Int(e.Time)
	}
	return e.Attr(name)
}

// Attr looks up a payload attribute by binary search.
func (e *Event) Attr(name string) Value {
	a := e.Attrs
	lo, hi := 0, len(a)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if a[m].Name < name {
			lo = m + 1
		} else {
			hi = m
		}
	}
	if lo < len(a) && a[lo].Name == name {
		return a[lo].Val
	}
	return Null
}

// Set inserts or replaces an attribute, maintaining sort order. It must only
// be called before the event is admitted into the engine.
func (e *Event) Set(name string, v Value) {
	i := sort.Search(len(e.Attrs), func(i int) bool { return e.Attrs[i].Name >= name })
	if i < len(e.Attrs) && e.Attrs[i].Name == name {
		e.Attrs[i].Val = v
		return
	}
	e.Attrs = append(e.Attrs, Attr{})
	copy(e.Attrs[i+1:], e.Attrs[i:])
	e.Attrs[i] = Attr{Name: name, Val: v}
}

// Normalize sorts attributes and validates all admission limits.
func (e *Event) Normalize() error {
	if e.Type == "" {
		return ErrMissingType
	}
	if len(e.Type) > MaxTypeLen {
		return ErrTypeTooLong
	}
	if len(e.Key) > MaxKeyLen {
		return ErrKeyTooLong
	}
	if e.Time <= 0 {
		return ErrMissingTime
	}
	if len(e.Attrs) > MaxAttrs {
		return ErrTooManyAttrs
	}
	if !sort.SliceIsSorted(e.Attrs, func(i, j int) bool { return e.Attrs[i].Name < e.Attrs[j].Name }) {
		sort.Slice(e.Attrs, func(i, j int) bool { return e.Attrs[i].Name < e.Attrs[j].Name })
	}
	for i := range e.Attrs {
		a := &e.Attrs[i]
		if a.Name == "" || len(a.Name) > MaxNameLen {
			return fmt.Errorf("%w: %q", ErrAttrName, a.Name)
		}
		if i > 0 && e.Attrs[i-1].Name == a.Name {
			return fmt.Errorf("%w: %q", ErrDuplicate, a.Name)
		}
		if a.Val.K == KindString && len(a.Val.S) > MaxStringLen {
			return fmt.Errorf("%w: %q", ErrAttrTooLong, a.Name)
		}
	}
	return nil
}

// Timestamp returns the event time as time.Time.
func (e *Event) Timestamp() time.Time { return time.Unix(0, e.Time).UTC() }

// Clone returns a deep copy (attribute slice copied; strings are immutable).
func (e *Event) Clone() *Event {
	c := *e
	c.Attrs = append([]Attr(nil), e.Attrs...)
	return &c
}
