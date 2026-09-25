package event

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Binary codec (used by the write-ahead log)
//
// Layout (all integers are unsigned varints unless noted):
//   version:u8 | seq | time(zigzag) | type | key | source | nattrs |
//   { name | kind:u8 | payload }*
// Strings are length-prefixed. Payloads: int -> zigzag varint, float -> 8 byte
// little endian, bool -> u8, string -> length prefixed, null -> empty.
// ---------------------------------------------------------------------------

const binaryVersion = 1

// ErrCorrupt is returned when a binary record cannot be decoded.
var ErrCorrupt = errors.New("event: corrupt binary encoding")

// AppendBinary appends the binary encoding of e to dst.
func AppendBinary(dst []byte, e *Event) []byte {
	dst = append(dst, binaryVersion)
	dst = binary.AppendUvarint(dst, e.Seq)
	dst = binary.AppendVarint(dst, e.Time)
	dst = appendString(dst, e.Type)
	dst = appendString(dst, e.Key)
	dst = appendString(dst, e.Source)
	dst = binary.AppendUvarint(dst, uint64(len(e.Attrs)))
	for i := range e.Attrs {
		a := &e.Attrs[i]
		dst = appendString(dst, a.Name)
		dst = append(dst, byte(a.Val.K))
		switch a.Val.K {
		case KindInt:
			dst = binary.AppendVarint(dst, int64(a.Val.N))
		case KindFloat:
			dst = binary.LittleEndian.AppendUint64(dst, a.Val.N)
		case KindBool:
			dst = append(dst, byte(a.Val.N))
		case KindString:
			dst = appendString(dst, a.Val.S)
		}
	}
	return dst
}

func appendString(dst []byte, s string) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(s)))
	return append(dst, s...)
}

type decoder struct {
	b   []byte
	err error
}

// uvarintLen is the length of the minimal (canonical) uvarint encoding of v.
func uvarintLen(v uint64) int {
	if v == 0 {
		return 1
	}
	return (bits.Len64(v) + 6) / 7
}

// uvarint decodes a canonical uvarint; overlong encodings are rejected so
// every accepted byte string has exactly one decoding and vice versa.
func (d *decoder) uvarint() uint64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Uvarint(d.b)
	if n <= 0 || n != uvarintLen(v) {
		d.err = ErrCorrupt
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *decoder) varint() int64 {
	ux := d.uvarint() // zigzag-encoded
	x := int64(ux >> 1)
	if ux&1 != 0 {
		x = ^x
	}
	return x
}

func (d *decoder) byte1() byte {
	if d.err != nil {
		return 0
	}
	if len(d.b) < 1 {
		d.err = ErrCorrupt
		return 0
	}
	c := d.b[0]
	d.b = d.b[1:]
	return c
}

func (d *decoder) str(limit int) string {
	n := d.uvarint()
	if d.err != nil {
		return ""
	}
	if n > uint64(limit) || n > uint64(len(d.b)) {
		d.err = ErrCorrupt
		return ""
	}
	s := string(d.b[:n])
	d.b = d.b[n:]
	return s
}

// DecodeBinary decodes one event produced by AppendBinary.
func DecodeBinary(b []byte) (*Event, error) {
	d := decoder{b: b}
	if d.byte1() != binaryVersion {
		return nil, ErrCorrupt
	}
	e := &Event{}
	e.Seq = d.uvarint()
	e.Time = d.varint()
	e.Type = d.str(MaxTypeLen)
	e.Key = d.str(MaxKeyLen)
	e.Source = d.str(MaxStringLen)
	n := d.uvarint()
	if d.err != nil {
		return nil, d.err
	}
	if n > MaxAttrs {
		return nil, ErrCorrupt
	}
	if n > 0 {
		e.Attrs = make([]Attr, n)
	}
	for i := range e.Attrs {
		a := &e.Attrs[i]
		a.Name = d.str(MaxNameLen)
		a.Val.K = Kind(d.byte1())
		switch a.Val.K {
		case KindNull:
		case KindInt:
			a.Val.N = uint64(d.varint())
		case KindFloat:
			if d.err == nil && len(d.b) < 8 {
				d.err = ErrCorrupt
			}
			if d.err == nil {
				a.Val.N = binary.LittleEndian.Uint64(d.b)
				d.b = d.b[8:]
			}
		case KindBool:
			b := d.byte1()
			if b > 1 {
				d.err = ErrCorrupt
			}
			a.Val.N = uint64(b)
		case KindString:
			a.Val.S = d.str(MaxStringLen)
		default:
			d.err = ErrCorrupt
		}
		if d.err != nil {
			return nil, d.err
		}
		// Enforce the in-memory invariant (strictly increasing, non-empty
		// names) so corrupt-but-checksummed input can never produce an event
		// that breaks binary-search attribute lookup.
		if a.Name == "" || (i > 0 && e.Attrs[i-1].Name >= a.Name) {
			return nil, ErrCorrupt
		}
	}
	if d.err != nil {
		return nil, d.err
	}
	if len(d.b) != 0 {
		return nil, ErrCorrupt
	}
	return e, nil
}

// ---------------------------------------------------------------------------
// JSON codec (used by HTTP / TCP ingestion and the alert API)
// ---------------------------------------------------------------------------

// Wire is the JSON wire format of an event.
//
//	{"type":"auth.failure","key":"10.0.0.7","ts":"2026-01-02T15:04:05Z",
//	 "source":"sshd","attrs":{"user":"root","port":22}}
//
// ts accepts RFC3339(Nano) strings or integer Unix nanoseconds / milliseconds
// / seconds (disambiguated by magnitude). A missing ts is stamped with the
// ingestion wall clock.
type Wire struct {
	Type   string          `json:"type"`
	Key    string          `json:"key,omitempty"`
	Source string          `json:"source,omitempty"`
	TS     json.RawMessage `json:"ts,omitempty"`
	Attrs  map[string]any  `json:"attrs,omitempty"`
}

// FromWire converts and validates a decoded wire event. now is used when ts
// is absent.
func FromWire(w *Wire, now time.Time) (*Event, error) {
	e := &Event{Type: w.Type, Key: w.Key, Source: w.Source}
	ts, err := parseTS(w.TS, now)
	if err != nil {
		return nil, err
	}
	e.Time = ts
	if len(w.Attrs) > MaxAttrs {
		return nil, ErrTooManyAttrs
	}
	if len(w.Attrs) > 0 {
		e.Attrs = make([]Attr, 0, len(w.Attrs))
	}
	for k, raw := range w.Attrs {
		v, err := valueFromJSON(raw)
		if err != nil {
			return nil, fmt.Errorf("event: attribute %q: %w", k, err)
		}
		e.Attrs = append(e.Attrs, Attr{Name: k, Val: v})
	}
	if err := e.Normalize(); err != nil {
		return nil, err
	}
	return e, nil
}

// ParseJSON decodes a single JSON event.
func ParseJSON(b []byte, now time.Time) (*Event, error) {
	var w Wire
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("event: invalid json: %w", err)
	}
	return FromWire(&w, now)
}

func parseTS(raw json.RawMessage, now time.Time) (int64, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return now.UnixNano(), nil
	}
	if s[0] == '"' {
		var str string
		if err := json.Unmarshal(raw, &str); err != nil {
			return 0, fmt.Errorf("event: invalid ts: %w", err)
		}
		t, err := time.Parse(time.RFC3339Nano, str)
		if err != nil {
			return 0, fmt.Errorf("event: invalid ts: %w", err)
		}
		return t.UnixNano(), nil
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, fmt.Errorf("event: invalid ts: %w", err)
	}
	if i, err := n.Int64(); err == nil {
		return normalizeEpoch(i), nil
	}
	f, err := n.Float64()
	if err != nil {
		return 0, fmt.Errorf("event: invalid ts: %w", err)
	}
	return normalizeEpoch(int64(f)), nil
}

// normalizeEpoch interprets an integer epoch as s, ms, us or ns by magnitude.
func normalizeEpoch(i int64) int64 {
	switch {
	case i < 1e11: // seconds (until year 5138)
		return i * int64(time.Second)
	case i < 1e14: // milliseconds
		return i * int64(time.Millisecond)
	case i < 1e17: // microseconds
		return i * int64(time.Microsecond)
	default:
		return i
	}
}

func valueFromJSON(raw any) (Value, error) {
	switch t := raw.(type) {
	case nil:
		return Null, nil
	case bool:
		return Bool(t), nil
	case string:
		return Str(t), nil
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return Int(i), nil
		}
		f, err := t.Float64()
		if err != nil {
			return Null, err
		}
		return Float(f), nil
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1<<53 {
			return Int(int64(t)), nil
		}
		return Float(t), nil
	case int:
		return Int(int64(t)), nil
	case int64:
		return Int(t), nil
	default:
		return Null, fmt.Errorf("unsupported attribute type %T (only scalars are allowed)", raw)
	}
}

// ToJSONMap renders the event as a JSON-friendly map.
func (e *Event) ToJSONMap() map[string]any {
	attrs := make(map[string]any, len(e.Attrs))
	for _, a := range e.Attrs {
		attrs[a.Name] = a.Val.Interface()
	}
	m := map[string]any{
		"seq":   e.Seq,
		"type":  e.Type,
		"ts":    time.Unix(0, e.Time).UTC().Format(time.RFC3339Nano),
		"attrs": attrs,
	}
	if e.Key != "" {
		m["key"] = e.Key
	}
	if e.Source != "" {
		m["source"] = e.Source
	}
	return m
}

// MarshalJSON implements json.Marshaler.
func (e *Event) MarshalJSON() ([]byte, error) { return json.Marshal(e.ToJSONMap()) }
