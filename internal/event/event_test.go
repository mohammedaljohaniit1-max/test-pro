package event

import (
	"errors"
	"math"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

func TestValueSemantics(t *testing.T) {
	cases := []struct {
		a, b  Value
		equal bool
		cmp   int
		ok    bool
	}{
		{Int(3), Float(3.0), true, 0, true},
		{Int(2), Int(5), false, -1, true},
		{Float(2.5), Int(2), false, 1, true},
		{Str("a"), Str("b"), false, -1, true},
		{Str("1"), Int(1), false, 0, false},
		{Null, Null, true, 0, false},
		{Null, Int(0), false, 0, false},
		{Bool(true), Bool(true), true, 0, true},
		{Float(math.NaN()), Float(math.NaN()), false, 0, false},
	}
	for i, c := range cases {
		if got := c.a.Equal(c.b); got != c.equal {
			t.Errorf("case %d: Equal(%v,%v)=%v want %v", i, c.a, c.b, got, c.equal)
		}
		cmp, ok := c.a.Compare(c.b)
		if ok != c.ok || (ok && cmp != c.cmp) {
			t.Errorf("case %d: Compare(%v,%v)=(%d,%v) want (%d,%v)", i, c.a, c.b, cmp, ok, c.cmp, c.ok)
		}
	}
	if !Str("x").AsBool() || Str("").AsBool() || Int(0).AsBool() || !Float(0.1).AsBool() || Null.AsBool() {
		t.Fatal("truthiness mismatch")
	}
	if Int(-7).AsString() != "-7" || Float(1.5).AsString() != "1.5" || Bool(false).AsString() != "false" {
		t.Fatal("AsString mismatch")
	}
}

func TestEventGetAndSet(t *testing.T) {
	e := &Event{Type: "x", Key: "k", Source: "s", Time: 42}
	e.Set("zeta", Int(1))
	e.Set("alpha", Str("a"))
	e.Set("mid", Float(2))
	e.Set("alpha", Str("b")) // replace
	if len(e.Attrs) != 3 || e.Attrs[0].Name != "alpha" || e.Attrs[2].Name != "zeta" {
		t.Fatalf("attrs not sorted/deduped: %+v", e.Attrs)
	}
	if e.Get("alpha").S != "b" || e.Get("missing").K != KindNull {
		t.Fatal("attr lookup failed")
	}
	if e.Get(FieldType).S != "x" || e.Get(FieldKey).S != "k" || e.Get(FieldSource).S != "s" || e.Get(FieldTime).AsInt() != 42 {
		t.Fatal("pseudo-field lookup failed")
	}
	var nilEv *Event
	if !nilEv.Get("x").IsNull() {
		t.Fatal("nil event must resolve to null")
	}
}

func TestNormalizeLimits(t *testing.T) {
	base := func() *Event { return &Event{Type: "t", Time: 1} }
	e := base()
	e.Type = ""
	if !errors.Is(e.Normalize(), ErrMissingType) {
		t.Fatal("expected ErrMissingType")
	}
	e = base()
	e.Time = 0
	if !errors.Is(e.Normalize(), ErrMissingTime) {
		t.Fatal("expected ErrMissingTime")
	}
	e = base()
	e.Key = strings.Repeat("k", MaxKeyLen+1)
	if !errors.Is(e.Normalize(), ErrKeyTooLong) {
		t.Fatal("expected ErrKeyTooLong")
	}
	e = base()
	e.Attrs = []Attr{{Name: "a", Val: Int(1)}, {Name: "a", Val: Int(2)}}
	if !errors.Is(e.Normalize(), ErrDuplicate) {
		t.Fatal("expected ErrDuplicate")
	}
	e = base()
	e.Attrs = []Attr{{Name: "s", Val: Str(strings.Repeat("x", MaxStringLen+1))}}
	if !errors.Is(e.Normalize(), ErrAttrTooLong) {
		t.Fatal("expected ErrAttrTooLong")
	}
	e = base()
	for i := 0; i <= MaxAttrs; i++ {
		e.Attrs = append(e.Attrs, Attr{Name: string(rune('a'+i%26)) + strings.Repeat("x", i), Val: Int(1)})
	}
	if !errors.Is(e.Normalize(), ErrTooManyAttrs) {
		t.Fatal("expected ErrTooManyAttrs")
	}
}

func randomEvent(r *rand.Rand) *Event {
	e := &Event{Seq: r.Uint64(), Time: r.Int64(), Type: "type." + string(rune('a'+r.IntN(26))), Key: "key-" + string(rune('a'+r.IntN(26))), Source: "src"}
	n := r.IntN(10)
	for i := 0; i < n; i++ {
		name := string(rune('a'+i)) + "_attr"
		var v Value
		switch r.IntN(5) {
		case 0:
			v = Int(r.Int64() - r.Int64())
		case 1:
			v = Float(r.NormFloat64() * 1e6)
		case 2:
			v = Str(strings.Repeat("z", r.IntN(50)))
		case 3:
			v = Bool(r.IntN(2) == 1)
		default:
			v = Null
		}
		e.Attrs = append(e.Attrs, Attr{Name: name, Val: v})
	}
	return e
}

func TestBinaryRoundTrip(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 5000; i++ {
		e := randomEvent(r)
		b := AppendBinary(nil, e)
		got, err := DecodeBinary(b)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Seq != e.Seq || got.Time != e.Time || got.Type != e.Type || got.Key != e.Key || got.Source != e.Source || len(got.Attrs) != len(e.Attrs) {
			t.Fatalf("header mismatch: %+v vs %+v", got, e)
		}
		for j := range e.Attrs {
			if got.Attrs[j].Name != e.Attrs[j].Name || got.Attrs[j].Val.K != e.Attrs[j].Val.K ||
				got.Attrs[j].Val.N != e.Attrs[j].Val.N || got.Attrs[j].Val.S != e.Attrs[j].Val.S {
				t.Fatalf("attr %d mismatch: %+v vs %+v", j, got.Attrs[j], e.Attrs[j])
			}
		}
	}
}

func TestBinaryRejectsCorruption(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	e := randomEvent(r)
	e.Attrs = append(e.Attrs, Attr{Name: "zz", Val: Str("payload")})
	b := AppendBinary(nil, e)
	for cut := 0; cut < len(b); cut++ {
		if _, err := DecodeBinary(b[:cut]); err == nil {
			t.Fatalf("truncation at %d/%d decoded without error", cut, len(b))
		}
	}
	if _, err := DecodeBinary(append(append([]byte(nil), b...), 0)); err == nil {
		t.Fatal("trailing garbage accepted")
	}
	bad := append([]byte(nil), b...)
	bad[0] = 99
	if _, err := DecodeBinary(bad); err == nil {
		t.Fatal("bad version accepted")
	}
}

func FuzzDecodeBinary(f *testing.F) {
	r := rand.New(rand.NewPCG(5, 6))
	for i := 0; i < 8; i++ {
		f.Add(AppendBinary(nil, randomEvent(r)))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := DecodeBinary(b)
		if err != nil {
			return
		}
		// Anything that decodes must re-encode to identical bytes.
		if got := AppendBinary(nil, e); string(got) != string(b) {
			t.Fatalf("non-canonical round trip")
		}
	})
}

func TestParseJSON(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	e, err := ParseJSON([]byte(`{"type":"auth.failure","key":"1.2.3.4","ts":"2026-01-02T03:04:05.5Z","attrs":{"user":"root","port":22,"ratio":0.5,"ok":false,"none":null}}`), now)
	if err != nil {
		t.Fatal(err)
	}
	if e.Timestamp() != time.Date(2026, 1, 2, 3, 4, 5, 5e8, time.UTC) {
		t.Fatalf("ts: %v", e.Timestamp())
	}
	if e.Get("port").K != KindInt || e.Get("port").AsInt() != 22 {
		t.Fatalf("port: %+v", e.Get("port"))
	}
	if e.Get("ratio").K != KindFloat || e.Get("ok").K != KindBool || e.Get("none").K != KindNull {
		t.Fatal("attr kinds")
	}
	// Epoch magnitude disambiguation.
	for _, c := range []struct {
		raw  string
		want int64
	}{
		{`1767225600`, 1767225600 * 1e9},
		{`1767225600123`, 1767225600123 * 1e6},
		{`1767225600123456`, 1767225600123456 * 1e3},
		{`1767225600123456789`, 1767225600123456789},
	} {
		e, err := ParseJSON([]byte(`{"type":"t","ts":`+c.raw+`}`), now)
		if err != nil || e.Time != c.want {
			t.Fatalf("ts %s: got %d err %v want %d", c.raw, e.Time, err, c.want)
		}
	}
	e, err = ParseJSON([]byte(`{"type":"t"}`), now)
	if err != nil || e.Time != now.UnixNano() {
		t.Fatal("missing ts should default to now")
	}
	for _, bad := range []string{`{`, `{"key":"x"}`, `{"type":"t","attrs":{"nested":{"a":1}}}`, `{"type":"t","ts":"yesterday"}`} {
		if _, err := ParseJSON([]byte(bad), now); err == nil {
			t.Fatalf("accepted invalid input %s", bad)
		}
	}
}

func BenchmarkAttrLookup(b *testing.B) {
	e := &Event{Type: "t", Time: 1}
	for i := 0; i < 12; i++ {
		e.Set(string(rune('a'+i))+"_field", Int(int64(i)))
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = e.Get("h_field")
	}
}

func BenchmarkBinaryEncode(b *testing.B) {
	e := randomEvent(rand.New(rand.NewPCG(7, 8)))
	buf := make([]byte, 0, 1024)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf = AppendBinary(buf[:0], e)
	}
}
