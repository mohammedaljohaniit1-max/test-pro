package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
)

func mustCompile(t *testing.T, src string) *Ruleset {
	t.Helper()
	rs, err := Compile(src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return rs
}

func TestLexerDurationsAndComments(t *testing.T) {
	toks, err := lex(`within 1.5s // c
	/* block */ # hash
	500ms 2m 1h 1d 10us 7 3.25 "a\"b" 'x'`)
	if err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{1500 * time.Millisecond, 500 * time.Millisecond, 2 * time.Minute, time.Hour, 24 * time.Hour, 10 * time.Microsecond}
	var ds []time.Duration
	for _, tk := range toks {
		if tk.kind == tDuration {
			ds = append(ds, tk.d)
		}
	}
	if len(ds) != len(want) {
		t.Fatalf("durations %v", ds)
	}
	for i := range want {
		if ds[i] != want[i] {
			t.Fatalf("duration %d: %v want %v", i, ds[i], want[i])
		}
	}
	if toks[len(toks)-3].text != `a"b` || toks[len(toks)-2].text != "x" {
		t.Fatal("string escapes")
	}
	// "5m" must be a duration, "5min" is not (identifier suffix).
	if _, err := lex(`"unterminated`); err == nil {
		t.Fatal("unterminated string accepted")
	}
}

func evalOn(t *testing.T, expr string, ev *event.Event) event.Value {
	t.Helper()
	n, err := (&parser{toks: mustLex(t, expr)}).parseExpr()
	if err != nil {
		t.Fatalf("parse %q: %v", expr, err)
	}
	fn, _, err := compileExpr(n, &scope{})
	if err != nil {
		t.Fatalf("compile %q: %v", expr, err)
	}
	return fn(&Ctx{Cur: ev})
}

func mustLex(t *testing.T, s string) []token {
	toks, err := lex(s)
	if err != nil {
		t.Fatal(err)
	}
	return toks
}

func TestExpressions(t *testing.T) {
	ev := &event.Event{Type: "http.request", Key: "10.1.2.3", Time: 1000}
	ev.Set("status", event.Int(503))
	ev.Set("latency", event.Float(12.5))
	ev.Set("path", event.Str("/admin/users"))
	ev.Set("user", event.Str("Root"))
	cases := map[string]any{
		`status >= 500 && status < 600`:     true,
		`status in [500, 502, 503]`:         true,
		`status not in [200, 204]`:          true,
		`user in ["root", "admin"]`:         false,
		`lower(user) in ["root", "admin"]`:  true,
		`starts_with(path, "/admin")`:       true,
		`matches(path, "^/admin/[a-z]+$")`:  true,
		`cidr(key, "10.0.0.0/8")`:           true,
		`cidr(key, "192.168.0.0/16")`:       false,
		`latency * 2 + 1`:                   26.0,
		`status % 100`:                      int64(3),
		`status / 2`:                        251.5,
		`missing == null`:                   true,
		`exists(missing) or exists(status)`: true,
		`not exists(missing)`:               true,
		`!(status == 503)`:                  false,
		`coalesce(missing, "fallback")`:     "fallback",
		`if(status >= 500, "err", "ok")`:    "err",
		`len(path)`:                         int64(12),
		`"a" + "b" + str(status)`:           "ab503",
		`int("42") + 1`:                     int64(43),
		`min(3, 1, 2)`:                      int64(1),
		`max(latency, 100)`:                 int64(100),
		`abs(-3)`:                           int64(3),
		`type == "http.request"`:            true,
		`status / 0`:                        nil,
		`missing > 3`:                       false,
		`floor(latency)`:                    int64(12),
		`500ms`:                             500.0,
		`contains(path, "users") and not contains(path, "..")`: true,
	}
	for src, want := range cases {
		got := evalOn(t, src, ev).Interface()
		if got != want {
			t.Errorf("%s = %#v, want %#v", src, got, want)
		}
	}
}

func TestExpressionCompileErrors(t *testing.T) {
	bad := []string{
		`matches(path, "(")`,
		`cidr(key, "not-a-prefix")`,
		`matches(path, user)`,
		`unknown_fn(1)`,
		`status in status`,
		`[1,2]`,
		`a < b < c`,
		`lower(a, b)`,
		`count()`,
	}
	for _, src := range bad {
		toks, err := lex(src)
		if err != nil {
			continue
		}
		n, err := (&parser{toks: toks}).parseExpr()
		if err != nil {
			continue
		}
		if _, _, err := compileExpr(n, &scope{}); err == nil {
			t.Errorf("expected compile error for %q", src)
		}
	}
}

func TestConstantFolding(t *testing.T) {
	n, _ := (&parser{toks: mustLex(t, `1 + 2 * 3`)}).parseExpr()
	fn, info, err := compileExpr(n, &scope{})
	if err != nil || !info.isConst {
		t.Fatalf("expected constant expression, err=%v", err)
	}
	if fn(nil).AsInt() != 7 {
		t.Fatal("folded value wrong")
	}
}

const seqRule = `
rule brute {
  severity high
  description "desc"
  tags ["a", "b"]
  within 2m
  suppress 5m
  max_runs 4
  sequence {
    fail: auth.failure[3:]
    !reset: auth.reset
    ok: auth.success where user == fail.user
  }
  emit { user = ok.user, n = count(fail) }
}`

func TestCompileSequence(t *testing.T) {
	rs := mustCompile(t, seqRule)
	r := rs.Get("brute")
	if r == nil || r.Kind != KindSequence || r.Severity != "high" || r.SeverityNum != 3 {
		t.Fatalf("rule meta: %+v", r)
	}
	if len(r.Positives) != 2 || len(r.Guards[0]) != 1 || len(r.Guards[1]) != 0 {
		t.Fatalf("plan: positives=%d guards=%v", len(r.Positives), r.Guards)
	}
	if r.Positives[0].Min != 3 || r.Positives[0].Max != 0 {
		t.Fatalf("quantifier: %+v", r.Positives[0])
	}
	if r.Within != 2*time.Minute || r.Suppress != 5*time.Minute || r.MaxRuns != 4 {
		t.Fatal("durations")
	}
	if r.IsAbsence() {
		t.Fatal("not an absence rule")
	}
	for _, typ := range []string{"auth.failure", "auth.reset", "auth.success"} {
		if !r.Relevant(typ) {
			t.Fatalf("%s should be relevant", typ)
		}
	}
	if r.Relevant("http.request") {
		t.Fatal("irrelevant type matched")
	}
	if !strings.HasPrefix(r.Source, "rule brute {") || !strings.HasSuffix(r.Source, "}") {
		t.Fatalf("source capture: %q", r.Source)
	}
	// Fingerprint changes with content, is stable otherwise.
	rs2 := mustCompile(t, seqRule)
	if rs2.Get("brute").Fingerprint != r.Fingerprint {
		t.Fatal("fingerprint not deterministic")
	}
	rs3 := mustCompile(t, strings.Replace(seqRule, "[3:]", "[4:]", 1))
	if rs3.Get("brute").Fingerprint == r.Fingerprint {
		t.Fatal("fingerprint ignores content change")
	}
}

func TestTypeMatchers(t *testing.T) {
	rs := mustCompile(t, `rule r { within 1s sequence { a: (auth.* | "proc.exec" | net.flow) } }`)
	r := rs.Get("r")
	for typ, want := range map[string]bool{"auth.failure": true, "auth.x.y": true, "proc.exec": true, "net.flow": true, "net.flows": false, "authx": false} {
		if got := r.Positives[0].Types.Match(typ); got != want {
			t.Errorf("%s: %v want %v", typ, got, want)
		}
	}
	rs = mustCompile(t, `rule any { within 1s sequence { a: * } }`)
	if !rs.Get("any").Relevant("anything.at.all") {
		t.Fatal("wildcard")
	}
}

func TestCompileAggregate(t *testing.T) {
	rs := mustCompile(t, `
rule lat {
  aggregate over 30s step 1s
  from http.request
  where status < 500
  by path
  having count() >= 20 and p99(latency) > 750 and p99(latency) > avg(latency)
  emit { p99 = p99(latency), g = group, q = quantile(latency, 0.5), d = distinct(user) }
}`)
	r := rs.Get("lat")
	if r.Kind != KindAggregate || r.NumBuckets != 30 || r.BucketW != time.Second {
		t.Fatalf("window plan: %+v", r)
	}
	// count, p99(latency) (deduplicated), avg, quantile .5, distinct = 5.
	if len(r.Aggs) != 5 {
		sigs := []string{}
		for _, a := range r.Aggs {
			sigs = append(sigs, a.Sig)
		}
		t.Fatalf("aggs: %v", sigs)
	}
	// Default step = over/12.
	rs = mustCompile(t, `rule x { aggregate over 60s from a having count() > 1 }`)
	if rs.Get("x").BucketW != 5*time.Second || rs.Get("x").NumBuckets != 12 {
		t.Fatal("default step")
	}
}

func TestRuleCompileErrors(t *testing.T) {
	cases := map[string]string{
		"no body":             `rule x { }`,
		"no within":           `rule x { sequence { a: t } }`,
		"leading negation":    `rule x { within 1s sequence { !a: t  b: u } }`,
		"dup alias":           `rule x { within 1s sequence { a: t  a: u } }`,
		"forward ref":         `rule x { within 1s sequence { a: t where b.x == 1  b: u } }`,
		"negated ref":         `rule x { within 1s sequence { a: t  !n: u  b: v where n.x == 1 } }`,
		"negated count":       `rule x { within 1s sequence { a: t  !n: u } emit { c = count(n) } }`,
		"bad quant":           `rule x { within 1s sequence { a: t[5:2] } }`,
		"zero quant":          `rule x { within 1s sequence { a: t[0:] } }`,
		"negated quant":       `rule x { within 1s sequence { a: t  !n: u+ } }`,
		"agg no from":         `rule x { aggregate over 1s having count() > 1 }`,
		"agg no having":       `rule x { aggregate over 1s from t }`,
		"having no agg":       `rule x { aggregate over 1s from t having 1 == 1 }`,
		"agg in where":        `rule x { aggregate over 1s from t where count() > 1 having count() > 1 }`,
		"agg in seq":          `rule x { within 1s sequence { a: t where avg(x) > 1 } }`,
		"nested agg":          `rule x { aggregate over 1s from t having avg(count()) > 1 }`,
		"step > over":         `rule x { aggregate over 1s step 2s from t having count() > 1 }`,
		"too many buckets":    `rule x { aggregate over 1h step 1s from t having count() > 1 }`,
		"bad severity":        `rule x { severity urgent within 1s sequence { a: t } }`,
		"dup rule":            `rule x { within 1s sequence { a: t } } rule x { within 1s sequence { a: t } }`,
		"dup clause":          `rule x { within 1s within 2s sequence { a: t } }`,
		"unknown clause":      `rule x { frobnicate 1 }`,
		"seq with from":       `rule x { within 1s from t sequence { a: t } }`,
		"agg with seq":        `rule x { aggregate over 1s from t having count() > 1 sequence { a: t } }`,
		"bad quantile":        `rule x { aggregate over 1s from t having quantile(x, 1.5) > 1 }`,
		"alias as value":      `rule x { within 1s sequence { a: t  b: u where a == 1 } }`,
		"unknown count alias": `rule x { within 1s sequence { a: t } emit { c = count(zz) } }`,
		"max_runs range":      `rule x { within 1s max_runs 0 sequence { a: t } }`,
		"dup emit":            `rule x { within 1s sequence { a: t } emit { a = 1, a = 2 } }`,
		"negative duration":   `rule x { within 0s sequence { a: t } }`,
	}
	for name, src := range cases {
		if _, err := Compile(src); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestErrorPositions(t *testing.T) {
	_, err := Compile("rule x {\n  within 1s\n  sequence {\n    a: t where matches(k, \"(\")\n  }\n}")
	if err == nil || !strings.Contains(err.Error(), "4:") {
		t.Fatalf("expected positioned error on line 4, got %v", err)
	}
}

func TestCompileFilesAndBundledRules(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.tcl"), []byte(`rule a { within 1s sequence { x: t } }`), 0o644)
	os.WriteFile(filepath.Join(dir, "b.tcl"), []byte(`rule b { aggregate over 1s from t having count() > 1 }`), 0o644)
	os.WriteFile(filepath.Join(dir, "ignored.txt"), []byte(`garbage`), 0o644)
	rs, err := CompileFiles(dir)
	if err != nil || len(rs.Rules) != 2 {
		t.Fatalf("CompileFiles: %v %v", rs, err)
	}
	os.WriteFile(filepath.Join(dir, "c.tcl"), []byte(`rule c { within }`), 0o644)
	if _, err := CompileFiles(dir); err == nil || !strings.Contains(err.Error(), "c.tcl") {
		t.Fatalf("error must name the file: %v", err)
	}
	// The shipped rule pack must always compile.
	rs, err = CompileFiles("../../rules")
	if err != nil {
		t.Fatalf("bundled rules: %v", err)
	}
	if len(rs.Rules) < 5 {
		t.Fatalf("bundled rules: only %d", len(rs.Rules))
	}
}

func FuzzCompile(f *testing.F) {
	f.Add(seqRule)
	f.Add(`rule x { aggregate over 10s from a.* by k having p99(v) > 1 && count() > 3 }`)
	f.Add(`rule y { within 5s sequence { a: t[2:5] where x in [1,"a",null] !n: u  b: v } }`)
	f.Fuzz(func(t *testing.T, src string) {
		// Must never panic; errors are fine.
		rs, err := Compile(src)
		if err != nil {
			return
		}
		ev := &event.Event{Type: "t", Key: "k", Time: 1}
		for _, r := range rs.Rules {
			ctx := &Ctx{Cur: ev, Bound: make([]*event.Event, r.NumSlots), Counts: make([]int, r.NumSlots)}
			for _, s := range r.Positives {
				if s.Where != nil {
					s.Where(ctx)
				}
			}
			for _, e := range r.Emit {
				e.Expr(ctx)
			}
		}
	})
}

func BenchmarkPredicate(b *testing.B) {
	rs, err := Compile(`rule x { within 1s sequence { a: http.request where status >= 500 and path in ["/a", "/b", "/c"] and cidr(key, "10.0.0.0/8") } }`)
	if err != nil {
		b.Fatal(err)
	}
	ev := &event.Event{Type: "http.request", Key: "10.0.0.1", Time: 1}
	ev.Set("status", event.Int(503))
	ev.Set("path", event.Str("/b"))
	st := rs.Rules[0].Positives[0]
	ctx := &Ctx{Cur: ev}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !st.Matches(ctx) {
			b.Fatal("no match")
		}
	}
}
