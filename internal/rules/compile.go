package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
)

// Kind distinguishes rule evaluation strategies.
type Kind int

// Rule kinds.
const (
	KindSequence Kind = iota
	KindAggregate
)

func (k Kind) String() string {
	if k == KindAggregate {
		return "aggregate"
	}
	return "sequence"
}

// Severity levels, ordered.
var severities = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Limits applied at compile time to bound per-key state.
const (
	MaxSteps       = 16
	MaxRunsCeiling = 4096
	MaxBuckets     = 1024
	MaxQuantifier  = 100000
	DefaultBuckets = 12
	MaxEmitFields  = 32
)

// Step is a compiled sequence step.
type Step struct {
	Index   int // position in the original step list (alias slot)
	Alias   string
	Types   TypeMatcher
	Where   Expr
	Min     int
	Max     int // 0 = unbounded
	Negated bool
}

// Matches reports whether e satisfies the step in context c (c.Cur must be e).
func (s *Step) Matches(c *Ctx) bool {
	if !s.Types.Match(c.Cur.Type) {
		return false
	}
	return s.Where == nil || s.Where(c).AsBool()
}

// EmitField is a compiled output projection.
type EmitField struct {
	Name string
	Expr Expr
}

// Rule is an immutable compiled rule. It is shared read-only across shards.
type Rule struct {
	Name        string
	Kind        Kind
	Severity    string
	SeverityNum int
	Description string
	Tags        []string
	Suppress    time.Duration
	Fingerprint string
	Source      string

	// Sequence plan.
	Within    time.Duration
	Positives []Step   // positive steps in order
	Guards    [][]Step // Guards[i]: negations active after Positives[i] is satisfied
	NumSlots  int      // len(original steps)
	MaxRuns   int

	// Aggregate plan.
	Over       time.Duration
	BucketW    time.Duration
	NumBuckets int
	From       TypeMatcher
	Where      Expr
	By         Expr
	Having     Expr
	Aggs       []AggSpec

	Emit []EmitField
	// types is the union of all event types that can affect this rule.
	types TypeMatcher
}

// Relevant reports whether an event of type t can affect the rule.
func (r *Rule) Relevant(t string) bool { return r.types.Match(t) }

// IsAbsence reports whether the rule completes by the absence of events.
func (r *Rule) IsAbsence() bool {
	return r.Kind == KindSequence && len(r.Guards[len(r.Guards)-1]) > 0
}

// Ruleset is an immutable, versioned collection of compiled rules.
type Ruleset struct {
	Rules    []*Rule
	Version  uint64
	LoadedAt time.Time
	byName   map[string]*Rule
}

// Get returns a rule by name.
func (rs *Ruleset) Get(name string) *Rule { return rs.byName[name] }

// Compile parses and compiles TCL source.
func Compile(src string) (*Ruleset, error) {
	asts, err := Parse(src)
	if err != nil {
		return nil, err
	}
	rs := &Ruleset{byName: make(map[string]*Rule), LoadedAt: time.Now()}
	for _, a := range asts {
		if _, dup := rs.byName[a.Name]; dup {
			return nil, errAt(a.P, "duplicate rule name %q", a.Name)
		}
		r, err := compileRule(a)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", a.Name, err)
		}
		rs.Rules = append(rs.Rules, r)
		rs.byName[r.Name] = r
	}
	return rs, nil
}

// CompileFiles compiles every *.tcl file in the given paths (files or
// directories, non-recursive) into a single ruleset.
func CompileFiles(paths ...string) (*Ruleset, error) {
	var files []string
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if st.IsDir() {
			m, err := filepath.Glob(filepath.Join(p, "*.tcl"))
			if err != nil {
				return nil, err
			}
			files = append(files, m...)
		} else {
			files = append(files, p)
		}
	}
	sort.Strings(files)
	var b strings.Builder
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		// Compile each file independently first for precise error locations.
		if _, err := Compile(string(data)); err != nil {
			return nil, fmt.Errorf("%s:%w", f, err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return Compile(b.String())
}

func compileRule(a *RuleAST) (*Rule, error) {
	sev, ok := severities[a.Severity]
	if !ok {
		return nil, errAt(a.P, "unknown severity %q (want info|low|medium|high|critical)", a.Severity)
	}
	sum := sha256.Sum256([]byte(a.Source))
	r := &Rule{
		Name: a.Name, Severity: a.Severity, SeverityNum: sev, Description: a.Description,
		Tags: a.Tags, Suppress: a.Suppress, Fingerprint: hex.EncodeToString(sum[:8]), Source: a.Source,
	}
	if len(a.Emit) > MaxEmitFields {
		return nil, errAt(a.P, "too many emit fields (max %d)", MaxEmitFields)
	}
	if a.IsAggregate {
		if len(a.Steps) > 0 || a.Within > 0 {
			return nil, errAt(a.P, "aggregate rules cannot declare 'sequence' or 'within'")
		}
		return r, compileAggregate(r, a)
	}
	if len(a.Steps) == 0 {
		return nil, errAt(a.P, "rule must declare either 'sequence' or 'aggregate'")
	}
	if a.From.Any || len(a.From.Exact)+len(a.From.Prefixes) > 0 || a.Where != nil || a.By != nil || a.Having != nil {
		return nil, errAt(a.P, "'from', 'where', 'by' and 'having' are only valid in aggregate rules")
	}
	return r, compileSequence(r, a)
}

func compileSequence(r *Rule, a *RuleAST) error {
	r.Kind = KindSequence
	if a.Within <= 0 {
		return errAt(a.P, "sequence rules require a 'within' duration (bounds state)")
	}
	if len(a.Steps) > MaxSteps {
		return errAt(a.P, "too many steps (max %d)", MaxSteps)
	}
	if a.MaxRuns < 1 || a.MaxRuns > MaxRunsCeiling {
		return errAt(a.P, "max_runs must be in [1,%d]", MaxRunsCeiling)
	}
	r.Within, r.MaxRuns, r.NumSlots = a.Within, a.MaxRuns, len(a.Steps)
	if a.Steps[0].Negated {
		return errAt(a.Steps[0].P, "a sequence cannot start with a negated step")
	}
	aliases := map[string]int{}
	negated := map[string]bool{}
	for i, st := range a.Steps {
		if _, dup := aliases[st.Alias]; dup {
			return errAt(st.P, "duplicate step alias %q", st.Alias)
		}
		aliases[st.Alias] = i
		negated[st.Alias] = st.Negated
	}
	// Scope for guard / step predicates excludes negated aliases, which never
	// bind events.
	positiveAliases := map[string]int{}
	for k, v := range aliases {
		if !negated[k] {
			positiveAliases[k] = v
		}
	}
	for i, st := range a.Steps {
		if st.Min < 0 || st.Max < 0 || (st.Max != 0 && st.Max < st.Min) || st.Min > MaxQuantifier || st.Max > MaxQuantifier {
			return errAt(st.P, "invalid quantifier [%d:%d]", st.Min, st.Max)
		}
		if st.Min == 0 {
			return errAt(st.P, "quantifier minimum must be >= 1 (use a negated step for absence)")
		}
		if st.Negated && (st.Min != 1 || st.Max != 1) {
			return errAt(st.P, "negated steps cannot have quantifiers")
		}
		sc := &scope{aliases: positiveAliases, visible: i}
		if err := rejectNegatedRefs(st.Where, negated); err != nil {
			return err
		}
		var where Expr
		if st.Where != nil {
			w, _, err := compileExpr(st.Where, sc)
			if err != nil {
				return err
			}
			where = w
		}
		cs := Step{Index: i, Alias: st.Alias, Types: st.Types, Where: where, Min: st.Min, Max: st.Max, Negated: st.Negated}
		r.types = unionTypes(r.types, st.Types)
		if st.Negated {
			if len(r.Positives) == 0 {
				return errAt(st.P, "a sequence cannot start with a negated step")
			}
			g := len(r.Positives) - 1
			r.Guards[g] = append(r.Guards[g], cs)
		} else {
			r.Positives = append(r.Positives, cs)
			r.Guards = append(r.Guards, nil)
		}
	}
	for _, e := range a.Emit {
		if err := rejectNegatedRefs(e.Expr, negated); err != nil {
			return err
		}
		fn, _, err := compileExpr(e.Expr, &scope{aliases: positiveAliases, visible: -1})
		if err != nil {
			return err
		}
		r.Emit = append(r.Emit, EmitField{Name: e.Name, Expr: fn})
	}
	return nil
}

func rejectNegatedRefs(n Node, negated map[string]bool) error {
	var err error
	walk(n, func(n Node) {
		if err != nil {
			return
		}
		switch x := n.(type) {
		case *FieldNode:
			if negated[x.Alias] {
				err = errAt(x.P, "negated step %q never binds an event and cannot be referenced", x.Alias)
			}
		case *CallNode:
			if x.Fn == "count" && len(x.Args) == 1 {
				if id, ok := x.Args[0].(*IdentNode); ok && negated[id.Name] {
					err = errAt(x.P, "negated step %q never binds an event and cannot be counted", id.Name)
				}
			}
		}
	})
	return err
}

func walk(n Node, fn func(Node)) {
	if n == nil {
		return
	}
	fn(n)
	switch x := n.(type) {
	case *UnaryNode:
		walk(x.X, fn)
	case *BinaryNode:
		walk(x.L, fn)
		walk(x.R, fn)
	case *ListNode:
		for _, it := range x.Items {
			walk(it, fn)
		}
	case *CallNode:
		for _, it := range x.Args {
			walk(it, fn)
		}
	}
}

func unionTypes(a, b TypeMatcher) TypeMatcher {
	if a.Any || b.Any {
		return TypeMatcher{Any: true}
	}
	return TypeMatcher{
		Exact:    append(append([]string(nil), a.Exact...), b.Exact...),
		Prefixes: append(append([]string(nil), a.Prefixes...), b.Prefixes...),
	}
}

func compileAggregate(r *Rule, a *RuleAST) error {
	r.Kind = KindAggregate
	if a.Over <= 0 {
		return errAt(a.P, "aggregate rules require 'over <duration>'")
	}
	if !a.From.Any && len(a.From.Exact)+len(a.From.Prefixes) == 0 {
		return errAt(a.P, "aggregate rules require a 'from' clause")
	}
	if a.Having == nil {
		return errAt(a.P, "aggregate rules require a 'having' clause")
	}
	r.Over, r.From, r.types = a.Over, a.From, a.From
	step := a.Step
	if step <= 0 {
		step = a.Over / DefaultBuckets
		if step < time.Millisecond {
			step = time.Millisecond
		}
	}
	if step > a.Over {
		return errAt(a.P, "window step %s exceeds window %s", step, a.Over)
	}
	nb := int(math.Ceil(float64(a.Over) / float64(step)))
	if nb > MaxBuckets {
		return errAt(a.P, "window has %d buckets (over/step); max is %d", nb, MaxBuckets)
	}
	r.BucketW, r.NumBuckets = step, nb

	plain := &scope{isAgg: true}
	if a.Where != nil {
		w, info, err := compileExpr(a.Where, plain)
		if err != nil {
			return err
		}
		if info.usesAgg {
			return errAt(a.P, "'where' cannot use aggregates; use 'having'")
		}
		r.Where = w
	}
	if a.By != nil {
		b, _, err := compileExpr(a.By, plain)
		if err != nil {
			return err
		}
		r.By = b
	}
	aggScope := &scope{isAgg: true, allowAgg: true, aggs: &r.Aggs}
	h, info, err := compileExpr(a.Having, aggScope)
	if err != nil {
		return err
	}
	if !info.usesAgg {
		return errAt(a.Having.pos(), "'having' must reference at least one aggregate (count(), avg(x), p99(x), ...)")
	}
	r.Having = h
	emitScope := &scope{isAgg: true, allowAgg: true, isEmit: true, aggs: &r.Aggs}
	for _, e := range a.Emit {
		fn, _, err := compileExpr(e.Expr, emitScope)
		if err != nil {
			return err
		}
		r.Emit = append(r.Emit, EmitField{Name: e.Name, Expr: fn})
	}
	return nil
}

// ValueToJSON converts an evaluated emit value for alert payloads.
func ValueToJSON(v event.Value) any { return v.Interface() }
