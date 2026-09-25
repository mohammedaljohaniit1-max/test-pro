package rules

import (
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strings"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
)

// Ctx is the evaluation context handed to compiled expressions. The engine
// reuses a single Ctx per shard, so evaluation performs no allocation for
// field access, comparison or arithmetic on numbers.
type Ctx struct {
	// Cur is the event under evaluation (the triggering event for emits).
	Cur *event.Event
	// Bound holds, per sequence step, the last event bound to that step.
	Bound []*event.Event
	// Counts holds, per sequence step, the number of events bound.
	Counts []int
	// StartTS is the event time of the first event of a sequence run.
	StartTS int64
	// AggEval lazily computes aggregate i of an aggregate rule. Laziness lets
	// short-circuiting operators skip expensive sketch merges entirely.
	AggEval func(i int) event.Value
	// Group is the value of the aggregate rule's `by` expression.
	Group event.Value
	// WindowStart / WindowEnd delimit the aggregate window (unix ns).
	WindowStart, WindowEnd int64
}

// Expr is a compiled expression.
type Expr func(*Ctx) event.Value

// exprKind tracks what an expression depends on, for validation and constant
// folding.
type exprInfo struct {
	isConst bool
	usesAgg bool
	usesCur bool
	aliases map[int]bool
}

func merge(a, b exprInfo) exprInfo {
	out := exprInfo{isConst: a.isConst && b.isConst, usesAgg: a.usesAgg || b.usesAgg, usesCur: a.usesCur || b.usesCur}
	if len(a.aliases)+len(b.aliases) > 0 {
		out.aliases = map[int]bool{}
		for k := range a.aliases {
			out.aliases[k] = true
		}
		for k := range b.aliases {
			out.aliases[k] = true
		}
	}
	return out
}

// scope describes what names are resolvable while compiling an expression.
type scope struct {
	aliases map[string]int // sequence step aliases -> step index
	visible int            // aliases with index < visible may be referenced (-1 = all)
	// aggregate context
	allowAgg bool
	aggs     *[]AggSpec
	overSec  float64
	isAgg    bool
	isEmit   bool
}

// AggKind enumerates windowed aggregate functions.
type AggKind int

// Aggregate kinds.
const (
	AggCount AggKind = iota
	AggSum
	AggAvg
	AggMin
	AggMax
	AggDistinct
	AggQuantile
	AggRate
)

// AggSpec is one aggregate computed by an aggregate rule.
type AggSpec struct {
	Kind AggKind
	Arg  Expr    // nil for count()/rate()
	Q    float64 // quantile for AggQuantile
	Sig  string  // canonical signature for de-duplication
}

var aggFuncs = map[string]AggKind{
	"count": AggCount, "sum": AggSum, "avg": AggAvg, "min": AggMin, "max": AggMax,
	"distinct": AggDistinct, "quantile": AggQuantile, "rate": AggRate,
	"p50": AggQuantile, "p90": AggQuantile, "p95": AggQuantile, "p99": AggQuantile, "p999": AggQuantile,
}

var fixedQuantiles = map[string]float64{"p50": 0.5, "p90": 0.9, "p95": 0.95, "p99": 0.99, "p999": 0.999}

func compileExpr(n Node, sc *scope) (Expr, exprInfo, error) {
	fn, info, err := compileNode(n, sc)
	if err != nil {
		return nil, info, err
	}
	if info.isConst {
		v := fn(&Ctx{})
		return func(*Ctx) event.Value { return v }, info, nil
	}
	return fn, info, nil
}

func litValue(v any) event.Value {
	switch t := v.(type) {
	case nil:
		return event.Null
	case bool:
		return event.Bool(t)
	case int64:
		return event.Int(t)
	case float64:
		return event.Float(t)
	case string:
		return event.Str(t)
	}
	return event.Null
}

func compileNode(n Node, sc *scope) (Expr, exprInfo, error) {
	switch x := n.(type) {
	case *LitNode:
		v := litValue(x.Val)
		return func(*Ctx) event.Value { return v }, exprInfo{isConst: true}, nil

	case *IdentNode:
		name := x.Name
		if sc.isAgg && sc.isEmit || sc.isAgg && sc.allowAgg {
			switch name {
			case "group":
				return func(c *Ctx) event.Value { return c.Group }, exprInfo{}, nil
			case "window_start":
				return func(c *Ctx) event.Value { return event.Int(c.WindowStart) }, exprInfo{}, nil
			case "window_end":
				return func(c *Ctx) event.Value { return event.Int(c.WindowEnd) }, exprInfo{}, nil
			}
		}
		if _, isAlias := sc.aliases[name]; isAlias {
			return nil, exprInfo{}, errAt(x.P, "%q is a step alias; reference one of its fields (e.g. %s.key) or use count(%s)", name, name, name)
		}
		return func(c *Ctx) event.Value { return c.Cur.Get(name) }, exprInfo{usesCur: true}, nil

	case *FieldNode:
		idx, ok := sc.aliases[x.Alias]
		if !ok {
			// Not an alias: treat as a dotted attribute name on the current event.
			full := x.Alias + "." + x.Name
			return func(c *Ctx) event.Value { return c.Cur.Get(full) }, exprInfo{usesCur: true}, nil
		}
		if sc.visible >= 0 && idx >= sc.visible {
			return nil, exprInfo{}, errAt(x.P, "step alias %q is not bound yet at this point of the sequence", x.Alias)
		}
		name := x.Name
		return func(c *Ctx) event.Value {
			if idx >= len(c.Bound) || c.Bound[idx] == nil {
				return event.Null
			}
			return c.Bound[idx].Get(name)
		}, exprInfo{aliases: map[int]bool{idx: true}}, nil

	case *UnaryNode:
		inner, info, err := compileNode(x.X, sc)
		if err != nil {
			return nil, info, err
		}
		if x.Op == tNot {
			return func(c *Ctx) event.Value { return event.Bool(!inner(c).AsBool()) }, info, nil
		}
		return func(c *Ctx) event.Value {
			v := inner(c)
			switch v.K {
			case event.KindInt:
				return event.Int(-v.AsInt())
			case event.KindFloat:
				return event.Float(-v.AsFloat())
			}
			return event.Null
		}, info, nil

	case *BinaryNode:
		return compileBinary(x, sc)

	case *ListNode:
		return nil, exprInfo{}, errAt(x.P, "list literals are only valid on the right-hand side of 'in'")

	case *CallNode:
		return compileCall(x, sc)
	}
	return nil, exprInfo{}, fmt.Errorf("rules: unknown node %T", n)
}

func compileBinary(x *BinaryNode, sc *scope) (Expr, exprInfo, error) {
	if x.Op == "in" || x.Op == "not in" {
		return compileIn(x, sc)
	}
	l, li, err := compileNode(x.L, sc)
	if err != nil {
		return nil, li, err
	}
	r, ri, err := compileNode(x.R, sc)
	if err != nil {
		return nil, ri, err
	}
	info := merge(li, ri)
	switch x.Op {
	case "&&":
		return func(c *Ctx) event.Value { return event.Bool(l(c).AsBool() && r(c).AsBool()) }, info, nil
	case "||":
		return func(c *Ctx) event.Value { return event.Bool(l(c).AsBool() || r(c).AsBool()) }, info, nil
	case "==":
		return func(c *Ctx) event.Value { return event.Bool(l(c).Equal(r(c))) }, info, nil
	case "!=":
		return func(c *Ctx) event.Value { return event.Bool(!l(c).Equal(r(c))) }, info, nil
	case "<", "<=", ">", ">=":
		op := x.Op
		return func(c *Ctx) event.Value {
			cmp, ok := l(c).Compare(r(c))
			if !ok {
				return event.Bool(false)
			}
			switch op {
			case "<":
				return event.Bool(cmp < 0)
			case "<=":
				return event.Bool(cmp <= 0)
			case ">":
				return event.Bool(cmp > 0)
			}
			return event.Bool(cmp >= 0)
		}, info, nil
	case "+":
		return func(c *Ctx) event.Value {
			a, b := l(c), r(c)
			if a.K == event.KindString || b.K == event.KindString {
				if a.IsNull() || b.IsNull() {
					return event.Null
				}
				return event.Str(a.AsString() + b.AsString())
			}
			return arith('+', a, b)
		}, info, nil
	case "-", "*", "/", "%":
		op := x.Op[0]
		return func(c *Ctx) event.Value { return arith(op, l(c), r(c)) }, info, nil
	}
	return nil, info, errAt(x.P, "unknown operator %q", x.Op)
}

func arith(op byte, a, b event.Value) event.Value {
	if !a.IsNumeric() || !b.IsNumeric() {
		return event.Null
	}
	if a.K == event.KindInt && b.K == event.KindInt && op != '/' {
		x, y := a.AsInt(), b.AsInt()
		switch op {
		case '+':
			return event.Int(x + y)
		case '-':
			return event.Int(x - y)
		case '*':
			return event.Int(x * y)
		case '%':
			if y == 0 {
				return event.Null
			}
			return event.Int(x % y)
		}
	}
	x, y := a.AsFloat(), b.AsFloat()
	switch op {
	case '+':
		return event.Float(x + y)
	case '-':
		return event.Float(x - y)
	case '*':
		return event.Float(x * y)
	case '/':
		if y == 0 {
			return event.Null
		}
		return event.Float(x / y)
	case '%':
		if y == 0 {
			return event.Null
		}
		return event.Float(math.Mod(x, y))
	}
	return event.Null
}

func compileIn(x *BinaryNode, sc *scope) (Expr, exprInfo, error) {
	negate := x.Op == "not in"
	l, li, err := compileNode(x.L, sc)
	if err != nil {
		return nil, li, err
	}
	list, ok := x.R.(*ListNode)
	if !ok {
		return nil, li, errAt(x.P, "right-hand side of 'in' must be a list literal [a, b, ...]")
	}
	// Fast path: all-literal list -> hash sets.
	allLit := true
	for _, it := range list.Items {
		if _, ok := it.(*LitNode); !ok {
			allLit = false
			break
		}
	}
	if allLit {
		strs := map[string]struct{}{}
		nums := map[float64]struct{}{}
		hasNull := false
		for _, it := range list.Items {
			v := litValue(it.(*LitNode).Val)
			switch {
			case v.K == event.KindString:
				strs[v.S] = struct{}{}
			case v.IsNumeric():
				nums[v.AsFloat()] = struct{}{}
			case v.K == event.KindBool:
				nums[v.AsFloat()] = struct{}{}
			default:
				hasNull = true
			}
		}
		return func(c *Ctx) event.Value {
			v := l(c)
			var found bool
			switch {
			case v.K == event.KindString:
				_, found = strs[v.S]
			case v.IsNumeric():
				_, found = nums[v.AsFloat()]
			case v.K == event.KindNull:
				found = hasNull
			}
			return event.Bool(found != negate)
		}, li, nil
	}
	items := make([]Expr, len(list.Items))
	info := li
	for i, it := range list.Items {
		e, ii, err := compileNode(it, sc)
		if err != nil {
			return nil, ii, err
		}
		items[i] = e
		info = merge(info, ii)
	}
	return func(c *Ctx) event.Value {
		v := l(c)
		for _, it := range items {
			if v.Equal(it(c)) {
				return event.Bool(!negate)
			}
		}
		return event.Bool(negate)
	}, info, nil
}

func constString(n Node, fn string, argi int) (string, error) {
	lit, ok := n.(*LitNode)
	if !ok {
		return "", errAt(n.pos(), "argument %d of %s() must be a string literal", argi+1, fn)
	}
	s, ok := lit.Val.(string)
	if !ok {
		return "", errAt(n.pos(), "argument %d of %s() must be a string literal", argi+1, fn)
	}
	return s, nil
}

func compileCall(x *CallNode, sc *scope) (Expr, exprInfo, error) {
	scalarMinMax := (x.Fn == "min" || x.Fn == "max") && len(x.Args) >= 2
	if kind, isAgg := aggFuncs[x.Fn]; isAgg && sc.isAgg && !scalarMinMax {
		// min/max are ambiguous with scalar min/max; in aggregate
		// having/emit they always denote window aggregates.
		if !sc.allowAgg {
			return nil, exprInfo{}, errAt(x.P, "aggregate %s() is only allowed in 'having' and 'emit'", x.Fn)
		}
		return compileAgg(x, kind, sc)
	}
	if x.Fn == "count" && len(sc.aliases) > 0 && len(x.Args) == 1 {
		if id, ok := x.Args[0].(*IdentNode); ok {
			idx, known := sc.aliases[id.Name]
			if !known {
				return nil, exprInfo{}, errAt(id.P, "unknown step alias %q", id.Name)
			}
			if sc.visible >= 0 && idx >= sc.visible {
				return nil, exprInfo{}, errAt(id.P, "step alias %q is not bound yet at this point of the sequence", id.Name)
			}
			return func(c *Ctx) event.Value {
				if idx >= len(c.Counts) {
					return event.Int(0)
				}
				return event.Int(int64(c.Counts[idx]))
			}, exprInfo{aliases: map[int]bool{idx: true}}, nil
		}
	}
	if _, isAgg := aggFuncs[x.Fn]; isAgg && x.Fn != "min" && x.Fn != "max" {
		return nil, exprInfo{}, errAt(x.P, "aggregate %s() is only valid in aggregate rules", x.Fn)
	}

	// Special-form functions with literal arguments compiled once.
	switch x.Fn {
	case "matches":
		if len(x.Args) != 2 {
			return nil, exprInfo{}, errAt(x.P, "matches(value, \"regex\") takes 2 arguments")
		}
		pat, err := constString(x.Args[1], x.Fn, 1)
		if err != nil {
			return nil, exprInfo{}, err
		}
		re, rerr := regexp.Compile(pat)
		if rerr != nil {
			return nil, exprInfo{}, errAt(x.Args[1].pos(), "invalid regex: %v", rerr)
		}
		a, info, err := compileNode(x.Args[0], sc)
		if err != nil {
			return nil, info, err
		}
		return func(c *Ctx) event.Value {
			v := a(c)
			if v.K != event.KindString {
				return event.Bool(false)
			}
			return event.Bool(re.MatchString(v.S))
		}, info, nil
	case "cidr":
		if len(x.Args) != 2 {
			return nil, exprInfo{}, errAt(x.P, "cidr(ip, \"prefix\") takes 2 arguments")
		}
		ps, err := constString(x.Args[1], x.Fn, 1)
		if err != nil {
			return nil, exprInfo{}, err
		}
		pfx, perr := netip.ParsePrefix(ps)
		if perr != nil {
			return nil, exprInfo{}, errAt(x.Args[1].pos(), "invalid CIDR prefix: %v", perr)
		}
		pfx = pfx.Masked()
		a, info, err := compileNode(x.Args[0], sc)
		if err != nil {
			return nil, info, err
		}
		return func(c *Ctx) event.Value {
			v := a(c)
			if v.K != event.KindString {
				return event.Bool(false)
			}
			ip, err := netip.ParseAddr(v.S)
			if err != nil {
				return event.Bool(false)
			}
			return event.Bool(pfx.Contains(ip.Unmap()))
		}, info, nil
	}

	args := make([]Expr, len(x.Args))
	info := exprInfo{isConst: true}
	for i, an := range x.Args {
		e, ai, err := compileNode(an, sc)
		if err != nil {
			return nil, ai, err
		}
		args[i] = e
		info = merge(info, ai)
	}
	arity := func(n int) error {
		if len(args) != n {
			return errAt(x.P, "%s() takes %d argument(s), got %d", x.Fn, n, len(args))
		}
		return nil
	}
	var fn Expr
	switch x.Fn {
	case "lower", "upper", "len", "str", "int", "float", "abs", "exists", "is_null", "trim", "floor", "ceil":
		if err := arity(1); err != nil {
			return nil, info, err
		}
		a := args[0]
		switch x.Fn {
		case "lower":
			fn = func(c *Ctx) event.Value {
				v := a(c)
				if v.K != event.KindString {
					return v
				}
				return event.Str(strings.ToLower(v.S))
			}
		case "upper":
			fn = func(c *Ctx) event.Value {
				v := a(c)
				if v.K != event.KindString {
					return v
				}
				return event.Str(strings.ToUpper(v.S))
			}
		case "trim":
			fn = func(c *Ctx) event.Value {
				v := a(c)
				if v.K != event.KindString {
					return v
				}
				return event.Str(strings.TrimSpace(v.S))
			}
		case "len":
			fn = func(c *Ctx) event.Value {
				v := a(c)
				if v.K != event.KindString {
					return event.Null
				}
				return event.Int(int64(len(v.S)))
			}
		case "str":
			fn = func(c *Ctx) event.Value {
				v := a(c)
				if v.IsNull() {
					return v
				}
				return event.Str(v.AsString())
			}
		case "int":
			fn = func(c *Ctx) event.Value { return toNumber(a(c), true) }
		case "float":
			fn = func(c *Ctx) event.Value { return toNumber(a(c), false) }
		case "abs":
			fn = func(c *Ctx) event.Value {
				v := a(c)
				switch v.K {
				case event.KindInt:
					i := v.AsInt()
					if i < 0 {
						i = -i
					}
					return event.Int(i)
				case event.KindFloat:
					return event.Float(math.Abs(v.AsFloat()))
				}
				return event.Null
			}
		case "floor", "ceil":
			f := math.Floor
			if x.Fn == "ceil" {
				f = math.Ceil
			}
			fn = func(c *Ctx) event.Value {
				v := a(c)
				if !v.IsNumeric() {
					return event.Null
				}
				return event.Int(int64(f(v.AsFloat())))
			}
		case "exists":
			fn = func(c *Ctx) event.Value { return event.Bool(!a(c).IsNull()) }
		case "is_null":
			fn = func(c *Ctx) event.Value { return event.Bool(a(c).IsNull()) }
		}
	case "contains", "starts_with", "ends_with":
		if err := arity(2); err != nil {
			return nil, info, err
		}
		a, b := args[0], args[1]
		op := map[string]func(string, string) bool{
			"contains": strings.Contains, "starts_with": strings.HasPrefix, "ends_with": strings.HasSuffix,
		}[x.Fn]
		fn = func(c *Ctx) event.Value {
			s, sub := a(c), b(c)
			if s.K != event.KindString || sub.K != event.KindString {
				return event.Bool(false)
			}
			return event.Bool(op(s.S, sub.S))
		}
	case "coalesce":
		if len(args) < 1 {
			return nil, info, errAt(x.P, "coalesce() takes at least 1 argument")
		}
		fn = func(c *Ctx) event.Value {
			for _, a := range args {
				if v := a(c); !v.IsNull() {
					return v
				}
			}
			return event.Null
		}
	case "min", "max":
		if len(args) < 2 {
			return nil, info, errAt(x.P, "scalar %s() takes at least 2 arguments", x.Fn)
		}
		wantLess := x.Fn == "min"
		fn = func(c *Ctx) event.Value {
			best := args[0](c)
			for _, a := range args[1:] {
				v := a(c)
				if best.IsNull() {
					best = v
					continue
				}
				if cmp, ok := v.Compare(best); ok && (cmp < 0) == wantLess && cmp != 0 {
					best = v
				}
			}
			return best
		}
	case "elapsed_ms":
		if err := arity(0); err != nil {
			return nil, info, err
		}
		if len(sc.aliases) == 0 {
			return nil, info, errAt(x.P, "elapsed_ms() is only valid in sequence rules")
		}
		info.isConst = false
		info.usesCur = true
		fn = func(c *Ctx) event.Value {
			if c.Cur == nil {
				return event.Null
			}
			return event.Float(float64(c.Cur.Time-c.StartTS) / 1e6)
		}
	case "if":
		if err := arity(3); err != nil {
			return nil, info, err
		}
		cond, a, b := args[0], args[1], args[2]
		fn = func(c *Ctx) event.Value {
			if cond(c).AsBool() {
				return a(c)
			}
			return b(c)
		}
	default:
		return nil, info, errAt(x.P, "unknown function %s()", x.Fn)
	}
	return fn, info, nil
}

func toNumber(v event.Value, asInt bool) event.Value {
	var f float64
	switch v.K {
	case event.KindInt, event.KindFloat, event.KindBool:
		f = v.AsFloat()
	case event.KindString:
		var err error
		if _, err = fmt.Sscan(v.S, &f); err != nil {
			return event.Null
		}
	default:
		return event.Null
	}
	if asInt {
		return event.Int(int64(f))
	}
	return event.Float(f)
}

func compileAgg(x *CallNode, kind AggKind, sc *scope) (Expr, exprInfo, error) {
	spec := AggSpec{Kind: kind}
	argScope := *sc
	argScope.allowAgg = false
	argScope.isEmit = false
	switch kind {
	case AggCount, AggRate:
		if len(x.Args) != 0 {
			return nil, exprInfo{}, errAt(x.P, "%s() takes no arguments", x.Fn)
		}
		spec.Sig = x.Fn + "()"
	case AggQuantile:
		want := 1
		if x.Fn == "quantile" {
			want = 2
		}
		if len(x.Args) != want {
			return nil, exprInfo{}, errAt(x.P, "%s() takes %d argument(s)", x.Fn, want)
		}
		if x.Fn == "quantile" {
			lit, ok := x.Args[1].(*LitNode)
			q, isF := 0.0, false
			if ok {
				switch t := lit.Val.(type) {
				case float64:
					q, isF = t, true
				case int64:
					q, isF = float64(t), true
				}
			}
			if !isF || q < 0 || q > 1 {
				return nil, exprInfo{}, errAt(x.P, "quantile() second argument must be a numeric literal in [0,1]")
			}
			spec.Q = q
		} else {
			spec.Q = fixedQuantiles[x.Fn]
		}
		arg, ai, err := compileExpr(x.Args[0], &argScope)
		if err != nil {
			return nil, ai, err
		}
		if ai.usesAgg {
			return nil, ai, errAt(x.P, "aggregates cannot be nested")
		}
		spec.Arg = arg
		spec.Sig = fmt.Sprintf("quantile(%s,%g)", exprSig(x.Args[0]), spec.Q)
	default:
		if len(x.Args) != 1 {
			return nil, exprInfo{}, errAt(x.P, "%s() takes 1 argument", x.Fn)
		}
		arg, ai, err := compileExpr(x.Args[0], &argScope)
		if err != nil {
			return nil, ai, err
		}
		if ai.usesAgg {
			return nil, ai, errAt(x.P, "aggregates cannot be nested")
		}
		spec.Arg = arg
		spec.Sig = x.Fn + "(" + exprSig(x.Args[0]) + ")"
	}
	aggs := sc.aggs
	idx := -1
	for i, s := range *aggs {
		if s.Sig == spec.Sig {
			idx = i
			break
		}
	}
	if idx < 0 {
		*aggs = append(*aggs, spec)
		idx = len(*aggs) - 1
	}
	return func(c *Ctx) event.Value {
		if c.AggEval == nil {
			return event.Null
		}
		return c.AggEval(idx)
	}, exprInfo{usesAgg: true}, nil
}

// exprSig renders a canonical textual signature of an expression AST.
func exprSig(n Node) string {
	switch x := n.(type) {
	case *LitNode:
		return fmt.Sprintf("%#v", x.Val)
	case *IdentNode:
		return x.Name
	case *FieldNode:
		return x.Alias + "." + x.Name
	case *UnaryNode:
		return x.Op.String() + exprSig(x.X)
	case *BinaryNode:
		return "(" + exprSig(x.L) + x.Op + exprSig(x.R) + ")"
	case *ListNode:
		parts := make([]string, len(x.Items))
		for i, it := range x.Items {
			parts[i] = exprSig(it)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case *CallNode:
		parts := make([]string, len(x.Args))
		for i, it := range x.Args {
			parts[i] = exprSig(it)
		}
		return x.Fn + "(" + strings.Join(parts, ",") + ")"
	}
	return "?"
}
