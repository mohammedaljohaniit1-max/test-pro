package rules

import (
	"strings"
	"time"
)

// Grammar (informal):
//
//	file      := rule*
//	rule      := "rule" IDENT "{" clause* "}"
//	clause    := "severity" (IDENT|STRING) | "description" STRING
//	           | "tags" "[" STRING {"," STRING} "]" | "within" DURATION
//	           | "suppress" DURATION | "max_runs" INT
//	           | "sequence" "{" step+ "}"
//	           | "aggregate" "over" DURATION ["step" DURATION]
//	           | "from" types | "where" expr | "by" expr | "having" expr
//	           | "emit" "{" {IDENT "=" expr [","]} "}"
//	step      := ["!"|"not"] IDENT ":" types [quant] ["where" expr]
//	quant     := "+" | "[" INT [":" [INT]] "]"
//	types     := "*" | tname | "(" tname {"|" tname} ")"
//	tname     := STRING | IDENT {"." (IDENT|"*")}
//	expr      := or
//	or        := and {("||"|"or") and}
//	and       := not {("&&"|"and") not}
//	not       := ("!"|"not") not | cmp
//	cmp       := add [("=="|"!="|"<"|"<="|">"|">="|"in"|"not" "in") add]
//	add       := mul {("+"|"-") mul}
//	mul       := unary {("*"|"/"|"%") unary}
//	unary     := "-" unary | primary
//	primary   := literal | path | IDENT "(" [expr {"," expr}] ")" | "(" expr ")"
//	           | "[" [expr {"," expr}] "]"
//	path      := IDENT {"." IDENT}

type parser struct {
	src  string
	toks []token
	i    int
}

// Parse parses TCL source into rule ASTs.
func Parse(src string) ([]*RuleAST, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{src: src, toks: toks}
	var out []*RuleAST
	for p.peek().kind != tEOF {
		r, err := p.parseRule()
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (p *parser) peek() token { return p.toks[p.i] }
func (p *parser) peekN(n int) token {
	if p.i+n < len(p.toks) {
		return p.toks[p.i+n]
	}
	return p.toks[len(p.toks)-1]
}
func (p *parser) nextTok() token {
	t := p.toks[p.i]
	if t.kind != tEOF {
		p.i++
	}
	return t
}

func (p *parser) isKw(t token, kw string) bool { return t.kind == tIdent && t.text == kw }

func (p *parser) expect(k tokKind) (token, error) {
	t := p.nextTok()
	if t.kind != k {
		return t, errAt(t.pos, "expected %s, found %s", k, describe(t))
	}
	return t, nil
}

func (p *parser) expectKw(kw string) error {
	t := p.nextTok()
	if !p.isKw(t, kw) {
		return errAt(t.pos, "expected %q, found %s", kw, describe(t))
	}
	return nil
}

func describe(t token) string {
	switch t.kind {
	case tIdent:
		return "identifier " + quote(t.text)
	case tString:
		return "string " + quote(t.text)
	case tInt, tFloat, tDuration:
		return t.kind.String() + " " + t.text
	}
	return t.kind.String()
}

func quote(s string) string { return "\"" + s + "\"" }

// offsetOf converts a Pos to a byte offset in src.
func (p *parser) offsetOf(pos Pos) int {
	line, col := 1, 1
	for i := 0; i < len(p.src); i++ {
		if line == pos.Line && col == pos.Col {
			return i
		}
		if p.src[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return len(p.src)
}

func (p *parser) parseRule() (*RuleAST, error) {
	start := p.peek()
	if err := p.expectKw("rule"); err != nil {
		return nil, err
	}
	name, err := p.expect(tIdent)
	if err != nil {
		return nil, err
	}
	r := &RuleAST{P: start.pos, Name: name.text, Severity: "medium", MaxRuns: 64}
	if _, err := p.expect(tLBrace); err != nil {
		return nil, err
	}
	seen := map[string]Pos{}
	for {
		t := p.peek()
		if t.kind == tRBrace {
			end := p.nextTok()
			r.Source = p.src[p.offsetOf(start.pos) : p.offsetOf(end.pos)+1]
			return r, nil
		}
		if t.kind != tIdent {
			return nil, errAt(t.pos, "expected clause keyword, found %s", describe(t))
		}
		if prev, dup := seen[t.text]; dup {
			return nil, errAt(t.pos, "duplicate %q clause (first at %s)", t.text, prev)
		}
		seen[t.text] = t.pos
		p.nextTok()
		switch t.text {
		case "severity":
			v := p.nextTok()
			if v.kind != tIdent && v.kind != tString {
				return nil, errAt(v.pos, "expected severity level, found %s", describe(v))
			}
			r.Severity = strings.ToLower(v.text)
		case "description":
			v, err := p.expect(tString)
			if err != nil {
				return nil, err
			}
			r.Description = v.text
		case "tags":
			if _, err := p.expect(tLBrack); err != nil {
				return nil, err
			}
			for p.peek().kind != tRBrack {
				v, err := p.expect(tString)
				if err != nil {
					return nil, err
				}
				r.Tags = append(r.Tags, v.text)
				if p.peek().kind == tComma {
					p.nextTok()
				}
			}
			p.nextTok()
		case "within":
			d, err := p.parseDuration()
			if err != nil {
				return nil, err
			}
			r.Within = d
		case "suppress":
			d, err := p.parseDuration()
			if err != nil {
				return nil, err
			}
			r.Suppress = d
		case "max_runs":
			v, err := p.expect(tInt)
			if err != nil {
				return nil, err
			}
			r.MaxRuns = int(v.i)
		case "sequence":
			steps, err := p.parseSteps()
			if err != nil {
				return nil, err
			}
			r.Steps = steps
		case "aggregate":
			r.IsAggregate = true
			if err := p.expectKw("over"); err != nil {
				return nil, err
			}
			d, err := p.parseDuration()
			if err != nil {
				return nil, err
			}
			r.Over = d
			if p.isKw(p.peek(), "step") {
				p.nextTok()
				s, err := p.parseDuration()
				if err != nil {
					return nil, err
				}
				r.Step = s
			}
		case "from":
			m, err := p.parseTypes()
			if err != nil {
				return nil, err
			}
			r.From = m
		case "where":
			e, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			r.Where = e
		case "by":
			e, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			r.By = e
		case "having":
			e, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			r.Having = e
		case "emit":
			em, err := p.parseEmit()
			if err != nil {
				return nil, err
			}
			r.Emit = em
		default:
			return nil, errAt(t.pos, "unknown clause %q", t.text)
		}
	}
}

func (p *parser) parseDuration() (time.Duration, error) {
	t := p.nextTok()
	if t.kind != tDuration {
		return 0, errAt(t.pos, "expected duration (e.g. 30s, 5m), found %s", describe(t))
	}
	if t.d <= 0 {
		return 0, errAt(t.pos, "duration must be positive")
	}
	return t.d, nil
}

func (p *parser) parseSteps() ([]StepAST, error) {
	if _, err := p.expect(tLBrace); err != nil {
		return nil, err
	}
	var steps []StepAST
	for p.peek().kind != tRBrace {
		st := StepAST{P: p.peek().pos, Min: 1, Max: 1}
		if p.peek().kind == tNot || p.isKw(p.peek(), "not") {
			p.nextTok()
			st.Negated = true
		}
		alias, err := p.expect(tIdent)
		if err != nil {
			return nil, err
		}
		st.Alias = alias.text
		if _, err := p.expect(tColon); err != nil {
			return nil, err
		}
		m, err := p.parseTypes()
		if err != nil {
			return nil, err
		}
		st.Types = m
		switch p.peek().kind {
		case tPlus:
			p.nextTok()
			st.Min, st.Max = 1, 0
		case tLBrack:
			p.nextTok()
			lo, err := p.expect(tInt)
			if err != nil {
				return nil, err
			}
			st.Min, st.Max = int(lo.i), int(lo.i)
			if p.peek().kind == tColon {
				p.nextTok()
				st.Max = 0
				if p.peek().kind == tInt {
					st.Max = int(p.nextTok().i)
				}
			}
			if _, err := p.expect(tRBrack); err != nil {
				return nil, err
			}
		}
		if p.isKw(p.peek(), "where") {
			p.nextTok()
			e, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			st.Where = e
		}
		steps = append(steps, st)
		if p.peek().kind == tComma {
			p.nextTok()
		}
		if p.peek().kind == tEOF {
			return nil, errAt(p.peek().pos, "unterminated sequence block")
		}
	}
	p.nextTok()
	return steps, nil
}

func (p *parser) parseTypes() (TypeMatcher, error) {
	var m TypeMatcher
	t := p.peek()
	if t.kind == tStar {
		p.nextTok()
		m.Any = true
		return m, nil
	}
	if t.kind == tLParen {
		p.nextTok()
		for {
			if err := p.parseTypeName(&m); err != nil {
				return m, err
			}
			if p.peek().kind == tPipe || p.peek().kind == tComma {
				p.nextTok()
				continue
			}
			break
		}
		if _, err := p.expect(tRParen); err != nil {
			return m, err
		}
		return m, nil
	}
	return m, p.parseTypeName(&m)
}

func (p *parser) parseTypeName(m *TypeMatcher) error {
	t := p.nextTok()
	if t.kind == tString {
		if strings.HasSuffix(t.text, "*") {
			m.Prefixes = append(m.Prefixes, strings.TrimSuffix(t.text, "*"))
		} else {
			m.Exact = append(m.Exact, t.text)
		}
		return nil
	}
	if t.kind != tIdent {
		return errAt(t.pos, "expected event type, found %s", describe(t))
	}
	var b strings.Builder
	b.WriteString(t.text)
	for p.peek().kind == tDot {
		p.nextTok()
		n := p.nextTok()
		switch n.kind {
		case tIdent:
			b.WriteByte('.')
			b.WriteString(n.text)
		case tStar:
			b.WriteByte('.')
			m.Prefixes = append(m.Prefixes, b.String())
			return nil
		default:
			return errAt(n.pos, "expected type segment, found %s", describe(n))
		}
	}
	m.Exact = append(m.Exact, b.String())
	return nil
}

func (p *parser) parseEmit() ([]EmitAST, error) {
	if _, err := p.expect(tLBrace); err != nil {
		return nil, err
	}
	var out []EmitAST
	seen := map[string]bool{}
	for p.peek().kind != tRBrace {
		name, err := p.expect(tIdent)
		if err != nil {
			return nil, err
		}
		if seen[name.text] {
			return nil, errAt(name.pos, "duplicate emit field %q", name.text)
		}
		seen[name.text] = true
		if _, err := p.expect(tAssign); err != nil {
			return nil, err
		}
		e, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		out = append(out, EmitAST{Name: name.text, Expr: e})
		if p.peek().kind == tComma {
			p.nextTok()
		}
		if p.peek().kind == tEOF {
			return nil, errAt(p.peek().pos, "unterminated emit block")
		}
	}
	p.nextTok()
	return out, nil
}

// ---- expressions ----------------------------------------------------------

func (p *parser) parseExpr() (Node, error) { return p.parseOr() }

func (p *parser) parseOr() (Node, error) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tOr || p.isKw(p.peek(), "or") {
		t := p.nextTok()
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l = &BinaryNode{P: t.pos, Op: "||", L: l, R: r}
	}
	return l, nil
}

func (p *parser) parseAnd() (Node, error) {
	l, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tAnd || p.isKw(p.peek(), "and") {
		t := p.nextTok()
		r, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		l = &BinaryNode{P: t.pos, Op: "&&", L: l, R: r}
	}
	return l, nil
}

func (p *parser) parseNot() (Node, error) {
	t := p.peek()
	if t.kind == tNot || (p.isKw(t, "not") && !p.isKw(p.peekN(1), "in")) {
		p.nextTok()
		x, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &UnaryNode{P: t.pos, Op: tNot, X: x}, nil
	}
	return p.parseCmp()
}

var cmpOps = map[tokKind]string{tEq: "==", tNe: "!=", tLt: "<", tLe: "<=", tGt: ">", tGe: ">="}

func (p *parser) parseCmp() (Node, error) {
	l, err := p.parseAdd()
	if err != nil {
		return nil, err
	}
	t := p.peek()
	op := ""
	if o, ok := cmpOps[t.kind]; ok {
		op = o
		p.nextTok()
	} else if p.isKw(t, "in") {
		op = "in"
		p.nextTok()
	} else if p.isKw(t, "not") && p.isKw(p.peekN(1), "in") {
		op = "not in"
		p.nextTok()
		p.nextTok()
	} else {
		return l, nil
	}
	r, err := p.parseAdd()
	if err != nil {
		return nil, err
	}
	if _, isCmp := cmpOps[p.peek().kind]; isCmp {
		return nil, errAt(p.peek().pos, "comparison operators cannot be chained; use && to combine")
	}
	return &BinaryNode{P: t.pos, Op: op, L: l, R: r}, nil
}

func (p *parser) parseAdd() (Node, error) {
	l, err := p.parseMul()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tPlus || p.peek().kind == tMinus {
		t := p.nextTok()
		r, err := p.parseMul()
		if err != nil {
			return nil, err
		}
		op := "+"
		if t.kind == tMinus {
			op = "-"
		}
		l = &BinaryNode{P: t.pos, Op: op, L: l, R: r}
	}
	return l, nil
}

func (p *parser) parseMul() (Node, error) {
	l, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		k := p.peek().kind
		if k != tStar && k != tSlash && k != tPercent {
			return l, nil
		}
		t := p.nextTok()
		r, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		op := map[tokKind]string{tStar: "*", tSlash: "/", tPercent: "%"}[k]
		l = &BinaryNode{P: t.pos, Op: op, L: l, R: r}
	}
}

func (p *parser) parseUnary() (Node, error) {
	if p.peek().kind == tMinus {
		t := p.nextTok()
		x, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		if lit, ok := x.(*LitNode); ok {
			switch v := lit.Val.(type) {
			case int64:
				return &LitNode{P: t.pos, Val: -v}, nil
			case float64:
				return &LitNode{P: t.pos, Val: -v}, nil
			}
		}
		return &UnaryNode{P: t.pos, Op: tMinus, X: x}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Node, error) {
	t := p.nextTok()
	switch t.kind {
	case tString:
		return &LitNode{P: t.pos, Val: t.text}, nil
	case tInt:
		return &LitNode{P: t.pos, Val: t.i}, nil
	case tFloat:
		return &LitNode{P: t.pos, Val: t.f}, nil
	case tDuration:
		// Durations inside expressions are expressed in milliseconds.
		return &LitNode{P: t.pos, Val: float64(t.d) / float64(time.Millisecond)}, nil
	case tLParen:
		e, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tRParen); err != nil {
			return nil, err
		}
		return e, nil
	case tLBrack:
		l := &ListNode{P: t.pos}
		for p.peek().kind != tRBrack {
			e, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			l.Items = append(l.Items, e)
			if p.peek().kind == tComma {
				p.nextTok()
			} else if p.peek().kind != tRBrack {
				return nil, errAt(p.peek().pos, "expected ',' or ']' in list, found %s", describe(p.peek()))
			}
		}
		p.nextTok()
		return l, nil
	case tIdent:
		switch t.text {
		case "true":
			return &LitNode{P: t.pos, Val: true}, nil
		case "false":
			return &LitNode{P: t.pos, Val: false}, nil
		case "null":
			return &LitNode{P: t.pos, Val: nil}, nil
		}
		if p.peek().kind == tLParen {
			p.nextTok()
			c := &CallNode{P: t.pos, Fn: strings.ToLower(t.text)}
			for p.peek().kind != tRParen {
				e, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				c.Args = append(c.Args, e)
				if p.peek().kind == tComma {
					p.nextTok()
				} else if p.peek().kind != tRParen {
					return nil, errAt(p.peek().pos, "expected ',' or ')' in call, found %s", describe(p.peek()))
				}
			}
			p.nextTok()
			return c, nil
		}
		if p.peek().kind == tDot && p.peekN(1).kind == tIdent {
			segs := []string{t.text}
			for p.peek().kind == tDot && p.peekN(1).kind == tIdent {
				p.nextTok()
				segs = append(segs, p.nextTok().text)
			}
			return &FieldNode{P: t.pos, Alias: segs[0], Name: strings.Join(segs[1:], ".")}, nil
		}
		return &IdentNode{P: t.pos, Name: t.text}, nil
	}
	return nil, errAt(t.pos, "unexpected %s in expression", describe(t))
}
