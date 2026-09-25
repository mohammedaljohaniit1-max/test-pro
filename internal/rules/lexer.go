// Package rules implements the Tempora Correlation Language (TCL): a small,
// strongly-validated DSL for temporal pattern (sequence / absence) and
// windowed aggregate rules. Source is lexed, parsed into an AST, validated and
// compiled into closure trees that evaluate without reflection or allocation
// on the hot path.
package rules

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tString
	tInt
	tFloat
	tDuration
	tLBrace
	tRBrace
	tLParen
	tRParen
	tLBrack
	tRBrack
	tComma
	tDot
	tAssign
	tEq
	tNe
	tLt
	tLe
	tGt
	tGe
	tAnd
	tOr
	tNot
	tPlus
	tMinus
	tStar
	tSlash
	tPercent
	tColon
	tPipe
)

var tokNames = map[tokKind]string{
	tEOF: "end of input", tIdent: "identifier", tString: "string", tInt: "integer",
	tFloat: "float", tDuration: "duration", tLBrace: "'{'", tRBrace: "'}'",
	tLParen: "'('", tRParen: "')'", tLBrack: "'['", tRBrack: "']'", tComma: "','",
	tDot: "'.'", tAssign: "'='", tEq: "'=='", tNe: "'!='", tLt: "'<'", tLe: "'<='",
	tGt: "'>'", tGe: "'>='", tAnd: "'&&'", tOr: "'||'", tNot: "'!'", tPlus: "'+'",
	tMinus: "'-'", tStar: "'*'", tSlash: "'/'", tPercent: "'%'", tColon: "':'", tPipe: "'|'",
}

func (k tokKind) String() string { return tokNames[k] }

// Pos is a 1-based source position.
type Pos struct {
	Line, Col int
}

func (p Pos) String() string { return fmt.Sprintf("%d:%d", p.Line, p.Col) }

type token struct {
	kind tokKind
	text string // identifier / raw literal text / decoded string
	pos  Pos
	i    int64
	f    float64
	d    time.Duration
}

// Error is a positioned compile error.
type Error struct {
	Pos Pos
	Msg string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Pos, e.Msg) }

func errAt(p Pos, format string, args ...any) *Error {
	return &Error{Pos: p, Msg: fmt.Sprintf(format, args...)}
}

type lexer struct {
	src  string
	off  int
	line int
	col  int
}

func lex(src string) ([]token, error) {
	l := &lexer{src: src, line: 1, col: 1}
	var toks []token
	for {
		t, err := l.next()
		if err != nil {
			return nil, err
		}
		toks = append(toks, t)
		if t.kind == tEOF {
			return toks, nil
		}
	}
}

func (l *lexer) peekc(ahead int) byte {
	if l.off+ahead < len(l.src) {
		return l.src[l.off+ahead]
	}
	return 0
}

func (l *lexer) adv(n int) {
	for i := 0; i < n && l.off < len(l.src); i++ {
		if l.src[l.off] == '\n' {
			l.line++
			l.col = 1
		} else {
			l.col++
		}
		l.off++
	}
}

func (l *lexer) skipSpaceAndComments() {
	for l.off < len(l.src) {
		c := l.src[l.off]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			l.adv(1)
		case c == '#' || (c == '/' && l.peekc(1) == '/'):
			for l.off < len(l.src) && l.src[l.off] != '\n' {
				l.adv(1)
			}
		case c == '/' && l.peekc(1) == '*':
			l.adv(2)
			for l.off < len(l.src) && !(l.src[l.off] == '*' && l.peekc(1) == '/') {
				l.adv(1)
			}
			l.adv(2)
		default:
			return
		}
	}
}

func (l *lexer) next() (token, error) {
	l.skipSpaceAndComments()
	p := Pos{l.line, l.col}
	if l.off >= len(l.src) {
		return token{kind: tEOF, pos: p}, nil
	}
	c := l.src[l.off]
	two := ""
	if l.off+1 < len(l.src) {
		two = l.src[l.off : l.off+2]
	}
	switch two {
	case "==":
		l.adv(2)
		return token{kind: tEq, pos: p}, nil
	case "!=":
		l.adv(2)
		return token{kind: tNe, pos: p}, nil
	case "<=":
		l.adv(2)
		return token{kind: tLe, pos: p}, nil
	case ">=":
		l.adv(2)
		return token{kind: tGe, pos: p}, nil
	case "&&":
		l.adv(2)
		return token{kind: tAnd, pos: p}, nil
	case "||":
		l.adv(2)
		return token{kind: tOr, pos: p}, nil
	}
	if k, ok := singleTokens[c]; ok {
		if !(c == '.' && isDigit(l.peekc(1))) {
			l.adv(1)
			return token{kind: k, pos: p}, nil
		}
	}
	switch {
	case c == '"' || c == '\'':
		return l.lexString(p, c)
	case isDigit(c) || c == '.':
		return l.lexNumber(p)
	case c == '_' || c < utf8.RuneSelf && unicode.IsLetter(rune(c)):
		start := l.off
		for l.off < len(l.src) {
			d := l.src[l.off]
			if d == '_' || isDigit(d) || d < utf8.RuneSelf && unicode.IsLetter(rune(d)) {
				l.adv(1)
				continue
			}
			break
		}
		return token{kind: tIdent, text: l.src[start:l.off], pos: p}, nil
	}
	return token{}, errAt(p, "unexpected character %q", c)
}

var singleTokens = map[byte]tokKind{
	'{': tLBrace, '}': tRBrace, '(': tLParen, ')': tRParen, '[': tLBrack, ']': tRBrack,
	',': tComma, '.': tDot, '=': tAssign, '<': tLt, '>': tGt, '!': tNot, '+': tPlus,
	'-': tMinus, '*': tStar, '/': tSlash, '%': tPercent, ':': tColon, '|': tPipe,
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (l *lexer) lexString(p Pos, quote byte) (token, error) {
	l.adv(1)
	var b strings.Builder
	for {
		if l.off >= len(l.src) || l.src[l.off] == '\n' {
			return token{}, errAt(p, "unterminated string literal")
		}
		c := l.src[l.off]
		if c == quote {
			l.adv(1)
			return token{kind: tString, text: b.String(), pos: p}, nil
		}
		if c == '\\' {
			l.adv(1)
			if l.off >= len(l.src) {
				return token{}, errAt(p, "unterminated string literal")
			}
			e := l.src[l.off]
			switch e {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '\\', '"', '\'':
				b.WriteByte(e)
			default:
				// Preserve unknown escapes verbatim (useful inside regexps).
				b.WriteByte('\\')
				b.WriteByte(e)
			}
			l.adv(1)
			continue
		}
		b.WriteByte(c)
		l.adv(1)
	}
}

var durationUnits = []struct {
	suffix string
	unit   time.Duration
}{
	{"ms", time.Millisecond}, {"us", time.Microsecond}, {"ns", time.Nanosecond},
	{"s", time.Second}, {"m", time.Minute}, {"h", time.Hour}, {"d", 24 * time.Hour},
}

func (l *lexer) lexNumber(p Pos) (token, error) {
	start := l.off
	isFloat := false
	for l.off < len(l.src) {
		c := l.src[l.off]
		if isDigit(c) || c == '_' {
			l.adv(1)
		} else if c == '.' && !isFloat && isDigit(l.peekc(1)) {
			isFloat = true
			l.adv(1)
		} else if (c == 'e' || c == 'E') && (isDigit(l.peekc(1)) || ((l.peekc(1) == '-' || l.peekc(1) == '+') && isDigit(l.peekc(2)))) {
			isFloat = true
			l.adv(2)
		} else {
			break
		}
	}
	num := strings.ReplaceAll(l.src[start:l.off], "_", "")
	// Duration suffix?
	rest := l.src[l.off:]
	for _, u := range durationUnits {
		if strings.HasPrefix(rest, u.suffix) {
			after := byte(0)
			if len(rest) > len(u.suffix) {
				after = rest[len(u.suffix)]
			}
			if after == '_' || isDigit(after) || after < utf8.RuneSelf && unicode.IsLetter(rune(after)) {
				continue
			}
			f, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return token{}, errAt(p, "invalid duration %q", num+u.suffix)
			}
			l.adv(len(u.suffix))
			d := time.Duration(f * float64(u.unit))
			return token{kind: tDuration, text: num + u.suffix, pos: p, d: d}, nil
		}
	}
	if isFloat {
		f, err := strconv.ParseFloat(num, 64)
		if err != nil {
			return token{}, errAt(p, "invalid number %q", num)
		}
		return token{kind: tFloat, text: num, pos: p, f: f}, nil
	}
	i, err := strconv.ParseInt(num, 10, 64)
	if err != nil {
		return token{}, errAt(p, "invalid integer %q", num)
	}
	return token{kind: tInt, text: num, pos: p, i: i}, nil
}
