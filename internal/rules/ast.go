package rules

import "time"

// Node is an expression AST node.
type Node interface{ pos() Pos }

type (
	// LitNode is a literal (string, int, float, bool, null, duration as ms).
	LitNode struct {
		P   Pos
		Val any // string | int64 | float64 | bool | nil
	}
	// IdentNode references a field of the current event.
	IdentNode struct {
		P    Pos
		Name string
	}
	// FieldNode references alias.field (a field of the last event bound to a
	// sequence step alias).
	FieldNode struct {
		P     Pos
		Alias string
		Name  string
	}
	// UnaryNode is !x or -x.
	UnaryNode struct {
		P  Pos
		Op tokKind
		X  Node
	}
	// BinaryNode is x op y. Op is a tokKind or one of the keyword ops.
	BinaryNode struct {
		P    Pos
		Op   string
		L, R Node
	}
	// ListNode is [a, b, c] (only valid as the rhs of `in`).
	ListNode struct {
		P     Pos
		Items []Node
	}
	// CallNode is fn(args...).
	CallNode struct {
		P    Pos
		Fn   string
		Args []Node
	}
)

func (n *LitNode) pos() Pos    { return n.P }
func (n *IdentNode) pos() Pos  { return n.P }
func (n *FieldNode) pos() Pos  { return n.P }
func (n *UnaryNode) pos() Pos  { return n.P }
func (n *BinaryNode) pos() Pos { return n.P }
func (n *ListNode) pos() Pos   { return n.P }
func (n *CallNode) pos() Pos   { return n.P }

// TypeMatcher matches event types: exact names or prefix globs ("auth.*").
type TypeMatcher struct {
	Exact    []string
	Prefixes []string
	Any      bool
}

// Match reports whether t is selected.
func (m *TypeMatcher) Match(t string) bool {
	if m.Any {
		return true
	}
	for _, e := range m.Exact {
		if e == t {
			return true
		}
	}
	for _, p := range m.Prefixes {
		if len(t) >= len(p) && t[:len(p)] == p {
			return true
		}
	}
	return false
}

// StepAST is one element of a sequence pattern.
type StepAST struct {
	P       Pos
	Negated bool
	Alias   string
	Types   TypeMatcher
	Where   Node
	Min     int
	Max     int // 0 = unbounded
}

// EmitAST is one `name = expr` output field.
type EmitAST struct {
	Name string
	Expr Node
}

// RuleAST is a parsed (not yet compiled) rule.
type RuleAST struct {
	P           Pos
	Name        string
	Severity    string
	Description string
	Tags        []string
	Suppress    time.Duration
	MaxRuns     int

	// Sequence rules.
	Within time.Duration
	Steps  []StepAST

	// Aggregate rules.
	IsAggregate bool
	Over        time.Duration
	Step        time.Duration
	From        TypeMatcher
	Where       Node
	By          Node
	Having      Node

	Emit   []EmitAST
	Source string // exact source text of the rule (for fingerprinting)
}
