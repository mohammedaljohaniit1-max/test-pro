// Package rules is SysPulse's user-configurable threshold alerting engine.
//
// A Rule compares one catalogued metric against a threshold and fires when
// the condition has held continuously for Rule.For (e.g. "CPU > 85 % for
// 30 s"). Scoped metrics (a disk, an interface, a process name, a service)
// are evaluated per instance, so one rule covers every volume or every NIC.
// Once firing, an instance re-arms only after the value crosses back past
// the threshold by the hysteresis margin, which prevents alert flapping.
//
// Collectors feed observations with Evaluate(metric, obs). Each call only
// touches rules for that metric; instances missing from obs are treated as
// "condition false". The engine is safe for concurrent use and can persist
// its rule set as JSON.
package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// Operators.
const (
	OpGT = ">"
	OpGE = ">="
	OpLT = "<"
	OpLE = "<="
)

// Rule is one user-editable alert condition.
type Rule struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	NameAr     string  `json:"nameAr,omitempty"`
	Metric     string  `json:"metric"`
	Op         string  `json:"op"`
	Threshold  float64 `json:"threshold"`
	ForSec     int     `json:"for"`                  // condition must hold this long (0 = immediately)
	Scope      string  `json:"scope,omitempty"`      // instance glob ("" / "*" = all); e.g. C:\, Wi-Fi, chrome.exe
	Severity   string  `json:"severity"`             // critical, warning, info
	Hysteresis float64 `json:"hysteresis,omitempty"` // re-arm margin; 0 = catalog default
	Enabled    bool    `json:"enabled"`
	Builtin    bool    `json:"builtin,omitempty"`
	Created    int64   `json:"created,omitempty"`
	Updated    int64   `json:"updated,omitempty"`
}

// Obs is one observation of a metric instance.
type Obs struct {
	Instance string  // "" for host-wide metrics
	Value    float64 //
	Label    string  // optional display label (e.g. "chrome.exe (PID 4120)")
}

// Firing is emitted when an instance starts or stops violating a rule.
type Firing struct {
	Rule     Rule
	Instance string
	Label    string
	Value    float64
	Since    time.Time
	Resolved bool
}

// Key is the stable alert de-duplication key.
func (f Firing) Key() string { return "rule:" + f.Rule.ID + ":" + f.Instance }

// InstanceState is exposed to the dashboard.
type InstanceState struct {
	Instance string  `json:"instance"`
	Label    string  `json:"label,omitempty"`
	Value    float64 `json:"value"`
	Since    int64   `json:"since"` // unix ms the condition became true (0 = not violating)
	Firing   bool    `json:"firing"`
}

// RuleState summarises one rule for the UI.
type RuleState struct {
	ID        string          `json:"id"`
	Firing    int             `json:"firing"`
	Pending   int             `json:"pending"` // violating but not yet for the full duration
	LastValue *float64        `json:"last,omitempty"`
	LastEval  int64           `json:"lastEval,omitempty"`
	Fired     int             `json:"fired"` // total firings since start
	Instances []InstanceState `json:"instances,omitempty"`
}

type inst struct {
	since  time.Time
	firing bool
	value  float64
	label  string
	seen   time.Time
}

type ruleRT struct {
	inst     map[string]*inst
	last     *float64
	lastEval time.Time
	fired    int
}

// Engine evaluates rules.
type Engine struct {
	mu    sync.Mutex
	rules []Rule
	rt    map[string]*ruleRT
	file  string
	now   func() time.Time
	seq   int
}

// ErrNotFound is returned for unknown rule IDs.
var ErrNotFound = errors.New("rule not found")

// MaxRules bounds the rule set.
const MaxRules = 100

// New creates an engine with the default rules. When file is non-empty the
// rule set is loaded from (and saved to) that JSON file.
func New(file string) *Engine {
	e := &Engine{file: file, rt: map[string]*ruleRT{}, now: time.Now}
	e.rules = Defaults()
	if file != "" {
		if b, err := os.ReadFile(file); err == nil {
			var rs []Rule
			if json.Unmarshal(b, &rs) == nil {
				valid := rs[:0]
				for _, r := range rs {
					if Validate(&r) == nil {
						valid = append(valid, r)
					}
				}
				if len(valid) > 0 {
					e.rules = valid
				}
			}
		}
	}
	return e
}

// SetClock overrides the clock (tests).
func (e *Engine) SetClock(now func() time.Time) { e.mu.Lock(); e.now = now; e.mu.Unlock() }

// Defaults returns the built-in rule set.
func Defaults() []Rule {
	r := func(id, en, ar, metric, op string, thr float64, forSec int, sev, scope string) Rule {
		return Rule{ID: id, Name: en, NameAr: ar, Metric: metric, Op: op, Threshold: thr, ForSec: forSec,
			Severity: sev, Scope: scope, Enabled: true, Builtin: true}
	}
	return []Rule{
		r("cpu-sustained", "Sustained high CPU", "استخدام مرتفع ومستمر للمعالج", MetricCPU, OpGT, 85, 30, model.SevWarning, ""),
		r("mem-pressure", "Memory pressure", "ضغط على الذاكرة", MetricMem, OpGE, 92, 15, model.SevWarning, ""),
		r("commit-exhaustion", "Commit charge near limit", "اقتراب الذاكرة الملتزمة من الحد", MetricCommit, OpGE, 90, 30, model.SevWarning, ""),
		r("disk-low", "Low disk space", "مساحة قرص منخفضة", MetricDisk, OpGE, 92, 0, model.SevWarning, ""),
		r("disk-critical", "Disk almost full", "القرص ممتلئ تقريبًا", MetricDisk, OpGE, 97, 0, model.SevCritical, ""),
		r("socket-burst", "Socket creation burst", "اندفاع في إنشاء المقابس", MetricSocketsNew, OpGT, 60, 3, model.SevWarning, ""),
		r("proc-runaway", "Runaway process (single process CPU)", "عملية منفلتة (معالج عملية واحدة)", MetricProcCPU, OpGT, 50, 60, model.SevWarning, ""),
		r("nic-saturation", "Network interface saturated", "تشبّع واجهة الشبكة", MetricIfUtil, OpGT, 90, 10, model.SevWarning, ""),
		r("svc-auto-failed", "Automatic service failed", "فشل خدمة تلقائية", MetricSvcAutoStopped, OpGE, 1, 30, model.SevWarning, ""),
	}
}

// List returns a copy of the rules.
func (e *Engine) List() []Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Rule(nil), e.rules...)
}

// Get returns one rule.
func (e *Engine) Get(id string) (Rule, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range e.rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// Validate normalises and checks a rule.
func Validate(r *Rule) error {
	r.Name = strings.TrimSpace(r.Name)
	r.NameAr = strings.TrimSpace(r.NameAr)
	r.Scope = strings.TrimSpace(r.Scope)
	if r.Scope == "*" {
		r.Scope = ""
	}
	m, ok := CatalogByKey(r.Metric)
	if !ok {
		return fmt.Errorf("unknown metric %q", r.Metric)
	}
	switch r.Op {
	case OpGT, OpGE, OpLT, OpLE:
	default:
		return fmt.Errorf("invalid operator %q", r.Op)
	}
	if math.IsNaN(r.Threshold) || math.IsInf(r.Threshold, 0) || r.Threshold < m.Min || r.Threshold > m.Max {
		return fmt.Errorf("threshold must be between %g and %g", m.Min, m.Max)
	}
	if r.ForSec < 0 || r.ForSec > 3600 {
		return errors.New("duration must be between 0 and 3600 seconds")
	}
	if r.Hysteresis < 0 || r.Hysteresis > m.Max {
		return errors.New("invalid hysteresis")
	}
	switch r.Severity {
	case model.SevCritical, model.SevWarning, model.SevInfo:
	default:
		return fmt.Errorf("invalid severity %q", r.Severity)
	}
	if r.Name == "" {
		r.Name = m.Label.En
	}
	if len(r.Name) > 120 || len(r.NameAr) > 240 || len(r.Scope) > 160 {
		return errors.New("name or scope too long")
	}
	if r.Scope != "" && !m.Scoped {
		return fmt.Errorf("metric %q has no instances; leave the scope empty", r.Metric)
	}
	if _, err := path.Match(globNorm(r.Scope), ""); err != nil {
		return fmt.Errorf("invalid scope pattern: %v", err)
	}
	return nil
}

// Create adds a rule (ID assigned).
func (e *Engine) Create(r Rule) (Rule, error) {
	if err := Validate(&r); err != nil {
		return Rule{}, err
	}
	e.mu.Lock()
	if len(e.rules) >= MaxRules {
		e.mu.Unlock()
		return Rule{}, fmt.Errorf("at most %d rules", MaxRules)
	}
	now := e.now()
	e.seq++
	r.ID = "r" + strconv.FormatInt(now.UnixMilli()%1e10, 36) + strconv.Itoa(e.seq)
	r.Builtin = false
	r.Created, r.Updated = now.UnixMilli(), now.UnixMilli()
	e.rules = append(e.rules, r)
	e.mu.Unlock()
	return r, e.save()
}

// Update replaces a rule by ID. Runtime state is reset when the condition
// itself changed.
func (e *Engine) Update(id string, r Rule) (Rule, error) {
	if err := Validate(&r); err != nil {
		return Rule{}, err
	}
	e.mu.Lock()
	idx := -1
	for i := range e.rules {
		if e.rules[i].ID == id {
			idx = i
		}
	}
	if idx < 0 {
		e.mu.Unlock()
		return Rule{}, ErrNotFound
	}
	old := e.rules[idx]
	r.ID, r.Builtin, r.Created, r.Updated = id, old.Builtin, old.Created, e.now().UnixMilli()
	if old.Metric != r.Metric || old.Op != r.Op || old.Threshold != r.Threshold || old.Scope != r.Scope || old.ForSec != r.ForSec || !r.Enabled {
		delete(e.rt, id)
	}
	e.rules[idx] = r
	e.mu.Unlock()
	return r, e.save()
}

// Delete removes a rule.
func (e *Engine) Delete(id string) error {
	e.mu.Lock()
	out := e.rules[:0]
	found := false
	for _, r := range e.rules {
		if r.ID == id {
			found = true
			continue
		}
		out = append(out, r)
	}
	e.rules = out
	delete(e.rt, id)
	e.mu.Unlock()
	if !found {
		return ErrNotFound
	}
	return e.save()
}

// Reset restores the built-in rule set.
func (e *Engine) Reset() error {
	e.mu.Lock()
	e.rules = Defaults()
	e.rt = map[string]*ruleRT{}
	e.mu.Unlock()
	return e.save()
}

func (e *Engine) save() error {
	if e.file == "" {
		return nil
	}
	b, err := json.MarshalIndent(e.List(), "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(e.file), 0o700); err != nil {
		return err
	}
	tmp := e.file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, e.file)
}

// File returns the persistence path ("" = in-memory only).
func (e *Engine) File() string { return e.file }

func violates(op string, v, thr float64) bool {
	switch op {
	case OpGT:
		return v > thr
	case OpGE:
		return v >= thr
	case OpLT:
		return v < thr
	case OpLE:
		return v <= thr
	}
	return false
}

// cleared reports whether a firing instance may re-arm.
func cleared(op string, v, thr, hyst float64) bool {
	switch op {
	case OpGT, OpGE:
		return v < thr-hyst
	default:
		return v > thr+hyst
	}
}

// globNorm lower-cases and turns Windows path separators into '/', which
// path.Match would otherwise treat as escape characters (C:\ scopes).
func globNorm(s string) string { return strings.ReplaceAll(strings.ToLower(s), `\`, "/") }

// MatchScope reports whether an instance matches a rule scope glob
// (case-insensitive; "" matches everything).
func MatchScope(scope, instance string) bool {
	if scope == "" {
		return true
	}
	s, i := globNorm(scope), globNorm(instance)
	for _, alt := range strings.Split(s, ",") {
		alt = strings.TrimSpace(alt)
		if alt == "" {
			continue
		}
		if ok, _ := path.Match(alt, i); ok || alt == i {
			return true
		}
	}
	return false
}

// Evaluate applies all enabled rules for metric to the observations and
// returns newly firing and newly resolved instances.
func (e *Engine) Evaluate(metric string, obs []Obs) []Firing {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	cat, _ := CatalogByKey(metric)
	var out []Firing
	for _, r := range e.rules {
		if r.Metric != metric || !r.Enabled {
			continue
		}
		rt := e.rt[r.ID]
		if rt == nil {
			rt = &ruleRT{inst: map[string]*inst{}}
			e.rt[r.ID] = rt
		}
		rt.lastEval = now
		hyst := r.Hysteresis
		if hyst == 0 {
			hyst = cat.Hysteresis
		}
		var worst *float64
		seen := map[string]bool{}
		for _, o := range obs {
			if !MatchScope(r.Scope, o.Instance) {
				continue
			}
			v := o.Value
			if worst == nil || (r.Op == OpGT || r.Op == OpGE) && v > *worst || (r.Op == OpLT || r.Op == OpLE) && v < *worst {
				vv := v
				worst = &vv
			}
			seen[o.Instance] = true
			st := rt.inst[o.Instance]
			if st == nil {
				st = &inst{}
				rt.inst[o.Instance] = st
			}
			st.value, st.label, st.seen = v, o.Label, now
			if violates(r.Op, v, r.Threshold) {
				if st.since.IsZero() {
					st.since = now
				}
				if !st.firing && now.Sub(st.since) >= time.Duration(r.ForSec)*time.Second {
					st.firing = true
					rt.fired++
					out = append(out, Firing{Rule: r, Instance: o.Instance, Label: o.Label, Value: v, Since: st.since})
				}
				continue
			}
			st.since = time.Time{}
			if st.firing && cleared(r.Op, v, r.Threshold, hyst) {
				st.firing = false
				out = append(out, Firing{Rule: r, Instance: o.Instance, Label: o.Label, Value: v, Resolved: true})
			}
		}
		// Instances that disappeared (process exited, NIC removed) resolve.
		for k, st := range rt.inst {
			if seen[k] {
				continue
			}
			if st.firing {
				out = append(out, Firing{Rule: r, Instance: k, Label: st.label, Value: st.value, Resolved: true})
			}
			delete(rt.inst, k)
		}
		rt.last = worst
	}
	return out
}

// States returns runtime state for every rule (instances limited to the
// ten most relevant per rule).
func (e *Engine) States() []RuleState {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]RuleState, 0, len(e.rules))
	for _, r := range e.rules {
		st := RuleState{ID: r.ID}
		if rt := e.rt[r.ID]; rt != nil && r.Enabled {
			st.LastValue, st.Fired = rt.last, rt.fired
			if !rt.lastEval.IsZero() {
				st.LastEval = rt.lastEval.UnixMilli()
			}
			for k, in := range rt.inst {
				is := InstanceState{Instance: k, Label: in.label, Value: round2(in.value), Firing: in.firing}
				if !in.since.IsZero() {
					is.Since = in.since.UnixMilli()
				}
				switch {
				case in.firing:
					st.Firing++
				case !in.since.IsZero():
					st.Pending++
				default:
					continue
				}
				st.Instances = append(st.Instances, is)
			}
			sort.Slice(st.Instances, func(i, j int) bool {
				if st.Instances[i].Firing != st.Instances[j].Firing {
					return st.Instances[i].Firing
				}
				return st.Instances[i].Value > st.Instances[j].Value
			})
			if len(st.Instances) > 10 {
				st.Instances = st.Instances[:10]
			}
		}
		out = append(out, st)
	}
	return out
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
