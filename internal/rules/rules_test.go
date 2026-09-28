package rules

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

func TestSustainedHysteresisAndResolve(t *testing.T) {
	e := New("")
	clock := time.Unix(0, 0)
	e.SetClock(func() time.Time { return clock })
	step := func(v float64) []Firing {
		clock = clock.Add(time.Second)
		return e.Evaluate(MetricCPU, []Obs{{Value: v}})
	}
	for i := 0; i < 30; i++ {
		if f := step(95); len(f) != 0 {
			t.Fatalf("fired early at %d", i)
		}
	}
	f := step(95)
	if len(f) != 1 || f[0].Rule.ID != "cpu-sustained" || f[0].Resolved {
		t.Fatalf("expected firing, got %+v", f)
	}
	if st := findState(e, "cpu-sustained"); st.Firing != 1 {
		t.Fatalf("state %+v", st)
	}
	// Dropping to 83 is below 85 but within the 5-point hysteresis: no resolve.
	if f := step(83); len(f) != 0 {
		t.Fatalf("flapped %+v", f)
	}
	if f := step(70); len(f) != 1 || !f[0].Resolved {
		t.Fatalf("expected resolve %+v", f)
	}
	title, detail := Describe(f[0])
	if title.En == "" || detail.Ar == "" {
		t.Fatal("describe")
	}
}

func TestScopedInstancesAndCRUD(t *testing.T) {
	file := filepath.Join(t.TempDir(), "rules.json")
	e := New(file)
	r, err := e.Create(Rule{Name: "Chrome hog", Metric: MetricProcCPU, Op: OpGT, Threshold: 20, ForSec: 0, Scope: "chrome*", Severity: model.SevCritical, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	obs := []Obs{{Instance: "chrome.exe", Value: 40, Label: "chrome.exe (PID 1)"}, {Instance: "code.exe", Value: 90}}
	var mine []Firing
	for _, f := range e.Evaluate(MetricProcCPU, obs) {
		if f.Rule.ID == r.ID {
			mine = append(mine, f)
		}
	}
	if len(mine) != 1 || mine[0].Instance != "chrome.exe" {
		t.Fatalf("scoped firing %+v", mine)
	}
	// The process exits: its firing instance resolves.
	res := e.Evaluate(MetricProcCPU, nil)
	if len(res) != 1 || !res[0].Resolved {
		t.Fatalf("exit resolve %+v", res)
	}
	if _, err := e.Create(Rule{Metric: "bogus", Op: OpGT, Severity: model.SevInfo}); err == nil {
		t.Fatal("bogus metric accepted")
	}
	if _, err := e.Create(Rule{Metric: MetricCPU, Op: OpGT, Threshold: 150, Severity: model.SevInfo}); err == nil {
		t.Fatal("threshold out of range accepted")
	}
	if _, err := e.Create(Rule{Metric: MetricDisk, Op: OpGE, Threshold: 50, Scope: `D:\`, Severity: model.SevInfo}); err != nil {
		t.Fatal("disk scope rejected", err)
	}
	if _, err := e.Create(Rule{Metric: MetricCPU, Op: OpGT, Threshold: 50, Scope: "x", Severity: model.SevInfo}); err == nil {
		t.Fatal("scope on host metric accepted")
	}
	r.Threshold = 30
	if _, err := e.Update(r.ID, r); err != nil {
		t.Fatal(err)
	}
	// Reload from disk.
	e2 := New(file)
	got, ok := e2.Get(r.ID)
	if !ok || got.Threshold != 30 || got.Scope != "chrome*" {
		t.Fatalf("persisted %+v", got)
	}
	if err := e2.Delete(r.ID); err != nil {
		t.Fatal(err)
	}
	if err := e2.Delete(r.ID); err != ErrNotFound {
		t.Fatal("double delete")
	}
	if err := e2.Reset(); err != nil || len(e2.List()) != len(Defaults()) {
		t.Fatal("reset")
	}
}

func TestMatchScope(t *testing.T) {
	for _, c := range []struct {
		s, i string
		ok   bool
	}{{"", "x", true}, {`C:\`, `c:\`, true}, {"wi-fi,ethernet*", "Ethernet 2", true}, {"svchost.exe", "chrome.exe", false}} {
		if MatchScope(c.s, c.i) != c.ok {
			t.Fatalf("%+v", c)
		}
	}
}

func findState(e *Engine, id string) RuleState {
	for _, s := range e.States() {
		if s.ID == id {
			return s
		}
	}
	return RuleState{}
}
