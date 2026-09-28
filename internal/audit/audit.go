// Package audit implements the one-click event-log diagnostics:
//
//   - Authentication & Access audit (Security log): repeated failed logons
//     (4625, with lockouts 4740) and administrative privilege assignments
//     (4672 — "special privileges assigned to new logon").
//   - System Reliability & Faults audit (System + Application logs):
//     service crashes (7034 / 7031), application faults (1000, hangs 1002),
//     bugchecks (WER-SystemErrorReporting 1001, Kernel-Power 41 with a stop
//     code) and unexpected shutdowns (6008 / Kernel-Power 41).
//
// Every finding carries a bilingual (English / Arabic) plain-language
// diagnosis and a recommended fix. Analysis is platform-independent and
// unit-tested; the Windows event reader supplies the events.
package audit

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/eventlog"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// Source runs an XPath query against one channel (eventlog.Reader on Windows).
type Source interface {
	QueryXPath(channel, xpath string, max int, format bool) ([]model.Event, error)
}

// Kinds of audit.
const (
	KindAuth        = "auth"
	KindReliability = "reliability"
)

// Finding kinds.
const (
	FFailedLogon     = "failed-logon"
	FPasswordSpray   = "password-spray"
	FLockout         = "account-lockout"
	FPrivilegedLogon = "privileged-logon"
	FServiceCrash    = "service-crash"
	FAppFault        = "app-fault"
	FAppHang         = "app-hang"
	FBugcheck        = "bugcheck"
	FUnexpectedShut  = "unexpected-shutdown"
)

// Options bound an audit run.
type Options struct {
	Window    time.Duration // how far back to read (default 7 days)
	MaxEvents int           // per channel (default 20000)
}

func (o *Options) defaults() {
	if o.Window <= 0 {
		o.Window = 7 * 24 * time.Hour
	}
	if o.MaxEvents <= 0 {
		o.MaxEvents = 20000
	}
}

// Run executes one audit kind against src.
func Run(ctx context.Context, src Source, kind string, opt Options, now time.Time) (model.AuditReport, error) {
	opt.defaults()
	rep := model.AuditReport{Kind: kind, Started: now, WindowH: int(opt.Window / time.Hour)}
	type q struct {
		channel string
		ids     []uint32
	}
	var qs []q
	switch kind {
	case KindAuth:
		qs = []q{{"Security", []uint32{4625, 4740, 4672}}}
	case KindReliability:
		qs = []q{{"System", []uint32{7031, 7034, 1001, 41, 6008}}, {"Application", []uint32{1000, 1002}}}
	default:
		return rep, fmt.Errorf("unknown audit kind %q", kind)
	}
	var evs []model.Event
	for _, x := range qs {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		got, err := src.QueryXPath(x.channel, eventlog.AuditXPath(x.ids, opt.Window), opt.MaxEvents, false)
		if err != nil {
			rep.Errors = append(rep.Errors, err.Error())
		}
		evs = append(evs, got...)
	}
	switch kind {
	case KindAuth:
		rep = AnalyzeAuth(evs, rep)
		if len(rep.Errors) > 0 {
			rep.Notes = append(rep.Notes, model.T(
				"The Security log can only be read by an elevated process. Restart SysPulse with \"Run as administrator\" and run the audit again.",
				"لا يمكن قراءة سجل الأمان إلا بصلاحيات المسؤول. أعد تشغيل SysPulse باستخدام «تشغيل كمسؤول» ثم أعد تنفيذ التدقيق."))
		}
	case KindReliability:
		rep = AnalyzeReliability(evs, rep)
	}
	rep.Finished = time.Now()
	if rep.Finished.Before(rep.Started) {
		rep.Finished = rep.Started
	}
	return rep, nil
}

func finalize(rep model.AuditReport, findings []model.Finding, evs []model.Event) model.AuditReport {
	rep.Scanned = len(evs)
	rep.ByEventID = map[string]int{}
	for _, e := range evs {
		rep.ByEventID[strconv.Itoa(int(e.EventID))]++
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if ra, rb := model.SeverityRank(a.Severity), model.SeverityRank(b.Severity); ra != rb {
			return ra < rb
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.Last.After(b.Last)
	})
	rep.BySev = map[string]int{model.SevCritical: 0, model.SevWarning: 0, model.SevInfo: 0}
	for i := range findings {
		findings[i].ID = fmt.Sprintf("%s-%03d", strings.ToUpper(rep.Kind[:3]), i+1)
		rep.BySev[findings[i].Severity]++
	}
	if findings == nil {
		findings = []model.Finding{}
	}
	rep.Findings = findings
	return rep
}

// field returns the first non-empty EventData value among names.
func field(e model.Event, names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(e.Data[n]); v != "" && v != "-" {
			return v
		}
	}
	return ""
}

type group struct {
	f     model.Finding
	times []time.Time
	set   map[string]map[string]bool
}

func (g *group) add(e model.Event, sample string) {
	g.f.Count++
	if g.f.First.IsZero() || e.Time.Before(g.f.First) {
		g.f.First = e.Time
	}
	if e.Time.After(g.f.Last) {
		g.f.Last = e.Time
	}
	found := false
	for _, id := range g.f.EventIDs {
		if id == e.EventID {
			found = true
		}
	}
	if !found {
		g.f.EventIDs = append(g.f.EventIDs, e.EventID)
		sort.Slice(g.f.EventIDs, func(i, j int) bool { return g.f.EventIDs[i] < g.f.EventIDs[j] })
	}
	g.times = append(g.times, e.Time)
	if sample != "" && len(g.f.Samples) < 5 {
		g.f.Samples = append(g.f.Samples, e.Time.UTC().Format("2006-01-02 15:04:05Z")+" — "+sample)
	}
}

func (g *group) note(key, val string) {
	if val == "" {
		return
	}
	if g.set == nil {
		g.set = map[string]map[string]bool{}
	}
	if g.set[key] == nil {
		g.set[key] = map[string]bool{}
	}
	g.set[key][val] = true
}

func (g *group) values(key string) []string {
	var out []string
	for v := range g.set[key] {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func (g *group) detail(key string, vals []string) {
	if len(vals) == 0 {
		return
	}
	if g.f.Details == nil {
		g.f.Details = map[string]string{}
	}
	if len(vals) > 8 {
		vals = append(vals[:8:8], fmt.Sprintf("+%d more", len(vals)-8))
	}
	g.f.Details[key] = strings.Join(vals, ", ")
}

// maxBurst returns the largest number of events inside any span of d.
func maxBurst(ts []time.Time, d time.Duration) int {
	s := append([]time.Time(nil), ts...)
	sort.Slice(s, func(i, j int) bool { return s[i].Before(s[j]) })
	best, j := 0, 0
	for i := range s {
		for s[i].Sub(s[j]) > d {
			j++
		}
		if n := i - j + 1; n > best {
			best = n
		}
	}
	return best
}

func sortedKeys[M ~map[string]V, V any](m M) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
