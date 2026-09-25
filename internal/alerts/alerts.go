// Package alerts keeps the Alerts & Incidents stream: a bounded, de-duplicated
// list of bilingual alerts with severity badges (critical / warning /
// informational), filtering, acknowledgement and CSV / JSON export.
//
// Producers (the network radar, the event-log collector, the diagnostic
// audits and resource monitors) call Raise with a dedup key; repeated
// occurrences of the same key inside the fold window increment Count on the
// existing alert instead of flooding the list.
package alerts

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// Store is safe for concurrent use.
type Store struct {
	mu     sync.Mutex
	max    int
	fold   time.Duration
	seq    int
	list   []*model.Alert // newest first
	byKey  map[string]*model.Alert
	keyOf  map[string]string
	now    func() time.Time
	notify func(model.Alert, bool)
}

// New creates a store keeping at most max alerts. Alerts with the same key
// raised within fold of the previous occurrence are merged.
func New(max int, fold time.Duration) *Store {
	if max <= 0 {
		max = 2000
	}
	if fold <= 0 {
		fold = 10 * time.Minute
	}
	return &Store{max: max, fold: fold, byKey: map[string]*model.Alert{}, keyOf: map[string]string{}, now: time.Now}
}

// SetClock overrides the time source (tests).
func (s *Store) SetClock(now func() time.Time) { s.mu.Lock(); s.now = now; s.mu.Unlock() }

// OnChange registers a callback invoked (outside the lock) after every
// raise; isNew is false when an existing alert was folded.
func (s *Store) OnChange(fn func(a model.Alert, isNew bool)) {
	s.mu.Lock()
	s.notify = fn
	s.mu.Unlock()
}

// Raise records an alert. key de-duplicates (empty = never merge). When a
// is merged, Detail/Fields/Severity are refreshed from the new occurrence
// and Count grows by max(1, a.Count).
func (s *Store) Raise(key string, a model.Alert) model.Alert {
	s.mu.Lock()
	now := s.now()
	if a.Time.IsZero() {
		a.Time = now
	}
	inc := a.Count
	if inc <= 0 {
		inc = 1
	}
	if key != "" {
		if ex, ok := s.byKey[key]; ok && a.Time.Sub(ex.Updated) <= s.fold {
			ex.Count += inc
			ex.Updated = a.Time
			ex.Detail = a.Detail
			if a.Title.En != "" {
				ex.Title = a.Title
			}
			if model.SeverityRank(a.Severity) < model.SeverityRank(ex.Severity) {
				ex.Severity = a.Severity
			}
			if a.Fields != nil {
				ex.Fields = a.Fields
			}
			ex.Acked = false
			out := *ex
			fn := s.notify
			s.mu.Unlock()
			if fn != nil {
				fn(out, false)
			}
			return out
		}
	}
	s.seq++
	a.ID = "ALR-" + strconv.FormatInt(now.UnixMilli()%1e9, 36) + "-" + strconv.Itoa(s.seq)
	a.Count = inc
	a.Updated = a.Time
	if a.Severity == "" {
		a.Severity = model.SevInfo
	}
	p := &a
	s.list = append([]*model.Alert{p}, s.list...)
	if key != "" {
		if old, ok := s.byKey[key]; ok {
			delete(s.keyOf, old.ID)
		}
		s.byKey[key] = p
		s.keyOf[p.ID] = key
	}
	if len(s.list) > s.max {
		for _, drop := range s.list[s.max:] {
			if k, ok := s.keyOf[drop.ID]; ok {
				if s.byKey[k] == drop {
					delete(s.byKey, k)
				}
				delete(s.keyOf, drop.ID)
			}
		}
		s.list = s.list[:s.max]
	}
	out := *p
	fn := s.notify
	s.mu.Unlock()
	if fn != nil {
		fn(out, true)
	}
	return out
}

// Update replaces fields of an existing alert by dedup key (used when
// asynchronous enrichment such as MAC attribution completes). It returns
// false when the key is unknown.
func (s *Store) Update(key string, fn func(*model.Alert)) (model.Alert, bool) {
	s.mu.Lock()
	ex, ok := s.byKey[key]
	if !ok {
		s.mu.Unlock()
		return model.Alert{}, false
	}
	fn(ex)
	out := *ex
	cb := s.notify
	s.mu.Unlock()
	if cb != nil {
		cb(out, false)
	}
	return out, true
}

// Ack marks alerts as acknowledged; ids empty = all. Returns the number changed.
func (s *Store) Ack(ids []string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	n := 0
	for _, a := range s.list {
		if (len(ids) == 0 || want[a.ID]) && !a.Acked {
			a.Acked = true
			n++
		}
	}
	return n
}

// Clear removes all alerts.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list = nil
	s.byKey = map[string]*model.Alert{}
	s.keyOf = map[string]string{}
}

// Filter selects alerts. Zero values match everything.
type Filter struct {
	Severity string // critical, warning, info (comma-separated allowed)
	Category string
	Query    string // case-insensitive substring over titles, details and fields
	Since    time.Time
	Unacked  bool
	Limit    int
}

// ParseFilter reads a Filter from URL-style parameters.
func ParseFilter(get func(string) string) Filter {
	f := Filter{Severity: get("severity"), Category: get("category"), Query: get("q"), Unacked: get("unacked") == "1" || get("unacked") == "true"}
	if v := get("since"); v != "" {
		if ms, err := strconv.ParseInt(v, 10, 64); err == nil {
			f.Since = time.UnixMilli(ms)
		} else if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = t
		}
	}
	if v := get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			f.Limit = n
		}
	}
	return f
}

func (f Filter) match(a *model.Alert) bool {
	if f.Severity != "" {
		ok := false
		for _, s := range strings.Split(f.Severity, ",") {
			if strings.TrimSpace(s) == a.Severity {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if f.Category != "" && a.Category != f.Category {
		return false
	}
	if f.Unacked && a.Acked {
		return false
	}
	if !f.Since.IsZero() && a.Updated.Before(f.Since) {
		return false
	}
	if q := strings.ToLower(strings.TrimSpace(f.Query)); q != "" {
		var b strings.Builder
		b.WriteString(a.Title.En + " " + a.Title.Ar + " " + a.Detail.En + " " + a.Detail.Ar + " " + a.Source + " " + a.Category)
		for k, v := range a.Fields {
			b.WriteString(" " + k + " " + v)
		}
		if !strings.Contains(strings.ToLower(b.String()), q) {
			return false
		}
	}
	return true
}

// List returns matching alerts, newest (by last update) first.
func (s *Store) List(f Filter) []model.Alert {
	s.mu.Lock()
	out := make([]model.Alert, 0, len(s.list))
	for _, a := range s.list {
		if f.match(a) {
			c := *a
			if a.Fields != nil {
				c.Fields = make(map[string]string, len(a.Fields))
				for k, v := range a.Fields {
					c.Fields[k] = v
				}
			}
			out = append(out, c)
		}
	}
	s.mu.Unlock()
	sort.SliceStable(out, func(i, j int) bool { return out[i].Updated.After(out[j].Updated) })
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out
}

// Counts summarises alerts by severity and category.
type Counts struct {
	Total      int            `json:"total"`
	Unacked    int            `json:"unacked"`
	BySeverity map[string]int `json:"bySeverity"`
	ByCategory map[string]int `json:"byCategory"`
	Last24h    int            `json:"last24h"`
}

// Counts returns the summary.
func (s *Store) Counts() Counts {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := Counts{BySeverity: map[string]int{model.SevCritical: 0, model.SevWarning: 0, model.SevInfo: 0}, ByCategory: map[string]int{}}
	day := s.now().Add(-24 * time.Hour)
	for _, a := range s.list {
		c.Total++
		c.BySeverity[a.Severity]++
		c.ByCategory[a.Category]++
		if !a.Acked {
			c.Unacked++
		}
		if a.Updated.After(day) {
			c.Last24h++
		}
	}
	return c
}

// Report is the JSON export envelope.
type Report struct {
	Generated time.Time     `json:"generated"`
	Host      string        `json:"host,omitempty"`
	Version   string        `json:"version,omitempty"`
	Filter    Filter        `json:"filter"`
	Counts    Counts        `json:"counts"`
	Alerts    []model.Alert `json:"alerts"`
}

// ExportJSON renders a pretty-printed JSON report.
func ExportJSON(r Report) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ExportCSV renders alerts as RFC 4180 CSV with a UTF-8 BOM (so Excel shows
// Arabic text correctly). Both languages are included; lang selects which
// language the header row uses ("ar" or English).
func ExportCSV(alerts []model.Alert, lang string) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("\ufeff")
	w := csv.NewWriter(&buf)
	hdr := []string{"id", "time_first", "time_last", "severity", "category", "source", "count", "acknowledged",
		"title_en", "title_ar", "detail_en", "detail_ar", "fields"}
	if lang == "ar" {
		hdr = []string{"المعرف", "أول ظهور", "آخر ظهور", "الخطورة", "الفئة", "المصدر", "التكرار", "تمت المراجعة",
			"العنوان (EN)", "العنوان (AR)", "التفاصيل (EN)", "التفاصيل (AR)", "الحقول"}
	}
	if err := w.Write(hdr); err != nil {
		return nil, err
	}
	for _, a := range alerts {
		keys := make([]string, 0, len(a.Fields))
		for k := range a.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fs := make([]string, len(keys))
		for i, k := range keys {
			fs[i] = k + "=" + a.Fields[k]
		}
		rec := []string{a.ID, a.Time.UTC().Format(time.RFC3339), a.Updated.UTC().Format(time.RFC3339), a.Severity, a.Category,
			a.Source, strconv.Itoa(a.Count), strconv.FormatBool(a.Acked), sanitize(a.Title.En), sanitize(a.Title.Ar),
			sanitize(a.Detail.En), sanitize(a.Detail.Ar), sanitize(strings.Join(fs, "; "))}
		if err := w.Write(rec); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// sanitize neutralises spreadsheet formula injection (CWE-1236): cells that
// start with = + - @ or a control character are prefixed with a quote.
func sanitize(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
