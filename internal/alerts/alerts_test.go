package alerts

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

func TestRaiseFoldFilterAck(t *testing.T) {
	now := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	s := New(10, time.Minute)
	s.SetClock(func() time.Time { return now })
	var notified []bool
	s.OnChange(func(a model.Alert, isNew bool) { notified = append(notified, isNew) })

	a := s.Raise("k1", model.Alert{Severity: model.SevWarning, Category: model.AlertReliability, Title: model.T("Spooler crash", "انهيار")})
	now = now.Add(30 * time.Second)
	b := s.Raise("k1", model.Alert{Severity: model.SevCritical, Category: model.AlertReliability, Title: model.T("Spooler crash", "انهيار"), Detail: model.T("again", "مجددًا")})
	if a.ID != b.ID || b.Count != 2 || b.Severity != model.SevCritical || b.Detail.En != "again" {
		t.Fatalf("fold %+v", b)
	}
	now = now.Add(2 * time.Minute) // beyond fold window: new alert
	c := s.Raise("k1", model.Alert{Severity: model.SevInfo, Category: model.AlertReliability})
	if c.ID == a.ID || c.Count != 1 {
		t.Fatalf("no new alert after fold window %+v", c)
	}
	s.Raise("", model.Alert{Severity: model.SevCritical, Category: model.AlertNetworkSweep, Title: model.T("Sweep", "مسح"), Fields: map[string]string{"remoteIp": "192.168.1.66"}})
	if len(notified) != 4 || notified[1] {
		t.Fatalf("notifications %v", notified)
	}
	if got := s.List(Filter{Severity: "critical"}); len(got) != 2 {
		t.Fatalf("severity filter %d", len(got))
	}
	if got := s.List(Filter{Severity: "warning,info"}); len(got) != 1 {
		t.Fatalf("multi severity %d", len(got))
	}
	if got := s.List(Filter{Query: "192.168.1.66"}); len(got) != 1 || got[0].Category != model.AlertNetworkSweep {
		t.Fatalf("field search %+v", got)
	}
	if got := s.List(Filter{Query: "مسح"}); len(got) != 1 {
		t.Fatal("arabic search")
	}
	if got := s.List(Filter{Category: model.AlertReliability}); len(got) != 2 {
		t.Fatal("category")
	}
	if n := s.Ack([]string{a.ID}); n != 1 {
		t.Fatalf("ack %d", n)
	}
	if got := s.List(Filter{Unacked: true}); len(got) != 2 {
		t.Fatalf("unacked %d", len(got))
	}
	c2 := s.Counts()
	if c2.Total != 3 || c2.Unacked != 2 || c2.BySeverity[model.SevCritical] != 2 {
		t.Fatalf("counts %+v", c2)
	}
	if s.Ack(nil) != 2 || s.Counts().Unacked != 0 {
		t.Fatal("ack all")
	}
	u, ok := s.Update("k1", func(a *model.Alert) { a.Detail = model.T("enriched", "محدّث") })
	if !ok || u.Detail.En != "enriched" {
		t.Fatal("update")
	}
	if _, ok := s.Update("missing", func(*model.Alert) {}); ok {
		t.Fatal("update unknown key")
	}
	s.Clear()
	if s.Counts().Total != 0 {
		t.Fatal("clear")
	}
}

func TestBoundedAndConcurrent(t *testing.T) {
	s := New(50, time.Minute)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				s.Raise(strings.Repeat("k", g+1)+string(rune('a'+i%26)), model.Alert{Severity: model.SevInfo})
				s.List(Filter{Limit: 5})
			}
		}(g)
	}
	wg.Wait()
	if n := s.Counts().Total; n != 50 {
		t.Fatalf("store not bounded: %d", n)
	}
}

func TestExports(t *testing.T) {
	s := New(10, time.Minute)
	s.Raise("", model.Alert{Severity: model.SevCritical, Category: model.AlertNetworkSweep, Title: model.T("Sweep", "مسح اتصالات"),
		Detail: model.T("-cmd|' /C calc'!A0", "تفاصيل"), Fields: map[string]string{"remoteIp": "10.0.0.9", "mac": "AA-BB"}})
	list := s.List(Filter{})
	b, err := ExportCSV(list, "ar")
	if err != nil {
		t.Fatal(err)
	}
	csv := string(b)
	if !strings.HasPrefix(csv, "\ufeff") || !strings.Contains(csv, "الخطورة") || !strings.Contains(csv, "مسح اتصالات") ||
		!strings.Contains(csv, "'-cmd") || !strings.Contains(csv, "mac=AA-BB; remoteIp=10.0.0.9") {
		t.Fatalf("csv:\n%s", csv)
	}
	j, err := ExportJSON(Report{Generated: time.Now(), Host: "PC", Counts: s.Counts(), Alerts: list})
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(j, &back); err != nil || len(back.Alerts) != 1 || back.Alerts[0].Title.Ar != "مسح اتصالات" || back.Counts.Total != 1 {
		t.Fatalf("json %v %+v", err, back)
	}
}

func TestParseFilter(t *testing.T) {
	q := map[string]string{"severity": "critical", "category": "network-sweep", "q": "x", "unacked": "1", "since": "1700000000000", "limit": "5"}
	f := ParseFilter(func(k string) string { return q[k] })
	if f.Severity != "critical" || !f.Unacked || f.Limit != 5 || f.Since.UnixMilli() != 1700000000000 || f.Category != "network-sweep" {
		t.Fatalf("%+v", f)
	}
}
