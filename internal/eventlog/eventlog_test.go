package eventlog

import (
	"strings"
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

const sampleXML = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System><Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' EventSourceName='Service Control Manager'/>
<EventID Qualifiers='49152'>7031</EventID><Version>0</Version><Level>2</Level><Task>0</Task>
<TimeCreated SystemTime='2026-09-20T10:15:30.1234567Z'/><EventRecordID>98765</EventRecordID>
<Channel>System</Channel><Computer>WS-01</Computer></System>
<EventData><Data Name='param1'>Print Spooler</Data><Data Name='param2'>1</Data><Data Name='param3'></Data></EventData></Event>`

func TestParseXML(t *testing.T) {
	e, err := ParseXML(sampleXML, "")
	if err != nil {
		t.Fatal(err)
	}
	if e.EventID != 7031 || e.Level != 2 || e.LevelStr != "error" || e.RecordID != 98765 ||
		e.Channel != "System" || e.Computer != "WS-01" || e.Provider != "Service Control Manager" {
		t.Fatalf("%+v", e)
	}
	if e.Time != time.Date(2026, 9, 20, 10, 15, 30, 123456700, time.UTC) {
		t.Fatalf("time %v", e.Time)
	}
	if e.Category != model.CatServiceCrash {
		t.Fatalf("category %s", e.Category)
	}
	if e.Message != "param1=Print Spooler; param2=1" {
		t.Fatalf("fallback message %q", e.Message)
	}
	e, _ = ParseXML(sampleXML, "The Print Spooler service terminated\r\n unexpectedly.  ")
	if e.Message != "The Print Spooler service terminated unexpectedly." {
		t.Fatalf("formatted message %q", e.Message)
	}
	if _, err := ParseXML("<Event><broken", ""); err == nil {
		t.Fatal("bad xml accepted")
	}
	long, _ := ParseXML(sampleXML, strings.Repeat("é", 3000))
	if len(long.Message) > 2010 || !strings.HasSuffix(long.Message, "…") {
		t.Fatalf("truncation len=%d", len(long.Message))
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		p     string
		id    uint32
		level int
		want  string
	}{
		{"Service Control Manager", 7034, 2, model.CatServiceCrash},
		{"Application Error", 1000, 2, model.CatAppFault},
		{"Application Hang", 1002, 2, model.CatAppFault},
		{"Microsoft-Windows-Kernel-Power", 41, 1, model.CatUnexpectedShutdn},
		{"EventLog", 6008, 2, model.CatUnexpectedShutdn},
		{"Microsoft-Windows-Kernel-Power", 42, 4, model.CatPower},
		{"Microsoft-Windows-Kernel-PnP", 219, 3, model.CatDriver},
		{"Microsoft-Windows-Kernel-PnP", 400, 4, model.CatOther}, // info-level PnP noise
		{"Display", 4101, 3, model.CatDriver},
		{"disk", 153, 3, model.CatDisk},
		{"Ntfs", 55, 2, model.CatDisk},
		{"Microsoft-Windows-WindowsUpdateClient", 20, 2, model.CatUpdate},
		{"Some Vendor Driver", 12, 2, model.CatDriver},
		{"Service Control Manager", 7036, 4, model.CatOther},
		{"Unrelated", 1, 4, model.CatOther},
	}
	for _, c := range cases {
		if got := Classify(c.p, c.id, c.level); got != c.want {
			t.Errorf("Classify(%q,%d,%d)=%s want %s", c.p, c.id, c.level, got, c.want)
		}
	}
}

func TestSummarize(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	evs := []model.Event{
		{Time: from.Add(30 * time.Minute), Level: 2, LevelStr: "error", Category: model.CatAppFault, Provider: "Application Error"},
		{Time: from.Add(40 * time.Minute), Level: 2, LevelStr: "error", Category: model.CatAppFault, Provider: "Application Error"},
		{Time: from.Add(5 * time.Hour), Level: 3, LevelStr: "warning", Category: model.CatDisk, Provider: "disk"},
		{Time: from.Add(23*time.Hour + 59*time.Minute), Level: 1, LevelStr: "critical", Category: model.CatUnexpectedShutdn, Provider: "Kernel-Power"},
		{Time: from.Add(12 * time.Hour), Level: 4, LevelStr: "info", Category: model.CatOther, Provider: "x"},
		{Time: to.Add(time.Hour), Level: 2, LevelStr: "error", Category: model.CatOther, Provider: "future"},
	}
	s := Summarize(evs, from, to, 24)
	if s.Total != 6 || s.ByLevel["error"] != 3 || s.ByCategory[model.CatAppFault] != 2 || s.ByCategory[model.CatOther] != 0 {
		t.Fatalf("%+v", s)
	}
	if len(s.Timeline) != 24 || s.Timeline[0].Error != 2 || s.Timeline[5].Warning != 1 ||
		s.Timeline[23].Critical != 1 || s.Timeline[12].Info != 1 {
		t.Fatalf("timeline %+v", s.Timeline)
	}
	if s.TopSources[0].Name != "Application Error" || s.TopSources[0].Count != 2 {
		t.Fatalf("top %+v", s.TopSources)
	}
	SortNewestFirst(evs)
	if !evs[0].Time.After(evs[1].Time) {
		t.Fatal("sort")
	}
}
