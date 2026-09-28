package services

import (
	"testing"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

func TestRefreshSummaryAndChanges(t *testing.T) {
	state := model.SvcRunning
	m := New(ListerFunc(func() ([]model.Service, error) {
		return []model.Service{
			{Name: "Spooler", Display: "Print Spooler", State: state, StartType: model.StartAuto, PID: 900, ExitCode: 1067},
			{Name: "edgeupdate", Display: "Microsoft Edge Update", State: model.SvcStopped, StartType: model.StartDelayed, ExitCode: 0},
			{Name: "sppsvc", Display: "Software Protection", State: model.SvcStopped, StartType: model.StartDelayed, ExitCode: 1077},
			{Name: "Dnscache", Display: "DNS Client", State: model.SvcRunning, StartType: model.StartAuto, PID: 1200},
			{Name: "Dhcp", Display: "DHCP Client", State: model.SvcRunning, StartType: model.StartAuto, PID: 1200},
			{Name: "Fax", Display: "Fax", State: model.SvcStopped, StartType: model.StartDisabled},
		}, nil
	}))
	if ch, _ := m.Refresh(); len(ch) != 0 {
		t.Fatal("first refresh must not report changes")
	}
	state = model.SvcStopped
	ch, _ := m.Refresh()
	if len(ch) != 1 || ch[0].Service.Name != "Spooler" || ch[0].From != model.SvcRunning || ch[0].To != model.SvcStopped {
		t.Fatalf("changes %+v", ch)
	}
	s := m.Summary()
	if s.Total != 6 || s.Running != 2 || s.Stopped != 4 || s.AutoStopped != 3 || s.AutoFailed != 1 || s.Disabled != 1 {
		t.Fatalf("summary %+v", s)
	}
	if l := m.List(); l[0].Display != "DHCP Client" {
		t.Fatalf("sort %v", l[0])
	}
	if bp := m.ByPID()[1200]; len(bp) != 2 {
		t.Fatalf("by pid %v", bp)
	}
}
