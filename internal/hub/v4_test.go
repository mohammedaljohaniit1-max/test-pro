package hub

import (
	"testing"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/ifstats"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/services"
)

func TestBuildTree(t *testing.T) {
	ps := []model.Process{
		{PID: 4, PPID: 0, Name: "System"},
		{PID: 700, PPID: 600, Name: "services.exe", StartedMs: 10},
		{PID: 1200, PPID: 700, Name: "svchost.exe", CPUPercent: 2, WorkingSet: 100, StartedMs: 20},
		{PID: 5000, PPID: 4400, Name: "chrome.exe", CPUPercent: 5, WorkingSet: 500, StartedMs: 30},
		{PID: 5100, PPID: 5000, Name: "chrome.exe", CPUPercent: 10, WorkingSet: 300, StartedMs: 31},
		{PID: 5200, PPID: 5000, Name: "chrome.exe", CPUPercent: 1, WorkingSet: 200, StartedMs: 32},
		// PID reuse: parent 5200 started after this process, so it is a root.
		{PID: 9000, PPID: 5200, Name: "old.exe", StartedMs: 1},
	}
	roots := BuildTree(ps, map[uint32][]string{1200: {"Dnscache", "Dhcp"}})
	if len(roots) != 4 {
		t.Fatalf("roots %d", len(roots))
	}
	ch := roots[0]
	if ch.PID != 5000 || ch.Descendants != 2 || ch.SubCPU != 16 || ch.SubWS != 1000 || ch.Children[0].PID != 5100 || ch.Children[0].Depth != 1 {
		t.Fatalf("chrome subtree %+v", ch)
	}
	var svc *model.ProcNode
	for _, r := range roots {
		if r.PID == 700 {
			svc = r.Children[0]
		}
	}
	if svc == nil || svc.Services[0] != "Dhcp" {
		t.Fatalf("svchost services %+v", svc)
	}
}

func TestInterfacesServicesSnapshot(t *testing.T) {
	h, _ := newHub(t)
	h.SetInterfaceReader(ifstats.ReaderFunc(func() ([]ifstats.Counter, error) {
		return []ifstats.Counter{{Index: 3, Name: "Ethernet", Kind: model.IfEthernet, Physical: true, Up: true, SpeedBps: 1e9, InOctets: 5}}, nil
	}))
	h.SetServiceLister(services.ListerFunc(func() ([]model.Service, error) {
		return []model.Service{{Name: "Spooler", Display: "Print Spooler", State: model.SvcStopped, StartType: model.StartAuto, ExitCode: 1067}}, nil
	}))
	h.collectInterfaces()
	h.collectServices()
	s := h.Snapshot()
	if !s.Interfaces.Available || len(s.Interfaces.Interfaces) != 1 || s.Services.Summary.AutoFailed != 1 || len(s.Rules.Rules) == 0 || len(s.Rules.Catalog) == 0 {
		t.Fatalf("snapshot v4 %+v %+v", s.Interfaces, s.Services)
	}
}
