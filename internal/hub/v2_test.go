package hub

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/netmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/procmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/radar"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/sysmon"
)

type fakeRadarPlat struct{}

func (fakeRadarPlat) Neighbors() ([]radar.Neighbor, error) {
	return []radar.Neighbor{{IP: "192.168.1.66", MAC: "00-0C-29-7D-E4-A0", IfIndex: 12, Interface: "Ethernet"}}, nil
}
func (fakeRadarPlat) Resolve(ip string) (radar.Neighbor, bool, error) {
	return radar.Neighbor{IP: ip, MAC: "00-0C-29-7D-E4-A0", Interface: "Ethernet"}, true, nil
}

func TestBlockedObservation5157(t *testing.T) {
	base := model.Event{Channel: "Security", Provider: "Microsoft-Windows-Security-Auditing", EventID: 5157,
		Time: time.Unix(1700000000, 0), Data: map[string]string{
			"Direction": "%%14592", "Protocol": "6", "SourceAddress": "192.168.1.42", "SourcePort": "8443",
			"DestAddress": "192.168.1.66", "DestPort": "50000",
		}}
	local := []string{"192.168.1.42"}
	obs, ok := BlockedObservation(base, local)
	if !ok || obs.RemoteIP != "192.168.1.66" || obs.LocalPort != 8443 || obs.RemotePort != 50000 || obs.Sensor != "wfp-5157" {
		t.Fatalf("incorrect WFP observation: %+v %v", obs, ok)
	}
	base.Data["SourceAddress"], base.Data["DestAddress"] = base.Data["DestAddress"], base.Data["SourceAddress"]
	base.Data["SourcePort"], base.Data["DestPort"] = base.Data["DestPort"], base.Data["SourcePort"]
	obs, ok = BlockedObservation(base, local)
	if !ok || obs.RemoteIP != "192.168.1.66" || obs.LocalPort != 8443 {
		t.Fatalf("reversed WFP endpoints: %+v %v", obs, ok)
	}
	for _, change := range []func(*model.Event){
		func(e *model.Event) { e.Data["Direction"] = "%%14593" },
		func(e *model.Event) { e.Data["Protocol"] = "17" },
		func(e *model.Event) { e.Data["DestAddress"] = "8.8.8.8" },
		func(e *model.Event) { e.EventID = 5156 },
	} {
		copy := base
		copy.Data = make(map[string]string, len(base.Data))
		for k, v := range base.Data {
			copy.Data[k] = v
		}
		change(&copy)
		if _, ok := BlockedObservation(copy, local); ok {
			t.Fatalf("false positive: %+v", copy)
		}
	}
}

// A remote host opening accepted connections to 15 listening ports shows up
// as new TCP-table rows; the hub must turn that into a sweep incident with
// MAC attribution from the ARP table and a critical alert.
func TestTableSensorDetectsSweep(t *testing.T) {
	var mu sync.Mutex
	conns := []model.Connection{}
	for p := uint16(1000); p < 1015; p++ {
		conns = append(conns, model.Connection{Proto: "TCP", LocalAddr: "0.0.0.0", LocalPort: p, State: "LISTEN", PID: 10})
	}
	src := func() ([]model.Connection, error) {
		mu.Lock()
		defer mu.Unlock()
		return append([]model.Connection(nil), conns...), nil
	}
	pm := procmon.New(fakeProcs{}, 1)
	h := New(Config{MetricsEvery: time.Hour, NetEvery: 20 * time.Millisecond, Channels: []string{"System"}},
		slog.New(slog.NewTextHandler(io.Discard, nil)), sysmon.New(fakePlat{}, 5), pm, netmon.NewTracker(src, pm.Resolve), nil)
	h.SetRadarPlatform(fakeRadarPlat{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	time.Sleep(80 * time.Millisecond) // baseline poll + ARP refresh
	mu.Lock()
	for p := uint16(1000); p < 1015; p++ {
		conns = append(conns, model.Connection{Proto: "TCP", LocalAddr: "192.168.1.42", LocalPort: p, RemoteAddr: "192.168.1.66", RemotePort: 50000 + p, State: "ESTABLISHED", PID: 10})
	}
	mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for len(h.Radar().Incidents()) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("no incident; radar %+v", h.Radar().Snapshot(5))
		}
		time.Sleep(10 * time.Millisecond)
	}
	inc := h.Radar().Incidents()[0]
	if inc.RemoteIP != "192.168.1.66" || inc.DistinctPorts != 15 || inc.MAC != "00-0C-29-7D-E4-A0" || inc.Sensor != radar.SensorTable || inc.PortRange != "1000-1014" {
		t.Fatalf("incident %+v", inc)
	}
	if c := h.Alerts().Counts(); c.ByCategory[model.AlertNetworkSweep] != 1 || c.BySeverity[model.SevCritical] != 1 {
		t.Fatalf("alerts %+v", c)
	}
}

func TestResourceRulesReplaceHardcodedAlerts(t *testing.T) {
	h, _ := newHub(t)
	clock := time.Unix(1_700_000_000, 0)
	h.Rules().SetClock(func() time.Time { return clock })
	m := model.SystemMetrics{Disks: []model.DiskUsage{{Mount: `C:\`, Percent: 95}}}
	h.evalHostRules(m, nil)
	h.evalHostRules(m, nil)
	if n := h.Alerts().Counts().ByCategory[model.AlertResource]; n != 1 {
		t.Fatalf("disk alerts %d", n)
	}
	for i := 0; i < 30; i++ {
		clock = clock.Add(time.Second)
		h.evalHostRules(model.SystemMetrics{CPUPercent: 99}, nil)
	}
	if n := h.Alerts().Counts().ByCategory[model.AlertResource]; n != 1 {
		t.Fatal("CPU alert raised before the rule duration elapsed")
	}
	clock = clock.Add(time.Second)
	h.evalHostRules(model.SystemMetrics{CPUPercent: 99}, nil)
	if n := h.Alerts().Counts().ByCategory[model.AlertResource]; n != 2 {
		t.Fatalf("CPU alert missing: %d", n)
	}
	if hl := h.Health(); hl.Score >= 100 || len(hl.Factors) == 0 {
		t.Fatalf("health %+v", hl)
	}
}
