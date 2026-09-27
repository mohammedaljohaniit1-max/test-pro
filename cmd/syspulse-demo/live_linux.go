//go:build linux

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/hub"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/linuxhost"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/netmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/netnames"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/procmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/radar"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/server"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/sysmon"
)

// liveStack wires genuine Linux host collectors: nothing is simulated and
// no traffic generator runs.
func liveStack(ctx context.Context, log *slog.Logger, addr string, selfTest, noResolve bool) (*hub.Hub, *server.Server, error) {
	pm := procmon.New(linuxhost.NewProcs(), 0)
	tracker := netmon.NewTracker(linuxhost.Sockets, pm.Resolve)
	sm := sysmon.New(linuxhost.NewSystem(), 300)
	var ev hub.EventSource
	if j := linuxhost.NewJournal(); j != nil {
		ev = j
	}
	h := hub.New(hub.Config{MetricsEvery: time.Second, NetEvery: time.Second, EventsEvery: 15 * time.Second,
		EventWindow: 7 * 24 * time.Hour, MaxEvents: 2000, Channels: []string{"System", "Application"},
		SelfTest: selfTest, NoResolve: noResolve, Resolver: netnames.New()}, log, sm, pm, tracker, ev)
	h.SetRadarPlatform(linuxhost.Neighbors{})
	h.SetGateways(linuxhost.Gateways())
	h.Radar().SetSensor(radar.SensorStatus{Name: radar.SensorTable, Active: true, Detail: "new inbound rows of /proc/net/tcp{,6} (accepted connections)"})
	h.Radar().SetSensor(radar.SensorStatus{Name: radar.SensorRaw, Detail: "raw SYN capture", Error: "available in the Windows build (SIO_RCVALL)"})
	srv := server.New(h, linuxhost.Software{}, log, addr)
	srv.Platform = "linux"
	return h, srv, nil
}
