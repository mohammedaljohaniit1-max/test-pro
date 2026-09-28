// Package hub runs the periodic collectors and fans telemetry out to
// WebSocket subscribers.
//
// Collectors run on independent tickers so a slow one (e.g. event log
// formatting) never delays the 1 s system/network cadence. Each subscriber
// has a bounded send queue; a subscriber that cannot keep up is dropped
// rather than slowing the others.
package hub

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/eventlog"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/netmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/procmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/sysmon"
)

// EventSource abstracts the event log reader (Windows) for tests.
type EventSource interface {
	Query(channel string, since time.Time, max int, maxLevel int, afterRecord uint64) ([]model.Event, error)
}

// Config controls collector cadence and retention.
type Config struct {
	MetricsEvery time.Duration // system + processes
	NetEvery     time.Duration
	EventsEvery  time.Duration
	EventWindow  time.Duration // how far back the initial event query goes
	MaxEvents    int
	Channels     []string

	// SysPulse 2.0: connection-sweep radar and alerts.
	RadarWindow    time.Duration // default 5 s
	RadarThreshold int           // flag when distinct ports > threshold (default 10)
	RadarCooldown  time.Duration // default 60 s
	RadarAllow     []string      // remote IPs never flagged
	AlertsMax      int           // default 2000

	// SysPulse 3.0.
	SelfTest    bool     // allow the synthetic radar self-test (off in live mode)
	ClientProcs []string // extra outbound-only process names ignored by the table sensor
	NoResolve   bool     // disable NetBIOS / mDNS / DNS name resolution of LAN devices
	Resolver    NameResolver

	// SysPulse 4.0.
	ServicesEvery time.Duration // service enumeration cadence (default 5 s)
	RulesFile     string        // JSON persistence of alert rules ("" = in-memory)
}

func (c *Config) defaults() {
	if c.MetricsEvery <= 0 {
		c.MetricsEvery = time.Second
	}
	if c.NetEvery <= 0 {
		c.NetEvery = time.Second
	}
	if c.EventsEvery <= 0 {
		c.EventsEvery = 15 * time.Second
	}
	if c.EventWindow <= 0 {
		c.EventWindow = 7 * 24 * time.Hour
	}
	if c.MaxEvents <= 0 {
		c.MaxEvents = 2000
	}
	if c.ServicesEvery <= 0 {
		c.ServicesEvery = 5 * time.Second
	}
	if len(c.Channels) == 0 {
		c.Channels = []string{"System", "Application"}
	}
}

// Hub owns collectors and subscribers.
type Hub struct {
	cfg    Config
	log    *slog.Logger
	sys    *sysmon.Monitor
	procs  *procmon.Monitor
	net    *netmon.Tracker
	events EventSource

	mu      sync.RWMutex
	subs    map[*Subscriber]struct{}
	evMu    sync.RWMutex
	evs     []model.Event
	lastRec map[string]uint64
	evErr   string
	netMu   sync.Mutex
	netErr  string
	dropped atomic.Uint64
	now     func() time.Time
	v2
	v4
}

// Subscriber is one connected dashboard.
type Subscriber struct {
	C    chan []byte
	done chan struct{}
	once sync.Once
}

// New wires a hub. events may be nil (event log unavailable).
func New(cfg Config, log *slog.Logger, sys *sysmon.Monitor, procs *procmon.Monitor, net *netmon.Tracker, events EventSource) *Hub {
	cfg.defaults()
	h := &Hub{cfg: cfg, log: log, sys: sys, procs: procs, net: net, events: events,
		subs: map[*Subscriber]struct{}{}, lastRec: map[string]uint64{}, now: time.Now}
	h.initV2()
	h.initV4()
	return h
}

// Subscribe registers a subscriber with a bounded queue.
func (h *Hub) Subscribe() *Subscriber {
	s := &Subscriber{C: make(chan []byte, 64), done: make(chan struct{})}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s
}

// Unsubscribe removes a subscriber (idempotent).
func (h *Hub) Unsubscribe(s *Subscriber) {
	h.mu.Lock()
	delete(h.subs, s)
	h.mu.Unlock()
	s.once.Do(func() { close(s.done) })
}

// Done is closed when the subscriber was removed (e.g. for being too slow).
func (s *Subscriber) Done() <-chan struct{} { return s.done }

// Subscribers returns the number of connected dashboards.
func (h *Hub) Subscribers() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs)
}

// Dropped returns the number of subscribers evicted for being slow.
func (h *Hub) Dropped() uint64 { return h.dropped.Load() }

// Broadcast encodes msg once and queues it for every subscriber.
func (h *Hub) Broadcast(typ string, data any) {
	b, err := json.Marshal(model.Message{Type: typ, Data: data})
	if err != nil {
		h.log.Error("broadcast encode", "type", typ, "err", err)
		return
	}
	h.mu.RLock()
	var slow []*Subscriber
	for s := range h.subs {
		select {
		case s.C <- b:
		default:
			slow = append(slow, s)
		}
	}
	h.mu.RUnlock()
	for _, s := range slow {
		h.dropped.Add(1)
		h.Unsubscribe(s)
	}
}

// Encode renders a message (used for the initial snapshot sent to one client).
func Encode(typ string, data any) []byte {
	b, _ := json.Marshal(model.Message{Type: typ, Data: data})
	return b
}

// Run starts all collectors and blocks until ctx is done.
func (h *Hub) Run(ctx context.Context) {
	var wg sync.WaitGroup
	loop := func(every time.Duration, fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
			t := time.NewTicker(every)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					fn()
				}
			}
		}()
	}
	loop(h.cfg.MetricsEvery, h.collectMetrics)
	loop(h.cfg.NetEvery, h.collectNet)
	if h.events != nil {
		loop(h.cfg.EventsEvery, h.collectEvents)
	}
	h.runV4(loop)
	wg.Wait()
}

func (h *Hub) collectMetrics() {
	ps, err := h.procs.Sample()
	if err != nil {
		h.log.Warn("process sample failed", "err", err)
	}
	threads := 0
	for _, p := range ps {
		threads += int(p.Threads)
	}
	m, err := h.sys.Sample(len(ps), threads)
	if err != nil {
		h.log.Warn("system sample failed", "err", err)
		return
	}
	h.evalHostRules(m, ps)
	if h.Subscribers() == 0 {
		return
	}
	h.Broadcast("metrics", m)
	// The full list is sent (not just the top 300) so the hierarchy view can
	// link every child to its parent.
	h.Broadcast("processes", ps)
	h.broadcastV4()
}

func (h *Hub) collectNet() {
	// The tracker is not concurrency-safe: Poll and all reads happen under
	// netMu so Snapshot (HTTP / new clients) never races with the poller.
	h.netMu.Lock()
	d, err := h.net.Poll()
	if err != nil {
		h.netErr = err.Error()
	} else {
		h.netErr = ""
	}
	var stats model.NetStats
	var listening map[string][]model.Listener
	var conns []model.Connection
	if err == nil {
		stats = h.net.Stats()
		listening = h.net.Listening()
		conns = h.net.Snapshot()
	}
	h.netMu.Unlock()
	if err == nil {
		h.evalNetRules(stats, conns)
	}
	if err != nil {
		h.log.Warn("connection poll failed", "err", err)
		h.radarTickFn()
		return
	}
	h.feedTableSensor(d, listening)
	h.radarTickFn()
	if h.Subscribers() == 0 {
		return
	}
	if !d.Empty() {
		h.Broadcast("netdiff", d)
	}
	h.Broadcast("netstats", stats)
}

// Connections returns the current socket table.
func (h *Hub) Connections() []model.Connection {
	h.netMu.Lock()
	defer h.netMu.Unlock()
	return h.net.Snapshot()
}

func (h *Hub) collectEvents() {
	var fresh []model.Event
	var errs []string
	for _, ch := range h.cfg.Channels {
		h.evMu.RLock()
		after := h.lastRec[ch]
		h.evMu.RUnlock()
		since := h.now().Add(-h.cfg.EventWindow)
		evs, err := h.events.Query(ch, since, h.cfg.MaxEvents, 0, after)
		if err != nil {
			errs = append(errs, ch+": "+err.Error())
			continue
		}
		var maxRec uint64
		for i := range evs {
			// Normalise the level name so filters, badges and translations
			// work regardless of how the source spelled it ("Error", "ERROR"…).
			evs[i].LevelStr = eventlog.LevelName(evs[i].Level)
			if evs[i].Category == "" {
				evs[i].Category = model.CatOther
			}
		}
		for _, e := range evs {
			if e.RecordID > maxRec {
				maxRec = e.RecordID
			}
		}
		h.evMu.Lock()
		if maxRec > h.lastRec[ch] {
			h.lastRec[ch] = maxRec
		}
		h.evMu.Unlock()
		fresh = append(fresh, evs...)
	}
	h.evMu.Lock()
	if len(errs) > 0 {
		h.evErr = errs[0]
	} else {
		h.evErr = ""
	}
	cut := h.now().Add(-h.cfg.EventWindow)
	all := append(fresh, h.evs...)
	eventlog.SortNewestFirst(all)
	keep := all[:0]
	for _, e := range all {
		if len(keep) >= h.cfg.MaxEvents*len(h.cfg.Channels) {
			break
		}
		if !e.Time.Before(cut) {
			keep = append(keep, e)
		}
	}
	h.evs = keep
	h.evMu.Unlock()
	if len(errs) == 0 || len(fresh) > 0 {
		h.eventAlerts(fresh)
	}
	if len(fresh) > 0 && h.Subscribers() > 0 {
		eventlog.SortNewestFirst(fresh)
		h.Broadcast("events", fresh)
		h.Broadcast("eventsummary", h.EventSummary())
	}
}

// Events returns retained events (newest first).
func (h *Hub) Events() ([]model.Event, string) {
	h.evMu.RLock()
	defer h.evMu.RUnlock()
	return append([]model.Event(nil), h.evs...), h.evErr
}

// EventSummary buckets the retained events into a 56-slot timeline
// (3 hours per slot for the default 7-day window).
func (h *Hub) EventSummary() eventlog.Summary {
	evs, _ := h.Events()
	to := h.now()
	return eventlog.Summarize(evs, to.Add(-h.cfg.EventWindow), to, 56)
}

// NetError returns the last connection-table error, if any.
func (h *Hub) NetError() string {
	h.netMu.Lock()
	defer h.netMu.Unlock()
	return h.netErr
}

// Snapshot is sent to a client right after it connects.
type Snapshot struct {
	Metrics     model.SystemMetrics   `json:"metrics"`
	History     []model.SystemMetrics `json:"history"`
	Processes   []model.Process       `json:"processes"`
	Connections []model.Connection    `json:"connections"`
	NetStats    model.NetStats        `json:"netstats"`
	Events      []model.Event         `json:"events"`
	EventStats  eventlog.Summary      `json:"eventsummary"`
	EventError  string                `json:"eventError,omitempty"`
	NetError    string                `json:"netError,omitempty"`
	Radar       any                   `json:"radar"`
	Devices     []model.Device        `json:"devices"`
	SelfTest    bool                  `json:"selfTest"`
	Alerts      []model.Alert         `json:"alerts"`
	AlertCounts any                   `json:"alertcounts"`
	Audit       AuditState            `json:"audit"`

	// SysPulse 4.0.
	Interfaces InterfacesState `json:"interfaces"`
	Services   ServicesState   `json:"services"`
	Rules      RulesState      `json:"rules"`
	Health     model.Health    `json:"health"`
	ProcMeta   ProcMeta        `json:"procmeta"`
}

// Snapshot builds the full current state.
func (h *Hub) Snapshot() Snapshot {
	evs, evErr := h.Events()
	if len(evs) > 500 {
		evs = evs[:500]
	}
	h.netMu.Lock()
	conns := h.net.Snapshot()
	ns := h.net.Stats()
	netErr := h.netErr
	h.netMu.Unlock()
	return Snapshot{
		Metrics: h.sys.Last(), History: h.sys.History(), Processes: h.procs.Last(),
		Connections: conns, NetStats: ns, Events: evs, EventStats: h.EventSummary(),
		EventError: evErr, NetError: netErr,
		Radar: h.radar.Snapshot(100), Devices: h.Devices(), SelfTest: h.cfg.SelfTest, Alerts: h.alerts.List(alertsFilter(500)), AlertCounts: h.alerts.Counts(),
		Audit:      h.AuditState(),
		Interfaces: h.Interfaces(), Services: h.Services(), Rules: h.RulesState(), Health: h.Health(), ProcMeta: h.ProcMeta(),
	}
}
