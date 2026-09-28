// Package services inventories background services: the Windows Service
// Control Manager in syspulse.exe (EnumServicesStatusEx + QueryServiceConfig)
// and systemd units in the Linux preview build.
//
// A Monitor refreshes the list on its own cadence (enumeration with
// configuration lookups costs tens of milliseconds, so it runs every few
// seconds rather than every telemetry tick) and reports transitions such as
// an auto-start service that stopped.
package services

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// Lister enumerates services.
type Lister interface {
	List() ([]model.Service, error)
}

// ListerFunc adapts a function to Lister.
type ListerFunc func() ([]model.Service, error)

// List implements Lister.
func (f ListerFunc) List() ([]model.Service, error) { return f() }

// Change describes a state transition between two refreshes.
type Change struct {
	Service model.Service `json:"service"`
	From    string        `json:"from"`
	To      string        `json:"to"`
}

// Monitor keeps the latest service list. Safe for concurrent use.
type Monitor struct {
	l   Lister
	now func() time.Time

	mu      sync.RWMutex
	list    []model.Service
	byName  map[string]model.Service
	summary model.ServiceSummary
	primed  bool
}

// New creates a monitor.
func New(l Lister) *Monitor {
	return &Monitor{l: l, now: time.Now, byName: map[string]model.Service{}}
}

// Refresh re-reads the services and returns the state transitions since the
// previous refresh (none on the first call).
func (m *Monitor) Refresh() ([]Change, error) {
	list, err := m.l.List()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.summary.Error = err.Error()
		m.summary.Updated = m.now().UnixMilli()
		return nil, err
	}
	sort.Slice(list, func(i, j int) bool { return strings.ToLower(list[i].Display) < strings.ToLower(list[j].Display) })
	var changes []Change
	next := make(map[string]model.Service, len(list))
	for _, s := range list {
		next[s.Name] = s
		if old, ok := m.byName[s.Name]; ok && m.primed && old.State != s.State {
			changes = append(changes, Change{Service: s, From: old.State, To: s.State})
		}
	}
	m.list, m.byName, m.primed = list, next, true
	m.summary = Summarize(list)
	m.summary.Updated = m.now().UnixMilli()
	return changes, nil
}

// Summarize counts states.
func Summarize(list []model.Service) model.ServiceSummary {
	var s model.ServiceSummary
	s.Total = len(list)
	for _, x := range list {
		switch x.State {
		case model.SvcRunning:
			s.Running++
		case model.SvcStopped:
			s.Stopped++
		}
		if x.StartType == model.StartDisabled {
			s.Disabled++
		}
		if IsAuto(x.StartType) && x.State == model.SvcStopped {
			s.AutoStopped++
			if Failed(x) {
				s.AutoFailed++
			}
		}
	}
	return s
}

// errServiceNeverStarted is ERROR_SERVICE_NEVER_STARTED (1077): the
// service has not been started since boot, which is normal for delayed and
// trigger-start services and is not a failure.
const errServiceNeverStarted = 1077

// Failed reports whether a stopped service exited with a failure code.
func Failed(s model.Service) bool {
	return s.State == model.SvcStopped && s.ExitCode != 0 && s.ExitCode != errServiceNeverStarted
}

// IsAuto reports whether the start type means "should be running after boot".
func IsAuto(st string) bool { return st == model.StartAuto || st == model.StartDelayed }

// List returns the latest services.
func (m *Monitor) List() []model.Service {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]model.Service(nil), m.list...)
}

// Summary returns the latest counts.
func (m *Monitor) Summary() model.ServiceSummary {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.summary
}

// ByPID maps host process IDs to the services they run (svchost groups).
func (m *Monitor) ByPID() map[uint32][]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[uint32][]string{}
	for _, s := range m.list {
		if s.PID != 0 && s.State == model.SvcRunning {
			out[s.PID] = append(out[s.PID], s.Name)
		}
	}
	return out
}
