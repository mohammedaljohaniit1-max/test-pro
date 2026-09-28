// Package sysmon samples system-wide CPU, memory and disk usage.
package sysmon

import (
	"sync"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// CPUTimes are cumulative system CPU counters (as from GetSystemTimes).
// Kernel time includes idle time on Windows.
type CPUTimes struct {
	Idle, Kernel, User time.Duration
}

// Platform supplies raw readings.
type Platform interface {
	CPUTimes() (CPUTimes, error)
	Memory() (total, avail, commitTotal, commitLimit uint64, err error)
	Disks() ([]model.DiskUsage, error)
	Uptime() time.Duration
	Info() (hostname, os string)
	Cores() int
}

// CoreReader is implemented by platforms that expose per-logical-processor
// counters (Windows: NtQuerySystemInformation(SystemProcessorPerformanceInformation)).
type CoreReader interface {
	CoreTimes() ([]CPUTimes, error)
}

// MemDetailer is implemented by platforms that report the memory composition.
type MemDetailer interface {
	MemDetail() (model.MemDetail, error)
}

// Monitor computes utilisation from counter deltas and keeps a bounded
// history for the dashboard charts. Safe for concurrent use.
type Monitor struct {
	p   Platform
	now func() time.Time

	mu       sync.Mutex
	prev     CPUTimes
	havePrv  bool
	prevCore []CPUTimes
	history  []model.SystemMetrics
	maxHist  int
	last     model.SystemMetrics
}

// New creates a monitor retaining maxHist samples.
func New(p Platform, maxHist int) *Monitor {
	if maxHist <= 0 {
		maxHist = 300
	}
	return &Monitor{p: p, now: time.Now, maxHist: maxHist}
}

// CPUPercent computes busy% between two counter samples:
// busy = (kernel + user − idle) / (kernel + user).
func CPUPercent(a, b CPUTimes) float64 {
	total := (b.Kernel - a.Kernel) + (b.User - a.User)
	idle := b.Idle - a.Idle
	if total <= 0 {
		return 0
	}
	pct := float64(total-idle) / float64(total) * 100
	switch {
	case pct < 0:
		return 0
	case pct > 100:
		return 100
	}
	return pct
}

// KernelUser splits busy time into privileged (kernel minus idle) and user
// shares of the total elapsed CPU time, in percent.
func KernelUser(a, b CPUTimes) (kernel, user float64) {
	total := (b.Kernel - a.Kernel) + (b.User - a.User)
	if total <= 0 {
		return 0, 0
	}
	k := (b.Kernel - a.Kernel) - (b.Idle - a.Idle)
	u := b.User - a.User
	if k < 0 {
		k = 0
	}
	if u < 0 {
		u = 0
	}
	return round1(float64(k) / float64(total) * 100), round1(float64(u) / float64(total) * 100)
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

// Sample reads the platform and appends to history. procs/threads are passed
// in from the process monitor so the snapshot is self-consistent.
func (m *Monitor) Sample(procs, threads int) (model.SystemMetrics, error) {
	ct, err := m.p.CPUTimes()
	if err != nil {
		return model.SystemMetrics{}, err
	}
	total, avail, cTotal, cLimit, err := m.p.Memory()
	if err != nil {
		return model.SystemMetrics{}, err
	}
	disks, err := m.p.Disks()
	if err != nil {
		disks = nil // disks are best-effort (e.g. offline network drive)
	}
	host, osName := m.p.Info()
	s := model.SystemMetrics{
		Timestamp: m.now().UnixMilli(), CPUCores: m.p.Cores(),
		MemTotal: total, MemUsed: total - avail,
		CommitTotal: cLimit, CommitUsed: cTotal,
		UptimeSec: uint64(m.p.Uptime().Seconds()),
		Processes: procs, Threads: threads, Disks: disks, Hostname: host, OS: osName,
	}
	if total > 0 {
		s.MemPercent = float64(s.MemUsed) / float64(total) * 100
	}
	var cores []CPUTimes
	if cr, ok := m.p.(CoreReader); ok {
		cores, _ = cr.CoreTimes()
	}
	if md, ok := m.p.(MemDetailer); ok {
		if d, err := md.MemDetail(); err == nil {
			d.Available = avail
			s.Mem = &d
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.havePrv {
		s.CPUPercent = CPUPercent(m.prev, ct)
		s.KernelPct, s.UserPct = KernelUser(m.prev, ct)
	}
	if len(cores) > 0 && len(cores) == len(m.prevCore) {
		s.PerCore = make([]float64, len(cores))
		for i := range cores {
			s.PerCore[i] = round1(CPUPercent(m.prevCore[i], cores[i]))
		}
	}
	m.prevCore = cores
	m.prev, m.havePrv = ct, true
	m.history = append(m.history, s)
	if len(m.history) > m.maxHist {
		m.history = append(m.history[:0], m.history[len(m.history)-m.maxHist:]...)
	}
	m.last = s
	return s, nil
}

// History returns a copy of the retained samples, oldest first.
func (m *Monitor) History() []model.SystemMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]model.SystemMetrics(nil), m.history...)
}

// Last returns the most recent sample.
func (m *Monitor) Last() model.SystemMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.last
}
