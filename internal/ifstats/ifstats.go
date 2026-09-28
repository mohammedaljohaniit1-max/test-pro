// Package ifstats measures per-interface network throughput.
//
// A platform Reader returns cumulative octet / packet counters per interface
// (Windows: GetIfTable2 / MIB_IF_ROW2; Linux preview: /proc/net/dev). The
// Monitor turns consecutive readings into bytes-per-second rates, keeps a
// short ring of samples per interface for the dashboard sparklines and
// classifies physical versus virtual adapters.
package ifstats

import (
	"sort"
	"sync"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// Counter is one cumulative reading of an interface.
type Counter struct {
	Index     uint32
	Name      string
	Desc      string
	Kind      string
	Physical  bool
	Up        bool
	MAC       string
	SpeedBps  uint64
	MTU       uint32
	InOctets  uint64
	OutOctets uint64
	InPkts    uint64
	OutPkts   uint64
	Errors    uint64
	Discards  uint64
}

// Reader returns the current counters of every relevant interface.
type Reader interface {
	Read() ([]Counter, error)
}

// ReaderFunc adapts a function to Reader.
type ReaderFunc func() ([]Counter, error)

// Read implements Reader.
func (f ReaderFunc) Read() ([]Counter, error) { return f() }

type prevReading struct {
	c  Counter
	at time.Time
}

// Monitor computes rates and history. Safe for concurrent use.
type Monitor struct {
	r       Reader
	now     func() time.Time
	maxHist int

	mu    sync.Mutex
	prev  map[uint32]prevReading
	hist  map[uint32]*model.IfHistory
	last  []model.IfStat
	err   string
	order []uint32
}

// New creates a monitor retaining maxHist samples per interface (default 60).
func New(r Reader, maxHist int) *Monitor {
	if maxHist <= 0 {
		maxHist = 60
	}
	return &Monitor{r: r, now: time.Now, maxHist: maxHist, prev: map[uint32]prevReading{}, hist: map[uint32]*model.IfHistory{}}
}

// SetClock overrides the clock (tests).
func (m *Monitor) SetClock(now func() time.Time) { m.mu.Lock(); m.now = now; m.mu.Unlock() }

// delta returns b-a, or 0 when the counter went backwards (driver reset / wrap).
func delta(a, b uint64) uint64 {
	if b < a {
		return 0
	}
	return b - a
}

// Sample reads the counters and returns the current rates.
func (m *Monitor) Sample() ([]model.IfStat, error) {
	cs, err := m.r.Read()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.err = err.Error()
		return m.last, err
	}
	m.err = ""
	now := m.now()
	next := make(map[uint32]prevReading, len(cs))
	out := make([]model.IfStat, 0, len(cs))
	for _, c := range cs {
		s := model.IfStat{Index: c.Index, Name: c.Name, Desc: c.Desc, Kind: c.Kind, Physical: c.Physical, Up: c.Up,
			MAC: c.MAC, SpeedBps: c.SpeedBps, MTU: c.MTU, InTotal: c.InOctets, OutTotal: c.OutOctets,
			Errors: c.Errors, Discards: c.Discards}
		if p, ok := m.prev[c.Index]; ok {
			if dt := now.Sub(p.at).Seconds(); dt > 0 {
				s.InBps = float64(delta(p.c.InOctets, c.InOctets)) / dt
				s.OutBps = float64(delta(p.c.OutOctets, c.OutOctets)) / dt
				s.InPkts = float64(delta(p.c.InPkts, c.InPkts)) / dt
				s.OutPkts = float64(delta(p.c.OutPkts, c.OutPkts)) / dt
			}
		}
		if c.SpeedBps > 0 {
			peak := s.InBps
			if s.OutBps > peak {
				peak = s.OutBps
			}
			s.Util = peak * 8 / float64(c.SpeedBps) * 100
			if s.Util > 100 {
				s.Util = 100
			}
		}
		next[c.Index] = prevReading{c: c, at: now}
		h := m.hist[c.Index]
		if h == nil {
			h = &model.IfHistory{}
			m.hist[c.Index] = h
		}
		h.Name = c.Name
		h.In = appendRing(h.In, s.InBps, m.maxHist)
		h.Out = appendRing(h.Out, s.OutBps, m.maxHist)
		out = append(out, s)
	}
	for idx := range m.hist {
		if _, ok := next[idx]; !ok {
			delete(m.hist, idx)
		}
	}
	Sort(out)
	m.order = m.order[:0]
	for _, s := range out {
		m.order = append(m.order, s.Index)
	}
	m.prev, m.last = next, out
	return out, nil
}

func appendRing(r []float64, v float64, max int) []float64 {
	r = append(r, v)
	if len(r) > max {
		r = append(r[:0], r[len(r)-max:]...)
	}
	return r
}

// Sort orders interfaces: up before down, physical before virtual, loopback
// last, then by current throughput and name.
func Sort(s []model.IfStat) {
	rank := func(x model.IfStat) int {
		r := 0
		if !x.Up {
			r += 4
		}
		if !x.Physical {
			r++
		}
		if x.Kind == model.IfLoopback {
			r += 8
		}
		return r
	}
	sort.SliceStable(s, func(i, j int) bool {
		ri, rj := rank(s[i]), rank(s[j])
		if ri != rj {
			return ri < rj
		}
		ti, tj := s[i].InBps+s[i].OutBps, s[j].InBps+s[j].OutBps
		if ti != tj {
			return ti > tj
		}
		return s[i].Name < s[j].Name
	})
}

// Last returns the latest rates.
func (m *Monitor) Last() []model.IfStat {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]model.IfStat(nil), m.last...)
}

// Err returns the last read error ("" when healthy).
func (m *Monitor) Err() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.err
}

// History returns a copy of the sparkline rings in display order.
func (m *Monitor) History() map[uint32]model.IfHistory {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[uint32]model.IfHistory, len(m.hist))
	for k, h := range m.hist {
		out[k] = model.IfHistory{Name: h.Name, In: append([]float64(nil), h.In...), Out: append([]float64(nil), h.Out...)}
	}
	return out
}

// Totals sums the rates of all non-loopback interfaces that are up.
func Totals(s []model.IfStat) (in, out float64) {
	for _, x := range s {
		if x.Up && x.Kind != model.IfLoopback {
			in += x.InBps
			out += x.OutBps
		}
	}
	return
}

// KindFromIfType maps an IANA ifType (as used by MIB_IF_ROW2.Type) to a kind.
func KindFromIfType(t uint32) string {
	switch t {
	case 6:
		return model.IfEthernet
	case 71:
		return model.IfWiFi
	case 24:
		return model.IfLoopback
	case 131:
		return model.IfTunnel
	case 243, 244:
		return model.IfCellular
	case 23, 53:
		return model.IfVirtual
	}
	return model.IfOther
}

// FormatMAC renders hardware address bytes as AA-BB-CC-DD-EE-FF.
func FormatMAC(b []byte) string {
	const hx = "0123456789ABCDEF"
	if len(b) == 0 {
		return ""
	}
	allZero := true
	out := make([]byte, 0, len(b)*3)
	for i, v := range b {
		if v != 0 {
			allZero = false
		}
		if i > 0 {
			out = append(out, '-')
		}
		out = append(out, hx[v>>4], hx[v&15])
	}
	if allZero {
		return ""
	}
	return string(out)
}
