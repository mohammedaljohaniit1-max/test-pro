// Package procmon samples per-process CPU and memory usage.
//
// CPU% is computed from the delta of cumulative (kernel+user) CPU time
// between two samples divided by wall time × logical cores, i.e. the share of
// the whole machine (Task Manager's "CPU" column). Process details are read
// concurrently by a bounded worker pool.
package procmon

import (
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// RawProcess is what a platform Reader returns for one process.
type RawProcess struct {
	PID, PPID  uint32
	Name       string
	Threads    uint32
	Path       string
	CPUTime    time.Duration // cumulative kernel+user time
	WorkingSet uint64
	Private    uint64
	Started    time.Time
	Access     bool
}

// Reader enumerates processes. List must return cheap identity data for every
// process; Details fills path/CPU/memory for one process (may be slow).
type Reader interface {
	List() ([]RawProcess, error)
	Details(p *RawProcess)
}

// Monitor keeps the previous sample to compute CPU deltas. Safe for
// concurrent use.
type Monitor struct {
	r       Reader
	workers int
	cores   int
	now     func() time.Time

	mu     sync.Mutex
	prev   map[procKey]prevSample
	prevAt time.Time
	last   []model.Process
	names  map[uint32]nameEntry
}

type procKey struct {
	pid     uint32
	started int64
}

type prevSample struct{ cpu time.Duration }

type nameEntry struct{ name, path string }

// New creates a monitor. workers <= 0 means 2×GOMAXPROCS (bounded to 32).
func New(r Reader, workers int) *Monitor {
	if workers <= 0 {
		workers = 2 * runtime.GOMAXPROCS(0)
		if workers > 32 {
			workers = 32
		}
	}
	return &Monitor{r: r, workers: workers, cores: runtime.NumCPU(), now: time.Now,
		prev: map[procKey]prevSample{}, names: map[uint32]nameEntry{}}
}

// Sample reads every process, computes CPU% since the previous sample and
// returns processes sorted by CPU then memory.
func (m *Monitor) Sample() ([]model.Process, error) {
	list, err := m.r.List()
	if err != nil {
		return nil, err
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < m.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				m.r.Details(&list[i])
			}
		}()
	}
	for i := range list {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	elapsed := now.Sub(m.prevAt)
	next := make(map[procKey]prevSample, len(list))
	names := make(map[uint32]nameEntry, len(list))
	out := make([]model.Process, 0, len(list))
	for _, p := range list {
		k := procKey{p.PID, p.Started.UnixNano()}
		mp := model.Process{
			PID: p.PID, PPID: p.PPID, Name: p.Name, Path: p.Path, Threads: p.Threads,
			WorkingSet: p.WorkingSet, PrivateB: p.Private, Access: p.Access,
		}
		if !p.Started.IsZero() {
			mp.StartedMs = p.Started.UnixMilli()
		}
		if old, ok := m.prev[k]; ok && elapsed > 0 && p.Access && p.CPUTime >= old.cpu {
			pct := float64(p.CPUTime-old.cpu) / float64(elapsed) / float64(m.cores) * 100
			if pct > 100 {
				pct = 100
			}
			mp.CPUPercent = pct
		}
		if p.Access {
			next[k] = prevSample{cpu: p.CPUTime}
		}
		names[p.PID] = nameEntry{p.Name, p.Path}
		out = append(out, mp)
	}
	m.prev, m.prevAt, m.names = next, now, names
	sort.Slice(out, func(i, j int) bool {
		if out[i].CPUPercent != out[j].CPUPercent {
			return out[i].CPUPercent > out[j].CPUPercent
		}
		if out[i].WorkingSet != out[j].WorkingSet {
			return out[i].WorkingSet > out[j].WorkingSet
		}
		return out[i].PID < out[j].PID
	})
	m.last = out
	return out, nil
}

// Last returns the most recent sample.
func (m *Monitor) Last() []model.Process {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.last
}

// Resolve maps a PID to its name and path from the latest sample, falling
// back to a direct lookup for processes started since then.
func (m *Monitor) Resolve(pid uint32) (string, string) {
	switch pid {
	case 0:
		return "System Idle Process", ""
	case 4:
		return "System", ""
	}
	m.mu.Lock()
	e, ok := m.names[pid]
	m.mu.Unlock()
	if ok {
		return e.name, e.path
	}
	rp := RawProcess{PID: pid}
	m.r.Details(&rp)
	if rp.Name == "" && rp.Path != "" {
		rp.Name = baseName(rp.Path)
	}
	if rp.Name == "" {
		// Not cached: the next Sample will learn the real name from the
		// process list, and callers retry placeholder names.
		return "pid " + itoa(pid), ""
	}
	m.mu.Lock()
	m.names[pid] = nameEntry{rp.Name, rp.Path}
	m.mu.Unlock()
	return rp.Name, rp.Path
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' || p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// Inspection holds the on-demand, more expensive process details.
type Inspection struct {
	CommandLine string
	User        string
	Handles     uint32
	Priority    string
	Cwd         string
	Extra       map[string]string
	Errors      []string
}

// Inspector is implemented by readers that can deep-inspect one process.
type Inspector interface {
	Inspect(pid uint32) Inspection
}

// Inspect returns full details for pid: the latest sample row, parent name,
// children and — when the reader supports it — command line, account,
// handle count and priority. ok is false when pid is not running.
func (m *Monitor) Inspect(pid uint32) (model.ProcessDetail, bool) {
	m.mu.Lock()
	last := m.last
	m.mu.Unlock()
	var d model.ProcessDetail
	found := false
	for _, p := range last {
		if p.PID == pid {
			d.Process, found = p, true
			break
		}
	}
	if !found {
		return d, false
	}
	for _, p := range last {
		if p.PID == d.PPID && p.PID != pid {
			d.ParentName = p.Name
		}
		if p.PPID == pid && p.PID != pid {
			d.Children = append(d.Children, p)
		}
	}
	if in, ok := m.r.(Inspector); ok {
		x := in.Inspect(pid)
		d.CommandLine, d.User, d.Handles, d.Priority, d.Cwd, d.Extra, d.Errors = x.CommandLine, x.User, x.Handles, x.Priority, x.Cwd, x.Extra, x.Errors
	}
	return d, true
}
