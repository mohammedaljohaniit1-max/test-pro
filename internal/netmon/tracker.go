package netmon

import (
	"sort"
	"strings"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// Source produces a full socket snapshot. The Windows implementation is
// NewSystemSource; tests inject fakes.
type Source func() ([]model.Connection, error)

// Resolver maps a PID to (name, path). Implemented by procmon.
type Resolver func(pid uint32) (name, path string)

// Diff is the change between two consecutive snapshots.
type Diff struct {
	Added   []model.Connection `json:"added"`
	Removed []string           `json:"removed"` // connection keys
	Changed []model.Connection `json:"changed"` // state transitions (e.g. SYN_SENT -> ESTABLISHED)
}

// Empty reports whether nothing changed.
func (d *Diff) Empty() bool { return len(d.Added)+len(d.Removed)+len(d.Changed) == 0 }

// Tracker keeps the current connection set and computes diffs and rates.
// It is not safe for concurrent use; the hub owns it on one goroutine.
type Tracker struct {
	src     Source
	resolve Resolver
	cur     map[string]model.Connection
	rateWin []rateSample
	now     func() time.Time
}

type rateSample struct {
	t     time.Time
	added int
}

// NewTracker creates a tracker.
func NewTracker(src Source, resolve Resolver) *Tracker {
	return &Tracker{src: src, resolve: resolve, cur: map[string]model.Connection{}, now: time.Now}
}

// Poll takes a snapshot, diffs it against the previous one and returns the
// diff. The first poll reports every socket as added.
func (t *Tracker) Poll() (Diff, error) {
	conns, err := t.src()
	if err != nil {
		return Diff{}, err
	}
	now := t.now()
	next := make(map[string]model.Connection, len(conns))
	var d Diff
	for _, c := range conns {
		k := c.Key()
		if old, ok := t.cur[k]; ok {
			c.FirstSeen = old.FirstSeen
			c.ProcessName, c.ProcessPath = old.ProcessName, old.ProcessPath
			// A socket seen before its process was sampled carries a
			// placeholder name; retry until it resolves.
			if t.resolve != nil && (c.ProcessName == "" || strings.HasPrefix(c.ProcessName, "pid ")) {
				if n, p := t.resolve(c.PID); n != "" && !strings.HasPrefix(n, "pid ") {
					c.ProcessName, c.ProcessPath = n, p
					if old.State == c.State {
						d.Changed = append(d.Changed, c)
					}
				}
			}
			if old.State != c.State {
				d.Changed = append(d.Changed, c)
			}
		} else {
			c.FirstSeen = now.UnixMilli()
			if t.resolve != nil {
				c.ProcessName, c.ProcessPath = t.resolve(c.PID)
			}
			d.Added = append(d.Added, c)
		}
		next[k] = c
	}
	for k := range t.cur {
		if _, ok := next[k]; !ok {
			d.Removed = append(d.Removed, k)
		}
	}
	t.cur = next
	t.rateWin = append(t.rateWin, rateSample{now, len(d.Added)})
	cut := now.Add(-10 * time.Second)
	i := 0
	for i < len(t.rateWin) && t.rateWin[i].t.Before(cut) {
		i++
	}
	t.rateWin = t.rateWin[i:]
	return d, nil
}

// Snapshot returns the current connections sorted for stable display.
func (t *Tracker) Snapshot() []model.Connection {
	out := make([]model.Connection, 0, len(t.cur))
	for _, c := range t.cur {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		if out[i].LocalPort != out[j].LocalPort {
			return out[i].LocalPort < out[j].LocalPort
		}
		return out[i].Key() < out[j].Key()
	})
	return out
}

// Stats summarises the current set. New connections per second are
// averaged over the last 10 s (excluding the initial full snapshot).
func (t *Tracker) Stats() model.NetStats {
	s := model.NetStats{ByState: map[string]int{}, ByProto: map[string]int{}, SampledAtMs: t.now().UnixMilli()}
	procs := map[string]int{}
	remotes := map[string]int{}
	for _, c := range t.cur {
		s.Total++
		s.ByProto[c.Proto]++
		if c.State != "-" {
			s.ByState[c.State]++
		}
		name := c.ProcessName
		if name == "" {
			name = "pid " + itoa(c.PID)
		}
		procs[name]++
		if c.RemoteAddr != "" && c.State == "ESTABLISHED" && !isLocal(c.RemoteAddr) {
			remotes[c.RemoteAddr]++
		}
	}
	if len(t.rateWin) > 1 {
		added := 0
		for _, r := range t.rateWin[1:] {
			added += r.added
		}
		span := t.rateWin[len(t.rateWin)-1].t.Sub(t.rateWin[0].t).Seconds()
		if span > 0 {
			s.NewPerSec = float64(added) / span
		}
	}
	s.TopProcs = topN(procs, 8)
	s.TopRemotes = topN(remotes, 8)
	return s
}

func isLocal(a string) bool {
	return a == "127.0.0.1" || a == "::1" || a == "0.0.0.0" || a == "::"
}

func itoa(v uint32) string {
	return formatUint(uint64(v))
}

func formatUint(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func topN(m map[string]int, n int) []model.ProcCount {
	out := make([]model.ProcCount, 0, len(m))
	for k, v := range m {
		out = append(out, model.ProcCount{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Listening returns the set of listening TCP ports keyed by
// radar-compatible "PROTO:port" (e.g. "TCP:445", "TCP6:3389").
func (t *Tracker) Listening() map[string]bool {
	m := map[string]bool{}
	for _, c := range t.cur {
		if c.State == "LISTEN" {
			m[c.Proto+":"+formatUint(uint64(c.LocalPort))] = true
		}
	}
	return m
}
