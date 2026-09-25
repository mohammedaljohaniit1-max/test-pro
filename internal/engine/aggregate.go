package engine

import (
	"math"
	"strconv"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/pq"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/rules"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/sketch"
)

// Sketch parameters for windowed aggregates. HLL p=10 gives ~3.25% standard
// error in 1 KiB per bucket; DDSketch alpha=1% with 512 buckets covers ~10
// orders of magnitude.
const (
	hllPrecision   = 10
	ddAlpha        = 0.01
	ddMaxBuckets   = 512
	maxEvidenceAgg = 8
)

// aggCell holds the per-bucket partial state of one AggSpec.
type aggCell struct {
	n   uint64 // numeric observations
	sum float64
	min float64
	max float64
	hll *sketch.HLL
	dd  *sketch.DDSketch
}

type aggBucket struct {
	epoch int64 // bucket index = floor(t / width); math.MinInt64 when empty
	count uint64
	cells []aggCell
}

// aggGroup is the sliding window of one (key, rule, group) triple, stored as
// a ring of NumBuckets tumbling sub-windows ("panes"). A window evaluation
// merges the live panes, so memory is O(buckets) regardless of event rate.
type aggGroup struct {
	ri       int
	ks       *keyState
	group    event.Value
	groupStr string
	buckets  []aggBucket
	timer    pq.TimerID
	evidence []*event.Event
	lastEp   int64
}

type aggScratch struct {
	hll *sketch.HLL
	dd  *sketch.DDSketch
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

func newGroup(r *rules.Rule, ri int, ks *keyState, g event.Value, gs string) *aggGroup {
	grp := &aggGroup{ri: ri, ks: ks, group: g, groupStr: gs, buckets: make([]aggBucket, r.NumBuckets), lastEp: math.MinInt64}
	for i := range grp.buckets {
		grp.buckets[i].epoch = math.MinInt64
	}
	return grp
}

func (s *shard) dropGroup(g *aggGroup) {
	if g.timer != 0 {
		s.timers.Cancel(g.timer)
		g.timer = 0
	}
	g.buckets, g.evidence = nil, nil
	s.nGroups--
}

func (s *shard) processAggregate(ks *keyState, ri int, r *rules.Rule, ev *event.Event) {
	st := &ks.states[ri]
	var gv event.Value
	gs := ""
	if r.By != nil {
		gv = r.By(&s.ctx)
		gs = gv.AsString()
	}
	grp := st.groups[gs]
	if grp == nil {
		if st.groups == nil {
			st.groups = make(map[string]*aggGroup, 1)
		}
		if len(st.groups) >= maxGroupsPerKey {
			// Cardinality guard: evict the group idle the longest.
			var victim *aggGroup
			for _, g := range st.groups {
				if victim == nil || g.lastEp < victim.lastEp {
					victim = g
				}
			}
			delete(st.groups, victim.groupStr)
			s.dropGroup(victim)
			s.stats.runEvicts.Add(1)
		}
		grp = newGroup(r, ri, ks, gv, gs)
		st.groups[gs] = grp
		s.nGroups++
	}

	w := int64(r.BucketW)
	ep := floorDiv(ev.Time, w)
	b := &grp.buckets[int(uint64(ep)%uint64(len(grp.buckets)))]
	if b.epoch != ep {
		b.epoch = ep
		b.count = 0
		if b.cells == nil {
			b.cells = make([]aggCell, len(r.Aggs))
		}
		for i := range b.cells {
			c := &b.cells[i]
			c.n, c.sum, c.min, c.max = 0, 0, math.Inf(1), math.Inf(-1)
			if c.hll != nil {
				c.hll.Reset()
			}
			if c.dd != nil {
				c.dd.Reset()
			}
		}
	}
	b.count++
	for i := range r.Aggs {
		spec := &r.Aggs[i]
		if spec.Arg == nil {
			continue
		}
		v := spec.Arg(&s.ctx)
		if v.IsNull() {
			continue
		}
		c := &b.cells[i]
		switch spec.Kind {
		case rules.AggDistinct:
			if c.hll == nil {
				c.hll = sketch.MustHLL(hllPrecision)
			}
			if v.K == event.KindString {
				c.hll.AddString(v.S)
			} else {
				c.hll.AddString(v.AsString())
			}
			c.n++
		case rules.AggQuantile:
			if !v.IsNumeric() {
				continue
			}
			if c.dd == nil {
				c.dd = sketch.MustDDSketch(ddAlpha, ddMaxBuckets)
			}
			c.dd.Add(v.AsFloat())
			c.n++
		default:
			if !v.IsNumeric() {
				continue
			}
			f := v.AsFloat()
			c.n++
			c.sum += f
			if f < c.min {
				c.min = f
			}
			if f > c.max {
				c.max = f
			}
		}
	}
	if len(grp.evidence) == maxEvidenceAgg {
		copy(grp.evidence, grp.evidence[1:])
		grp.evidence[maxEvidenceAgg-1] = ev
	} else {
		grp.evidence = append(grp.evidence, ev)
	}

	// Idle reclamation: once no pane of this group can be inside any future
	// window, drop it.
	if ep > grp.lastEp || grp.timer == 0 {
		if ep > grp.lastEp {
			grp.lastEp = ep
		}
		// The window spans exactly NumBuckets panes, so the newest pane
		// leaves every future window NumBuckets panes after it closes.
		idleAt := (grp.lastEp + 1 + int64(len(grp.buckets))) * w
		if grp.timer == 0 {
			grp.timer = s.timers.Schedule(idleAt, timerRef{kind: timerWindow, ks: ks, grp: grp})
		} else {
			s.timers.Reset(grp.timer, idleAt)
		}
	}

	// Continuous evaluation of the window ending at the current pane.
	head := grp.lastEp
	if ep < head {
		head = ep
	}
	winStart := (head - int64(len(grp.buckets)) + 1) * w
	winEnd := (head + 1) * w
	s.evalGroup(r, grp, ev, head, winStart, winEnd)
}

// aggEvalState carries the pane range of the window under evaluation so the
// lazily-invoked aggregate callback can be a pre-bound method value (no
// per-event closure allocation).
type aggEvalState struct {
	r        *rules.Rule
	grp      *aggGroup
	lo, head int64
	cache    [16]event.Value
	have     uint32
}

func (s *shard) aggEval(i int) event.Value {
	st := &s.aggState
	if i < len(st.cache) && st.have&(1<<uint(i)) != 0 {
		return st.cache[i]
	}
	v := s.computeAgg(st.r, st.grp, i, st.lo, st.head)
	if i < len(st.cache) {
		st.cache[i] = v
		st.have |= 1 << uint(i)
	}
	return v
}

func (s *shard) evalGroup(r *rules.Rule, grp *aggGroup, ev *event.Event, head, winStart, winEnd int64) {
	lo := head - int64(len(grp.buckets)) + 1
	s.aggState.r, s.aggState.grp, s.aggState.lo, s.aggState.head, s.aggState.have = r, grp, lo, head, 0
	if s.aggEvalFn == nil {
		s.aggEvalFn = s.aggEval
	}
	s.ctx = rules.Ctx{Cur: ev, AggEval: s.aggEvalFn, Group: grp.group, WindowStart: winStart, WindowEnd: winEnd}
	if !r.Having(&s.ctx).AsBool() {
		return
	}
	if s.suppressed(grp.ks, r, grp.groupStr, ev.Time) {
		return
	}
	fields := make(map[string]any, len(r.Emit)+2)
	for _, f := range r.Emit {
		fields[f.Name] = f.Expr(&s.ctx).Interface()
	}
	var total uint64
	for i := range grp.buckets {
		if b := &grp.buckets[i]; b.epoch >= lo && b.epoch <= head {
			total += b.count
		}
	}
	fields["window_count"] = total
	a := &Alert{
		ID:          r.Name + "-" + strconv.FormatUint(ev.Seq, 36) + "-" + strconv.FormatInt(ev.Time, 36),
		Rule:        r.Name,
		Fingerprint: r.Fingerprint,
		Kind:        "aggregate",
		Severity:    r.Severity,
		Description: r.Description,
		Tags:        r.Tags,
		Key:         grp.ks.key,
		Group:       grp.groupStr,
		EventTime:   ev.Time,
		WindowStart: winStart,
		WindowEnd:   winEnd,
		Fields:      fields,
		Evidence:    append([]*event.Event(nil), grp.evidence...),
	}
	if ev.Ingested > 0 {
		a.LatencyNs = timeNow() - ev.Ingested
	}
	s.emit(a)
}

// computeAgg merges the live panes [lo, head] for aggregate i.
func (s *shard) computeAgg(r *rules.Rule, grp *aggGroup, i int, lo, head int64) event.Value {
	spec := &r.Aggs[i]
	var (
		count uint64
		n     uint64
		sum   float64
		mn    = math.Inf(1)
		mx    = math.Inf(-1)
	)
	switch spec.Kind {
	case rules.AggDistinct:
		if s.scratch.hll == nil {
			s.scratch.hll = sketch.MustHLL(hllPrecision)
		}
		s.scratch.hll.Reset()
	case rules.AggQuantile:
		if s.scratch.dd == nil {
			s.scratch.dd = sketch.MustDDSketch(ddAlpha, ddMaxBuckets)
		}
		s.scratch.dd.Reset()
	}
	for bi := range grp.buckets {
		b := &grp.buckets[bi]
		if b.epoch < lo || b.epoch > head {
			continue
		}
		count += b.count
		if b.cells == nil {
			continue
		}
		c := &b.cells[i]
		switch spec.Kind {
		case rules.AggDistinct:
			if c.hll != nil {
				_ = s.scratch.hll.Merge(c.hll)
			}
		case rules.AggQuantile:
			if c.dd != nil {
				_ = s.scratch.dd.Merge(c.dd)
			}
		default:
			n += c.n
			sum += c.sum
			if c.min < mn {
				mn = c.min
			}
			if c.max > mx {
				mx = c.max
			}
		}
	}
	switch spec.Kind {
	case rules.AggCount:
		return event.Int(int64(count))
	case rules.AggRate:
		return event.Float(float64(count) / r.Over.Seconds())
	case rules.AggSum:
		if n == 0 {
			return event.Float(0)
		}
		return event.Float(sum)
	case rules.AggAvg:
		if n == 0 {
			return event.Null
		}
		return event.Float(sum / float64(n))
	case rules.AggMin:
		if n == 0 {
			return event.Null
		}
		return event.Float(mn)
	case rules.AggMax:
		if n == 0 {
			return event.Null
		}
		return event.Float(mx)
	case rules.AggDistinct:
		return event.Int(int64(s.scratch.hll.Estimate()))
	case rules.AggQuantile:
		if s.scratch.dd.Count() == 0 {
			return event.Null
		}
		return event.Float(s.scratch.dd.Quantile(spec.Q))
	}
	return event.Null
}

// onGroupIdle drops a group once its newest pane has left every window.
func (s *shard) onGroupIdle(grp *aggGroup, _ int64) {
	grp.timer = 0
	if grp.buckets == nil {
		return
	}
	st := &grp.ks.states[grp.ri]
	if st.groups[grp.groupStr] == grp {
		delete(st.groups, grp.groupStr)
	}
	s.dropGroup(grp)
}

// timeNow is the wall clock used for latency accounting (overridable in
// tests).
var timeNow = func() int64 { return time.Now().UnixNano() }
