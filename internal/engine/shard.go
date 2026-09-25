package engine

import (
	"sync/atomic"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/pq"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/ring"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/rules"
)

type ctlKind uint8

const (
	ctlSync ctlKind = iota + 1
	ctlAdvance
	ctlFlush
)

type control struct {
	kind ctlKind
	ts   int64
	done chan struct{}
}

// item is the unit carried by shard rings. Exactly one of ev / ctl is set;
// an all-nil item is a wake-up used to prompt ruleset migration.
type item struct {
	ev  *event.Event
	ctl *control
}

type shardStats struct {
	processed, late, rejected, blocked  atomic.Uint64
	alerts, suppressed, muted           atomic.Uint64
	keyEvicts, keyExpired               atomic.Uint64
	runEvicts, runsExpired, forced      atomic.Uint64
	keys, runs, groups, timers, reorder atomic.Int64
	watermark                           atomic.Int64
	ruleVersion                         atomic.Uint64
}

type timerKind uint8

const (
	timerRun timerKind = iota + 1
	timerWindow
)

type timerRef struct {
	kind timerKind
	ks   *keyState
	run  *seqRun
	grp  *aggGroup
}

// ruleState is the per-key state of one rule.
type ruleState struct {
	runs   []*seqRun
	groups map[string]*aggGroup
}

// keyState holds every rule's state for one partition key. keyStates form an
// intrusive LRU list ordered by last touch (which, because shards process in
// event-time order, is also ordered by last event time).
type keyState struct {
	key        string
	states     []ruleState
	suppress   map[string]int64
	lastSeen   int64
	prev, next *keyState
}

type shard struct {
	id  int
	eng *Engine
	in  *ring.Ring[item]
	cfg Config

	rs        *rules.Ruleset
	ttl       int64
	relevance map[string][]int

	reorder  *pq.Heap[*event.Event]
	timers   *pq.Timers[timerRef]
	maxSeen  int64
	wm       int64
	lastRecv time.Time

	keys       map[string]*keyState
	lruHead    *keyState // most recently touched
	lruTail    *keyState // least recently touched
	nRuns      int64
	nGroups    int64
	ctx        rules.Ctx
	aggState   aggEvalState
	aggEvalFn  func(int) event.Value
	scratch    aggScratch
	sampleMask uint64
	stats      shardStats
}

const (
	relevanceCacheMax = 4096
	sweepBudget       = 1024
	maxGroupsPerKey   = 1024
	minInt64          = -1 << 63
)

func newShard(id int, e *Engine) *shard {
	s := &shard{
		id:  id,
		eng: e,
		cfg: e.cfg,
		in:  ring.New[item](e.cfg.RingSize),
		reorder: pq.NewHeap(func(a, b *event.Event) bool {
			if a.Time != b.Time {
				return a.Time < b.Time
			}
			return a.Seq < b.Seq
		}, 1024),
		timers:     pq.NewTimers[timerRef](),
		keys:       make(map[string]*keyState),
		maxSeen:    minInt64,
		wm:         minInt64,
		sampleMask: 1<<e.cfg.LatencySampleShift - 1,
	}
	s.stats.watermark.Store(minInt64)
	return s
}

func (s *shard) run() {
	buf := make([]item, s.cfg.BatchSize)
	s.lastRecv = time.Now()
	s.syncRules()
	for {
		n := s.in.PopBatch(buf)
		if n > 0 {
			s.syncRules()
			for i := 0; i < n; i++ {
				s.handle(buf[i])
				buf[i] = item{}
			}
			s.lastRecv = time.Now()
			s.sweep()
			s.publishGauges()
			continue
		}
		if s.in.Closed() && s.in.Len() == 0 {
			// Final drain: release everything already admitted in order.
			s.flushReorder()
			s.publishGauges()
			return
		}
		s.syncRules()
		if s.cfg.IdleAdvance > 0 {
			if idle := time.Since(s.lastRecv); idle >= s.cfg.IdleAdvance {
				target := time.Now().Add(-s.cfg.AllowedLateness).UnixNano()
				if target > s.wm {
					s.advanceTo(target)
					s.sweep()
					s.publishGauges()
				}
			}
		}
		wait := 50 * time.Millisecond
		if s.cfg.IdleAdvance > 0 && s.cfg.IdleAdvance < wait {
			wait = s.cfg.IdleAdvance
		}
		s.in.Wait(wait)
	}
}

func (s *shard) handle(it item) {
	switch {
	case it.ev != nil:
		s.admit(it.ev)
	case it.ctl != nil:
		switch it.ctl.kind {
		case ctlAdvance:
			s.advanceTo(it.ctl.ts)
			s.sweep()
		case ctlFlush:
			// Release every buffered event: the watermark moves to just past
			// the newest event seen, so only timers strictly in the past fire.
			if s.maxSeen != minInt64 {
				s.advanceTo(s.maxSeen + 1)
			}
			s.sweep()
		case ctlSync:
		}
		s.publishGauges()
		close(it.ctl.done)
	}
}

// admit applies watermark logic to a newly arrived event.
func (s *shard) admit(ev *event.Event) {
	if ev.Time < s.wm {
		s.stats.late.Add(1)
		return
	}
	if ev.Time > s.maxSeen {
		s.maxSeen = ev.Time
	}
	lateness := int64(s.cfg.AllowedLateness)
	if lateness == 0 {
		// Fast path: nothing can be reordered, but events can still share a
		// timestamp; release through the same ordering logic without the heap.
		s.advanceWatermark(ev.Time)
		s.process(ev)
		return
	}
	s.reorder.Push(ev)
	if s.reorder.Len() > s.cfg.MaxReorder {
		oldest, _ := s.reorder.Peek()
		s.stats.forced.Add(1)
		s.advanceTo(oldest.Time)
	}
	if target := s.maxSeen - lateness; target > s.wm {
		s.advanceTo(target)
	}
}

// advanceWatermark raises wm to target and fires timers strictly before it.
// Used by the zero-lateness fast path where events are processed on arrival.
func (s *shard) advanceWatermark(target int64) {
	if target <= s.wm {
		return
	}
	s.wm = target
	s.fireTimers(target)
}

// advanceTo raises the watermark and releases buffered events and timers in
// event-time order. Invariant: an event at time t is processed before any
// timer with deadline >= t.
func (s *shard) advanceTo(target int64) {
	if target <= s.wm {
		return
	}
	s.wm = target
	for {
		ev, hasEv := s.reorder.Peek()
		if hasEv && ev.Time > target {
			hasEv = false
		}
		dl, hasT := s.timers.Next()
		if hasT && dl >= target {
			hasT = false
		}
		switch {
		case hasT && (!hasEv || dl < ev.Time):
			s.fireOneTimer()
		case hasEv:
			s.reorder.Pop()
			s.process(ev)
		default:
			return
		}
	}
}

// flushReorder releases every buffered event at shutdown without firing
// timers past the last event (absence deadlines in the future are not
// reported on shutdown).
func (s *shard) flushReorder() {
	for s.reorder.Len() > 0 {
		ev, _ := s.reorder.Pop()
		if ev.Time > s.wm {
			s.wm = ev.Time
		}
		s.fireTimers(ev.Time)
		s.process(ev)
	}
}

func (s *shard) fireTimers(before int64) {
	for {
		dl, ok := s.timers.Next()
		if !ok || dl >= before {
			return
		}
		s.fireOneTimer()
	}
}

func (s *shard) fireOneTimer() {
	t, ok := s.timers.PopMin()
	if !ok {
		return
	}
	switch t.Payload.kind {
	case timerRun:
		s.onRunDeadline(t.Payload.run, t.Deadline)
	case timerWindow:
		s.onGroupIdle(t.Payload.grp, t.Deadline)
	}
}

// syncRules migrates state to a newly published ruleset.
func (s *shard) syncRules() {
	rs := s.eng.ruleset.Load()
	if rs == s.rs {
		return
	}
	old := s.rs
	s.rs = rs
	s.relevance = make(map[string][]int)
	s.stats.ruleVersion.Store(rs.Version)

	// Horizon bounds how long idle key state must be retained.
	var horizon time.Duration
	for _, r := range rs.Rules {
		for _, d := range []time.Duration{r.Within, r.Over, r.Suppress, effectiveSuppress(r)} {
			if d > horizon {
				horizon = d
			}
		}
	}
	ttl := s.cfg.KeyTTL
	if 2*horizon > ttl {
		ttl = 2 * horizon
	}
	s.ttl = int64(ttl + s.cfg.AllowedLateness)

	if old == nil || len(s.keys) == 0 {
		return
	}
	remap := make([]int, len(old.Rules))
	newIdx := make(map[string]int, len(rs.Rules))
	for i, r := range rs.Rules {
		newIdx[r.Name+"\x00"+r.Fingerprint] = i
	}
	for i, r := range old.Rules {
		if ni, ok := newIdx[r.Name+"\x00"+r.Fingerprint]; ok {
			remap[i] = ni
		} else {
			remap[i] = -1
		}
	}
	for _, ks := range s.keys {
		ns := make([]ruleState, len(rs.Rules))
		for oi := range ks.states {
			st := &ks.states[oi]
			ni := -1
			if oi < len(remap) {
				ni = remap[oi]
			}
			if ni < 0 {
				s.dropRuleState(st)
				continue
			}
			for _, r := range st.runs {
				r.ri = ni
			}
			for _, g := range st.groups {
				g.ri = ni
			}
			ns[ni] = *st
		}
		ks.states = ns
	}
}

// relevant returns the indexes of rules affected by an event type.
func (s *shard) relevant(t string) []int {
	if idx, ok := s.relevance[t]; ok {
		return idx
	}
	var idx []int
	for i, r := range s.rs.Rules {
		if r.Relevant(t) {
			idx = append(idx, i)
		}
	}
	if len(s.relevance) < relevanceCacheMax {
		s.relevance[t] = idx
	}
	return idx
}

func (s *shard) process(ev *event.Event) {
	sampled := ev.Seq&s.sampleMask == 0
	var t0 time.Time
	if sampled {
		t0 = time.Now()
	}
	s.stats.processed.Add(1)
	rel := s.relevant(ev.Type)
	if len(rel) > 0 {
		var ks *keyState
		for _, ri := range rel {
			r := s.rs.Rules[ri]
			s.ctx = rules.Ctx{Cur: ev}
			if r.Kind == rules.KindAggregate {
				if r.Where != nil && !r.Where(&s.ctx).AsBool() {
					continue
				}
				if ks == nil {
					ks = s.touch(ev)
				}
				s.processAggregate(ks, ri, r, ev)
				continue
			}
			if ks == nil {
				existing := s.keys[ev.Key]
				if existing == nil && !s.couldStart(r, ev) {
					continue
				}
				ks = s.touch(ev)
			}
			s.processSequence(ks, ri, r, ev)
		}
	}
	if sampled {
		s.eng.metrics.EvalLatency.Observe(time.Since(t0).Seconds())
	}
}

// couldStart reports whether ev can open a new run of r (used to avoid
// allocating key state for events that cannot affect anything).
func (s *shard) couldStart(r *rules.Rule, ev *event.Event) bool {
	s.ctx = rules.Ctx{Cur: ev}
	return r.Positives[0].Matches(&s.ctx)
}

// touch returns (creating if needed) the key state and moves it to the LRU
// head.
func (s *shard) touch(ev *event.Event) *keyState {
	ks := s.keys[ev.Key]
	if ks == nil {
		ks = &keyState{key: ev.Key, states: make([]ruleState, len(s.rs.Rules))}
		s.keys[ev.Key] = ks
		s.lruPushFront(ks)
		if len(s.keys) > s.cfg.MaxKeysPerShard {
			victim := s.lruTail
			if victim != ks {
				s.removeKey(victim)
				s.stats.keyEvicts.Add(1)
			}
		}
	} else if s.lruHead != ks {
		s.lruUnlink(ks)
		s.lruPushFront(ks)
	}
	if ev.Time > ks.lastSeen {
		ks.lastSeen = ev.Time
	}
	return ks
}

func (s *shard) lruPushFront(ks *keyState) {
	ks.prev = nil
	ks.next = s.lruHead
	if s.lruHead != nil {
		s.lruHead.prev = ks
	}
	s.lruHead = ks
	if s.lruTail == nil {
		s.lruTail = ks
	}
}

func (s *shard) lruUnlink(ks *keyState) {
	if ks.prev != nil {
		ks.prev.next = ks.next
	} else {
		s.lruHead = ks.next
	}
	if ks.next != nil {
		ks.next.prev = ks.prev
	} else {
		s.lruTail = ks.prev
	}
	ks.prev, ks.next = nil, nil
}

func (s *shard) removeKey(ks *keyState) {
	for i := range ks.states {
		s.dropRuleState(&ks.states[i])
	}
	s.lruUnlink(ks)
	delete(s.keys, ks.key)
}

func (s *shard) dropRuleState(st *ruleState) {
	for _, r := range st.runs {
		s.killRun(r)
	}
	st.runs = nil
	for _, g := range st.groups {
		s.dropGroup(g)
	}
	st.groups = nil
}

// sweep reclaims keys idle for longer than the TTL (in event time).
func (s *shard) sweep() {
	if s.wm == minInt64 {
		return
	}
	for i := 0; i < sweepBudget && s.lruTail != nil; i++ {
		ks := s.lruTail
		if ks.lastSeen+s.ttl >= s.wm {
			return
		}
		s.removeKey(ks)
		s.stats.keyExpired.Add(1)
	}
}

func (s *shard) publishGauges() {
	s.stats.keys.Store(int64(len(s.keys)))
	s.stats.runs.Store(s.nRuns)
	s.stats.groups.Store(s.nGroups)
	s.stats.timers.Store(int64(s.timers.Len()))
	s.stats.reorder.Store(int64(s.reorder.Len()))
	s.stats.watermark.Store(s.wm)
}

// suppressed checks and arms the per (rule, key, group) suppression window.
func (s *shard) suppressed(ks *keyState, r *rules.Rule, group string, at int64) bool {
	d := effectiveSuppress(r)
	if d <= 0 {
		return false
	}
	k := r.Name + "\x00" + group
	if until, ok := ks.suppress[k]; ok && at < until {
		s.stats.suppressed.Add(1)
		return true
	}
	if ks.suppress == nil {
		ks.suppress = make(map[string]int64, 2)
	}
	if len(ks.suppress) > 4*maxGroupsPerKey {
		for kk, until := range ks.suppress {
			if until <= at {
				delete(ks.suppress, kk)
			}
		}
	}
	ks.suppress[k] = at + int64(d)
	return false
}

// effectiveSuppress: aggregate rules default to suppressing for one window
// length so that a sustained condition produces one alert per window.
func effectiveSuppress(r *rules.Rule) time.Duration {
	if r.Suppress > 0 {
		return r.Suppress
	}
	if r.Kind == rules.KindAggregate {
		return r.Over
	}
	return 0
}

func (s *shard) emit(a *Alert) {
	a.Shard = s.id
	a.DetectedAt = time.Now().UnixNano()
	s.stats.alerts.Add(1)
	s.eng.countRule(a.Rule)
	if s.eng.muted.Load() {
		s.stats.muted.Add(1)
		return
	}
	if a.LatencyNs > 0 {
		s.eng.metrics.AlertLatency.Observe(float64(a.LatencyNs) / 1e9)
	}
	s.eng.alerts <- a
}
