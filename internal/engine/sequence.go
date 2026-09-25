package engine

import (
	"strconv"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/pq"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/rules"
)

// seqRun is one partial match (an NFA thread) of a sequence rule for a key.
//
// Semantics (skip-till-next-match):
//   - A run is positioned at positive stage p with count c events bound to it.
//   - Stage p is "satisfied" once c >= Min(p).
//   - While positioned at stage p, events matching any guard (negated step)
//     of stage p kill the run. Negation takes precedence over progress.
//   - A satisfied stage p advances to p+1 when an event matches step p+1;
//     otherwise an event matching step p is absorbed while c < Max(p).
//   - When the last stage is satisfied the run completes immediately, unless
//     the rule ends in a negation (absence rule), in which case it completes
//     when the run deadline (start + within) passes with no guard event.
//   - Stage-0 quantified runs keep the timestamps of their stage-0 events;
//     when the deadline is reached while still in stage 0 the run slides its
//     start forward instead of dying, giving exact sliding-window semantics
//     for "N events within T" prefixes.
type seqRun struct {
	ri       int
	ks       *keyState
	stage    int
	count    int
	bound    []*event.Event
	counts   []int
	times    []int64 // stage-0 timestamps (ring), only when stage 0 is quantified
	tHead    int
	tLen     int
	start    int64
	deadline int64
	timer    pq.TimerID
	evidence []*event.Event
	dead     bool
}

func stage0Cap(st *rules.Step) int {
	if st.Max == 1 {
		return 0
	}
	if st.Max > 0 {
		return st.Max
	}
	c := st.Min * 4
	if c < 64 {
		c = 64
	}
	if c > rules.MaxQuantifier {
		c = rules.MaxQuantifier
	}
	return c
}

func (s *shard) newRun(ks *keyState, ri int, r *rules.Rule, ev *event.Event) *seqRun {
	run := &seqRun{
		ri:     ri,
		ks:     ks,
		bound:  make([]*event.Event, r.NumSlots),
		counts: make([]int, r.NumSlots),
		start:  ev.Time,
	}
	if c := stage0Cap(&r.Positives[0]); c > 0 {
		run.times = make([]int64, c)
	}
	run.deadline = ev.Time + int64(r.Within)
	run.timer = s.timers.Schedule(run.deadline, timerRef{kind: timerRun, ks: ks, run: run})
	s.nRuns++
	return run
}

func (s *shard) killRun(run *seqRun) {
	if run.dead {
		return
	}
	run.dead = true
	s.timers.Cancel(run.timer)
	s.nRuns--
	run.bound, run.evidence, run.times = nil, nil, nil
}

func (run *seqRun) bind(r *rules.Rule, st *rules.Step, ev *event.Event) {
	run.bound[st.Index] = ev
	run.counts[st.Index]++
	run.count++
	if run.stage == 0 && run.times != nil {
		i := (run.tHead + run.tLen) % len(run.times)
		if run.tLen == len(run.times) {
			// Ring full (bounded quantifier at Max): slide the oldest out.
			run.tHead = (run.tHead + 1) % len(run.times)
			run.counts[st.Index]--
			run.count--
			i = (run.tHead + run.tLen - 1) % len(run.times)
		} else {
			run.tLen++
		}
		run.times[i] = ev.Time
	}
	if len(run.evidence) == MaxEvidence {
		copy(run.evidence, run.evidence[1:])
		run.evidence[MaxEvidence-1] = ev
	} else {
		run.evidence = append(run.evidence, ev)
	}
}

func (s *shard) setCtx(run *seqRun, ev *event.Event) *rules.Ctx {
	s.ctx = rules.Ctx{Cur: ev, Bound: run.bound, Counts: run.counts, StartTS: run.start}
	return &s.ctx
}

func (s *shard) guardHit(r *rules.Rule, run *seqRun, ev *event.Event) bool {
	for i := range r.Guards[run.stage] {
		g := &r.Guards[run.stage][i]
		if g.Matches(s.setCtx(run, ev)) {
			return true
		}
	}
	return false
}

type stepOutcome uint8

const (
	outNone stepOutcome = iota
	outAbsorbed0
	outProgress
	outComplete
	outKilled
)

// stepRun feeds ev to run and reports what happened.
func (s *shard) stepRun(r *rules.Rule, run *seqRun, ev *event.Event) stepOutcome {
	if ev.Time > run.deadline {
		return outNone // timer will reap it
	}
	cur := &r.Positives[run.stage]
	if s.guardHit(r, run, ev) {
		return outKilled
	}
	satisfied := run.count >= cur.Min
	last := run.stage == len(r.Positives)-1
	if satisfied && !last {
		next := &r.Positives[run.stage+1]
		if next.Matches(s.setCtx(run, ev)) {
			run.stage++
			run.count = 0
			run.bind(r, next, ev)
			if run.count >= next.Min && run.stage == len(r.Positives)-1 && !r.IsAbsence() {
				return outComplete
			}
			return outProgress
		}
	}
	if cur.Max == 0 || run.count < cur.Max || (run.stage == 0 && run.times != nil) {
		if cur.Matches(s.setCtx(run, ev)) {
			stage0 := run.stage == 0
			run.bind(r, cur, ev)
			if stage0 && run.times != nil {
				s.retimeRun(r, run)
			}
			if last && run.count >= cur.Min && !r.IsAbsence() {
				return outComplete
			}
			if stage0 {
				return outAbsorbed0
			}
			return outProgress
		}
	}
	return outNone
}

// retimeRun recomputes the deadline of a stage-0 run from its oldest retained
// stage-0 timestamp.
func (s *shard) retimeRun(r *rules.Rule, run *seqRun) {
	if run.tLen == 0 {
		return
	}
	start := run.times[run.tHead]
	if start == run.start {
		return
	}
	run.start = start
	run.deadline = start + int64(r.Within)
	s.timers.Reset(run.timer, run.deadline)
}

func (s *shard) processSequence(ks *keyState, ri int, r *rules.Rule, ev *event.Event) {
	st := &ks.states[ri]
	absorbed0 := false
	kept := st.runs[:0]
	for _, run := range st.runs {
		if run.dead {
			continue
		}
		switch s.stepRun(r, run, ev) {
		case outKilled:
			s.killRun(run)
			continue
		case outComplete:
			s.completeRun(r, run, ev, ev.Time, ev)
			s.killRun(run)
			continue
		case outAbsorbed0:
			absorbed0 = true
		}
		kept = append(kept, run)
	}
	for i := len(kept); i < len(st.runs); i++ {
		st.runs[i] = nil
	}
	st.runs = kept

	if absorbed0 {
		return
	}
	first := &r.Positives[0]
	s.ctx = rules.Ctx{Cur: ev, StartTS: ev.Time}
	if !first.Matches(&s.ctx) {
		return
	}
	if len(st.runs) >= r.MaxRuns {
		s.killRun(st.runs[0])
		copy(st.runs, st.runs[1:])
		st.runs[len(st.runs)-1] = nil
		st.runs = st.runs[:len(st.runs)-1]
		s.stats.runEvicts.Add(1)
	}
	run := s.newRun(ks, ri, r, ev)
	run.bind(r, first, ev)
	if len(r.Positives) == 1 && run.count >= first.Min && !r.IsAbsence() {
		s.completeRun(r, run, ev, ev.Time, ev)
		s.killRun(run)
		return
	}
	st.runs = append(st.runs, run)
}

// onRunDeadline handles a run's deadline timer.
func (s *shard) onRunDeadline(run *seqRun, dl int64) {
	if run.dead {
		return
	}
	r := s.rs.Rules[run.ri]
	lastStage := len(r.Positives) - 1
	if run.stage == lastStage && run.count >= r.Positives[lastStage].Min && r.IsAbsence() {
		trigger := run.bound[r.Positives[lastStage].Index]
		s.completeRun(r, run, trigger, dl, nil)
		s.removeRun(run)
		return
	}
	if run.stage == 0 && run.tLen > 1 {
		// Slide the window: drop the oldest stage-0 event.
		run.tHead = (run.tHead + 1) % len(run.times)
		run.tLen--
		run.count--
		run.counts[r.Positives[0].Index]--
		run.start = run.times[run.tHead]
		run.deadline = run.start + int64(r.Within)
		if len(run.evidence) > 1 {
			copy(run.evidence, run.evidence[1:])
			run.evidence[len(run.evidence)-1] = nil
			run.evidence = run.evidence[:len(run.evidence)-1]
		}
		run.timer = s.timers.Schedule(run.deadline, timerRef{kind: timerRun, ks: run.ks, run: run})
		return
	}
	s.stats.runsExpired.Add(1)
	s.removeRun(run)
}

// removeRun kills a run and unlinks it from its rule state.
func (s *shard) removeRun(run *seqRun) {
	run.timer = 0 // already popped
	st := &run.ks.states[run.ri]
	for i, r := range st.runs {
		if r == run {
			copy(st.runs[i:], st.runs[i+1:])
			st.runs[len(st.runs)-1] = nil
			st.runs = st.runs[:len(st.runs)-1]
			break
		}
	}
	s.killRun(run)
}

func (s *shard) completeRun(r *rules.Rule, run *seqRun, cur *event.Event, at int64, trigger *event.Event) {
	if s.suppressed(run.ks, r, "", at) {
		return
	}
	ctx := s.setCtx(run, cur)
	fields := make(map[string]any, len(r.Emit)+1)
	for _, f := range r.Emit {
		fields[f.Name] = f.Expr(ctx).Interface()
	}
	fields["duration_ms"] = float64(at-run.start) / 1e6
	a := &Alert{
		ID:          r.Name + "-" + strconv.FormatUint(cur.Seq, 36) + "-" + strconv.FormatInt(at, 36),
		Rule:        r.Name,
		Fingerprint: r.Fingerprint,
		Kind:        r.Kind.String(),
		Severity:    r.Severity,
		Description: r.Description,
		Tags:        r.Tags,
		Key:         run.ks.key,
		EventTime:   at,
		Fields:      fields,
		Evidence:    append([]*event.Event(nil), run.evidence...),
	}
	if r.IsAbsence() {
		a.Kind = "absence"
	}
	if trigger != nil && trigger.Ingested > 0 {
		a.LatencyNs = timeNow() - trigger.Ingested
	}
	s.emit(a)
}
