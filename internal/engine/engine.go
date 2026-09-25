// Package engine is the Tempora temporal correlation engine.
//
// # Architecture
//
// Events are hash-partitioned by Key across N shards. Each shard is a single
// goroutine that exclusively owns all state for its keys (NFA runs, window
// buckets, timers, suppression), so the evaluation hot path takes no locks.
// Producers hand events to shards through bounded lock-free MPMC rings.
//
// Each shard maintains an event-time watermark:
//
//	watermark = max(observed event time) - AllowedLateness
//
// Events are buffered in a reorder heap and released in (time, seq) order once
// the watermark passes them; events older than the watermark are late and are
// dropped (counted). Timers (sequence expiry, absence deadlines, window
// closes) fire strictly in event-time order interleaved with released events,
// which makes evaluation deterministic regardless of arrival order within the
// lateness bound. When a shard goes idle its watermark advances with the wall
// clock (IdleAdvance) so that absence rules still fire without traffic.
package engine

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/metrics"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/ring"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/rules"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/sketch"
)

// Errors returned by Submit.
var (
	ErrClosed       = errors.New("engine: closed")
	ErrBackpressure = errors.New("engine: shard queue full")
)

// Config tunes the engine. Zero values are replaced by defaults.
type Config struct {
	// Shards is the number of shard goroutines (default GOMAXPROCS).
	Shards int
	// RingSize is the per-shard queue capacity (rounded to a power of two).
	RingSize int
	// BatchSize is the maximum number of items a shard drains per iteration.
	BatchSize int
	// AllowedLateness bounds out-of-order tolerance in event time.
	AllowedLateness time.Duration
	// IdleAdvance: when a shard receives nothing for this long (wall clock),
	// its event clock advances with the wall clock. 0 disables.
	IdleAdvance time.Duration
	// MaxReorder bounds the reorder buffer per shard; on overflow the oldest
	// event is force-released (advancing the watermark).
	MaxReorder int
	// MaxKeysPerShard bounds per-shard key state (LRU eviction beyond it).
	MaxKeysPerShard int
	// KeyTTL: idle keys with no live state are reclaimed after this much
	// event time (raised automatically to the largest rule suppress window).
	KeyTTL time.Duration
	// DropOnFull makes Submit fail fast with ErrBackpressure instead of
	// blocking when a shard queue is full.
	DropOnFull bool
	// AlertBuffer is the capacity of the alert channel.
	AlertBuffer int
	// LatencySampleShift samples 1 in 2^shift events for evaluation-latency
	// histograms (default 6 = 1/64).
	LatencySampleShift uint
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.Shards <= 0 {
		out.Shards = runtime.GOMAXPROCS(0)
	}
	if out.RingSize <= 0 {
		out.RingSize = 1 << 14
	}
	if out.BatchSize <= 0 {
		out.BatchSize = 256
	}
	if out.AllowedLateness < 0 {
		out.AllowedLateness = 0
	}
	if out.MaxReorder <= 0 {
		out.MaxReorder = 1 << 16
	}
	if out.MaxKeysPerShard <= 0 {
		out.MaxKeysPerShard = 1 << 18
	}
	if out.KeyTTL <= 0 {
		out.KeyTTL = 10 * time.Minute
	}
	if out.AlertBuffer <= 0 {
		out.AlertBuffer = 1 << 14
	}
	if out.LatencySampleShift == 0 {
		out.LatencySampleShift = 6
	}
	return out
}

// Metrics are engine-wide histograms (shared, sampled).
type Metrics struct {
	EvalLatency  *metrics.Histogram // seconds, per sampled event
	AlertLatency *metrics.Histogram // seconds, ingest -> alert
}

// Engine is the correlation engine. All methods are safe for concurrent use.
type Engine struct {
	cfg     Config
	shards  []*shard
	ruleset atomic.Pointer[rules.Ruleset]
	version atomic.Uint64
	seq     atomic.Uint64
	alerts  chan *Alert
	wg      sync.WaitGroup
	closed  atomic.Bool
	muted   atomic.Bool
	closeMu sync.RWMutex
	metrics Metrics

	ruleCounters sync.Map // rule name -> *atomic.Uint64
}

// New constructs and starts an engine with the given ruleset.
func New(cfg Config, rs *rules.Ruleset) *Engine {
	c := cfg.withDefaults()
	e := &Engine{
		cfg:    c,
		alerts: make(chan *Alert, c.AlertBuffer),
		metrics: Metrics{
			EvalLatency:  metrics.NewHistogram(metrics.ExponentialBuckets(250e-9, 2, 20)),
			AlertLatency: metrics.NewHistogram(metrics.ExponentialBuckets(1e-6, 2, 24)),
		},
	}
	if rs == nil {
		rs = &rules.Ruleset{}
	}
	e.storeRules(rs)
	e.shards = make([]*shard, c.Shards)
	for i := range e.shards {
		e.shards[i] = newShard(i, e)
	}
	for _, s := range e.shards {
		e.wg.Add(1)
		go func(s *shard) {
			defer e.wg.Done()
			s.run()
		}(s)
	}
	return e
}

func (e *Engine) storeRules(rs *rules.Ruleset) {
	rs.Version = e.version.Add(1)
	e.ruleset.Store(rs)
}

// Config returns the effective configuration.
func (e *Engine) Config() Config { return e.cfg }

// Metrics returns the shared latency histograms.
func (e *Engine) Metrics() *Metrics { return &e.metrics }

// Rules returns the active ruleset.
func (e *Engine) Rules() *rules.Ruleset { return e.ruleset.Load() }

// SetRules atomically swaps the ruleset. Shards migrate state on their next
// iteration: state of rules whose name and fingerprint are unchanged is
// preserved; state of removed or modified rules is discarded.
func (e *Engine) SetRules(rs *rules.Ruleset) {
	e.storeRules(rs)
	for _, s := range e.shards {
		s.in.TryPush(item{}) // wake; a nil item is a no-op
	}
}

// Alerts returns the channel on which alerts are delivered. It is closed
// after Close returns.
func (e *Engine) Alerts() <-chan *Alert { return e.alerts }

// SetMuted suppresses alert delivery (used during WAL replay to rebuild state
// without re-notifying). Muted alerts are still counted.
func (e *Engine) SetMuted(m bool) { e.muted.Store(m) }

// NextSeq reserves and returns the next sequence number.
func (e *Engine) NextSeq() uint64 { return e.seq.Add(1) }

// ObserveSeq raises the sequence counter to at least s (after WAL replay).
func (e *Engine) ObserveSeq(s uint64) {
	for {
		cur := e.seq.Load()
		if cur >= s || e.seq.CompareAndSwap(cur, s) {
			return
		}
	}
}

// ShardFor returns the shard index a key routes to.
func (e *Engine) ShardFor(key string) int {
	return int(sketch.Hash64(key) % uint64(len(e.shards)))
}

// Submit admits one validated event. The event must not be mutated
// afterwards.
func (e *Engine) Submit(ctx context.Context, ev *event.Event) error {
	e.closeMu.RLock()
	defer e.closeMu.RUnlock()
	if e.closed.Load() {
		return ErrClosed
	}
	return e.submitLocked(ctx, ev)
}

func (e *Engine) submitLocked(ctx context.Context, ev *event.Event) error {
	if ev.Seq == 0 {
		ev.Seq = e.seq.Add(1)
	}
	if ev.Ingested == 0 {
		ev.Ingested = time.Now().UnixNano()
	}
	s := e.shards[e.ShardFor(ev.Key)]
	it := item{ev: ev}
	if s.in.TryPush(it) {
		return nil
	}
	if e.cfg.DropOnFull {
		s.stats.rejected.Add(1)
		return ErrBackpressure
	}
	s.stats.blocked.Add(1)
	if err := s.in.Push(ctx, it); err != nil {
		if errors.Is(err, ring.ErrClosed) {
			return ErrClosed
		}
		return err
	}
	return nil
}

// SubmitBatch admits a batch; it stops at the first error and returns the
// number of events accepted.
func (e *Engine) SubmitBatch(ctx context.Context, evs []*event.Event) (int, error) {
	e.closeMu.RLock()
	defer e.closeMu.RUnlock()
	if e.closed.Load() {
		return 0, ErrClosed
	}
	for i, ev := range evs {
		if err := e.submitLocked(ctx, ev); err != nil {
			return i, err
		}
	}
	return len(evs), nil
}

func (e *Engine) broadcast(ctx context.Context, mk func() *control) error {
	e.closeMu.RLock()
	defer e.closeMu.RUnlock()
	if e.closed.Load() {
		return ErrClosed
	}
	ctls := make([]*control, len(e.shards))
	for i, s := range e.shards {
		c := mk()
		c.done = make(chan struct{})
		ctls[i] = c
		if err := s.in.Push(ctx, item{ctl: c}); err != nil {
			return err
		}
	}
	for _, c := range ctls {
		select {
		case <-c.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// Sync blocks until every event submitted before the call has been admitted
// by its shard, and released events have been evaluated.
func (e *Engine) Sync(ctx context.Context) error {
	return e.broadcast(ctx, func() *control { return &control{kind: ctlSync} })
}

// Advance raises every shard's watermark to at least ts (Unix ns), releasing
// buffered events and firing due timers. It is the event-time equivalent of
// a punctuation / heartbeat.
func (e *Engine) Advance(ctx context.Context, ts int64) error {
	return e.broadcast(ctx, func() *control { return &control{kind: ctlAdvance, ts: ts} })
}

// Flush releases every event held in shard reorder buffers by advancing each
// shard's watermark to just past the newest event it has observed. It is used
// at the end of WAL replay, while the engine is still muted, so that no
// replayed event is evaluated after alert delivery resumes (which would
// re-deliver pre-crash alerts). Live events older than the flushed watermark
// are subsequently treated as late.
func (e *Engine) Flush(ctx context.Context) error {
	return e.broadcast(ctx, func() *control { return &control{kind: ctlFlush} })
}

// Close stops accepting events, drains queued events and stops all shards.
// Pending timers are not fired (absence deadlines that have not been reached
// in event time are not reported).
func (e *Engine) Close() {
	e.closeMu.Lock()
	if e.closed.Swap(true) {
		e.closeMu.Unlock()
		return
	}
	e.closeMu.Unlock()
	for _, s := range e.shards {
		s.in.Close()
	}
	e.wg.Wait()
	close(e.alerts)
}

func (e *Engine) countRule(name string) {
	v, ok := e.ruleCounters.Load(name)
	if !ok {
		v, _ = e.ruleCounters.LoadOrStore(name, new(atomic.Uint64))
	}
	v.(*atomic.Uint64).Add(1)
}

// RuleMatches returns per-rule alert counts.
func (e *Engine) RuleMatches() map[string]uint64 {
	out := map[string]uint64{}
	e.ruleCounters.Range(func(k, v any) bool {
		out[k.(string)] = v.(*atomic.Uint64).Load()
		return true
	})
	return out
}

// ShardStats is a point-in-time snapshot of one shard.
type ShardStats struct {
	Shard       int    `json:"shard"`
	Queued      int    `json:"queued"`
	Processed   uint64 `json:"processed"`
	Late        uint64 `json:"late"`
	Rejected    uint64 `json:"rejected"`
	Blocked     uint64 `json:"blocked"`
	Alerts      uint64 `json:"alerts"`
	Suppressed  uint64 `json:"suppressed"`
	Muted       uint64 `json:"muted"`
	Keys        int64  `json:"keys"`
	KeyEvicts   uint64 `json:"key_evictions"`
	KeyExpired  uint64 `json:"key_expired"`
	Runs        int64  `json:"runs"`
	RunEvicts   uint64 `json:"run_evictions"`
	RunsExpired uint64 `json:"runs_expired"`
	Groups      int64  `json:"groups"`
	Timers      int64  `json:"timers"`
	Reorder     int64  `json:"reorder_buffered"`
	ForcedOut   uint64 `json:"reorder_forced"`
	Watermark   int64  `json:"watermark"`
	RuleVersion uint64 `json:"rule_version"`
}

// Stats returns a snapshot of every shard.
func (e *Engine) Stats() []ShardStats {
	out := make([]ShardStats, len(e.shards))
	for i, s := range e.shards {
		st := &s.stats
		out[i] = ShardStats{
			Shard: i, Queued: s.in.Len(), Processed: st.processed.Load(), Late: st.late.Load(),
			Rejected: st.rejected.Load(), Blocked: st.blocked.Load(), Alerts: st.alerts.Load(),
			Suppressed: st.suppressed.Load(), Muted: st.muted.Load(), Keys: st.keys.Load(),
			KeyEvicts: st.keyEvicts.Load(), KeyExpired: st.keyExpired.Load(), Runs: st.runs.Load(),
			RunEvicts: st.runEvicts.Load(), RunsExpired: st.runsExpired.Load(), Groups: st.groups.Load(),
			Timers: st.timers.Load(), Reorder: st.reorder.Load(), ForcedOut: st.forced.Load(),
			Watermark: st.watermark.Load(), RuleVersion: st.ruleVersion.Load(),
		}
	}
	return out
}

// NumShards returns the shard count.
func (e *Engine) NumShards() int { return len(e.shards) }

// ShardQueueDepth returns the queued item count of shard i.
func (e *Engine) ShardQueueDepth(i int) int { return e.shards[i].in.Len() }

// ShardProcessed returns the processed event count of shard i.
func (e *Engine) ShardProcessed(i int) uint64 { return e.shards[i].stats.processed.Load() }

// Totals sums shard stats.
func (e *Engine) Totals() ShardStats {
	var t ShardStats
	t.Shard = -1
	t.Watermark = 1<<63 - 1
	for _, s := range e.Stats() {
		t.Queued += s.Queued
		t.Processed += s.Processed
		t.Late += s.Late
		t.Rejected += s.Rejected
		t.Blocked += s.Blocked
		t.Alerts += s.Alerts
		t.Suppressed += s.Suppressed
		t.Muted += s.Muted
		t.Keys += s.Keys
		t.KeyEvicts += s.KeyEvicts
		t.KeyExpired += s.KeyExpired
		t.Runs += s.Runs
		t.RunEvicts += s.RunEvicts
		t.RunsExpired += s.RunsExpired
		t.Groups += s.Groups
		t.Timers += s.Timers
		t.Reorder += s.Reorder
		t.ForcedOut += s.ForcedOut
		if s.Watermark < t.Watermark {
			t.Watermark = s.Watermark
		}
		t.RuleVersion = s.RuleVersion
	}
	return t
}

func (e *Engine) String() string {
	return fmt.Sprintf("engine(shards=%d ring=%d lateness=%s)", len(e.shards), e.cfg.RingSize, e.cfg.AllowedLateness)
}
