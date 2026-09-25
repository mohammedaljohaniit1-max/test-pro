// Package server exposes the engine over HTTP (JSON / NDJSON ingest, query
// API, SSE alert stream, Prometheus metrics, rule management) and a raw TCP
// NDJSON ingest listener.
package server

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/engine"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/wal"
)

// Ingestor is the single admission path for events. It assigns sequence
// numbers and journals batches to the WAL under one mutex so the log is
// strictly seq-ordered (a precondition for deterministic replay and
// seq-based truncation), then hands events to the engine outside the lock.
type Ingestor struct {
	eng *engine.Engine
	log *wal.Log // may be nil

	mu sync.Mutex

	accepted atomic.Uint64
	invalid  atomic.Uint64
	rejected atomic.Uint64
	batches  atomic.Uint64
}

// NewIngestor wires an ingestor. log may be nil (no durability).
func NewIngestor(eng *engine.Engine, log *wal.Log) *Ingestor {
	return &Ingestor{eng: eng, log: log}
}

// IngestStats is a counter snapshot.
type IngestStats struct {
	Accepted uint64 `json:"accepted"`
	Invalid  uint64 `json:"invalid"`
	Rejected uint64 `json:"rejected"`
	Batches  uint64 `json:"batches"`
}

// Stats returns counters.
func (in *Ingestor) Stats() IngestStats {
	return IngestStats{
		Accepted: in.accepted.Load(), Invalid: in.invalid.Load(),
		Rejected: in.rejected.Load(), Batches: in.batches.Load(),
	}
}

// CountInvalid records n events rejected by validation before Admit.
func (in *Ingestor) CountInvalid(n int) { in.invalid.Add(uint64(n)) }

// Admit journals and submits a batch of validated events. It returns the
// number of events accepted by the engine.
//
// Sequence assignment, journaling and shard hand-off all happen inside one
// critical section when journaling is enabled. This guarantees that the per-key arrival order observed
// by shards equals WAL order, so replay reproduces the exact same state even
// with zero allowed lateness. Hand-off is a lock-free ring push (tens of ns),
// so the critical section is dominated by the buffered WAL write.
func (in *Ingestor) Admit(ctx context.Context, evs []*event.Event) (int, error) {
	if len(evs) == 0 {
		return 0, nil
	}
	in.batches.Add(1)
	if in.log != nil {
		in.mu.Lock()
		defer in.mu.Unlock()
		for _, ev := range evs {
			ev.Seq = in.eng.NextSeq()
		}
		if err := in.log.AppendBatch(evs); err != nil {
			in.rejected.Add(uint64(len(evs)))
			return 0, fmt.Errorf("journal: %w", err)
		}
	}
	n, err := in.eng.SubmitBatch(ctx, evs)
	in.accepted.Add(uint64(n))
	if err != nil {
		in.rejected.Add(uint64(len(evs) - n))
		return n, err
	}
	return n, nil
}

// ErrBackpressure is re-exported for HTTP status mapping.
var ErrBackpressure = engine.ErrBackpressure
