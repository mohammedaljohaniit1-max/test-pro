// Package sink delivers alerts to downstream systems.
//
// The Dispatcher reads the engine's alert channel and fans each alert out to
// every registered Sink through a dedicated bounded queue and worker per sink,
// so a slow or failing sink (e.g. an unreachable webhook) can never stall the
// engine or the other sinks. When a sink queue is full the alert is dropped
// for that sink and counted.
package sink

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/engine"
)

// Sink consumes alerts. Deliver is called from a single goroutine per sink.
type Sink interface {
	Name() string
	Deliver(ctx context.Context, a *engine.Alert) error
	Close() error
}

// Stats counts per-sink outcomes.
type Stats struct {
	Name      string `json:"name"`
	Delivered uint64 `json:"delivered"`
	Failed    uint64 `json:"failed"`
	Dropped   uint64 `json:"dropped"`
	Queued    int    `json:"queued"`
}

type worker struct {
	sink      Sink
	q         chan *engine.Alert
	delivered atomic.Uint64
	failed    atomic.Uint64
	dropped   atomic.Uint64
}

// Dispatcher fans alerts out to sinks.
type Dispatcher struct {
	workers []*worker
	log     *slog.Logger
	wg      sync.WaitGroup
	total   atomic.Uint64
}

// NewDispatcher creates a dispatcher with a per-sink queue of queueSize.
func NewDispatcher(log *slog.Logger, queueSize int, sinks ...Sink) *Dispatcher {
	if queueSize <= 0 {
		queueSize = 4096
	}
	d := &Dispatcher{log: log}
	for _, s := range sinks {
		d.workers = append(d.workers, &worker{sink: s, q: make(chan *engine.Alert, queueSize)})
	}
	return d
}

// Run consumes alerts until the channel is closed, then drains every sink
// queue and closes the sinks. ctx cancellation aborts in-flight deliveries.
func (d *Dispatcher) Run(ctx context.Context, alerts <-chan *engine.Alert) {
	for _, w := range d.workers {
		d.wg.Add(1)
		go func(w *worker) {
			defer d.wg.Done()
			for a := range w.q {
				if err := w.sink.Deliver(ctx, a); err != nil {
					w.failed.Add(1)
					d.log.Warn("alert delivery failed", "sink", w.sink.Name(), "rule", a.Rule, "err", err)
					continue
				}
				w.delivered.Add(1)
			}
		}(w)
	}
	for a := range alerts {
		d.total.Add(1)
		for _, w := range d.workers {
			select {
			case w.q <- a:
			default:
				w.dropped.Add(1)
			}
		}
	}
	for _, w := range d.workers {
		close(w.q)
	}
	d.wg.Wait()
	for _, w := range d.workers {
		if err := w.sink.Close(); err != nil {
			d.log.Warn("sink close failed", "sink", w.sink.Name(), "err", err)
		}
	}
}

// Total returns the number of alerts dispatched.
func (d *Dispatcher) Total() uint64 { return d.total.Load() }

// Stats returns per-sink counters.
func (d *Dispatcher) Stats() []Stats {
	out := make([]Stats, len(d.workers))
	for i, w := range d.workers {
		out[i] = Stats{
			Name: w.sink.Name(), Delivered: w.delivered.Load(), Failed: w.failed.Load(),
			Dropped: w.dropped.Load(), Queued: len(w.q),
		}
	}
	return out
}
