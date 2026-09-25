package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/pprof"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/engine"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/metrics"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/rules"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/sink"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/wal"
)

// Version is stamped at build time via -ldflags.
var Version = "dev"

// API bundles the dependencies of the HTTP handlers.
type API struct {
	Engine       *engine.Engine
	Ingest       *Ingestor
	Hub          *sink.Hub
	Dispatcher   *sink.Dispatcher
	WAL          *wal.Log
	TCP          *TCPServer
	Registry     *metrics.Registry
	Log          *slog.Logger
	RulesPath    string
	AuthToken    string
	MaxBodyBytes int64
	EnablePprof  bool
	Started      time.Time

	ready atomic.Bool
}

// SetReady flips the readiness probe.
func (a *API) SetReady(v bool) { a.ready.Store(v) }

// Handler builds the HTTP routing table.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.healthz)
	mux.HandleFunc("GET /readyz", a.readyz)
	mux.HandleFunc("GET /metrics", a.metrics)
	mux.HandleFunc("POST /v1/events", a.auth(a.ingest))
	mux.HandleFunc("POST /v1/advance", a.auth(a.advance))
	mux.HandleFunc("GET /v1/alerts", a.alerts)
	mux.HandleFunc("GET /v1/alerts/stream", a.stream)
	mux.HandleFunc("GET /v1/rules", a.listRules)
	mux.HandleFunc("PUT /v1/rules", a.auth(a.putRules))
	mux.HandleFunc("POST /v1/rules/reload", a.auth(a.reloadRules))
	mux.HandleFunc("POST /v1/rules/validate", a.validateRules)
	mux.HandleFunc("GET /v1/stats", a.stats)
	mux.HandleFunc("GET /", a.index)
	if a.EnablePprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
	return a.recoverer(mux)
}

func (a *API) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				buf := make([]byte, 8<<10)
				buf = buf[:runtime.Stack(buf, false)]
				a.Log.Error("http handler panic", "path", r.URL.Path, "panic", fmt.Sprint(v), "stack", string(buf))
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (a *API) auth(h http.HandlerFunc) http.HandlerFunc {
	if a.AuthToken == "" {
		return h
	}
	want := []byte("Bearer " + a.AuthToken)
	return func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="tempora"`)
			writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		h(w, r)
	}
}

// writeJSON encodes before writing the status line so that an encoding
// failure yields a 500 instead of a truncated 2xx body.
func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "{\"error\":%q}\n", "response encoding failed: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// finite maps NaN/Inf (empty histograms) to nil, since JSON cannot encode them.
func finite(f float64) any {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil
	}
	return f
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func (a *API) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": Version})
}

func (a *API) readyz(w http.ResponseWriter, _ *http.Request) {
	if !a.ready.Load() {
		writeError(w, http.StatusServiceUnavailable, "not ready (replaying or shutting down)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

func (a *API) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "tempora",
		"version": Version,
		"endpoints": []string{
			"POST /v1/events", "POST /v1/advance", "GET /v1/alerts", "GET /v1/alerts/stream",
			"GET /v1/rules", "PUT /v1/rules", "POST /v1/rules/reload", "POST /v1/rules/validate",
			"GET /v1/stats", "GET /metrics", "GET /healthz", "GET /readyz",
		},
	})
}

// ingest accepts either a JSON array, a single JSON object, or NDJSON
// (Content-Type application/x-ndjson, or any body whose first non-space byte
// is '{' followed by multiple lines). Response reports per-line errors
// (first 20) and counts. Partial acceptance returns 207-like semantics via
// 200 with rejected > 0; full backpressure returns 429.
func (a *API) ingest(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, a.MaxBodyBytes)
	defer body.Close()
	now := time.Now()
	var (
		evs  []*event.Event
		errs []string
		bad  int
	)
	addErr := func(i int, err error) {
		bad++
		if len(errs) < 20 {
			errs = append(errs, fmt.Sprintf("event %d: %v", i, err))
		}
	}
	br := bufio.NewReaderSize(body, 64<<10)
	first, err := peekNonSpace(br)
	if err != nil {
		if errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "empty body")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ndjson := strings.Contains(r.Header.Get("Content-Type"), "ndjson")
	switch {
	case first == '[' && !ndjson:
		dec := json.NewDecoder(br)
		dec.UseNumber()
		var wires []event.Wire
		if err := dec.Decode(&wires); err != nil {
			writeError(w, statusForBodyErr(err), "invalid JSON array: "+err.Error())
			return
		}
		evs = make([]*event.Event, 0, len(wires))
		for i := range wires {
			ev, err := event.FromWire(&wires[i], now)
			if err != nil {
				addErr(i, err)
				continue
			}
			evs = append(evs, ev)
		}
	default:
		i := 0
		for {
			line, err := readLine(br, event.MaxEncodedSize)
			if len(line) > 0 {
				ev, perr := event.ParseJSON(line, now)
				if perr != nil {
					addErr(i, perr)
				} else {
					evs = append(evs, ev)
				}
				i++
			}
			if err != nil {
				if errors.Is(err, errLineTooLong) {
					addErr(i, err)
					i++
					continue
				}
				if !errors.Is(err, io.EOF) {
					writeError(w, statusForBodyErr(err), err.Error())
					return
				}
				break
			}
		}
	}
	a.Ingest.CountInvalid(bad)
	accepted, err := a.Ingest.Admit(r.Context(), evs)
	resp := map[string]any{"accepted": accepted, "invalid": bad, "rejected": len(evs) - accepted}
	if len(errs) > 0 {
		resp["errors"] = errs
	}
	if err != nil {
		resp["error"] = err.Error()
		status := http.StatusServiceUnavailable
		if errors.Is(err, engine.ErrBackpressure) {
			status = http.StatusTooManyRequests
			w.Header().Set("Retry-After", "1")
		}
		writeJSON(w, status, resp)
		return
	}
	status := http.StatusAccepted
	if accepted == 0 && bad > 0 {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, resp)
}

func statusForBodyErr(err error) int {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

func peekNonSpace(r *bufio.Reader) (byte, error) {
	for {
		b, err := r.Peek(1)
		if err != nil {
			return 0, err
		}
		switch b[0] {
		case ' ', '\t', '\r', '\n':
			_, _ = r.ReadByte()
		default:
			return b[0], nil
		}
	}
}

// advance: {"ts": <RFC3339 | unix>} or {"now": true}.
func (a *API) advance(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TS  json.RawMessage `json:"ts"`
		Now bool            `json:"now"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	var ts int64
	if req.Now {
		ts = time.Now().UnixNano()
	} else {
		probe := event.Wire{Type: "_", TS: req.TS}
		if len(req.TS) == 0 {
			writeError(w, http.StatusBadRequest, "ts or now required")
			return
		}
		ev, err := event.FromWire(&probe, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		ts = ev.Time
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := a.Engine.Advance(ctx, ts); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"watermark": time.Unix(0, ts).UTC().Format(time.RFC3339Nano)})
}

func (a *API) alerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 100
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 10000 {
			writeError(w, http.StatusBadRequest, "limit must be in [1,10000]")
			return
		}
		limit = n
	}
	list := a.Hub.Recent(limit, q.Get("rule"), q.Get("key"))
	writeJSON(w, http.StatusOK, map[string]any{"count": len(list), "alerts": list})
}

// stream is a Server-Sent Events feed of live alerts.
func (a *API) stream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	rule := r.URL.Query().Get("rule")
	ch, cancel := a.Hub.Subscribe(1024)
	defer cancel()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()
	hb := time.NewTicker(15 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-hb.C:
			fmt.Fprint(w, ": heartbeat\n\n")
			fl.Flush()
		case al, ok := <-ch:
			if !ok {
				return
			}
			if rule != "" && al.Rule != rule {
				continue
			}
			b, err := json.Marshal(al)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "id: %s\nevent: alert\ndata: %s\n\n", al.ID, b)
			fl.Flush()
		}
	}
}

type ruleView struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Fingerprint string   `json:"fingerprint"`
	Within      string   `json:"within,omitempty"`
	Over        string   `json:"over,omitempty"`
	Buckets     int      `json:"buckets,omitempty"`
	Steps       int      `json:"steps,omitempty"`
	Absence     bool     `json:"absence,omitempty"`
	Matches     uint64   `json:"matches"`
	Source      string   `json:"source"`
}

func (a *API) listRules(w http.ResponseWriter, _ *http.Request) {
	rs := a.Engine.Rules()
	counts := a.Engine.RuleMatches()
	out := make([]ruleView, 0, len(rs.Rules))
	for _, r := range rs.Rules {
		v := ruleView{
			Name: r.Name, Kind: r.Kind.String(), Severity: r.Severity, Description: r.Description,
			Tags: r.Tags, Fingerprint: r.Fingerprint, Matches: counts[r.Name], Source: r.Source,
		}
		if r.Kind == rules.KindSequence {
			v.Within, v.Steps, v.Absence = r.Within.String(), r.NumSlots, r.IsAbsence()
		} else {
			v.Over, v.Buckets = r.Over.String(), r.NumBuckets
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": rs.Version, "loaded_at": rs.LoadedAt, "rules": out})
}

func (a *API) readRuleBody(w http.ResponseWriter, r *http.Request) (*rules.Ruleset, bool) {
	src, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, statusForBodyErr(err), err.Error())
		return nil, false
	}
	rs, err := rules.Compile(string(bytes.TrimSpace(src)))
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "compile failed", "detail": err.Error()})
		return nil, false
	}
	return rs, true
}

func (a *API) validateRules(w http.ResponseWriter, r *http.Request) {
	rs, ok := a.readRuleBody(w, r)
	if !ok {
		return
	}
	names := make([]string, len(rs.Rules))
	for i, rr := range rs.Rules {
		names[i] = rr.Name
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "rules": names})
}

func (a *API) putRules(w http.ResponseWriter, r *http.Request) {
	rs, ok := a.readRuleBody(w, r)
	if !ok {
		return
	}
	a.Engine.SetRules(rs)
	a.Log.Info("ruleset replaced via API", "rules", len(rs.Rules), "version", rs.Version)
	writeJSON(w, http.StatusOK, map[string]any{"version": rs.Version, "rules": len(rs.Rules)})
}

func (a *API) reloadRules(w http.ResponseWriter, _ *http.Request) {
	rs, err := rules.CompileFiles(a.RulesPath)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "compile failed", "detail": err.Error()})
		return
	}
	a.Engine.SetRules(rs)
	a.Log.Info("ruleset reloaded from disk", "path", a.RulesPath, "rules", len(rs.Rules), "version", rs.Version)
	writeJSON(w, http.StatusOK, map[string]any{"version": rs.Version, "rules": len(rs.Rules)})
}

func (a *API) stats(w http.ResponseWriter, _ *http.Request) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	tot := a.Engine.Totals()
	m := a.Engine.Metrics()
	resp := map[string]any{
		"version":    Version,
		"uptime_s":   time.Since(a.Started).Seconds(),
		"engine":     tot,
		"shards":     a.Engine.Stats(),
		"ingest":     a.Ingest.Stats(),
		"rules":      a.Engine.RuleMatches(),
		"goroutines": runtime.NumGoroutine(),
		"memory": map[string]any{
			"heap_alloc_bytes": ms.HeapAlloc, "heap_inuse_bytes": ms.HeapInuse,
			"sys_bytes": ms.Sys, "gc_cycles": ms.NumGC, "gc_pause_total_ns": ms.PauseTotalNs,
		},
		"latency": map[string]any{
			"eval_p50_us":  finite(m.EvalLatency.Quantile(0.5) * 1e6),
			"eval_p99_us":  finite(m.EvalLatency.Quantile(0.99) * 1e6),
			"alert_p50_us": finite(m.AlertLatency.Quantile(0.5) * 1e6),
			"alert_p99_us": finite(m.AlertLatency.Quantile(0.99) * 1e6),
		},
	}
	if a.Dispatcher != nil {
		resp["sinks"] = a.Dispatcher.Stats()
	}
	if a.WAL != nil {
		resp["wal"] = a.WAL.Stats()
	}
	if a.TCP != nil {
		resp["tcp_connections"] = a.TCP.Connections()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *API) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if err := a.Registry.WritePrometheus(w); err != nil {
		a.Log.Warn("metrics write failed", "err", err)
	}
}

// RegisterMetrics exposes engine, ingest, WAL and sink state as Prometheus
// series sampled at scrape time.
func (a *API) RegisterMetrics() {
	reg := a.Registry
	e := a.Engine
	total := func(f func(engine.ShardStats) float64) func() float64 {
		return func() float64 { return f(e.Totals()) }
	}
	reg.CounterFunc("tempora_events_processed_total", "Events evaluated by shards.", total(func(s engine.ShardStats) float64 { return float64(s.Processed) }))
	reg.CounterFunc("tempora_events_late_total", "Events dropped for arriving behind the watermark.", total(func(s engine.ShardStats) float64 { return float64(s.Late) }))
	reg.CounterFunc("tempora_events_backpressure_total", "Events rejected because a shard queue was full.", total(func(s engine.ShardStats) float64 { return float64(s.Rejected) }))
	reg.CounterFunc("tempora_events_blocked_total", "Submissions that had to wait for shard queue space.", total(func(s engine.ShardStats) float64 { return float64(s.Blocked) }))
	reg.CounterFunc("tempora_alerts_total", "Alerts produced (including muted during replay).", total(func(s engine.ShardStats) float64 { return float64(s.Alerts) }))
	reg.CounterFunc("tempora_alerts_suppressed_total", "Matches suppressed by rule suppression windows.", total(func(s engine.ShardStats) float64 { return float64(s.Suppressed) }))
	reg.CounterFunc("tempora_key_evictions_total", "Keys evicted by the per-shard LRU cap.", total(func(s engine.ShardStats) float64 { return float64(s.KeyEvicts) }))
	reg.CounterFunc("tempora_key_expired_total", "Idle keys reclaimed by TTL.", total(func(s engine.ShardStats) float64 { return float64(s.KeyExpired) }))
	reg.CounterFunc("tempora_run_evictions_total", "Partial matches evicted by max_runs / group caps.", total(func(s engine.ShardStats) float64 { return float64(s.RunEvicts) }))
	reg.CounterFunc("tempora_reorder_forced_total", "Watermark advances forced by reorder buffer overflow.", total(func(s engine.ShardStats) float64 { return float64(s.ForcedOut) }))
	reg.GaugeFunc("tempora_keys", "Live partition keys.", total(func(s engine.ShardStats) float64 { return float64(s.Keys) }))
	reg.GaugeFunc("tempora_runs", "Live sequence partial matches.", total(func(s engine.ShardStats) float64 { return float64(s.Runs) }))
	reg.GaugeFunc("tempora_groups", "Live aggregate window groups.", total(func(s engine.ShardStats) float64 { return float64(s.Groups) }))
	reg.GaugeFunc("tempora_timers", "Pending event-time timers.", total(func(s engine.ShardStats) float64 { return float64(s.Timers) }))
	reg.GaugeFunc("tempora_reorder_buffered", "Events buffered awaiting the watermark.", total(func(s engine.ShardStats) float64 { return float64(s.Reorder) }))
	reg.GaugeFunc("tempora_rule_version", "Active ruleset version.", total(func(s engine.ShardStats) float64 { return float64(s.RuleVersion) }))
	reg.GaugeFunc("tempora_watermark_lag_seconds", "Wall clock minus the minimum shard watermark.", func() float64 {
		wm := e.Totals().Watermark
		if wm <= 0 || wm == 1<<63-1 {
			return 0
		}
		return time.Since(time.Unix(0, wm)).Seconds()
	})
	for i := 0; i < e.NumShards(); i++ {
		idx := i
		lbl := strconv.Itoa(i)
		reg.GaugeFunc("tempora_shard_queue_depth", "Items queued per shard.", func() float64 { return float64(e.ShardQueueDepth(idx)) }, "shard", lbl)
		reg.CounterFunc("tempora_shard_processed_total", "Events processed per shard.", func() float64 { return float64(e.ShardProcessed(idx)) }, "shard", lbl)
	}
	in := a.Ingest
	reg.CounterFunc("tempora_ingest_accepted_total", "Events accepted by the ingest path.", func() float64 { return float64(in.Stats().Accepted) })
	reg.CounterFunc("tempora_ingest_invalid_total", "Events rejected by validation.", func() float64 { return float64(in.Stats().Invalid) })
	reg.CounterFunc("tempora_ingest_rejected_total", "Valid events rejected (journal error / backpressure / shutdown).", func() float64 { return float64(in.Stats().Rejected) })
	m := e.Metrics()
	for _, q := range []float64{0.5, 0.9, 0.99, 0.999} {
		qq := q
		ql := strconv.FormatFloat(q, 'f', -1, 64)
		reg.GaugeFunc("tempora_eval_latency_seconds", "Sampled per-event evaluation latency (quantile estimate).", func() float64 { return m.EvalLatency.Quantile(qq) }, "quantile", ql)
		reg.GaugeFunc("tempora_alert_latency_seconds", "Ingest-to-alert latency (quantile estimate).", func() float64 { return m.AlertLatency.Quantile(qq) }, "quantile", ql)
	}
	if a.WAL != nil {
		wl := a.WAL
		reg.GaugeFunc("tempora_wal_bytes", "Bytes on disk across WAL segments.", func() float64 { return float64(wl.Stats().Bytes) })
		reg.GaugeFunc("tempora_wal_segments", "WAL segment count.", func() float64 { return float64(wl.Stats().Segments) })
		reg.CounterFunc("tempora_wal_records_total", "Records appended to the WAL.", func() float64 { return float64(wl.Stats().Records) })
		reg.CounterFunc("tempora_wal_fsyncs_total", "WAL fsync calls.", func() float64 { return float64(wl.Stats().Syncs) })
	}
	if a.Dispatcher != nil {
		d := a.Dispatcher
		for i, st := range d.Stats() {
			idx := i
			reg.CounterFunc("tempora_sink_delivered_total", "Alerts delivered per sink.", func() float64 { return float64(d.Stats()[idx].Delivered) }, "sink", st.Name)
			reg.CounterFunc("tempora_sink_failed_total", "Failed deliveries per sink.", func() float64 { return float64(d.Stats()[idx].Failed) }, "sink", st.Name)
			reg.CounterFunc("tempora_sink_dropped_total", "Alerts dropped due to full sink queue.", func() float64 { return float64(d.Stats()[idx].Dropped) }, "sink", st.Name)
		}
	}
	reg.GaugeFunc("tempora_go_goroutines", "Goroutines.", func() float64 { return float64(runtime.NumGoroutine()) })
	reg.GaugeFunc("tempora_go_heap_inuse_bytes", "Go heap in use.", func() float64 {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return float64(ms.HeapInuse)
	})
	start := a.Started
	reg.GaugeFunc("tempora_uptime_seconds", "Process uptime.", func() float64 { return time.Since(start).Seconds() })
}
