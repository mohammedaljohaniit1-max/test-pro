// Command tempora runs the Tempora temporal correlation engine server.
//
// Startup sequence:
//  1. load configuration (env TEMPORA_* <- flags) and compile rules
//  2. start the engine muted, replay the WAL to rebuild in-memory state
//     (alerts produced during replay are counted but not re-delivered)
//  3. unmute, open the WAL for appends, start sinks, HTTP and TCP listeners
//  4. mark ready
//
// Shutdown on SIGINT/SIGTERM: mark unready, stop listeners (draining
// in-flight requests within the grace period), close the engine (drains
// shard queues), drain sinks, fsync and close the WAL. SIGHUP reloads rules.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/config"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/engine"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/metrics"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/rules"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/server"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/sink"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/wal"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "check" {
		os.Exit(check(os.Args[2:], os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "probe" {
		os.Exit(probe(os.Args[2:], os.Stderr))
	}
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println("tempora", server.Version)
		return
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tempora:", err)
		os.Exit(1)
	}
}

// check compiles rule files and reports errors (CI / pre-commit usage).
func check(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		args = []string{"rules"}
	}
	rs, err := rules.CompileFiles(args...)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	for _, r := range rs.Rules {
		fmt.Fprintf(stdout, "ok  %-28s %-9s %-8s %s\n", r.Name, r.Kind, r.Severity, r.Fingerprint)
	}
	return 0
}

// probe performs an HTTP readiness check against a running instance. It lets
// shell-less (distroless) images implement container health checks:
//
//	tempora probe [http://127.0.0.1:8080/readyz]
func probe(args []string, stderr io.Writer) int {
	url := "http://127.0.0.1:8080/readyz"
	if len(args) > 0 {
		url = args[0]
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		fmt.Fprintln(stderr, "probe:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "probe: status", resp.StatusCode)
		return 1
	}
	return 0
}

func newLogger(level, format string, w io.Writer) *slog.Logger {
	var lv slog.Level
	_ = lv.UnmarshalText([]byte(strings.ToUpper(level)))
	opts := &slog.HandlerOptions{Level: lv}
	if format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

func run(args []string) error {
	cfg, err := config.Load(args, nil)
	if err != nil {
		return err
	}
	// Logs go to stderr; stdout is reserved for the alert stream.
	log := newLogger(cfg.LogLevel, cfg.LogFormat, os.Stderr)
	started := time.Now()

	rs, err := rules.CompileFiles(cfg.RulesPath)
	if err != nil {
		return fmt.Errorf("compile rules: %w", err)
	}
	log.Info("rules compiled", "path", cfg.RulesPath, "rules", len(rs.Rules))

	eng := engine.New(engine.Config{
		Shards: cfg.Shards, RingSize: cfg.RingSize, BatchSize: cfg.BatchSize,
		AllowedLateness: cfg.AllowedLateness, IdleAdvance: cfg.IdleAdvance,
		MaxKeysPerShard: cfg.MaxKeysPerShard, KeyTTL: cfg.KeyTTL, DropOnFull: cfg.DropOnFull,
	}, rs)
	log.Info("engine started", "engine", eng.String())

	// Sinks.
	hub := sink.NewHub(cfg.HubSize)
	sinks := []sink.Sink{hub}
	switch cfg.AlertLog {
	case "":
	case "stdout", "-":
		sinks = append(sinks, sink.NewJSONLines("stdout", os.Stdout))
	default:
		fs, err := sink.OpenJSONLinesFile(cfg.AlertLog)
		if err != nil {
			return fmt.Errorf("open alert log: %w", err)
		}
		sinks = append(sinks, fs)
	}
	if cfg.WebhookURL != "" {
		wh, err := sink.NewWebhook(sink.WebhookOptions{URL: cfg.WebhookURL, Secret: cfg.WebhookSecret, MaxRetries: 4})
		if err != nil {
			return err
		}
		sinks = append(sinks, wh)
	}
	disp := sink.NewDispatcher(log, cfg.SinkQueue, sinks...)

	// WAL replay (muted) then open for append.
	var wlog *wal.Log
	if cfg.WALDir != "" {
		if cfg.Replay {
			eng.SetMuted(true)
			t0 := time.Now()
			ctx := context.Background()
			rstats, err := wal.Replay(cfg.WALDir, 0, func(ev *event.Event) error {
				eng.ObserveSeq(ev.Seq)
				return eng.Submit(ctx, ev)
			})
			if err != nil {
				return fmt.Errorf("wal replay: %w", err)
			}
			if err := eng.Flush(ctx); err != nil {
				return err
			}
			eng.SetMuted(false)
			log.Info("wal replayed", "records", rstats.Records, "segments", rstats.Segments,
				"torn_bytes", rstats.TornBytes, "last_seq", rstats.LastSeq, "took", time.Since(t0).String())
		}
		wlog, err = wal.Open(wal.Options{
			Dir: cfg.WALDir, SegmentBytes: cfg.WALSegment, Sync: cfg.WALSync,
			SyncEvery: cfg.WALSyncEvery, Retain: cfg.WALRetain,
		})
		if err != nil {
			return fmt.Errorf("open wal: %w", err)
		}
		eng.ObserveSeq(wlog.LastSeq())
		log.Info("wal opened", "dir", cfg.WALDir, "sync", cfg.WALSync.String(), "last_seq", wlog.LastSeq())
	}

	dispCtx, dispCancel := context.WithCancel(context.Background())
	defer dispCancel()
	dispDone := make(chan struct{})
	go func() {
		defer close(dispDone)
		disp.Run(dispCtx, eng.Alerts())
	}()

	ing := server.NewIngestor(eng, wlog)
	api := &server.API{
		Engine: eng, Ingest: ing, Hub: hub, Dispatcher: disp, WAL: wlog,
		Registry: metrics.NewRegistry(), Log: log, RulesPath: cfg.RulesPath,
		AuthToken: cfg.AuthToken, MaxBodyBytes: cfg.MaxBodyBytes, EnablePprof: cfg.EnablePprof,
		Started: started,
	}

	var tcp *server.TCPServer
	if cfg.TCPAddr != "" {
		tcp = &server.TCPServer{Addr: cfg.TCPAddr, Ingest: ing, Log: log, BatchSize: cfg.BatchSize}
		if err := tcp.Listen(); err != nil {
			return fmt.Errorf("tcp listen: %w", err)
		}
		api.TCP = tcp
	}
	api.RegisterMetrics()

	hs := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	ln, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("http listen: %w", err)
	}

	errc := make(chan error, 2)
	go func() {
		log.Info("http listening", "addr", ln.Addr().String())
		if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("http: %w", err)
		}
	}()
	serveCtx, serveCancel := context.WithCancel(context.Background())
	defer serveCancel()
	if tcp != nil {
		go func() {
			log.Info("tcp ingest listening", "addr", tcp.ListenAddr())
			if err := tcp.Serve(serveCtx); err != nil {
				errc <- fmt.Errorf("tcp: %w", err)
			}
		}()
	}
	api.SetReady(true)
	log.Info("tempora ready", "startup", time.Since(started).String())

	sigc := make(chan os.Signal, 4)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	var runErr error
loop:
	for {
		select {
		case sig := <-sigc:
			if sig == syscall.SIGHUP {
				nrs, err := rules.CompileFiles(cfg.RulesPath)
				if err != nil {
					log.Error("rule reload failed; keeping current ruleset", "err", err)
					continue
				}
				eng.SetRules(nrs)
				log.Info("rules reloaded", "rules", len(nrs.Rules), "version", nrs.Version)
				continue
			}
			log.Info("shutdown requested", "signal", sig.String())
			break loop
		case err := <-errc:
			runErr = err
			log.Error("listener failed; shutting down", "err", err)
			break loop
		}
	}

	api.SetReady(false)
	shCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	if err := hs.Shutdown(shCtx); err != nil {
		log.Warn("http shutdown", "err", err)
	}
	serveCancel()
	if tcp != nil {
		_ = tcp.Close()
	}
	eng.Close() // drains shards; closes alert channel
	select {
	case <-dispDone:
	case <-shCtx.Done():
		log.Warn("sink drain timed out")
		dispCancel()
		<-dispDone
	}
	if wlog != nil {
		if err := wlog.Close(); err != nil {
			log.Warn("wal close", "err", err)
		}
	}
	t := eng.Totals()
	log.Info("tempora stopped", "processed", t.Processed, "alerts", t.Alerts, "late", t.Late, "uptime", time.Since(started).String())
	return runErr
}
