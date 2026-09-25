// Package config loads Tempora configuration from environment variables
// (12-factor) with command-line flag overrides.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/wal"
)

// Config is the full process configuration.
type Config struct {
	HTTPAddr        string
	TCPAddr         string
	RulesPath       string
	Shards          int
	RingSize        int
	BatchSize       int
	AllowedLateness time.Duration
	IdleAdvance     time.Duration
	MaxKeysPerShard int
	KeyTTL          time.Duration
	DropOnFull      bool

	WALDir       string
	WALSync      wal.SyncMode
	WALSyncEvery time.Duration
	WALSegment   int64
	WALRetain    int
	Replay       bool

	AlertLog      string // "stdout", "", or a file path
	WebhookURL    string
	WebhookSecret string
	HubSize       int
	SinkQueue     int
	MaxBodyBytes  int64
	AuthToken     string
	LogLevel      string
	LogFormat     string
	ShutdownGrace time.Duration
	EnablePprof   bool
}

// Default returns defaults suitable for a single-node deployment.
func Default() Config {
	return Config{
		HTTPAddr:        ":8080",
		TCPAddr:         ":9090",
		RulesPath:       "rules",
		AllowedLateness: 2 * time.Second,
		IdleAdvance:     5 * time.Second,
		RingSize:        1 << 14,
		BatchSize:       256,
		MaxKeysPerShard: 1 << 18,
		KeyTTL:          10 * time.Minute,
		WALSync:         wal.SyncInterval,
		WALSyncEvery:    200 * time.Millisecond,
		WALSegment:      64 << 20,
		WALRetain:       16,
		Replay:          true,
		AlertLog:        "stdout",
		HubSize:         2000,
		SinkQueue:       8192,
		MaxBodyBytes:    8 << 20,
		LogLevel:        "info",
		LogFormat:       "json",
		ShutdownGrace:   15 * time.Second,
	}
}

// Load builds configuration: defaults <- environment (TEMPORA_*) <- flags.
func Load(args []string, getenv func(string) string) (Config, error) {
	c := Default()
	if getenv == nil {
		getenv = os.Getenv
	}
	var errs []error
	str := func(dst *string, key string) {
		if v := getenv(key); v != "" {
			*dst = v
		}
	}
	num := func(dst *int, key string) {
		if v := getenv(key); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", key, err))
				return
			}
			*dst = n
		}
	}
	dur := func(dst *time.Duration, key string) {
		if v := getenv(key); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", key, err))
				return
			}
			*dst = d
		}
	}
	boolean := func(dst *bool, key string) {
		if v := getenv(key); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", key, err))
				return
			}
			*dst = b
		}
	}
	str(&c.HTTPAddr, "TEMPORA_HTTP_ADDR")
	str(&c.TCPAddr, "TEMPORA_TCP_ADDR")
	str(&c.RulesPath, "TEMPORA_RULES")
	num(&c.Shards, "TEMPORA_SHARDS")
	num(&c.RingSize, "TEMPORA_RING_SIZE")
	num(&c.BatchSize, "TEMPORA_BATCH_SIZE")
	dur(&c.AllowedLateness, "TEMPORA_ALLOWED_LATENESS")
	dur(&c.IdleAdvance, "TEMPORA_IDLE_ADVANCE")
	num(&c.MaxKeysPerShard, "TEMPORA_MAX_KEYS_PER_SHARD")
	dur(&c.KeyTTL, "TEMPORA_KEY_TTL")
	boolean(&c.DropOnFull, "TEMPORA_DROP_ON_FULL")
	str(&c.WALDir, "TEMPORA_WAL_DIR")
	syncMode := c.WALSync.String()
	str(&syncMode, "TEMPORA_WAL_SYNC")
	dur(&c.WALSyncEvery, "TEMPORA_WAL_SYNC_EVERY")
	seg := int(c.WALSegment)
	num(&seg, "TEMPORA_WAL_SEGMENT_BYTES")
	num(&c.WALRetain, "TEMPORA_WAL_RETAIN")
	boolean(&c.Replay, "TEMPORA_REPLAY")
	str(&c.AlertLog, "TEMPORA_ALERT_LOG")
	str(&c.WebhookURL, "TEMPORA_WEBHOOK_URL")
	str(&c.WebhookSecret, "TEMPORA_WEBHOOK_SECRET")
	num(&c.HubSize, "TEMPORA_HUB_SIZE")
	num(&c.SinkQueue, "TEMPORA_SINK_QUEUE")
	maxBody := int(c.MaxBodyBytes)
	num(&maxBody, "TEMPORA_MAX_BODY_BYTES")
	str(&c.AuthToken, "TEMPORA_AUTH_TOKEN")
	str(&c.LogLevel, "TEMPORA_LOG_LEVEL")
	str(&c.LogFormat, "TEMPORA_LOG_FORMAT")
	dur(&c.ShutdownGrace, "TEMPORA_SHUTDOWN_GRACE")
	boolean(&c.EnablePprof, "TEMPORA_PPROF")

	fs := flag.NewFlagSet("tempora", flag.ContinueOnError)
	fs.StringVar(&c.HTTPAddr, "http", c.HTTPAddr, "HTTP listen address (API, ingest, metrics)")
	fs.StringVar(&c.TCPAddr, "tcp", c.TCPAddr, "TCP NDJSON ingest listen address (empty disables)")
	fs.StringVar(&c.RulesPath, "rules", c.RulesPath, "rule file or directory of *.tcl files")
	fs.IntVar(&c.Shards, "shards", c.Shards, "number of shards (0 = GOMAXPROCS)")
	fs.IntVar(&c.RingSize, "ring-size", c.RingSize, "per-shard queue capacity")
	fs.IntVar(&c.BatchSize, "batch-size", c.BatchSize, "shard drain batch size")
	fs.DurationVar(&c.AllowedLateness, "lateness", c.AllowedLateness, "allowed out-of-order lateness")
	fs.DurationVar(&c.IdleAdvance, "idle-advance", c.IdleAdvance, "advance watermark with wall clock after this idle period (0 disables)")
	fs.IntVar(&c.MaxKeysPerShard, "max-keys", c.MaxKeysPerShard, "max keys per shard (LRU)")
	fs.DurationVar(&c.KeyTTL, "key-ttl", c.KeyTTL, "idle key TTL in event time")
	fs.BoolVar(&c.DropOnFull, "drop-on-full", c.DropOnFull, "reject instead of block when shard queues are full")
	fs.StringVar(&c.WALDir, "wal-dir", c.WALDir, "write-ahead log directory (empty disables)")
	fs.StringVar(&syncMode, "wal-sync", syncMode, "WAL sync mode: none|interval|always")
	fs.DurationVar(&c.WALSyncEvery, "wal-sync-every", c.WALSyncEvery, "WAL fsync interval")
	fs.IntVar(&seg, "wal-segment-bytes", seg, "WAL segment size")
	fs.IntVar(&c.WALRetain, "wal-retain", c.WALRetain, "WAL closed segments retained (0 = unlimited)")
	fs.BoolVar(&c.Replay, "replay", c.Replay, "replay WAL on startup to rebuild state")
	fs.StringVar(&c.AlertLog, "alert-log", c.AlertLog, "alert JSON-lines output: stdout | <path> | empty")
	fs.StringVar(&c.WebhookURL, "webhook", c.WebhookURL, "alert webhook URL")
	fs.StringVar(&c.WebhookSecret, "webhook-secret", c.WebhookSecret, "HMAC secret for webhook signatures")
	fs.IntVar(&c.HubSize, "hub-size", c.HubSize, "recent alerts retained for the API")
	fs.IntVar(&c.SinkQueue, "sink-queue", c.SinkQueue, "per-sink queue size")
	fs.IntVar(&maxBody, "max-body", maxBody, "max HTTP ingest body bytes")
	fs.StringVar(&c.AuthToken, "auth-token", c.AuthToken, "bearer token required for mutating endpoints")
	fs.StringVar(&c.LogLevel, "log-level", c.LogLevel, "debug|info|warn|error")
	fs.StringVar(&c.LogFormat, "log-format", c.LogFormat, "json|text")
	fs.DurationVar(&c.ShutdownGrace, "shutdown-grace", c.ShutdownGrace, "graceful shutdown timeout")
	fs.BoolVar(&c.EnablePprof, "pprof", c.EnablePprof, "expose /debug/pprof")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	m, err := wal.ParseSyncMode(syncMode)
	if err != nil {
		errs = append(errs, err)
	}
	c.WALSync = m
	c.WALSegment = int64(seg)
	c.MaxBodyBytes = int64(maxBody)
	if err := c.Validate(); err != nil {
		errs = append(errs, err)
	}
	return c, errors.Join(errs...)
}

// Validate checks invariants.
func (c *Config) Validate() error {
	var errs []string
	if c.HTTPAddr == "" {
		errs = append(errs, "http address required")
	}
	if c.RulesPath == "" {
		errs = append(errs, "rules path required")
	}
	if c.Shards < 0 || c.Shards > 1024 {
		errs = append(errs, "shards must be in [0,1024]")
	}
	if c.RingSize < 2 || c.RingSize > 1<<24 {
		errs = append(errs, "ring size must be in [2, 16M]")
	}
	if c.BatchSize < 1 || c.BatchSize > 1<<16 {
		errs = append(errs, "batch size must be in [1, 65536]")
	}
	if c.AllowedLateness < 0 {
		errs = append(errs, "lateness must be >= 0")
	}
	if c.WALSegment < 1<<16 {
		errs = append(errs, "wal segment must be >= 64KiB")
	}
	if c.MaxBodyBytes < 1024 {
		errs = append(errs, "max body must be >= 1KiB")
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, "log level must be debug|info|warn|error")
	}
	switch c.LogFormat {
	case "json", "text":
	default:
		errs = append(errs, "log format must be json|text")
	}
	if len(errs) > 0 {
		return errors.New("config: " + strings.Join(errs, "; "))
	}
	return nil
}
