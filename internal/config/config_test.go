package config

import (
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/wal"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaultsValid(t *testing.T) {
	c, err := Load(nil, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPAddr != ":8080" || c.WALSync != wal.SyncInterval || c.AllowedLateness != 2*time.Second {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestEnvThenFlagsPrecedence(t *testing.T) {
	c, err := Load([]string{"-shards", "8", "-wal-sync", "always"}, env(map[string]string{
		"TEMPORA_SHARDS":           "4",
		"TEMPORA_HTTP_ADDR":        ":9999",
		"TEMPORA_ALLOWED_LATENESS": "750ms",
		"TEMPORA_DROP_ON_FULL":     "true",
		"TEMPORA_WAL_SYNC":         "none",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Shards != 8 || c.HTTPAddr != ":9999" || c.AllowedLateness != 750*time.Millisecond || !c.DropOnFull || c.WALSync != wal.SyncAlways {
		t.Fatalf("precedence: %+v", c)
	}
}

func TestInvalidValues(t *testing.T) {
	cases := []map[string]string{
		{"TEMPORA_SHARDS": "many"},
		{"TEMPORA_ALLOWED_LATENESS": "soon"},
		{"TEMPORA_DROP_ON_FULL": "maybe"},
		{"TEMPORA_WAL_SYNC": "sometimes"},
		{"TEMPORA_SHARDS": "5000"},
		{"TEMPORA_LOG_LEVEL": "loud"},
		{"TEMPORA_RING_SIZE": "1"},
		{"TEMPORA_WAL_SEGMENT_BYTES": "10"},
	}
	for _, e := range cases {
		if _, err := Load(nil, env(e)); err == nil {
			t.Errorf("accepted %v", e)
		}
	}
	if _, err := Load([]string{"-no-such-flag"}, env(nil)); err == nil {
		t.Error("unknown flag accepted")
	}
}
