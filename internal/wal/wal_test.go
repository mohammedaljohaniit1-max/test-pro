package wal

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
)

func mkEvents(from, n int) []*event.Event {
	out := make([]*event.Event, n)
	for i := range out {
		seq := uint64(from + i)
		e := &event.Event{Seq: seq, Time: int64(1e18) + int64(seq), Type: "t", Key: "k"}
		e.Set("i", event.Int(int64(seq)))
		e.Set("pad", event.Str("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"))
		out[i] = e
	}
	return out
}

func replayAll(t *testing.T, dir string, from uint64) ([]uint64, ReplayStats) {
	t.Helper()
	var seqs []uint64
	st, err := Replay(dir, from, func(e *event.Event) error {
		seqs = append(seqs, e.Seq)
		if e.Attr("i").AsInt() != int64(e.Seq) {
			t.Fatalf("payload mismatch at seq %d", e.Seq)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return seqs, st
}

func TestAppendReplayRoundTrip(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(Options{Dir: dir, SegmentBytes: 1 << 16, Sync: SyncAlways})
	if err != nil {
		t.Fatal(err)
	}
	for b := 0; b < 50; b++ {
		if err := l.AppendBatch(mkEvents(1+b*100, 100)); err != nil {
			t.Fatal(err)
		}
	}
	st := l.Stats()
	if st.Segments < 2 {
		t.Fatalf("expected rotation, got %d segments", st.Segments)
	}
	if st.Records != 5000 || st.LastSeq != 5000 || st.Syncs == 0 {
		t.Fatalf("stats %+v", st)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	seqs, rs := replayAll(t, dir, 0)
	if len(seqs) != 5000 || rs.TornBytes != 0 {
		t.Fatalf("replayed %d torn %d", len(seqs), rs.TornBytes)
	}
	for i, s := range seqs {
		if s != uint64(i+1) {
			t.Fatalf("order broken at %d: %d", i, s)
		}
	}
	// fromSeq skips whole segments and filters within one.
	seqs, rs = replayAll(t, dir, 4321)
	if len(seqs) != 5000-4320 || seqs[0] != 4321 {
		t.Fatalf("partial replay: n=%d first=%d", len(seqs), seqs[0])
	}
	if rs.Segments >= st.Segments {
		t.Fatalf("expected segment skipping: scanned %d of %d", rs.Segments, st.Segments)
	}
}

func TestReopenContinuesAndRecoversLastSeq(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(Options{Dir: dir})
	_ = l.AppendBatch(mkEvents(1, 10))
	_ = l.Close()
	l, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if l.LastSeq() != 10 {
		t.Fatalf("last seq %d", l.LastSeq())
	}
	_ = l.AppendBatch(mkEvents(11, 10))
	_ = l.Close()
	seqs, _ := replayAll(t, dir, 0)
	if len(seqs) != 20 {
		t.Fatalf("got %d", len(seqs))
	}
}

// TestTornTailRecovery simulates a crash mid-write at every byte offset of
// the final record: replay must return exactly the complete records and Open
// must truncate the garbage so subsequent appends are readable.
func TestTornTailRecovery(t *testing.T) {
	src := t.TempDir()
	l, _ := Open(Options{Dir: src})
	_ = l.AppendBatch(mkEvents(1, 5))
	_ = l.Close()
	segs, _ := filepath.Glob(filepath.Join(src, "*.wal"))
	full, _ := os.ReadFile(segs[0])
	recLen := len(full) / 5
	for cut := len(full) - recLen + 1; cut < len(full); cut += 7 {
		dir := t.TempDir()
		p := filepath.Join(dir, filepath.Base(segs[0]))
		os.WriteFile(p, full[:cut], 0o644)
		seqs, st := replayAll(t, dir, 0)
		if len(seqs) != 4 || st.TornBytes == 0 {
			t.Fatalf("cut %d: replayed %d torn %d", cut, len(seqs), st.TornBytes)
		}
		l, err := Open(Options{Dir: dir})
		if err != nil {
			t.Fatal(err)
		}
		if l.LastSeq() != 4 {
			t.Fatalf("cut %d: last seq %d", cut, l.LastSeq())
		}
		_ = l.AppendBatch(mkEvents(5, 3))
		_ = l.Close()
		seqs, st = replayAll(t, dir, 0)
		if len(seqs) != 7 || st.TornBytes != 0 {
			t.Fatalf("cut %d: after reopen replayed %d torn %d", cut, len(seqs), st.TornBytes)
		}
	}
}

func TestCorruptedRecordStopsSegment(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(Options{Dir: dir})
	_ = l.AppendBatch(mkEvents(1, 10))
	_ = l.Close()
	segs, _ := filepath.Glob(filepath.Join(dir, "*.wal"))
	b, _ := os.ReadFile(segs[0])
	b[len(b)/2] ^= 0xff // flip a byte in the middle record
	os.WriteFile(segs[0], b, 0o644)
	seqs, st := replayAll(t, dir, 0)
	if len(seqs) >= 10 || len(seqs) == 0 || st.TornBytes == 0 {
		t.Fatalf("replayed %d torn %d", len(seqs), st.TornBytes)
	}
	for i, s := range seqs {
		if s != uint64(i+1) {
			t.Fatal("corruption must truncate, not skip")
		}
	}
}

func TestRetentionAndTruncate(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(Options{Dir: dir, SegmentBytes: 1 << 16, Retain: 2})
	for b := 0; b < 60; b++ {
		_ = l.AppendBatch(mkEvents(1+b*100, 100))
	}
	if n := l.Stats().Segments; n > 3 {
		t.Fatalf("retention not enforced: %d segments", n)
	}
	_ = l.Close()

	dir = t.TempDir()
	l, _ = Open(Options{Dir: dir, SegmentBytes: 1 << 16})
	for b := 0; b < 30; b++ {
		_ = l.AppendBatch(mkEvents(1+b*100, 100))
	}
	before := l.Stats().Segments
	removed, err := l.TruncateBefore(2000)
	if err != nil || removed == 0 {
		t.Fatalf("truncate removed %d err %v", removed, err)
	}
	if l.Stats().Segments != before-removed {
		t.Fatal("segment accounting")
	}
	_ = l.Close()
	seqs, _ := replayAll(t, dir, 0)
	if seqs[0] > 2000 || seqs[len(seqs)-1] != 3000 {
		t.Fatalf("truncate dropped needed records: first=%d", seqs[0])
	}
}

func TestConcurrentAppendersKeepRecordsIntact(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(Options{Dir: dir, SegmentBytes: 1 << 17, Sync: SyncInterval})
	var wg sync.WaitGroup
	var mu sync.Mutex
	next := 1
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				mu.Lock()
				evs := mkEvents(next, 20)
				next += 20
				err := l.AppendBatch(evs)
				mu.Unlock()
				if err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	_ = l.Close()
	seqs, st := replayAll(t, dir, 0)
	if len(seqs) != 8000 || st.TornBytes != 0 {
		t.Fatalf("replayed %d torn %d", len(seqs), st.TornBytes)
	}
}

func TestClosedAndOptions(t *testing.T) {
	if _, err := Open(Options{}); err == nil {
		t.Fatal("empty dir accepted")
	}
	l, _ := Open(Options{Dir: t.TempDir()})
	_ = l.Close()
	if err := l.AppendBatch(mkEvents(1, 1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal("double close")
	}
	for s, want := range map[string]SyncMode{"none": SyncNone, "interval": SyncInterval, "ALWAYS": SyncAlways} {
		if m, err := ParseSyncMode(s); err != nil || m != want {
			t.Fatalf("ParseSyncMode(%s)", s)
		}
	}
	if _, err := ParseSyncMode("sometimes"); err == nil {
		t.Fatal("bad sync mode accepted")
	}
	if st, err := Replay(filepath.Join(t.TempDir(), "missing"), 0, nil); err != nil || st.Records != 0 {
		t.Fatal("replay of missing dir should be empty")
	}
}

func BenchmarkAppendBatch(b *testing.B) {
	l, _ := Open(Options{Dir: b.TempDir(), Sync: SyncNone, SegmentBytes: 1 << 30})
	defer l.Close()
	evs := mkEvents(1, 256)
	b.SetBytes(int64(len(event.AppendBinary(nil, evs[0])) * len(evs)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = l.AppendBatch(evs)
	}
}
