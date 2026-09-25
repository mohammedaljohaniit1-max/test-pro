// Package wal implements a segmented, checksummed write-ahead log for
// admitted events.
//
// # On-disk format
//
// A log directory contains segments named %020d.wal where the number is the
// sequence number of the first record the segment may contain. Each record:
//
//	length:u32le | crc32c(payload):u32le | payload
//
// payload is event.AppendBinary. Records are appended in batches under a
// single mutex acquisition (group commit); durability is governed by
// SyncMode:
//
//   - SyncNone: rely on the OS page cache (fastest; loses data on power loss)
//   - SyncInterval: a background goroutine fsyncs every SyncEvery
//   - SyncAlways: fsync before AppendBatch returns
//
// Replay tolerates a torn tail: an incomplete or checksum-failing record
// terminates the segment (it can only be the last write before a crash). The
// active segment is truncated to the last valid record on Open so new
// appends never follow garbage.
package wal

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
)

// SyncMode selects the durability policy.
type SyncMode int

// Sync modes.
const (
	SyncNone SyncMode = iota
	SyncInterval
	SyncAlways
)

// ParseSyncMode parses "none" | "interval" | "always".
func ParseSyncMode(s string) (SyncMode, error) {
	switch strings.ToLower(s) {
	case "none", "":
		return SyncNone, nil
	case "interval":
		return SyncInterval, nil
	case "always":
		return SyncAlways, nil
	}
	return 0, fmt.Errorf("wal: unknown sync mode %q", s)
}

func (m SyncMode) String() string {
	return [...]string{"none", "interval", "always"}[m]
}

const (
	headerSize = 8
	segSuffix  = ".wal"
	// MaxRecord bounds a single record to protect replay from corrupt lengths.
	MaxRecord = event.MaxEncodedSize + 1024
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// ErrClosed is returned after Close.
var ErrClosed = errors.New("wal: closed")

// Options configure a Log.
type Options struct {
	Dir          string
	SegmentBytes int64
	Sync         SyncMode
	SyncEvery    time.Duration
	// Retain is the maximum number of closed segments kept (0 = unlimited).
	Retain int
}

// Stats is a snapshot of log counters.
type Stats struct {
	Segments      int    `json:"segments"`
	Bytes         int64  `json:"bytes"`
	Records       uint64 `json:"records"`
	Batches       uint64 `json:"batches"`
	Syncs         uint64 `json:"syncs"`
	LastSeq       uint64 `json:"last_seq"`
	ActiveSegment string `json:"active_segment"`
}

// Log is a segmented write-ahead log. Safe for concurrent use.
type Log struct {
	opts Options

	mu       sync.Mutex
	f        *os.File
	w        *bufio.Writer
	segName  string
	segSize  int64
	segments []string
	total    int64
	lastSeq  uint64
	records  uint64
	batches  uint64
	syncs    uint64
	dirty    bool
	closed   bool
	buf      []byte

	stop chan struct{}
	done chan struct{}
}

// Open opens (creating if necessary) a log in opts.Dir.
func Open(opts Options) (*Log, error) {
	if opts.Dir == "" {
		return nil, errors.New("wal: empty directory")
	}
	if opts.SegmentBytes <= 0 {
		opts.SegmentBytes = 64 << 20
	}
	if opts.SyncEvery <= 0 {
		opts.SyncEvery = 200 * time.Millisecond
	}
	if err := os.MkdirAll(opts.Dir, 0o755); err != nil {
		return nil, fmt.Errorf("wal: mkdir: %w", err)
	}
	l := &Log{opts: opts, stop: make(chan struct{}), done: make(chan struct{})}
	segs, err := l.listSegments()
	if err != nil {
		return nil, err
	}
	l.segments = segs
	for _, s := range segs {
		if st, err := os.Stat(filepath.Join(opts.Dir, s)); err == nil {
			l.total += st.Size()
		}
	}
	if len(segs) > 0 {
		// Recover the tail: find last valid offset and last seq.
		last := segs[len(segs)-1]
		path := filepath.Join(opts.Dir, last)
		valid, lastSeq, err := scanSegment(path, nil)
		if err != nil {
			return nil, err
		}
		st, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if valid < st.Size() {
			if err := os.Truncate(path, valid); err != nil {
				return nil, fmt.Errorf("wal: truncate torn tail: %w", err)
			}
			l.total -= st.Size() - valid
		}
		l.lastSeq = lastSeq
		if lastSeq == 0 {
			// Empty tail segment: seq is its start number - 1.
			if n, err := segStart(last); err == nil && n > 0 {
				l.lastSeq = n - 1
			}
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, err
		}
		l.f, l.segName, l.segSize = f, last, valid
		l.w = bufio.NewWriterSize(f, 256<<10)
	} else if err := l.rotateLocked(1); err != nil {
		return nil, err
	}
	if opts.Sync == SyncInterval {
		go l.syncLoop()
	} else {
		close(l.done)
	}
	return l, nil
}

func segStart(name string) (uint64, error) {
	return strconv.ParseUint(strings.TrimSuffix(name, segSuffix), 10, 64)
}

func (l *Log) listSegments() ([]string, error) {
	ents, err := os.ReadDir(l.opts.Dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), segSuffix) {
			continue
		}
		if _, err := segStart(e.Name()); err != nil {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out) // zero-padded names sort numerically
	return out, nil
}

// LastSeq returns the highest sequence number durably appended (or recovered).
func (l *Log) LastSeq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastSeq
}

// AppendBatch appends events in order. Sequence numbers must be increasing.
func (l *Log) AppendBatch(evs []*event.Event) error {
	if len(evs) == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	for _, ev := range evs {
		if l.segSize >= l.opts.SegmentBytes {
			if err := l.rotateLocked(ev.Seq); err != nil {
				return err
			}
		}
		l.buf = l.buf[:0]
		l.buf = append(l.buf, make([]byte, headerSize)...)
		l.buf = event.AppendBinary(l.buf, ev)
		payload := l.buf[headerSize:]
		if len(payload) > MaxRecord {
			return fmt.Errorf("wal: record of %d bytes exceeds limit", len(payload))
		}
		binary.LittleEndian.PutUint32(l.buf[0:4], uint32(len(payload)))
		binary.LittleEndian.PutUint32(l.buf[4:8], crc32.Checksum(payload, castagnoli))
		n, err := l.w.Write(l.buf)
		if err != nil {
			return fmt.Errorf("wal: write: %w", err)
		}
		l.segSize += int64(n)
		l.total += int64(n)
		if ev.Seq > l.lastSeq {
			l.lastSeq = ev.Seq
		}
		l.records++
	}
	l.batches++
	l.dirty = true
	if err := l.w.Flush(); err != nil {
		return fmt.Errorf("wal: flush: %w", err)
	}
	if l.opts.Sync == SyncAlways {
		return l.syncLocked()
	}
	return nil
}

func (l *Log) syncLocked() error {
	if !l.dirty || l.f == nil {
		return nil
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("wal: fsync: %w", err)
	}
	l.syncs++
	l.dirty = false
	return nil
}

// Sync flushes and fsyncs the active segment.
func (l *Log) Sync() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	if err := l.w.Flush(); err != nil {
		return err
	}
	return l.syncLocked()
}

func (l *Log) syncLoop() {
	defer close(l.done)
	t := time.NewTicker(l.opts.SyncEvery)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			l.mu.Lock()
			if !l.closed {
				_ = l.syncLocked()
			}
			l.mu.Unlock()
		}
	}
}

func (l *Log) rotateLocked(startSeq uint64) error {
	if l.f != nil {
		if err := l.w.Flush(); err != nil {
			return err
		}
		if err := l.f.Sync(); err != nil {
			return err
		}
		if err := l.f.Close(); err != nil {
			return err
		}
	}
	name := fmt.Sprintf("%020d%s", startSeq, segSuffix)
	if len(l.segments) > 0 && l.segments[len(l.segments)-1] == name {
		// Same start sequence (empty segment): reopen it.
		f, err := os.OpenFile(filepath.Join(l.opts.Dir, name), os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return err
		}
		l.f, l.segName, l.segSize = f, name, 0
		l.w = bufio.NewWriterSize(f, 256<<10)
		return nil
	}
	f, err := os.OpenFile(filepath.Join(l.opts.Dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("wal: create segment: %w", err)
	}
	l.f, l.segName, l.segSize = f, name, 0
	l.w = bufio.NewWriterSize(f, 256<<10)
	l.segments = append(l.segments, name)
	if err := syncDir(l.opts.Dir); err != nil {
		return err
	}
	return l.enforceRetentionLocked()
}

func (l *Log) enforceRetentionLocked() error {
	if l.opts.Retain <= 0 {
		return nil
	}
	for len(l.segments)-1 > l.opts.Retain {
		old := l.segments[0]
		p := filepath.Join(l.opts.Dir, old)
		if st, err := os.Stat(p); err == nil {
			l.total -= st.Size()
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("wal: retention: %w", err)
		}
		l.segments = l.segments[1:]
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		// Some filesystems do not support directory fsync; not fatal.
		return nil
	}
	return nil
}

// TruncateBefore deletes closed segments whose records are all < seq.
// The active segment is never deleted.
func (l *Log) TruncateBefore(seq uint64) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	removed := 0
	for len(l.segments) > 1 {
		next, err := segStart(l.segments[1])
		if err != nil || next > seq {
			break
		}
		p := filepath.Join(l.opts.Dir, l.segments[0])
		if st, err := os.Stat(p); err == nil {
			l.total -= st.Size()
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return removed, err
		}
		l.segments = l.segments[1:]
		removed++
	}
	return removed, nil
}

// Stats returns counters.
func (l *Log) Stats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()
	return Stats{
		Segments: len(l.segments), Bytes: l.total, Records: l.records, Batches: l.batches,
		Syncs: l.syncs, LastSeq: l.lastSeq, ActiveSegment: l.segName,
	}
}

// Close flushes, fsyncs and closes the log.
func (l *Log) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	var err error
	if l.w != nil {
		err = l.w.Flush()
	}
	if l.f != nil {
		if e := l.f.Sync(); err == nil {
			err = e
		}
		if e := l.f.Close(); err == nil {
			err = e
		}
	}
	l.mu.Unlock()
	close(l.stop)
	<-l.done
	return err
}

// ReplayStats reports what Replay did.
type ReplayStats struct {
	Segments  int
	Records   uint64
	Skipped   uint64 // records with seq < fromSeq
	TornBytes int64  // bytes discarded after the last valid record of a segment
	LastSeq   uint64
}

// Replay streams every record with seq >= fromSeq, in log order, to fn. It
// can run on a closed log directory or before Open.
func Replay(dir string, fromSeq uint64, fn func(*event.Event) error) (ReplayStats, error) {
	var rs ReplayStats
	l := &Log{opts: Options{Dir: dir}}
	segs, err := l.listSegments()
	if err != nil {
		if os.IsNotExist(err) {
			return rs, nil
		}
		return rs, err
	}
	// Skip segments entirely below fromSeq.
	startIdx := 0
	for i := 1; i < len(segs); i++ {
		if n, err := segStart(segs[i]); err == nil && n <= fromSeq {
			startIdx = i
		}
	}
	for _, s := range segs[startIdx:] {
		path := filepath.Join(dir, s)
		valid, last, err := scanSegment(path, func(ev *event.Event) error {
			if ev.Seq < fromSeq {
				rs.Skipped++
				return nil
			}
			rs.Records++
			return fn(ev)
		})
		if err != nil {
			return rs, err
		}
		if st, err := os.Stat(path); err == nil && st.Size() > valid {
			rs.TornBytes += st.Size() - valid
		}
		if last > rs.LastSeq {
			rs.LastSeq = last
		}
		rs.Segments++
	}
	return rs, nil
}

// scanSegment reads records until EOF or the first invalid record. It returns
// the byte offset just past the last valid record and the last seq seen.
func scanSegment(path string, fn func(*event.Event) error) (int64, uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 256<<10)
	var (
		off     int64
		lastSeq uint64
		hdr     [headerSize]byte
		payload []byte
	)
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return off, lastSeq, nil // EOF or torn header
		}
		n := binary.LittleEndian.Uint32(hdr[0:4])
		sum := binary.LittleEndian.Uint32(hdr[4:8])
		if n == 0 || n > MaxRecord {
			return off, lastSeq, nil
		}
		if cap(payload) < int(n) {
			payload = make([]byte, n)
		}
		payload = payload[:n]
		if _, err := io.ReadFull(r, payload); err != nil {
			return off, lastSeq, nil
		}
		if crc32.Checksum(payload, castagnoli) != sum {
			return off, lastSeq, nil
		}
		ev, err := event.DecodeBinary(payload)
		if err != nil {
			return off, lastSeq, nil
		}
		off += headerSize + int64(n)
		lastSeq = ev.Seq
		if fn != nil {
			if err := fn(ev); err != nil {
				return off, lastSeq, err
			}
		}
	}
}
