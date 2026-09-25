package sink

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/engine"
)

// JSONLines writes one JSON object per alert to a writer (stdout or a file).
type JSONLines struct {
	name   string
	mu     sync.Mutex
	w      *bufio.Writer
	closer io.Closer
}

// NewJSONLines wraps w. If w is also an io.Closer (and not stdout/stderr) it
// is closed on Close.
func NewJSONLines(name string, w io.Writer) *JSONLines {
	s := &JSONLines{name: name, w: bufio.NewWriterSize(w, 64<<10)}
	if c, ok := w.(io.Closer); ok && w != os.Stdout && w != os.Stderr {
		s.closer = c
	}
	return s
}

// OpenJSONLinesFile appends to path (created with 0644).
func OpenJSONLinesFile(path string) (*JSONLines, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return NewJSONLines("file:"+path, f), nil
}

// Name implements Sink.
func (s *JSONLines) Name() string { return s.name }

// Deliver implements Sink. Output is flushed per alert so tail -f works; the
// buffered writer still coalesces the syscall for the encoded line.
func (s *JSONLines) Deliver(_ context.Context, a *engine.Alert) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(append(b, '\n')); err != nil {
		return err
	}
	return s.w.Flush()
}

// Close implements Sink.
func (s *JSONLines) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.w.Flush()
	if s.closer != nil {
		if e := s.closer.Close(); err == nil {
			err = e
		}
	}
	return err
}
