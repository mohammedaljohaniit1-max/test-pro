package server

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
)

// TCPServer accepts newline-delimited JSON events. Each connection is read
// by one goroutine that batches up to BatchSize lines (or whatever is
// buffered when the reader would block) per Admit call. Invalid lines are
// counted and skipped; they never terminate the connection. The protocol is
// fire-and-forget: backpressure is applied by not reading from the socket
// while the engine is saturated (TCP flow control propagates it upstream).
type TCPServer struct {
	Addr        string
	Ingest      *Ingestor
	Log         *slog.Logger
	BatchSize   int
	IdleTimeout time.Duration
	MaxConns    int

	ln    net.Listener
	wg    sync.WaitGroup
	mu    sync.Mutex
	conns map[net.Conn]struct{}
	open  atomic.Int64
	quit  atomic.Bool
}

// Listen binds the listener (separate from Serve so tests can use :0).
func (s *TCPServer) Listen() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.conns = make(map[net.Conn]struct{})
	if s.BatchSize <= 0 {
		s.BatchSize = 512
	}
	if s.IdleTimeout <= 0 {
		s.IdleTimeout = 5 * time.Minute
	}
	if s.MaxConns <= 0 {
		s.MaxConns = 4096
	}
	return nil
}

// ListenAddr returns the bound address.
func (s *TCPServer) ListenAddr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Connections returns the number of open connections.
func (s *TCPServer) Connections() int64 { return s.open.Load() }

// Serve accepts connections until Close.
func (s *TCPServer) Serve(ctx context.Context) error {
	var backoff time.Duration
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if s.quit.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if backoff == 0 {
					backoff = 5 * time.Millisecond
				} else if backoff < time.Second {
					backoff *= 2
				}
				time.Sleep(backoff)
				continue
			}
			return err
		}
		backoff = 0
		if s.open.Load() >= int64(s.MaxConns) {
			s.Log.Warn("tcp connection limit reached; rejecting", "remote", c.RemoteAddr().String())
			c.Close()
			continue
		}
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		s.open.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, c)
				s.mu.Unlock()
				s.open.Add(-1)
				c.Close()
			}()
			s.handle(ctx, c)
		}()
	}
}

func (s *TCPServer) handle(ctx context.Context, c net.Conn) {
	r := bufio.NewReaderSize(c, 256<<10)
	batch := make([]*event.Event, 0, s.BatchSize)
	flush := func() bool {
		if len(batch) == 0 {
			return true
		}
		_, err := s.Ingest.Admit(ctx, batch)
		batch = batch[:0]
		if err != nil {
			s.Log.Warn("tcp ingest admit failed", "remote", c.RemoteAddr().String(), "err", err)
			return !errors.Is(err, context.Canceled)
		}
		return true
	}
	for {
		_ = c.SetReadDeadline(time.Now().Add(s.IdleTimeout))
		line, err := readLine(r, event.MaxEncodedSize)
		if len(line) > 0 {
			ev, perr := event.ParseJSON(line, time.Now())
			if perr != nil {
				s.Ingest.CountInvalid(1)
			} else {
				batch = append(batch, ev)
			}
		}
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				s.Ingest.CountInvalid(1)
				continue
			}
			flush()
			return
		}
		// Flush when full or when no more input is immediately buffered.
		if len(batch) >= s.BatchSize || r.Buffered() == 0 {
			if !flush() {
				return
			}
		}
	}
}

var errLineTooLong = errors.New("line too long")

// readLine returns one line without the trailing newline. Overlong lines
// are discarded through their terminating newline and errLineTooLong is
// returned.
func readLine(r *bufio.Reader, limit int) ([]byte, error) {
	var out []byte
	for {
		frag, err := r.ReadSlice('\n')
		if len(out)+len(frag) > limit+1 {
			// Discard the remainder of this line.
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = r.ReadSlice('\n')
			}
			if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
				return nil, err
			}
			return nil, errLineTooLong
		}
		out = append(out, frag...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		n := len(out)
		if n > 0 && out[n-1] == '\n' {
			out = out[:n-1]
			if n > 1 && out[n-2] == '\r' {
				out = out[:n-2]
			}
		}
		trimmed := trimSpace(out)
		if err != nil {
			return trimmed, err
		}
		if len(trimmed) == 0 {
			out = out[:0]
			continue // skip blank lines
		}
		return trimmed, nil
	}
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\r') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// Close stops accepting, closes live connections and waits for handlers.
func (s *TCPServer) Close() error {
	s.quit.Store(true)
	var err error
	if s.ln != nil {
		err = s.ln.Close()
	}
	s.mu.Lock()
	for c := range s.conns {
		_ = c.SetReadDeadline(time.Now())
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}
