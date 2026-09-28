// Package ws is a small, dependency-free server-side WebSocket implementation
// (RFC 6455) sufficient for pushing JSON telemetry to browsers: handshake,
// text/binary/ping/pong/close frames, client-frame unmasking, fragmentation
// reassembly and size limits.
package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Opcodes.
const (
	OpContinuation = 0x0
	OpText         = 0x1
	OpBinary       = 0x2
	OpClose        = 0x8
	OpPing         = 0x9
	OpPong         = 0xA
)

// Errors.
var (
	ErrNotWebSocket = errors.New("ws: not a websocket upgrade request")
	ErrTooLarge     = errors.New("ws: message too large")
	ErrProtocol     = errors.New("ws: protocol error")
	ErrClosed       = errors.New("ws: connection closed")
)

// MaxMessage bounds inbound messages (clients only send small commands).
const MaxMessage = 1 << 20

// Conn is a server-side WebSocket connection. WriteMessage is safe for
// concurrent use; ReadMessage must be called from a single goroutine.
type Conn struct {
	c      net.Conn
	br     *bufio.Reader
	wmu    sync.Mutex
	closed bool
}

// AcceptKey computes Sec-WebSocket-Accept for a client key.
func AcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key + guid))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func headerContains(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// Upgrade performs the server handshake. checkOrigin, if non-nil, must return
// true for the request to be accepted (protects against cross-site use).
func Upgrade(w http.ResponseWriter, r *http.Request, checkOrigin func(*http.Request) bool) (*Conn, error) {
	if r.Method != http.MethodGet ||
		!headerContains(r.Header, "Connection", "upgrade") ||
		!headerContains(r.Header, "Upgrade", "websocket") {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return nil, ErrNotWebSocket
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		http.Error(w, "unsupported websocket version", http.StatusUpgradeRequired)
		return nil, ErrNotWebSocket
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, ErrNotWebSocket
	}
	if checkOrigin != nil && !checkOrigin(r) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return nil, ErrNotWebSocket
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return nil, ErrNotWebSocket
	}
	nc, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + AcceptKey(key) + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		nc.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		nc.Close()
		return nil, err
	}
	return &Conn{c: nc, br: rw.Reader}, nil
}

// NewConn wraps an established connection (used by tests / clients).
func NewConn(c net.Conn) *Conn { return &Conn{c: c, br: bufio.NewReader(c)} }

// WriteMessage writes one unfragmented, unmasked frame (server→client).
func (c *Conn) WriteMessage(op byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return ErrClosed
	}
	_ = c.c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := c.c.Write(EncodeFrame(op, payload, nil))
	return err
}

// EncodeFrame builds a FIN frame; mask (4 bytes) is applied when non-nil
// (clients must mask, servers must not).
func EncodeFrame(op byte, payload []byte, mask []byte) []byte {
	n := len(payload)
	hdr := make([]byte, 0, 14+n)
	hdr = append(hdr, 0x80|op)
	mbit := byte(0)
	if mask != nil {
		mbit = 0x80
	}
	switch {
	case n < 126:
		hdr = append(hdr, mbit|byte(n))
	case n <= 0xFFFF:
		hdr = append(hdr, mbit|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, mbit|127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	if mask != nil {
		hdr = append(hdr, mask[:4]...)
		start := len(hdr)
		hdr = append(hdr, payload...)
		for i := 0; i < n; i++ {
			hdr[start+i] ^= mask[i&3]
		}
		return hdr
	}
	return append(hdr, payload...)
}

type frame struct {
	fin     bool
	op      byte
	payload []byte
}

func (c *Conn) readFrame(requireMask bool) (frame, error) {
	var h [2]byte
	if _, err := io.ReadFull(c.br, h[:]); err != nil {
		return frame{}, err
	}
	f := frame{fin: h[0]&0x80 != 0, op: h[0] & 0x0F}
	if h[0]&0x70 != 0 {
		return f, ErrProtocol // no extensions negotiated
	}
	masked := h[1]&0x80 != 0
	if requireMask && !masked {
		return f, ErrProtocol
	}
	n := uint64(h[1] & 0x7F)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(c.br, b[:]); err != nil {
			return f, err
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(c.br, b[:]); err != nil {
			return f, err
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if f.op >= 0x8 && (n > 125 || !f.fin) {
		return f, ErrProtocol // control frames: short and unfragmented
	}
	if n > MaxMessage {
		return f, ErrTooLarge
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.br, mask[:]); err != nil {
			return f, err
		}
	}
	f.payload = make([]byte, n)
	if _, err := io.ReadFull(c.br, f.payload); err != nil {
		return f, err
	}
	if masked {
		for i := range f.payload {
			f.payload[i] ^= mask[i&3]
		}
	}
	return f, nil
}

// ReadMessage returns the next data message, transparently answering pings
// and reassembling fragments. It returns ErrClosed on a close frame.
func (c *Conn) ReadMessage() (byte, []byte, error) {
	var (
		op  byte
		buf []byte
	)
	for {
		f, err := c.readFrame(true)
		if err != nil {
			return 0, nil, err
		}
		switch f.op {
		case OpPing:
			if err := c.WriteMessage(OpPong, f.payload); err != nil {
				return 0, nil, err
			}
			continue
		case OpPong:
			continue
		case OpClose:
			_ = c.WriteMessage(OpClose, f.payload)
			c.Close()
			return 0, nil, ErrClosed
		case OpText, OpBinary:
			if op != 0 {
				return 0, nil, ErrProtocol
			}
			op = f.op
			buf = f.payload
		case OpContinuation:
			if op == 0 {
				return 0, nil, ErrProtocol
			}
			if len(buf)+len(f.payload) > MaxMessage {
				return 0, nil, ErrTooLarge
			}
			buf = append(buf, f.payload...)
		default:
			return 0, nil, ErrProtocol
		}
		if f.fin {
			return op, buf, nil
		}
	}
}

// SetReadDeadline sets the underlying read deadline.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.c.SetReadDeadline(t) }

// Close closes the connection.
func (c *Conn) Close() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.c.Close()
}

// ReadServerFrame reads one frame without requiring a mask. It is intended
// for clients and tests reading server→client traffic.
func ReadServerFrame(c *Conn) (byte, []byte, error) {
	f, err := c.readFrame(false)
	return f.op, f.payload, err
}
