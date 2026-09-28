package ws

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAcceptKeyRFCExample(t *testing.T) {
	// RFC 6455 section 1.3 example.
	if got := AcceptKey("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("accept key %q", got)
	}
}

func dial(t *testing.T, srv *httptest.Server, origin string) (net.Conn, *bufio.Reader, string) {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	req := "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
	if origin != "" {
		req += "Origin: " + origin + "\r\n"
	}
	req += "\r\n"
	c.Write([]byte(req))
	br := bufio.NewReader(c)
	status, _ := br.ReadString('\n')
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
	}
	return c, br, status
}

func TestEchoRoundTripPingFragmentsClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			op, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			c.WriteMessage(op, append([]byte("echo:"), msg...))
		}
	}))
	defer srv.Close()
	c, br, status := dial(t, srv, "")
	defer c.Close()
	if !strings.Contains(status, "101") {
		t.Fatalf("status %q", status)
	}
	mask := []byte{1, 2, 3, 4}
	client := &Conn{c: c, br: br}

	// Ping is answered with a pong carrying the same payload.
	c.Write(EncodeFrame(OpPing, []byte("hi"), mask))
	f, err := client.readFrame(false)
	if err != nil || f.op != OpPong || string(f.payload) != "hi" {
		t.Fatalf("pong: %+v %v", f, err)
	}
	// Fragmented text message (non-FIN first frame + continuation).
	first := EncodeFrame(OpText, []byte("hel"), mask)
	first[0] &^= 0x80
	c.Write(first)
	c.Write(EncodeFrame(OpContinuation, []byte("lo"), mask))
	f, err = client.readFrame(false)
	if err != nil || string(f.payload) != "echo:hello" {
		t.Fatalf("fragmented: %+v %v", f, err)
	}
	// 70 KB message exercises the 64-bit length path both ways.
	big := bytes.Repeat([]byte("x"), 70000)
	c.Write(EncodeFrame(OpText, big, mask))
	f, err = client.readFrame(false)
	if err != nil || len(f.payload) != 70005 {
		t.Fatalf("big: len=%d err=%v", len(f.payload), err)
	}
	// Close handshake.
	c.Write(EncodeFrame(OpClose, []byte{0x03, 0xE8}, mask))
	f, err = client.readFrame(false)
	if err != nil || f.op != OpClose {
		t.Fatalf("close: %+v %v", f, err)
	}
}

func TestRejectsUnmaskedClientFrames(t *testing.T) {
	done := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_, _, err = c.ReadMessage()
		done <- err
		c.Close()
	}))
	defer srv.Close()
	c, _, _ := dial(t, srv, "")
	defer c.Close()
	c.Write(EncodeFrame(OpText, []byte("x"), nil))
	select {
	case err := <-done:
		if err != ErrProtocol {
			t.Fatalf("got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestOriginCheckAndBadRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := Upgrade(w, r, func(r *http.Request) bool { return r.Header.Get("Origin") == "http://localhost:9099" })
		if err == nil {
			c.Close()
		}
	}))
	defer srv.Close()
	c, _, status := dial(t, srv, "http://evil.example")
	c.Close()
	if !strings.Contains(status, "403") {
		t.Fatalf("cross-origin should be rejected: %q", status)
	}
	c, _, status = dial(t, srv, "http://localhost:9099")
	c.Close()
	if !strings.Contains(status, "101") {
		t.Fatalf("same origin should be accepted: %q", status)
	}
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("plain GET: %d", resp.StatusCode)
	}
}
