package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/hub"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/netmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/procmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/sysmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/ws"
)

type fakeProcs struct{}

func (fakeProcs) List() ([]procmon.RawProcess, error) {
	return []procmon.RawProcess{{PID: 10, Name: "svc.exe", Threads: 1}}, nil
}
func (fakeProcs) Details(p *procmon.RawProcess) { p.Access = true }

type fakePlat struct{}

func (fakePlat) CPUTimes() (sysmon.CPUTimes, error)              { return sysmon.CPUTimes{}, nil }
func (fakePlat) Memory() (uint64, uint64, uint64, uint64, error) { return 8 << 30, 2 << 30, 1, 2, nil }
func (fakePlat) Disks() ([]model.DiskUsage, error)               { return nil, nil }
func (fakePlat) Uptime() time.Duration                           { return time.Minute }
func (fakePlat) Info() (string, string)                          { return "HOST", "Windows" }
func (fakePlat) Cores() int                                      { return 2 }

type fakeEvents struct{}

func (fakeEvents) Query(ch string, since time.Time, max, lvl int, after uint64) ([]model.Event, error) {
	if after > 0 {
		return nil, nil
	}
	return []model.Event{
		{Channel: ch, RecordID: 2, Time: time.Now(), Level: 2, LevelStr: "error", Provider: "Application Error", Category: model.CatAppFault, Message: "Faulting application app.exe"},
		{Channel: ch, RecordID: 1, Time: time.Now().Add(-time.Hour), Level: 4, LevelStr: "info", Provider: "Service Control Manager", Category: model.CatOther, Message: "started"},
	}, nil
}

type fakeSW struct {
	mu       sync.Mutex
	upgraded []string
	fail     bool
}

func (f *fakeSW) Inventory() ([]model.App, error) {
	return []model.App{{Name: "Mozilla Firefox (x64 en-US)", Version: "129.0.1", Scope: "machine"}}, nil
}
func (f *fakeSW) ListUpgrades(ctx context.Context) ([]model.Upgrade, string, error) {
	return []model.Upgrade{{Name: "Mozilla Firefox (x64 en-US)", ID: "Mozilla.Firefox", Version: "129.0.1", Available: "130.0", Source: "winget"}}, "", nil
}
func (f *fakeSW) RunUpgrade(ctx context.Context, id string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upgraded = append(f.upgraded, id)
	if f.fail {
		return "installer failed", errors.New("exit status 1")
	}
	return "Successfully installed", nil
}

type env struct {
	srv  *Server
	ts   *httptest.Server
	sw   *fakeSW
	stop context.CancelFunc
	host string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pm := procmon.New(fakeProcs{}, 1)
	conns := []model.Connection{{Proto: "TCP", LocalAddr: "127.0.0.1", LocalPort: 9099, State: "LISTEN", PID: 10}}
	tr := netmon.NewTracker(func() ([]model.Connection, error) { return conns, nil }, pm.Resolve)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := hub.New(hub.Config{MetricsEvery: 20 * time.Millisecond, NetEvery: 20 * time.Millisecond, EventsEvery: 20 * time.Millisecond, Channels: []string{"System"}},
		log, sysmon.New(fakePlat{}, 50), pm, tr, fakeEvents{})
	ctx, cancel := context.WithCancel(context.Background())
	go h.Run(ctx)
	sw := &fakeSW{}
	s := New(h, sw, log, "127.0.0.1:0")
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { cancel(); ts.Close() })
	// Let collectors populate.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if evs, _ := h.Events(); len(evs) > 0 && len(h.Connections()) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	return &env{srv: s, ts: ts, sw: sw, stop: cancel, host: strings.TrimPrefix(ts.URL, "http://")}
}

func (e *env) req(t *testing.T, method, path, body string, hdr map[string]string) (int, map[string]any, string) {
	t.Helper()
	r, _ := http.NewRequest(method, e.ts.URL+path, strings.NewReader(body))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m, string(b)
}

func (e *env) auth() map[string]string {
	return map[string]string{"Origin": "http://" + e.host, "X-SysPulse-Token": e.srv.Token(), "Content-Type": "application/json"}
}

func TestIndexEmbedsTokenAndAssets(t *testing.T) {
	e := newEnv(t)
	code, _, body := e.req(t, "GET", "/", "", nil)
	if code != 200 || !strings.Contains(body, e.srv.Token()) || strings.Contains(body, "{{TOKEN}}") {
		t.Fatalf("index: %d", code)
	}
	for _, p := range []string{"/assets/app.js", "/assets/app.css", "/assets/i18n.js", "/assets/guide.js", "/favicon.svg"} {
		resp, err := http.Get(e.ts.URL + p)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v %v", p, err, resp.StatusCode)
		}
		resp.Body.Close()
	}
	resp, _ := http.Get(e.ts.URL + "/")
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("csp %q", csp)
	}
	resp.Body.Close()
}

func TestDNSRebindingRejected(t *testing.T) {
	e := newEnv(t)
	r, _ := http.NewRequest("GET", e.ts.URL+"/", nil)
	r.Host = "attacker.example:9099"
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-loopback Host served the dashboard: %d", resp.StatusCode)
	}
}

func TestReadAPIs(t *testing.T) {
	e := newEnv(t)
	if code, m, _ := e.req(t, "GET", "/api/health", "", nil); code != 200 || m["status"] != "ok" {
		t.Fatalf("health %d %v", code, m)
	}
	code, m, _ := e.req(t, "GET", "/api/snapshot", "", nil)
	if code != 200 || m["metrics"] == nil || len(m["connections"].([]any)) != 1 {
		t.Fatalf("snapshot %d %v", code, m)
	}
	code, m, _ = e.req(t, "GET", "/api/events?level=error&q=faulting", "", nil)
	evs := m["events"].([]any)
	if code != 200 || len(evs) != 1 || m["summary"] == nil {
		t.Fatalf("events filter %d %v", code, m)
	}
	_, m, _ = e.req(t, "GET", "/api/events?category=other", "", nil)
	if len(m["events"].([]any)) != 1 {
		t.Fatal("category filter")
	}
	code, _, body := e.req(t, "GET", "/api/processes", "", nil)
	if code != 200 || !strings.Contains(body, "svc.exe") {
		t.Fatalf("processes %d %s", code, body)
	}
}

func TestMutationsRequireOriginAndToken(t *testing.T) {
	e := newEnv(t)
	cases := []map[string]string{
		nil,
		{"X-SysPulse-Token": e.srv.Token()}, // no origin
		{"Origin": "http://evil.example", "X-SysPulse-Token": e.srv.Token()}, // cross-site
		{"Origin": "http://" + e.host, "X-SysPulse-Token": "wrong"},          // bad token
	}
	for i, h := range cases {
		if code, _, _ := e.req(t, "POST", "/api/software/refresh", "{}", h); code != http.StatusForbidden {
			t.Errorf("case %d: got %d", i, code)
		}
	}
	if code, _, _ := e.req(t, "POST", "/api/software/refresh", "{}", e.auth()); code != http.StatusAccepted {
		t.Fatalf("authorised refresh: %d", code)
	}
}

func waitSoftware(t *testing.T, e *env, cond func(SoftwareState) bool) SoftwareState {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st := e.srv.softwareState()
		if cond(st) {
			return st
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not reached: %+v", e.srv.softwareState())
	return SoftwareState{}
}

func TestSoftwareFlow(t *testing.T) {
	e := newEnv(t)
	code, m, _ := e.req(t, "GET", "/api/software", "", nil)
	if code != 200 || len(m["apps"].([]any)) != 1 {
		t.Fatalf("inventory %d %v", code, m)
	}
	// Unknown package: must refresh first.
	if code, _, _ := e.req(t, "POST", "/api/software/upgrade", `{"id":"Mozilla.Firefox"}`, e.auth()); code != http.StatusNotFound {
		t.Fatalf("upgrade before refresh: %d", code)
	}
	e.req(t, "POST", "/api/software/refresh", "{}", e.auth())
	st := waitSoftware(t, e, func(s SoftwareState) bool { return !s.Checking && len(s.Upgrades) == 1 })
	if st.Apps[0].AvailableVersion != "130.0" || st.Apps[0].WingetID != "Mozilla.Firefox" {
		t.Fatalf("merge %+v", st.Apps[0])
	}
	// Injection attempts are rejected before reaching winget.
	for _, bad := range []string{`{"id":"--all"}`, `{"id":"a b"}`, `{"id":"x;calc"}`, `not json`} {
		if code, _, _ := e.req(t, "POST", "/api/software/upgrade", bad, e.auth()); code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, code)
		}
	}
	if code, _, _ := e.req(t, "POST", "/api/software/upgrade", `{"id":"Mozilla.Firefox"}`, e.auth()); code != http.StatusAccepted {
		t.Fatalf("upgrade: %d", code)
	}
	st = waitSoftware(t, e, func(s SoftwareState) bool { return len(s.Results) == 1 && len(s.Upgrading) == 0 })
	if !st.Results[0].OK || st.Results[0].Output != "Successfully installed" {
		t.Fatalf("result %+v", st.Results[0])
	}
	e.sw.fail = true
	e.req(t, "POST", "/api/software/upgrade", `{"id":"Mozilla.Firefox"}`, e.auth())
	st = waitSoftware(t, e, func(s SoftwareState) bool { return len(s.Results) == 2 && len(s.Upgrading) == 0 })
	if st.Results[0].OK || !strings.Contains(st.Results[0].Output, "exit status 1") {
		t.Fatalf("failed result %+v", st.Results[0])
	}
}

// wsDial performs a client handshake and returns a masked-frame writer.
func wsDial(t *testing.T, e *env, origin, token string) (net.Conn, *bufio.Reader, string) {
	t.Helper()
	c, err := net.Dial("tcp", e.host)
	if err != nil {
		t.Fatal(err)
	}
	req := "GET /ws?token=" + token + " HTTP/1.1\r\nHost: " + e.host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: " + origin + "\r\n\r\n"
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

func TestWebSocketStream(t *testing.T) {
	e := newEnv(t)
	c, _, status := wsDial(t, e, "http://evil.example", e.srv.Token())
	c.Close()
	if !strings.Contains(status, "403") {
		t.Fatalf("cross-origin ws accepted: %q", status)
	}
	c, _, status = wsDial(t, e, "http://"+e.host, "badtoken")
	c.Close()
	if !strings.Contains(status, "403") {
		t.Fatalf("bad token accepted: %q", status)
	}
	c, br, status := wsDial(t, e, "http://"+e.host, e.srv.Token())
	defer c.Close()
	if !strings.Contains(status, "101") {
		t.Fatalf("status %q", status)
	}
	client := ws.NewConn(&readerConn{Conn: c, r: br})
	seen := map[string]bool{}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	for !(seen["snapshot"] && seen["metrics"] && seen["netstats"]) {
		op, payload, err := readServerFrame(client)
		if err != nil {
			t.Fatalf("read: %v (seen %v)", err, seen)
		}
		if op != ws.OpText {
			continue
		}
		var m model.Message
		if err := json.Unmarshal(payload, &m); err != nil {
			t.Fatal(err)
		}
		if !seen[m.Type] && m.Type == "snapshot" && len(seen) > 0 {
			t.Fatal("snapshot must be the first message")
		}
		seen[m.Type] = true
	}
	if e.srv.Hub.Subscribers() != 1 {
		t.Fatalf("subscribers %d", e.srv.Hub.Subscribers())
	}
	c.Write(ws.EncodeFrame(ws.OpClose, []byte{3, 232}, []byte{9, 9, 9, 9}))
	deadline := time.Now().Add(2 * time.Second)
	for e.srv.Hub.Subscribers() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if e.srv.Hub.Subscribers() != 0 {
		t.Fatal("subscriber not released after close")
	}
}

// readerConn lets a ws.Conn reuse the handshake's buffered reader.
type readerConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// readServerFrame reads one unmasked server frame.
func readServerFrame(c *ws.Conn) (byte, []byte, error) { return ws.ReadServerFrame(c) }
