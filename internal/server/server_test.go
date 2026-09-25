package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/engine"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/metrics"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/rules"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/sink"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/wal"
)

const testRules = `
rule brute {
  severity critical
  within 1m
  sequence {
    fail: auth.failure[3:]
    ok: auth.success where user == fail.user
  }
  emit { user = ok.user, failures = count(fail) }
}
rule missing_hb {
  within 30s
  sequence { s: service.start  !h: service.heartbeat }
}`

type stack struct {
	t    *testing.T
	eng  *engine.Engine
	hub  *sink.Hub
	api  *API
	srv  *httptest.Server
	tcp  *TCPServer
	disp chan struct{}
	log  *wal.Log
	done bool
}

func newStack(t *testing.T, walDir, token string) *stack {
	return newStackL(t, walDir, token, 0)
}

func newStackL(t *testing.T, walDir, token string, lateness time.Duration) *stack {
	t.Helper()
	rs, err := rules.Compile(testRules)
	if err != nil {
		t.Fatal(err)
	}
	eng := engine.New(engine.Config{Shards: 2, AllowedLateness: lateness}, rs)
	var wl *wal.Log
	if walDir != "" {
		eng.SetMuted(true)
		if _, err := wal.Replay(walDir, 0, func(e *event.Event) error {
			eng.ObserveSeq(e.Seq)
			return eng.Submit(context.Background(), e)
		}); err != nil {
			t.Fatal(err)
		}
		if err := eng.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
		eng.SetMuted(false)
		wl, err = wal.Open(wal.Options{Dir: walDir, Sync: wal.SyncAlways})
		if err != nil {
			t.Fatal(err)
		}
		eng.ObserveSeq(wl.LastSeq())
	}
	hub := sink.NewHub(100)
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := sink.NewDispatcher(lg, 100, hub)
	done := make(chan struct{})
	go func() { d.Run(context.Background(), eng.Alerts()); close(done) }()
	ing := NewIngestor(eng, wl)
	tcp := &TCPServer{Addr: "127.0.0.1:0", Ingest: ing, Log: lg, BatchSize: 64}
	if err := tcp.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = tcp.Serve(context.Background()) }()
	api := &API{
		Engine: eng, Ingest: ing, Hub: hub, Dispatcher: d, WAL: wl, TCP: tcp,
		Registry: metrics.NewRegistry(), Log: lg, AuthToken: token,
		MaxBodyBytes: 1 << 20, Started: time.Now(), RulesPath: "../../rules",
	}
	api.RegisterMetrics()
	api.SetReady(true)
	s := &stack{t: t, eng: eng, hub: hub, api: api, srv: httptest.NewServer(api.Handler()), tcp: tcp, disp: done, log: wl}
	t.Cleanup(s.stop)
	return s
}

func (s *stack) stop() {
	if s.done {
		return
	}
	s.done = true
	s.srv.Close()
	_ = s.tcp.Close()
	s.eng.Close()
	<-s.disp
	if s.log != nil {
		_ = s.log.Close()
	}
}

func (s *stack) do(method, path, body, ctype string, hdr ...string) (int, map[string]any) {
	s.t.Helper()
	req, _ := http.NewRequest(method, s.srv.URL+path, strings.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m
}

func (s *stack) waitAlerts(n int) []*engine.Alert {
	s.t.Helper()
	_ = s.eng.Sync(context.Background())
	deadline := time.Now().Add(3 * time.Second)
	for {
		a := s.hub.Recent(1000, "", "")
		if len(a) >= n || time.Now().After(deadline) {
			return a
		}
		time.Sleep(2 * time.Millisecond)
	}
}

var base = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

func bruteNDJSON(key string) string {
	var b strings.Builder
	for i := 0; i < 3; i++ {
		fmt.Fprintf(&b, `{"type":"auth.failure","key":%q,"ts":%q,"attrs":{"user":"root"}}`+"\n", key, base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano))
	}
	fmt.Fprintf(&b, `{"type":"auth.success","key":%q,"ts":%q,"attrs":{"user":"root"}}`+"\n", key, base.Add(4*time.Second).Format(time.RFC3339Nano))
	return b.String()
}

func TestHTTPIngestNDJSONProducesAlert(t *testing.T) {
	s := newStack(t, "", "")
	code, resp := s.do("POST", "/v1/events", bruteNDJSON("1.2.3.4"), "application/x-ndjson")
	if code != http.StatusAccepted || resp["accepted"] != 4.0 {
		t.Fatalf("code=%d resp=%v", code, resp)
	}
	a := s.waitAlerts(1)
	if len(a) != 1 || a[0].Rule != "brute" || a[0].Key != "1.2.3.4" || a[0].Severity != "critical" {
		t.Fatalf("alerts: %+v", a)
	}
	code, list := s.do("GET", "/v1/alerts?rule=brute&limit=10", "", "")
	if code != 200 || list["count"] != 1.0 {
		t.Fatalf("list: %d %v", code, list)
	}
	if code, _ := s.do("GET", "/v1/alerts?limit=0", "", ""); code != http.StatusBadRequest {
		t.Fatalf("bad limit accepted: %d", code)
	}
}

func TestHTTPIngestJSONArrayAndPartialInvalid(t *testing.T) {
	s := newStack(t, "", "")
	body := `[{"type":"x","key":"a"},{"key":"missing-type"},{"type":"y","attrs":{"n":{"nested":1}}},{"type":"z"}]`
	code, resp := s.do("POST", "/v1/events", body, "application/json")
	if code != http.StatusAccepted || resp["accepted"] != 2.0 || resp["invalid"] != 2.0 {
		t.Fatalf("code=%d resp=%v", code, resp)
	}
	if errs, _ := resp["errors"].([]any); len(errs) != 2 {
		t.Fatalf("errors: %v", resp["errors"])
	}
	if code, _ := s.do("POST", "/v1/events", `[{"key":"only-invalid"}]`, "application/json"); code != http.StatusBadRequest {
		t.Fatalf("all-invalid batch: %d", code)
	}
	if code, _ := s.do("POST", "/v1/events", "", "application/json"); code != http.StatusBadRequest {
		t.Fatalf("empty body: %d", code)
	}
	if code, _ := s.do("POST", "/v1/events", `[{"type":`, "application/json"); code != http.StatusBadRequest {
		t.Fatalf("broken json: %d", code)
	}
}

func TestHTTPBodyLimit(t *testing.T) {
	s := newStack(t, "", "")
	s.api.MaxBodyBytes = 2048
	s.srv.Config.Handler = s.api.Handler()
	big := "[" + strings.Repeat(`{"type":"x","key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},`, 200) + `{"type":"x"}]`
	if code, _ := s.do("POST", "/v1/events", big, "application/json"); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code=%d", code)
	}
}

func TestAuthRequiredForMutations(t *testing.T) {
	s := newStack(t, "", "tok")
	if code, _ := s.do("POST", "/v1/events", `{"type":"x"}`, ""); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated ingest: %d", code)
	}
	if code, _ := s.do("POST", "/v1/events", `{"type":"x"}`, "", "Authorization", "Bearer wrong"); code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", code)
	}
	if code, _ := s.do("POST", "/v1/events", `{"type":"x"}`, "", "Authorization", "Bearer tok"); code != http.StatusAccepted {
		t.Fatalf("valid token: %d", code)
	}
	if code, _ := s.do("PUT", "/v1/rules", `rule a { within 1s sequence { x: t } }`, ""); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated rule replace: %d", code)
	}
	// Stats must be a valid, non-empty document even before any latency
	// sample exists (empty histograms yield NaN quantiles).
	code, st := s.do("GET", "/v1/stats", "", "")
	if code != 200 || st["engine"] == nil || st["latency"] == nil {
		t.Fatalf("stats: %d %v", code, st)
	}
}

func TestAdvanceTriggersAbsence(t *testing.T) {
	s := newStack(t, "", "")
	s.do("POST", "/v1/events", fmt.Sprintf(`{"type":"service.start","key":"svc","ts":%q}`, base.Format(time.RFC3339)), "")
	if code, _ := s.do("POST", "/v1/advance", fmt.Sprintf(`{"ts":%q}`, base.Add(time.Minute).Format(time.RFC3339)), ""); code != 200 {
		t.Fatalf("advance: %d", code)
	}
	a := s.waitAlerts(1)
	if len(a) != 1 || a[0].Rule != "missing_hb" || a[0].Kind != "absence" {
		t.Fatalf("alerts %+v", a)
	}
	if code, _ := s.do("POST", "/v1/advance", `{}`, ""); code != http.StatusBadRequest {
		t.Fatalf("advance without ts: %d", code)
	}
}

func TestRulesAPI(t *testing.T) {
	s := newStack(t, "", "")
	code, list := s.do("GET", "/v1/rules", "", "")
	if code != 200 || len(list["rules"].([]any)) != 2 {
		t.Fatalf("list %d %v", code, list)
	}
	code, v := s.do("POST", "/v1/rules/validate", `rule bad { within }`, "")
	if code != http.StatusUnprocessableEntity || !strings.Contains(fmt.Sprint(v["detail"]), "expected duration") {
		t.Fatalf("validate bad: %d %v", code, v)
	}
	if code, _ := s.do("POST", "/v1/rules/validate", `rule ok { within 1s sequence { a: t } }`, ""); code != 200 {
		t.Fatalf("validate ok: %d", code)
	}
	code, put := s.do("PUT", "/v1/rules", `rule only { within 1s sequence { a: ping } }`, "")
	if code != 200 || put["rules"] != 1.0 {
		t.Fatalf("put: %d %v", code, put)
	}
	s.do("POST", "/v1/events", `{"type":"ping","key":"k"}`, "")
	if a := s.waitAlerts(1); len(a) != 1 || a[0].Rule != "only" {
		t.Fatalf("new ruleset not active: %+v", a)
	}
	code, rl := s.do("POST", "/v1/rules/reload", "", "")
	if code != 200 || rl["rules"].(float64) < 5 {
		t.Fatalf("reload from disk: %d %v", code, rl)
	}
}

func TestMetricsAndProbes(t *testing.T) {
	s := newStack(t, "", "")
	s.do("POST", "/v1/events", bruteNDJSON("m"), "")
	s.waitAlerts(1)
	resp, err := http.Get(s.srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	out := string(b)
	for _, want := range []string{
		"tempora_events_processed_total 4", "tempora_alerts_total 1", "tempora_ingest_accepted_total 4",
		`tempora_shard_queue_depth{shard="0"}`, `tempora_eval_latency_seconds{quantile="0.99"}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	if code, _ := s.do("GET", "/healthz", "", ""); code != 200 {
		t.Fatal("healthz")
	}
	if code, _ := s.do("GET", "/", "", ""); code != 200 {
		t.Fatal("index")
	}
	s.api.SetReady(false)
	if code, _ := s.do("GET", "/readyz", "", ""); code != http.StatusServiceUnavailable {
		t.Fatal("readyz should fail when not ready")
	}
	if code, _ := s.do("GET", "/nope", "", ""); code != 404 {
		t.Fatal("404")
	}
}

func TestSSEStream(t *testing.T) {
	s := newStack(t, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", s.srv.URL+"/v1/alerts/stream?rule=brute", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal("content type")
	}
	r := bufio.NewReader(resp.Body)
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, ": connected") {
		t.Fatalf("preamble %q", line)
	}
	s.do("POST", "/v1/events", bruteNDJSON("sse"), "")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("stream ended: %v", err)
		}
		if strings.HasPrefix(line, "data: ") {
			var m map[string]any
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &m); err != nil {
				t.Fatal(err)
			}
			if m["rule"] != "brute" || m["key"] != "sse" {
				t.Fatalf("event %v", m)
			}
			return
		}
	}
}

func TestTCPIngest(t *testing.T) {
	s := newStack(t, "", "")
	c, err := net.Dial("tcp", s.tcp.ListenAddr())
	if err != nil {
		t.Fatal(err)
	}
	payload := "garbage line\n\n   \n" + strings.Repeat("x", 70000) + "\n" + bruteNDJSON("tcp-key")
	if _, err := io.WriteString(c, payload); err != nil {
		t.Fatal(err)
	}
	c.Close()
	deadline := time.Now().Add(3 * time.Second)
	for s.api.Ingest.Stats().Accepted < 4 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	a := s.waitAlerts(1)
	if len(a) != 1 || a[0].Key != "tcp-key" {
		t.Fatalf("alerts %+v", a)
	}
	if st := s.api.Ingest.Stats(); st.Accepted != 4 || st.Invalid != 2 {
		t.Fatalf("ingest stats %+v", st)
	}
}

// TestCrashRecoveryFromWAL: partial detection state built before a restart
// is rebuilt from the WAL, pre-restart alerts are re-derived but muted, and
// the sequence counter continues.
func TestCrashRecoveryFromWAL(t *testing.T) {
	dir := t.TempDir()
	s1 := newStack(t, dir, "")
	s1.do("POST", "/v1/events", bruteNDJSON("done"), "")
	partial := strings.SplitAfter(bruteNDJSON("partial"), "\n")
	s1.do("POST", "/v1/events", strings.Join(partial[:3], ""), "")
	if a := s1.waitAlerts(1); len(a) != 1 {
		t.Fatalf("pre-crash alerts %d", len(a))
	}
	lastSeq := s1.log.LastSeq()
	s1.stop()

	s2 := newStack(t, dir, "")
	if got := s2.eng.Totals().Muted; got != 1 {
		t.Fatalf("replay should re-derive (and mute) the old alert, muted=%d", got)
	}
	s2.do("POST", "/v1/events", partial[3], "")
	a := s2.waitAlerts(1)
	if len(a) != 1 || a[0].Key != "partial" {
		t.Fatalf("post-recovery alerts: %+v", a)
	}
	if s2.log.LastSeq() != lastSeq+1 {
		t.Fatalf("sequence did not continue: %d after %d", s2.log.LastSeq(), lastSeq)
	}
}

// TestReplayDoesNotRedeliverBufferedAlerts reproduces a production bug: with
// non-zero lateness the last replayed events sit in the reorder buffer; they
// must be flushed while muted, otherwise the pre-crash alert is re-delivered
// once the watermark advances after startup.
func TestReplayDoesNotRedeliverBufferedAlerts(t *testing.T) {
	dir := t.TempDir()
	s1 := newStackL(t, dir, "", 5*time.Second)
	s1.do("POST", "/v1/events", bruteNDJSON("x"), "")
	if err := s1.eng.Advance(context.Background(), base.Add(time.Minute).UnixNano()); err != nil {
		t.Fatal(err)
	}
	if a := s1.waitAlerts(1); len(a) != 1 {
		t.Fatalf("pre-crash alerts %d", len(a))
	}
	s1.stop()

	s2 := newStackL(t, dir, "", 5*time.Second)
	if err := s2.eng.Advance(context.Background(), base.Add(time.Hour).UnixNano()); err != nil {
		t.Fatal(err)
	}
	if a := s2.waitAlerts(1); len(a) != 0 {
		t.Fatalf("replayed alert re-delivered after restart: %+v", a[0])
	}
	if m := s2.eng.Totals().Muted; m != 1 {
		t.Fatalf("muted=%d, want the replayed alert counted as muted", m)
	}
}
