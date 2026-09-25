package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/hub"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/ws"
)

type fakeAuditSrc struct{}

func (fakeAuditSrc) QueryXPath(ch, xpath string, max int, format bool) ([]model.Event, error) {
	if ch != "Security" {
		return nil, nil
	}
	var out []model.Event
	for i := 0; i < 12; i++ {
		out = append(out, model.Event{EventID: 4625, Time: time.Now().Add(-time.Duration(i) * time.Second),
			Data: map[string]string{"TargetUserName": "admin", "IpAddress": "203.0.113.9", "LogonType": "10", "SubStatus": "0xc000006a"}})
	}
	return out, nil
}

func TestRadarSelfTestRaisesAlertAndStreams(t *testing.T) {
	e := newEnv(t)
	c, br, status := wsDial(t, e, "http://"+e.host, e.srv.Token())
	defer c.Close()
	if !strings.Contains(status, "101") {
		t.Fatal(status)
	}
	// Mutations are guarded.
	if code, _, _ := e.req(t, "POST", "/api/radar/selftest", "{}", nil); code != http.StatusForbidden {
		t.Fatalf("unguarded selftest: %d", code)
	}
	code, m, _ := e.req(t, "POST", "/api/radar/selftest", `{"ports":20}`, e.auth())
	if code != 200 {
		t.Fatalf("selftest %d", code)
	}
	inc := m["incident"].(map[string]any)
	if inc["remoteIp"] != hub.SelfTestIP || inc["distinctPorts"].(float64) != 20 || inc["test"] != true {
		t.Fatalf("incident %v", inc)
	}
	client := ws.NewConn(&readerConn{Conn: c, r: br})
	c.SetReadDeadline(time.Now().Add(4 * time.Second))
	seen := map[string]bool{}
	for !(seen["sweep"] && seen["alert"] && seen["radar"]) {
		op, payload, err := readServerFrame(client)
		if err != nil {
			t.Fatalf("read: %v (seen %v)", err, seen)
		}
		if op != ws.OpText {
			continue
		}
		var msg model.Message
		json.Unmarshal(payload, &msg)
		seen[msg.Type] = true
	}
	// Attribution for the self-test completes with the documentation MAC.
	deadline := time.Now().Add(2 * time.Second)
	for {
		incs := e.srv.Hub.Radar().Incidents()
		if len(incs) > 0 && incs[0].MAC == hub.SelfTestMAC {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("self-test not attributed: %+v", incs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	code, m, _ = e.req(t, "GET", "/api/alerts?category=network-sweep", "", nil)
	list := m["alerts"].([]any)
	if code != 200 || len(list) != 1 {
		t.Fatalf("alerts %d %v", code, m)
	}
	a := list[0].(map[string]any)
	if a["severity"] != "critical" || a["fields"].(map[string]any)["mac"] != hub.SelfTestMAC || a["title"].(map[string]any)["ar"] == "" {
		t.Fatalf("alert %v", a)
	}
	code, m, _ = e.req(t, "GET", "/api/radar", "", nil)
	if code != 200 || m["threshold"].(float64) != 10 || m["windowSec"].(float64) != 5 || m["active"].(float64) != 1 {
		t.Fatalf("radar %v", m)
	}
}

func TestAlertExportRequiresTokenAndAck(t *testing.T) {
	e := newEnv(t)
	e.srv.Hub.RadarSelfTest(0)
	if code, _, _ := e.req(t, "GET", "/api/alerts/export?format=csv", "", nil); code != http.StatusForbidden {
		t.Fatalf("export without token: %d", code)
	}
	resp, err := http.Get(e.ts.URL + "/api/alerts/export?format=csv&lang=ar&token=" + e.srv.Token())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Disposition"), ".csv") || !strings.Contains(body, "الخطورة") {
		t.Fatalf("csv %d %q", resp.StatusCode, body)
	}
	code, m, _ := e.req(t, "GET", "/api/alerts/export?format=json&severity=critical", "", map[string]string{"X-SysPulse-Token": e.srv.Token()})
	if code != 200 || len(m["alerts"].([]any)) != 1 {
		t.Fatalf("json export %d %v", code, m)
	}
	if code, _, _ := e.req(t, "GET", "/api/alerts/export?format=xml&token="+e.srv.Token(), "", nil); code != http.StatusBadRequest {
		t.Fatalf("bad format %d", code)
	}
	if code, m, _ := e.req(t, "POST", "/api/alerts/ack", `{"ids":[]}`, e.auth()); code != 200 || m["acked"].(float64) < 1 {
		t.Fatalf("ack %d %v", code, m)
	}
	if code, _, _ := e.req(t, "POST", "/api/alerts/clear", `{}`, e.auth()); code != 200 || e.srv.Hub.Alerts().Counts().Total != 0 {
		t.Fatal("clear")
	}
}

func TestAuditEndpoints(t *testing.T) {
	e := newEnv(t)
	if code, _, _ := e.req(t, "POST", "/api/audit/auth", `{}`, e.auth()); code != http.StatusNotImplemented {
		t.Fatalf("audit without source: %d", code)
	}
	e.srv.Hub.SetAuditSource(fakeAuditSrc{})
	if code, _, _ := e.req(t, "POST", "/api/audit/nope", `{}`, e.auth()); code != http.StatusNotFound {
		t.Fatalf("unknown kind: %d", code)
	}
	if code, _, _ := e.req(t, "POST", "/api/audit/auth", `{}`, nil); code != http.StatusForbidden {
		t.Fatalf("unguarded audit: %d", code)
	}
	if code, _, _ := e.req(t, "GET", "/api/audit/auth/export?token="+e.srv.Token(), "", nil); code != http.StatusNotFound {
		t.Fatalf("export before run: %d", code)
	}
	code, m, _ := e.req(t, "POST", "/api/audit/auth", `{"hours":24}`, e.auth())
	if code != 200 || m["scanned"].(float64) != 12 || m["windowHours"].(float64) != 24 {
		t.Fatalf("audit %d %v", code, m)
	}
	f := m["findings"].([]any)[0].(map[string]any)
	if f["severity"] != "critical" || f["diagnosis"].(map[string]any)["ar"] == "" || f["fix"].(map[string]any)["en"] == "" {
		t.Fatalf("finding %v", f)
	}
	// The critical finding became an alert.
	if got := e.srv.Hub.Alerts().Counts().ByCategory[model.AlertAuth]; got != 1 {
		t.Fatalf("auth alerts %d", got)
	}
	_, st, _ := e.req(t, "GET", "/api/audit", "", nil)
	if st["available"] != true || st["reports"].(map[string]any)["auth"] == nil {
		t.Fatalf("state %v", st)
	}
	resp, err := http.Get(e.ts.URL + "/api/audit/auth/export?format=csv&token=" + e.srv.Token())
	if err != nil || resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") {
		t.Fatalf("csv export %v %v", err, resp.StatusCode)
	}
	resp.Body.Close()
}

func TestSnapshotIncludesV2State(t *testing.T) {
	e := newEnv(t)
	_, m, _ := e.req(t, "GET", "/api/snapshot", "", nil)
	for _, k := range []string{"radar", "alerts", "alertcounts", "audit"} {
		if _, ok := m[k]; !ok {
			t.Errorf("snapshot missing %s", k)
		}
	}
}
