package server

import (
	"net/http"
	"testing"
)

func TestRulesCRUDGuardedAndValidated(t *testing.T) {
	e := newEnv(t)
	code, m, _ := e.req(t, "GET", "/api/rules", "", nil)
	if code != 200 || len(m["rules"].([]any)) == 0 || len(m["catalog"].([]any)) == 0 {
		t.Fatalf("list %d %v", code, m)
	}
	body := `{"name":"Chrome hog","metric":"proc_cpu","op":">","threshold":40,"for":10,"scope":"chrome*","severity":"critical","enabled":true}`
	if code, _, _ := e.req(t, "POST", "/api/rules", body, nil); code != http.StatusForbidden {
		t.Fatalf("unguarded create %d", code)
	}
	code, m, raw := e.req(t, "POST", "/api/rules", body, e.auth())
	if code != http.StatusCreated || m["id"] == "" || m["scope"] != "chrome*" {
		t.Fatalf("create %d %s", code, raw)
	}
	id := m["id"].(string)
	if code, _, _ := e.req(t, "POST", "/api/rules", `{"metric":"cpu","op":"~","threshold":1,"severity":"info"}`, e.auth()); code != http.StatusBadRequest {
		t.Fatalf("invalid op accepted %d", code)
	}
	if code, _, _ := e.req(t, "POST", "/api/rules", `{"metric":"cpu","op":">","threshold":1,"severity":"info","evil":1}`, e.auth()); code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted %d", code)
	}
	upd := `{"name":"Chrome hog","metric":"proc_cpu","op":">","threshold":60,"for":10,"scope":"chrome*","severity":"warning","enabled":false}`
	if code, m, _ := e.req(t, "PUT", "/api/rules/"+id, upd, e.auth()); code != 200 || m["threshold"].(float64) != 60 || m["enabled"] != false {
		t.Fatalf("update %d %v", code, m)
	}
	if code, _, _ := e.req(t, "PUT", "/api/rules/nope", upd, e.auth()); code != http.StatusNotFound {
		t.Fatalf("update missing %d", code)
	}
	if code, _, _ := e.req(t, "DELETE", "/api/rules/"+id, "", e.auth()); code != 200 {
		t.Fatalf("delete %d", code)
	}
	if code, _, _ := e.req(t, "POST", "/api/rules/reset", "{}", e.auth()); code != 200 {
		t.Fatalf("reset %d", code)
	}
	for _, p := range []string{"/api/interfaces", "/api/services", "/api/processes/tree", "/api/health/score"} {
		if code, _, raw := e.req(t, "GET", p, "", nil); code != 200 {
			t.Fatalf("%s %d %s", p, code, raw)
		}
	}
}
