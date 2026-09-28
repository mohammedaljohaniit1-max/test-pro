package server

// SysPulse 4.0 HTTP API: interface throughput, Windows services, the
// process hierarchy, the executive health score and CRUD for the
// user-configurable alert rules. Every mutating route goes through guard()
// (loopback Host + same Origin + session token).

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/rules"
)

func (s *Server) routesV4(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/interfaces", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.Hub.Interfaces()) })
	mux.HandleFunc("GET /api/services", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.Hub.Services()) })
	mux.HandleFunc("GET /api/processes/tree", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.Hub.ProcessTree()) })
	mux.HandleFunc("GET /api/health/score", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.Hub.Health()) })
	mux.HandleFunc("GET /api/rules", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.Hub.RulesState()) })
	mux.HandleFunc("POST /api/rules", s.guard(s.ruleCreate))
	mux.HandleFunc("PUT /api/rules/{id}", s.guard(s.ruleUpdate))
	mux.HandleFunc("DELETE /api/rules/{id}", s.guard(s.ruleDelete))
	mux.HandleFunc("POST /api/rules/reset", s.guard(s.ruleReset))
}

func decodeRule(w http.ResponseWriter, r *http.Request) (rules.Rule, bool) {
	var rule rules.Rule
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rule); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid rule JSON: "+err.Error())
		return rule, false
	}
	return rule, true
}

func (s *Server) ruleResult(w http.ResponseWriter, code int, rule rules.Rule, err error) {
	switch {
	case errors.Is(err, rules.ErrNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	case err != nil && rule.ID == "":
		writeErr(w, http.StatusBadRequest, err.Error())
	default:
		if err != nil { // saved in memory; persistence failed
			s.Log.Warn("rules not persisted", "err", err)
		}
		s.Hub.BroadcastRules()
		writeJSON(w, code, rule)
	}
}

func (s *Server) ruleCreate(w http.ResponseWriter, r *http.Request) {
	rule, ok := decodeRule(w, r)
	if !ok {
		return
	}
	out, err := s.Hub.Rules().Create(rule)
	s.ruleResult(w, http.StatusCreated, out, err)
}

func (s *Server) ruleUpdate(w http.ResponseWriter, r *http.Request) {
	rule, ok := decodeRule(w, r)
	if !ok {
		return
	}
	out, err := s.Hub.Rules().Update(r.PathValue("id"), rule)
	s.ruleResult(w, http.StatusOK, out, err)
}

func (s *Server) ruleDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.Hub.Rules().Delete(r.PathValue("id")); errors.Is(err, rules.ErrNotFound) {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	} else if err != nil {
		s.Log.Warn("rules not persisted", "err", err)
	}
	s.Hub.BroadcastRules()
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func (s *Server) ruleReset(w http.ResponseWriter, _ *http.Request) {
	if err := s.Hub.Rules().Reset(); err != nil {
		s.Log.Warn("rules not persisted", "err", err)
	}
	s.Hub.BroadcastRules()
	writeJSON(w, http.StatusOK, s.Hub.RulesState())
}
