package server

// SysPulse 2.0 HTTP API: network radar, alerts & incidents (with CSV/JSON
// export) and the one-click event-log audits.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/alerts"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/audit"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/hub"
)

func (s *Server) routesV2(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/radar", s.radarState)
	mux.HandleFunc("GET /api/radar/neighbors", s.radarNeighbors)
	mux.HandleFunc("POST /api/radar/selftest", s.guard(s.radarSelfTest))
	mux.HandleFunc("GET /api/alerts", s.alertsList)
	mux.HandleFunc("GET /api/alerts/export", s.alertsExport)
	mux.HandleFunc("POST /api/alerts/ack", s.guard(s.alertsAck))
	mux.HandleFunc("POST /api/alerts/clear", s.guard(s.alertsClear))
	mux.HandleFunc("GET /api/audit", s.auditState)
	mux.HandleFunc("POST /api/audit/{kind}", s.guard(s.auditRun))
	mux.HandleFunc("GET /api/audit/{kind}/export", s.auditExport)
}

// exportGuard protects downloads of sensitive reports. Browser downloads
// (<a download>) cannot send custom headers, so the token may be passed as
// ?token=; the Host must still be loopback.
func (s *Server) exportAllowed(r *http.Request) bool {
	if !isLoopbackHost(r.Host) {
		return false
	}
	return r.Header.Get("X-SysPulse-Token") == s.token || r.URL.Query().Get("token") == s.token
}

func (s *Server) radarState(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 5000 {
		limit = v
	}
	writeJSON(w, http.StatusOK, s.Hub.Radar().Snapshot(limit))
}

func (s *Server) radarNeighbors(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"neighbors": s.Hub.Radar().Neighbors()})
}

func (s *Server) radarSelfTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ports int `json:"ports"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req)
	inc, err := s.Hub.RadarSelfTest(req.Ports)
	if err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"incident": inc, "remoteIp": hub.SelfTestIP})
}

func (s *Server) alertsList(w http.ResponseWriter, r *http.Request) {
	f := alerts.ParseFilter(r.URL.Query().Get)
	if f.Limit == 0 {
		f.Limit = 1000
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": s.Hub.Alerts().List(f), "counts": s.Hub.Alerts().Counts()})
}

func (s *Server) alertsExport(w http.ResponseWriter, r *http.Request) {
	if !s.exportAllowed(r) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	q := r.URL.Query()
	f := alerts.ParseFilter(q.Get)
	list := s.Hub.Alerts().List(f)
	stamp := time.Now().Format("20060102-150405")
	w.Header().Set("Cache-Control", "no-store")
	switch q.Get("format") {
	case "csv":
		b, err := alerts.ExportCSV(list, q.Get("lang"))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="syspulse-alerts-`+stamp+`.csv"`)
		_, _ = w.Write(b)
	case "json", "":
		b, err := alerts.ExportJSON(alerts.Report{Generated: time.Now().UTC(), Host: s.Hub.Metrics().Hostname, Version: Version, Filter: f,
			Counts: s.Hub.Alerts().Counts(), Alerts: list})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="syspulse-alerts-`+stamp+`.json"`)
		_, _ = w.Write(b)
	default:
		writeErr(w, http.StatusBadRequest, "format must be csv or json")
	}
}

func (s *Server) alertsAck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	n := s.Hub.Alerts().Ack(req.IDs)
	s.Hub.Broadcast("alertcounts", s.Hub.Alerts().Counts())
	writeJSON(w, http.StatusOK, map[string]any{"acked": n})
}

func (s *Server) alertsClear(w http.ResponseWriter, _ *http.Request) {
	s.Hub.Alerts().Clear()
	s.Hub.Broadcast("alertsreset", s.Hub.Alerts().Counts())
	writeJSON(w, http.StatusOK, map[string]any{"cleared": true})
}

func (s *Server) auditState(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Hub.AuditState())
}

func validAuditKind(k string) bool { return k == audit.KindAuth || k == audit.KindReliability }

func (s *Server) auditRun(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if !validAuditKind(kind) {
		writeErr(w, http.StatusNotFound, "unknown audit")
		return
	}
	var req struct {
		Hours int `json:"hours"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req)
	if req.Hours <= 0 {
		req.Hours = 168
	}
	if req.Hours > 24*90 {
		req.Hours = 24 * 90
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	rep, err := s.Hub.RunAudit(ctx, kind, time.Duration(req.Hours)*time.Hour)
	switch {
	case errors.Is(err, hub.ErrAuditBusy):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, hub.ErrAuditUnavailable):
		writeErr(w, http.StatusNotImplemented, err.Error())
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
	default:
		writeJSON(w, http.StatusOK, rep)
	}
}

func (s *Server) auditExport(w http.ResponseWriter, r *http.Request) {
	if !s.exportAllowed(r) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	kind := r.PathValue("kind")
	if !validAuditKind(kind) {
		writeErr(w, http.StatusNotFound, "unknown audit")
		return
	}
	rep, ok := s.Hub.AuditState().Reports[kind]
	if !ok {
		writeErr(w, http.StatusNotFound, "run the audit first")
		return
	}
	stamp := rep.Finished.Format("20060102-150405")
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Query().Get("format") == "csv" {
		b, err := audit.ExportCSV(rep, r.URL.Query().Get("lang"))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="syspulse-audit-`+kind+`-`+stamp+`.csv"`)
		_, _ = w.Write(b)
		return
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="syspulse-audit-`+kind+`-`+stamp+`.json"`)
	_, _ = w.Write(b)
}
