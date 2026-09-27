package server

// SysPulse 3.0 HTTP API: LAN device inventory (OUI vendor + resolved host
// names), deep process inspection, and runtime mode information.

import (
	"net/http"
	"strconv"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/oui"
)

func (s *Server) routesV3(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/devices", s.devices)
	mux.HandleFunc("POST /api/devices/resolve", s.guard(s.devicesResolve))
	mux.HandleFunc("GET /api/oui", s.ouiLookup)
	mux.HandleFunc("GET /api/processes/{pid}", s.processDetail)
	mux.HandleFunc("GET /api/mode", s.mode)
}

// Mode describes how this instance was started (shown in the UI).
type Mode struct {
	Version  string `json:"version"`
	Live     bool   `json:"live"`     // telemetry from the real host only
	SelfTest bool   `json:"selfTest"` // synthetic self-test allowed
	Platform string `json:"platform"`
	OUISize  int    `json:"ouiPrefixes"`
}

func (s *Server) mode(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, Mode{Version: Version, Live: !s.Synthetic, SelfTest: s.Hub.SelfTestEnabled(), Platform: s.Platform, OUISize: oui.Size()})
}

func (s *Server) devices(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"devices": s.Hub.Devices(), "ouiPrefixes": oui.Size()})
}

func (s *Server) devicesResolve(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusAccepted, map[string]any{"resolving": s.Hub.ResolveDevices()})
}

func (s *Server) ouiLookup(w http.ResponseWriter, r *http.Request) {
	v, ok := oui.Lookup(r.URL.Query().Get("mac"))
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown or invalid MAC address")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) processDetail(w http.ResponseWriter, r *http.Request) {
	pid, err := strconv.ParseUint(r.PathValue("pid"), 10, 32)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid pid")
		return
	}
	d, ok := s.Hub.InspectProcess(uint32(pid))
	if !ok {
		writeErr(w, http.StatusNotFound, "process not running")
		return
	}
	writeJSON(w, http.StatusOK, d)
}
