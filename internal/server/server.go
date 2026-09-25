// Package server serves the embedded dashboard, the JSON REST API and the
// WebSocket telemetry stream.
//
// Security model: the server binds to loopback only. Every state-changing
// request (winget upgrade) and every WebSocket upgrade must carry the Origin
// of the dashboard itself, which blocks drive-by requests from other websites
// (CSRF / cross-site WebSocket hijacking). Upgrades additionally require the
// per-process session token that is embedded in the served dashboard.
package server

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/hub"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/software"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/ws"
)

//go:embed web
var webFS embed.FS

// Version is set at build time.
var Version = "dev"

// SoftwareBackend abstracts registry/winget access for tests.
type SoftwareBackend interface {
	Inventory() ([]model.App, error)
	ListUpgrades(ctx context.Context) ([]model.Upgrade, string, error)
	RunUpgrade(ctx context.Context, id string) (string, error)
}

// Server is the HTTP front end.
type Server struct {
	Hub      *hub.Hub
	Software SoftwareBackend
	Log      *slog.Logger
	Addr     string // e.g. 127.0.0.1:9099
	token    string

	swMu       sync.Mutex
	apps       []model.App
	appsAt     time.Time
	appsErr    string
	ups        []model.Upgrade
	upsAt      time.Time
	upsErr     string
	upsRunning bool
	upgrading  map[string]bool
	results    []UpgradeResult
}

// UpgradeResult records one upgrade attempt.
type UpgradeResult struct {
	ID       string    `json:"id"`
	OK       bool      `json:"ok"`
	Output   string    `json:"output"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
}

// New creates a server with a random session token.
func New(h *hub.Hub, sw SoftwareBackend, log *slog.Logger, addr string) *Server {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return &Server{Hub: h, Software: sw, Log: log, Addr: addr, token: hex.EncodeToString(b[:]), upgrading: map[string]bool{}}
}

// Token returns the per-process session token.
func (s *Server) Token() string { return s.token }

// Handler builds the routing table.
func (s *Server) Handler() http.Handler {
	static, _ := fs.Sub(webFS, "web")
	files := http.FileServer(http.FS(static))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.Handle("GET /assets/", files)
	mux.HandleFunc("GET /favicon.svg", func(w http.ResponseWriter, r *http.Request) { files.ServeHTTP(w, r) })
	mux.HandleFunc("GET /ws", s.websocket)
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/snapshot", s.snapshot)
	mux.HandleFunc("GET /api/connections", s.connections)
	mux.HandleFunc("GET /api/processes", s.processes)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("GET /api/software", s.software)
	mux.HandleFunc("POST /api/software/refresh", s.guard(s.refreshSoftware))
	mux.HandleFunc("POST /api/software/upgrade", s.guard(s.upgrade))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws://"+r.Host+"; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// allowedOrigin accepts only the dashboard's own origin (host must match the
// request Host, which is a loopback address we are bound to).
func (s *Server) allowedOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return false
	}
	return o == "http://"+r.Host && isLoopbackHost(r.Host)
}

func isLoopbackHost(hostport string) bool {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		h = hostport
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// guard protects mutating endpoints: loopback Host (DNS-rebinding defence),
// same Origin, and the session token header.
func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackHost(r.Host) || !s.allowedOrigin(r) || r.Header.Get("X-SysPulse-Token") != s.token {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, `{"error":"encode failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if !isLoopbackHost(r.Host) {
		writeErr(w, http.StatusForbidden, "dashboard is only available on localhost")
		return
	}
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "missing index")
		return
	}
	page := strings.Replace(string(b), "{{TOKEN}}", s.token, 1)
	page = strings.Replace(page, "{{VERSION}}", Version, 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(page))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": Version, "clients": s.Hub.Subscribers()})
}

func (s *Server) snapshot(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Hub.Snapshot())
}

func (s *Server) connections(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Hub.Connections())
}

func (s *Server) processes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Hub.Snapshot().Processes)
}

// events supports ?level=critical|error|warning|info, ?category=, ?q= and ?limit=.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	evs, errMsg := s.Hub.Events()
	q := r.URL.Query()
	level, cat, needle := q.Get("level"), q.Get("category"), strings.ToLower(q.Get("q"))
	limit := 1000
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 10000 {
			limit = n
		}
	}
	out := make([]model.Event, 0, limit)
	for _, e := range evs {
		if level != "" && e.LevelStr != level {
			continue
		}
		if cat != "" && e.Category != cat {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(e.Provider+" "+e.Message), needle) {
			continue
		}
		out = append(out, e)
		if len(out) >= limit {
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out, "summary": s.Hub.EventSummary(), "error": errMsg})
}

// websocket upgrades and streams telemetry. The first message is a full
// snapshot; subsequent messages are incremental.
func (s *Server) websocket(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("token") != s.token {
		writeErr(w, http.StatusForbidden, "bad token")
		return
	}
	c, err := ws.Upgrade(w, r, s.allowedOrigin)
	if err != nil {
		return
	}
	sub := s.Hub.Subscribe()
	defer s.Hub.Unsubscribe(sub)
	defer c.Close()
	if err := c.WriteMessage(ws.OpText, hub.Encode("snapshot", s.Hub.Snapshot())); err != nil {
		return
	}
	// Reader: detects disconnects and answers pings. Clients send nothing
	// else of significance.
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		for {
			_ = c.SetReadDeadline(time.Now().Add(90 * time.Second))
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}()
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	for {
		select {
		case b := <-sub.C:
			if err := c.WriteMessage(ws.OpText, b); err != nil {
				return
			}
		case <-ping.C:
			if err := c.WriteMessage(ws.OpPing, nil); err != nil {
				return
			}
		case <-sub.Done():
			return
		case <-gone:
			return
		}
	}
}

// SoftwareState is the payload of GET /api/software.
type SoftwareState struct {
	Apps          []model.App     `json:"apps"`
	AppsAt        time.Time       `json:"appsAt"`
	AppsError     string          `json:"appsError,omitempty"`
	Upgrades      []model.Upgrade `json:"upgrades"`
	UpgradesAt    time.Time       `json:"upgradesAt"`
	UpgradesError string          `json:"upgradesError,omitempty"`
	Checking      bool            `json:"checking"`
	Upgrading     []string        `json:"upgrading"`
	Results       []UpgradeResult `json:"results"`
}

func (s *Server) softwareState() SoftwareState {
	s.swMu.Lock()
	defer s.swMu.Unlock()
	up := make([]string, 0, len(s.upgrading))
	for id := range s.upgrading {
		up = append(up, id)
	}
	sort.Strings(up)
	return SoftwareState{
		Apps: software.Merge(s.apps, s.ups), AppsAt: s.appsAt, AppsError: s.appsErr,
		Upgrades: s.ups, UpgradesAt: s.upsAt, UpgradesError: s.upsErr, Checking: s.upsRunning,
		Upgrading: up, Results: append([]UpgradeResult(nil), s.results...),
	}
}

func (s *Server) software(w http.ResponseWriter, _ *http.Request) {
	s.swMu.Lock()
	empty := s.appsAt.IsZero()
	s.swMu.Unlock()
	if empty {
		s.loadInventory()
	}
	writeJSON(w, http.StatusOK, s.softwareState())
}

func (s *Server) loadInventory() {
	apps, err := s.Software.Inventory()
	s.swMu.Lock()
	defer s.swMu.Unlock()
	s.apps, s.appsAt = apps, time.Now()
	s.appsErr = ""
	if err != nil {
		s.appsErr = err.Error()
	}
}

// RefreshUpgrades runs `winget upgrade` in the background (idempotent while
// a check is already running) and broadcasts the result.
func (s *Server) RefreshUpgrades() bool {
	s.swMu.Lock()
	if s.upsRunning {
		s.swMu.Unlock()
		return false
	}
	s.upsRunning = true
	s.swMu.Unlock()
	go func() {
		s.loadInventory()
		ups, _, err := s.Software.ListUpgrades(context.Background())
		s.swMu.Lock()
		s.upsRunning = false
		s.upsAt = time.Now()
		s.upsErr = ""
		if err != nil {
			s.upsErr = err.Error()
		} else {
			s.ups = ups
		}
		s.swMu.Unlock()
		s.Hub.Broadcast("software", s.softwareState())
	}()
	return true
}

func (s *Server) refreshSoftware(w http.ResponseWriter, _ *http.Request) {
	started := s.RefreshUpgrades()
	writeJSON(w, http.StatusAccepted, map[string]any{"started": started})
}

func (s *Server) upgrade(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if !software.ValidID(req.ID) {
		writeErr(w, http.StatusBadRequest, "invalid package id")
		return
	}
	s.swMu.Lock()
	known := false
	for _, u := range s.ups {
		if u.ID == req.ID {
			known = true
			break
		}
	}
	if !known {
		s.swMu.Unlock()
		writeErr(w, http.StatusNotFound, "package has no pending upgrade; refresh first")
		return
	}
	if s.upgrading[req.ID] {
		s.swMu.Unlock()
		writeErr(w, http.StatusConflict, "upgrade already running")
		return
	}
	s.upgrading[req.ID] = true
	s.swMu.Unlock()
	s.Hub.Broadcast("software", s.softwareState())
	go func(id string) {
		res := UpgradeResult{ID: id, Started: time.Now()}
		out, err := s.Software.RunUpgrade(context.Background(), id)
		res.Finished, res.Output, res.OK = time.Now(), tail(out, 4000), err == nil
		if err != nil && !strings.Contains(res.Output, err.Error()) {
			res.Output = strings.TrimSpace(res.Output + "\n" + err.Error())
		}
		s.Log.Info("winget upgrade finished", "id", id, "ok", res.OK, "took", res.Finished.Sub(res.Started).String())
		s.swMu.Lock()
		delete(s.upgrading, id)
		s.results = append([]UpgradeResult{res}, s.results...)
		if len(s.results) > 20 {
			s.results = s.results[:20]
		}
		s.swMu.Unlock()
		if res.OK {
			s.RefreshUpgrades()
		} else {
			s.Hub.Broadcast("software", s.softwareState())
		}
	}(req.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{"started": req.ID})
}

func tail(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r", ""))
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// ListenAndServe binds the loopback listener and serves until ctx is done.
func (s *Server) ListenAndServe(ctx context.Context, ready func(url string)) error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	if ready != nil {
		ready("http://" + ln.Addr().String() + "/")
	}
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
