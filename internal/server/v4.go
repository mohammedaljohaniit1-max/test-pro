package server

// SysPulse 4.0 HTTP API: interface throughput, Windows services, the
// process hierarchy, the executive health score and CRUD for the
// user-configurable alert rules. Every mutating route goes through guard()
// (loopback Host + same Origin + session token).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
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
	mux.HandleFunc("GET /api/care", s.careState)
	mux.HandleFunc("POST /api/care/{action}", s.guard(s.startCare))
	mux.HandleFunc("GET /api/flow", s.flow)
	mux.HandleFunc("POST /api/software/manifests", s.guard(s.manifests))
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

// GeoRecord is best-effort third-party attribution; unavailable values are
// omitted, never inferred from an OUI or invented from the local gateway.
type GeoRecord struct {
	IP      string    `json:"ip"`
	Country string    `json:"country,omitempty"`
	ISP     string    `json:"isp,omitempty"`
	Error   string    `json:"error,omitempty"`
	At      time.Time `json:"at"`
}

// FlowRate holds measured TCP payload-byte deltas, not interface-wide totals.
type FlowRate struct {
	InBps     float64 `json:"inBps"`
	OutBps    float64 `json:"outBps"`
	Error     string  `json:"error,omitempty"`
	Available bool    `json:"available"`
}

// FlowSampler is implemented by the Windows TCP EStats sampler.
type FlowSampler interface {
	Sample([]model.Connection) map[string]FlowRate
}

type Flow struct {
	Application         string  `json:"application"`
	Local               string  `json:"local"`
	Remote              string  `json:"remote"`
	Protocol            string  `json:"protocol"`
	Direction           string  `json:"direction"`
	Country             string  `json:"country,omitempty"`
	ISP                 string  `json:"isp,omitempty"`
	Classification      string  `json:"classification"`
	ThroughputAvailable bool    `json:"throughputAvailable"`
	InBps               float64 `json:"inBps"`
	OutBps              float64 `json:"outBps"`
	RateError           string  `json:"rateError,omitempty"`
}

func lookupGeo(ctx context.Context, ip string) GeoRecord {
	g := GeoRecord{IP: ip, At: time.Now().UTC()}
	parsed := net.ParseIP(ip)
	if parsed == nil || !parsed.IsGlobalUnicast() || parsed.IsPrivate() {
		return g
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://ipwho.is/"+parsed.String(), nil)
	if err != nil {
		g.Error = err.Error()
		return g
	}
	resp, err := (&http.Client{Timeout: 4 * time.Second}).Do(req)
	if err != nil {
		g.Error = err.Error()
		return g
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		g.Error = resp.Status
		return g
	}
	var body struct {
		Success    bool   `json:"success"`
		Country    string `json:"country"`
		Connection struct {
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&body); err != nil {
		g.Error = err.Error()
		return g
	}
	if !body.Success {
		g.Error = "attribution unavailable"
		return g
	}
	g.Country, g.ISP = body.Country, body.Connection.ISP
	return g
}

func (s *Server) flow(w http.ResponseWriter, _ *http.Request) {
	conns := s.Hub.Connections()
	var selected []model.Connection
	for _, c := range conns {
		if c.RemoteAddr != "" && c.RemotePort != 0 && c.State == "ESTABLISHED" {
			selected = append(selected, c)
			if len(selected) == 200 {
				break
			}
		}
	}
	var rates map[string]FlowRate
	if s.FlowSampler != nil {
		rates = s.FlowSampler.Sample(selected)
	}
	var flows []Flow
	var next string
	s.geoMu.Lock()
	if s.geo == nil {
		s.geo = make(map[string]GeoRecord)
	}
	for _, c := range conns {
		if c.RemoteAddr == "" || c.RemotePort == 0 || c.State != "ESTABLISHED" {
			continue
		}
		ip := net.ParseIP(c.RemoteAddr)
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if len(flows) >= 200 {
			break
		}
		f := Flow{Application: c.ProcessName, Local: net.JoinHostPort(c.LocalAddr, fmt.Sprint(c.LocalPort)),
			Remote: net.JoinHostPort(c.RemoteAddr, fmt.Sprint(c.RemotePort)), Protocol: c.Proto,
			Direction: "outbound/unknown", Classification: "not classified"}
		if rate, ok := rates[c.Key()]; ok {
			f.InBps, f.OutBps, f.ThroughputAvailable, f.RateError = rate.InBps, rate.OutBps, rate.Available, rate.Error
		}
		if c.LocalPort < 1024 && c.RemotePort >= 1024 {
			f.Direction = "inbound/likely"
		}
		if g, ok := s.geo[ip.String()]; ok {
			f.Country, f.ISP = g.Country, g.ISP
		} else if next == "" && ip.IsGlobalUnicast() && !ip.IsPrivate() {
			next = ip.String()
		}
		flows = append(flows, f)
	}
	if next != "" && time.Since(s.geoLast) > 10*time.Second && len(s.geo) < 256 {
		s.geoLast = time.Now()
		go func(ip string) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			g := lookupGeo(ctx, ip)
			s.geoMu.Lock()
			s.geo[ip] = g
			s.geoMu.Unlock()
		}(next)
	}
	wan := s.wan
	if time.Since(s.wanAt) > time.Hour {
		s.wanAt = time.Now()
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// The no-IP endpoint returns our public egress address and provider.
			req, err := http.NewRequestWithContext(ctx, "GET", "https://ipwho.is/", nil)
			if err != nil {
				return
			}
			resp, err := (&http.Client{Timeout: 4 * time.Second}).Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			var body struct {
				Success    bool   `json:"success"`
				IP         string `json:"ip"`
				Country    string `json:"country"`
				Connection struct {
					ISP string `json:"isp"`
				} `json:"connection"`
			}
			if json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&body) == nil && body.Success {
				s.geoMu.Lock()
				s.wan = GeoRecord{IP: body.IP, ISP: body.Connection.ISP, Country: body.Country, At: time.Now().UTC()}
				s.geoMu.Unlock()
			}
		}()
	}
	s.geoMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"flows": flows, "wan": wan, "rateNote": "Per-socket rates are TCP EStats payload-byte deltas when Windows collection is enabled; unavailable when access is denied or the flow is too new."})
}

// ManifestAudit checks explicitly supported official publisher endpoints.
// A missing/unparseable publisher response is reported as an error, not
// misclassified as "up to date". No arbitrary user-supplied URLs are fetched.
type ManifestAudit struct {
	Name      string `json:"name"`
	Installed string `json:"installed"`
	Latest    string `json:"latest,omitempty"`
	Source    string `json:"source"`
	Update    bool   `json:"update"`
	Error     string `json:"error,omitempty"`
}

type manifestSpec struct{ name, match, url, kind string }

var officialManifests = []manifestSpec{
	{"Google Chrome", "google chrome", "https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions?pageSize=1", "chrome"},
	{"Visual Studio Code", "visual studio code", "https://update.code.visualstudio.com/api/update/win32-x64/stable/latest", "vscode"},
	{"Git for Windows", "git", "https://api.github.com/repos/git-for-windows/git/releases/latest", "git"},
	{"Wireshark", "wireshark", "https://www.wireshark.org/download.html", "wireshark"},
	{"VLC", "vlc media player", "https://www.videolan.org/vlc/", "vlc"},
	{"7-Zip", "7-zip", "https://www.7-zip.org/", "7zip"},
}
var versionNumber = regexp.MustCompile(`\d+(?:\.\d+){1,3}`)

func officialVersion(ctx context.Context, spec manifestSpec) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", spec.url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "SysPulse/5.0 (+local-version-audit)")
	resp, err := (&http.Client{Timeout: 6 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("publisher returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	if err != nil {
		return "", err
	}
	var v string
	switch spec.kind {
	case "chrome":
		var doc struct {
			Versions []struct {
				Version string `json:"version"`
			} `json:"versions"`
		}
		if err = json.Unmarshal(body, &doc); err == nil && len(doc.Versions) > 0 {
			v = doc.Versions[0].Version
		}
	case "vscode":
		var doc struct {
			ProductVersion string `json:"productVersion"`
		}
		if err = json.Unmarshal(body, &doc); err == nil {
			v = doc.ProductVersion
		}
	case "git":
		var doc struct {
			Tag string `json:"tag_name"`
		}
		if err = json.Unmarshal(body, &doc); err == nil {
			v = versionNumber.FindString(doc.Tag)
		}
	case "wireshark", "vlc", "7zip":
		pattern := map[string]string{"wireshark": `Wireshark\s+(\d+\.\d+(?:\.\d+)?)`, "vlc": `VLC(?: media player)?\s+(\d+\.\d+\.\d+)`, "7zip": `7-Zip\s+(\d+\.\d+)`}[spec.kind]
		if match := regexp.MustCompile(pattern).FindSubmatch(body); len(match) > 1 {
			v = string(match[1])
		}
	}
	if err != nil {
		return "", err
	}
	if !versionNumber.MatchString(v) {
		return "", errors.New("official release version not found")
	}
	return v, nil
}

func laterVersion(installed, latest string) bool {
	a, b := versionNumber.FindString(installed), versionNumber.FindString(latest)
	if a == "" || b == "" {
		return false
	}
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 4; i++ {
		x, y := 0, 0
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if y != x {
			return y > x
		}
	}
	return false
}

func (s *Server) manifests(w http.ResponseWriter, r *http.Request) {
	if s.Software == nil || s.Synthetic || runtime.GOOS != "windows" {
		writeErr(w, http.StatusNotImplemented, "audit requires a live Windows installation")
		return
	}
	apps, err := s.Software.Inventory()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	var audits []ManifestAudit
	for _, spec := range officialManifests {
		var installed string
		for _, app := range apps {
			name := strings.ToLower(app.Name)
			if spec.kind == "git" {
				if name != "git" && !strings.HasPrefix(name, "git version") {
					continue
				}
			} else if !strings.Contains(name, spec.match) {
				continue
			}
			if app.Version != "" {
				installed = app.Version
				break
			}
		}
		if installed == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(r.Context(), 7*time.Second)
		latest, checkErr := officialVersion(ctx, spec)
		cancel()
		item := ManifestAudit{Name: spec.name, Installed: installed, Latest: latest, Source: spec.url}
		if checkErr != nil {
			item.Error = checkErr.Error()
		} else {
			item.Update = laterVersion(installed, latest)
		}
		audits = append(audits, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"audits": audits, "note": "Publisher manifest comparisons are informational. Updates are applied only through supported package managers."})
}

// CareJob reports actual command output, not a simulated success indicator.
type CareJob struct {
	Action   string    `json:"action"`
	Status   string    `json:"status"`
	Output   string    `json:"output,omitempty"`
	Error    string    `json:"error,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitempty"`
}

func (s *Server) careSnapshot() map[string]CareJob {
	s.careMu.Lock()
	defer s.careMu.Unlock()
	out := make(map[string]CareJob, len(s.careJobs))
	for k, v := range s.careJobs {
		out[k] = v
	}
	return out
}

func (s *Server) careState(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"available": runtime.GOOS == "windows" && !s.Synthetic, "jobs": s.careSnapshot()})
}

func (s *Server) startCare(w http.ResponseWriter, r *http.Request) {
	if runtime.GOOS != "windows" || s.Synthetic {
		writeErr(w, http.StatusNotImplemented, "maintenance requires a live Windows host")
		return
	}
	action := r.PathValue("action")
	if action != "purge" && action != "dns" && action != "integrity" {
		writeErr(w, http.StatusBadRequest, "unknown maintenance action")
		return
	}
	// Require an explicit, action-bound confirmation beyond the CSRF token.
	var req struct {
		Confirm string `json:"confirm"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || req.Confirm != action {
		writeErr(w, http.StatusBadRequest, "confirm must equal the action name")
		return
	}
	s.careMu.Lock()
	if s.careJobs == nil {
		s.careJobs = map[string]CareJob{}
	}
	if s.careJobs[action].Status == "running" {
		s.careMu.Unlock()
		writeErr(w, http.StatusConflict, "action already running")
		return
	}
	job := CareJob{Action: action, Status: "running", Started: time.Now().UTC()}
	s.careJobs[action] = job
	s.careMu.Unlock()
	s.Hub.Broadcast("care", job)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
		defer cancel()
		output, err := runCare(ctx, action)
		job.Output = output
		if err != nil {
			job.Status, job.Error = "failed", err.Error()
		} else {
			job.Status = "complete"
		}
		job.Finished = time.Now().UTC()
		s.careMu.Lock()
		s.careJobs[action] = job
		s.careMu.Unlock()
		s.Hub.Broadcast("care", job)
	}()
	writeJSON(w, http.StatusAccepted, job)
}

func runCare(ctx context.Context, action string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", errors.New("Windows only")
	}
	run := func(exe string, args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, exe, args...).CombinedOutput()
		if len(out) > 16384 {
			out = out[len(out)-16384:]
		}
		return string(out), err
	}
	switch action {
	case "dns":
		return run("ipconfig", "/flushdns")
	case "integrity":
		first, err := run("DISM.exe", "/Online", "/Cleanup-Image", "/ScanHealth")
		if err != nil {
			return "DISM:\n" + first, fmt.Errorf("DISM failed: %w", err)
		}
		second, err := run("sfc.exe", "/scannow")
		return "DISM:\n" + first + "\nSFC:\n" + second, err
	case "purge":
		// Never follow the TEMP root if it is a junction/symlink and never
		// delete the root itself. Remove only entries owned by this account.
		root := os.TempDir()
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("unsafe TEMP root")
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return "", err
		}
		removed, failed := 0, 0
		for _, e := range entries {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if err := os.RemoveAll(filepath.Join(root, e.Name())); err != nil {
				failed++
			} else {
				removed++
			}
		}
		wer := filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Windows", "WER")
		if os.Getenv("LOCALAPPDATA") != "" {
			for _, folder := range []string{"ReportArchive", "ReportQueue"} {
				path := filepath.Join(wer, folder)
				if st, err := os.Lstat(path); err == nil && st.IsDir() && st.Mode()&os.ModeSymlink == 0 {
					items, _ := os.ReadDir(path)
					for _, e := range items {
						if ctx.Err() != nil {
							return "", ctx.Err()
						}
						if err := os.RemoveAll(filepath.Join(path, e.Name())); err != nil {
							failed++
						} else {
							removed++
						}
					}
				}
			}
		}
		bin, binErr := run("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Clear-RecycleBin -Force -ErrorAction Stop")
		message := fmt.Sprintf("Removed %d user TEMP/WER entries; %d locked or inaccessible.\nRecycle Bin: %s", removed, failed, strings.TrimSpace(bin))
		if binErr != nil || failed > 0 {
			return message, fmt.Errorf("partial cleanup: %d entries failed; recycle bin: %v", failed, binErr)
		}
		return message, nil
	}
	return "", errors.New("unknown action")
}
