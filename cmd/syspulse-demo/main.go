// Command syspulse-demo serves the real SysPulse dashboard with synthetic
// telemetry so the UI can be developed and reviewed on any operating system.
// It uses the same hub, server and embedded web assets as syspulse.exe; only
// the platform collectors are replaced by deterministic simulators.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/hub"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/netmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/procmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/server"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/sysmon"
)

const gib = 1 << 30

// ---- system platform ----

type demoPlat struct {
	mu    sync.Mutex
	start time.Time
	idle  time.Duration
	busy  time.Duration
	last  time.Time
}

func newPlat() *demoPlat { n := time.Now(); return &demoPlat{start: n, last: n} }

func (p *demoPlat) CPUTimes() (sysmon.CPUTimes, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	dt := now.Sub(p.last) * 8 // 8 cores
	p.last = now
	t := now.Sub(p.start).Seconds()
	load := 0.25 + 0.15*math.Sin(t/9) + 0.1*rand.Float64()
	if int(t)%40 < 4 {
		load += 0.35 // periodic burst
	}
	load = math.Min(math.Max(load, 0.02), 0.98)
	b := time.Duration(float64(dt) * load)
	p.busy += b
	p.idle += dt - b
	// Kernel time includes idle time on Windows.
	return sysmon.CPUTimes{Idle: p.idle, Kernel: p.idle + p.busy/3, User: p.busy - p.busy/3}, nil
}

func (p *demoPlat) Memory() (uint64, uint64, uint64, uint64, error) {
	t := time.Since(p.start).Seconds()
	total := uint64(32 * gib)
	used := uint64((0.52 + 0.06*math.Sin(t/23)) * float64(total))
	return total, total - used, used + 3*gib, total + 8*gib, nil
}

func (p *demoPlat) Disks() ([]model.DiskUsage, error) {
	mk := func(m, typ string, total, free uint64) model.DiskUsage {
		return model.DiskUsage{Mount: m, Type: typ, Total: total, Free: free, Used: total - free,
			Percent: 100 * float64(total-free) / float64(total)}
	}
	return []model.DiskUsage{
		mk(`C:\`, "fixed", 953*gib, 212*gib),
		mk(`D:\`, "fixed", 1863*gib, 1210*gib),
		mk(`E:\`, "removable", 58*gib, 51*gib),
	}, nil
}

func (p *demoPlat) Uptime() time.Duration { return 3*24*time.Hour + 7*time.Hour + time.Since(p.start) }
func (p *demoPlat) Info() (string, string) {
	return "DEMO-WORKSTATION", "Windows 11 Pro 23H2 (build 22631) — demo data"
}
func (p *demoPlat) Cores() int { return 8 }

// ---- processes ----

type demoProc struct {
	pid, ppid uint32
	name      string
	path      string
	threads   uint32
	ws        uint64
	load      float64 // average share of one core
	access    bool
}

type demoProcs struct {
	mu    sync.Mutex
	start time.Time
	cpu   map[uint32]time.Duration
	last  time.Time
	list  []demoProc
}

func newProcs() *demoProcs {
	pf := `C:\Program Files\`
	list := []demoProc{
		{4, 0, "System", "", 240, 2 << 20, 0.05, false},
		{128, 4, "Registry", "", 4, 60 << 20, 0, false},
		{612, 4, "smss.exe", `C:\Windows\System32\smss.exe`, 2, 1 << 20, 0, false},
		{880, 812, "csrss.exe", `C:\Windows\System32\csrss.exe`, 13, 6 << 20, 0.01, false},
		{972, 812, "wininit.exe", `C:\Windows\System32\wininit.exe`, 3, 7 << 20, 0, false},
		{1044, 972, "services.exe", `C:\Windows\System32\services.exe`, 9, 12 << 20, 0.01, true},
		{1068, 972, "lsass.exe", `C:\Windows\System32\lsass.exe`, 11, 24 << 20, 0.02, false},
		{1210, 1044, "svchost.exe", `C:\Windows\System32\svchost.exe`, 24, 48 << 20, 0.03, true},
		{1388, 1044, "svchost.exe", `C:\Windows\System32\svchost.exe`, 18, 31 << 20, 0.01, true},
		{2200, 1044, "MsMpEng.exe", `C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe`, 42, 310 << 20, 0.15, false},
		{3100, 3050, "explorer.exe", `C:\Windows\explorer.exe`, 96, 185 << 20, 0.04, true},
		{4012, 3100, "chrome.exe", pf + `Google\Chrome\Application\chrome.exe`, 48, 420 << 20, 0.35, true},
		{4020, 4012, "chrome.exe", pf + `Google\Chrome\Application\chrome.exe`, 22, 260 << 20, 0.2, true},
		{4034, 4012, "chrome.exe", pf + `Google\Chrome\Application\chrome.exe`, 17, 140 << 20, 0.08, true},
		{5120, 3100, "Code.exe", `C:\Users\demo\AppData\Local\Programs\Microsoft VS Code\Code.exe`, 38, 520 << 20, 0.22, true},
		{5188, 5120, "gopls.exe", `C:\Users\demo\go\bin\gopls.exe`, 21, 610 << 20, 0.12, true},
		{6200, 3100, "Teams.exe", `C:\Users\demo\AppData\Local\Microsoft\Teams\current\Teams.exe`, 55, 380 << 20, 0.1, true},
		{6400, 3100, "Spotify.exe", `C:\Users\demo\AppData\Roaming\Spotify\Spotify.exe`, 30, 210 << 20, 0.05, true},
		{7010, 1044, "sqlservr.exe", pf + `Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn\sqlservr.exe`, 70, 1400 << 20, 0.18, true},
		{7300, 1044, "OneDrive.exe", `C:\Users\demo\AppData\Local\Microsoft\OneDrive\OneDrive.exe`, 26, 95 << 20, 0.02, true},
		{7702, 3100, "WindowsTerminal.exe", pf + `WindowsApps\Microsoft.WindowsTerminal\WindowsTerminal.exe`, 19, 88 << 20, 0.01, true},
		{7780, 7702, "syspulse.exe", `C:\Tools\syspulse.exe`, 14, 28 << 20, 0.02, true},
		{8120, 1044, "nginx.exe", `C:\nginx\nginx.exe`, 3, 14 << 20, 0.01, true},
		{8400, 1044, "postgres.exe", pf + `PostgreSQL\16\bin\postgres.exe`, 8, 72 << 20, 0.03, true},
		{9001, 3100, "Discord.exe", `C:\Users\demo\AppData\Local\Discord\app-1.0.9164\Discord.exe`, 34, 260 << 20, 0.04, true},
	}
	n := time.Now()
	return &demoProcs{start: n, last: n, cpu: map[uint32]time.Duration{}, list: list}
}

func (d *demoProcs) List() ([]procmon.RawProcess, error) {
	out := make([]procmon.RawProcess, len(d.list))
	for i, p := range d.list {
		out[i] = procmon.RawProcess{PID: p.pid, PPID: p.ppid, Name: p.name, Threads: p.threads}
	}
	return out, nil
}

func (d *demoProcs) Details(r *procmon.RawProcess) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, p := range d.list {
		if p.pid != r.PID {
			continue
		}
		t := time.Since(d.start).Seconds()
		jitter := 0.6 + 0.8*rand.Float64()
		// A gentle per-process wave keeps the ranking lively.
		f := p.load * jitter * (1 + 0.5*math.Sin(t/7+float64(p.pid)))
		d.cpu[p.pid] += time.Duration(f * float64(time.Second))
		r.CPUTime = d.cpu[p.pid]
		r.WorkingSet = uint64(float64(p.ws) * (0.95 + 0.1*math.Sin(t/13+float64(p.pid))))
		r.Private = r.WorkingSet * 3 / 4
		r.Started = d.start.Add(-time.Duration(p.pid) * time.Minute)
		r.Access = p.access
		if p.access {
			r.Path = p.path
		}
		return
	}
}

// ---- network ----

type demoNet struct {
	mu    sync.Mutex
	conns []model.Connection
	next  uint16
	procs *demoProcs
}

func newNet(p *demoProcs) *demoNet {
	d := &demoNet{next: 50000, procs: p}
	listen := func(proto, addr string, port uint16, pid uint32) {
		st := "LISTEN"
		if strings.HasPrefix(proto, "UDP") {
			st = "-"
		}
		d.conns = append(d.conns, model.Connection{Proto: proto, LocalAddr: addr, LocalPort: port, State: st, PID: pid})
	}
	listen("TCP", "0.0.0.0", 135, 1210)
	listen("TCP", "0.0.0.0", 445, 4)
	listen("TCP6", "::", 445, 4)
	listen("TCP", "0.0.0.0", 1433, 7010)
	listen("TCP", "0.0.0.0", 5432, 8400)
	listen("TCP", "0.0.0.0", 80, 8120)
	listen("TCP", "127.0.0.1", 9099, 7780)
	listen("UDP", "0.0.0.0", 5353, 4012)
	listen("UDP", "0.0.0.0", 123, 1388)
	listen("UDP6", "::", 5355, 1388)
	for i := 0; i < 12; i++ {
		d.spawn()
	}
	return d
}

var remotes = []struct {
	ip   string
	port uint16
	pid  uint32
}{
	{"142.250.185.78", 443, 4012}, {"142.250.74.206", 443, 4020}, {"151.101.1.69", 443, 4034},
	{"140.82.112.21", 443, 5120}, {"13.107.42.14", 443, 6200}, {"52.112.95.4", 443, 6200},
	{"35.186.224.25", 443, 6400}, {"162.159.135.232", 443, 9001}, {"20.190.160.14", 443, 7300},
	{"192.168.1.20", 5432, 5188}, {"2606:4700::6810:84e5", 443, 4012}, {"104.18.32.7", 443, 4020},
}

func (d *demoNet) spawn() {
	r := remotes[rand.Intn(len(remotes))]
	proto, local := "TCP", "192.168.1.42"
	if strings.Contains(r.ip, ":") {
		proto, local = "TCP6", "2001:db8::42"
	}
	d.next++
	if d.next > 64000 {
		d.next = 50000
	}
	d.conns = append(d.conns, model.Connection{Proto: proto, LocalAddr: local, LocalPort: d.next,
		RemoteAddr: r.ip, RemotePort: r.port, State: "SYN_SENT", PID: r.pid})
}

func (d *demoNet) Source() ([]model.Connection, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	kept := d.conns[:0]
	for _, c := range d.conns {
		switch {
		case c.State == "SYN_SENT":
			c.State = "ESTABLISHED"
		case c.State == "ESTABLISHED" && rand.Float64() < 0.04:
			c.State = "TIME_WAIT"
		case c.State == "TIME_WAIT" && rand.Float64() < 0.3:
			continue // closed
		}
		kept = append(kept, c)
	}
	d.conns = kept
	for i := rand.Intn(3); i > 0; i-- {
		d.spawn()
	}
	out := make([]model.Connection, len(d.conns))
	copy(out, d.conns)
	return out, nil
}

// ---- event log ----

type demoEvents struct {
	mu   sync.Mutex
	rec  map[string]uint64
	evs  map[string][]model.Event
	last time.Time
}

type evTpl struct {
	ch, prov string
	id       uint32
	lvl      int
	cat, msg string
}

var evTemplates = []evTpl{
	{"System", "Service Control Manager", 7031, 2, model.CatServiceCrash, "The Print Spooler service terminated unexpectedly. It has done this 1 time(s). The following corrective action will be taken in 60000 milliseconds: Restart the service."},
	{"System", "Service Control Manager", 7034, 2, model.CatServiceCrash, "The Windows Search service terminated unexpectedly. It has done this 2 time(s)."},
	{"System", "Microsoft-Windows-Kernel-Power", 41, 1, model.CatUnexpectedShutdn, "The system has rebooted without cleanly shutting down first. This error could be caused if the system stopped responding, crashed, or lost power unexpectedly."},
	{"System", "EventLog", 6008, 2, model.CatUnexpectedShutdn, "The previous system shutdown at 02:14:07 was unexpected."},
	{"System", "Display", 4101, 3, model.CatDriver, "Display driver nvlddmkm stopped responding and has successfully recovered."},
	{"System", "Microsoft-Windows-DriverFrameworks-UserMode", 10110, 3, model.CatDriver, "A problem has occurred with one or more user-mode drivers and the hosting process has been terminated."},
	{"System", "disk", 153, 3, model.CatDisk, "The IO operation at logical block address 0x1c3a2f for Disk 1 (PDO name: \\Device\\00000034) was retried."},
	{"System", "Microsoft-Windows-WindowsUpdateClient", 20, 2, model.CatUpdate, "Installation Failure: Windows failed to install the following update with error 0x80070643: 2026-09 Security Update (KB5044284)."},
	{"System", "Microsoft-Windows-WindowsUpdateClient", 19, 4, model.CatUpdate, "Installation Successful: Windows successfully installed the following update: Security Intelligence Update for Microsoft Defender Antivirus."},
	{"System", "Microsoft-Windows-Kernel-Power", 42, 4, model.CatPower, "The system is entering sleep. Sleep Reason: Application API"},
	{"System", "Microsoft-Windows-Time-Service", 35, 4, model.CatOther, "The time service is now synchronizing the system time with the time source time.windows.com."},
	{"Application", "Application Error", 1000, 2, model.CatAppFault, "Faulting application name: Teams.exe, version: 1.7.0.1864, faulting module name: ntdll.dll, exception code: 0xc0000005."},
	{"Application", "Application Hang", 1002, 2, model.CatAppFault, "The program Code.exe version 1.93.1 stopped interacting with Windows and was closed."},
	{"Application", "Windows Error Reporting", 1001, 4, model.CatAppFault, "Fault bucket 2178543901, type 5. Event Name: APPCRASH. Response: Not available."},
	{"Application", ".NET Runtime", 1026, 2, model.CatAppFault, "Application: Contoso.Agent.exe. Framework Version: v4.0.30319. Description: The process was terminated due to an unhandled exception System.NullReferenceException."},
	{"Application", "MSSQLSERVER", 17890, 3, model.CatOther, "A significant part of sql server process memory has been paged out. This may result in a performance degradation."},
}

func newEvents() *demoEvents {
	d := &demoEvents{rec: map[string]uint64{}, evs: map[string][]model.Event{}, last: time.Now()}
	now := time.Now()
	r := rand.New(rand.NewSource(42))
	for i := 0; i < 420; i++ {
		ago := time.Duration(r.Int63n(int64(7 * 24 * time.Hour)))
		d.add(evTemplates[r.Intn(len(evTemplates))], now.Add(-ago))
	}
	return d
}

func (d *demoEvents) add(t evTpl, at time.Time) {
	d.rec[t.ch]++
	d.evs[t.ch] = append(d.evs[t.ch], model.Event{Channel: t.ch, RecordID: 0, EventID: t.id, Level: t.lvl,
		Provider: t.prov, Time: at.UTC(), Computer: "DEMO-WORKSTATION", Message: t.msg, Category: t.cat,
		LevelStr: [...]string{"Info", "Critical", "Error", "Warning", "Info"}[t.lvl]})
}

func (d *demoEvents) Query(ch string, since time.Time, max, maxLevel int, after uint64) ([]model.Event, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if time.Since(d.last) > 20*time.Second {
		d.last = time.Now()
		d.add(evTemplates[rand.Intn(len(evTemplates))], time.Now())
	}
	// Record IDs are assigned in chronological order on first read so the
	// hub's incremental "after" cursor behaves like the real log.
	list := d.evs[ch]
	assignIDs(list)
	var out []model.Event
	for i := len(list) - 1; i >= 0 && len(out) < max; i-- {
		e := list[i]
		if e.RecordID <= after || e.Time.Before(since) || (maxLevel > 0 && e.Level > maxLevel) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// ---- software ----

type demoSW struct {
	mu  sync.Mutex
	ups []model.Upgrade
}

func newSW() *demoSW {
	return &demoSW{ups: []model.Upgrade{
		{Name: "Google Chrome", ID: "Google.Chrome", Version: "128.0.6613.138", Available: "129.0.6668.59", Source: "winget"},
		{Name: "Microsoft Visual Studio Code", ID: "Microsoft.VisualStudioCode", Version: "1.93.0", Available: "1.93.1", Source: "winget"},
		{Name: "7-Zip 23.01 (x64)", ID: "7zip.7zip", Version: "23.01", Available: "24.08", Source: "winget"},
		{Name: "Git", ID: "Git.Git", Version: "2.45.2", Available: "2.46.2", Source: "winget"},
		{Name: "Node.js", ID: "OpenJS.NodeJS.LTS", Version: "20.15.0", Available: "20.17.0", Source: "winget"},
	}}
}

func (s *demoSW) Inventory() ([]model.App, error) {
	a := func(n, v, p, d string, kb uint64, scope string) model.App {
		return model.App{Name: n, Version: v, Publisher: p, InstallDate: d, SizeKB: kb, Scope: scope, UninstallKey: n}
	}
	return []model.App{
		a("Google Chrome", "128.0.6613.138", "Google LLC", "2026-08-30", 512000, "machine"),
		a("Microsoft Visual Studio Code", "1.93.0", "Microsoft Corporation", "2026-09-04", 380000, "user"),
		a("7-Zip 23.01 (x64)", "23.01", "Igor Pavlov", "2024-02-11", 5800, "machine"),
		a("Git", "2.45.2", "The Git Development Community", "2026-06-17", 330000, "machine"),
		a("Node.js", "20.15.0", "Node.js Foundation", "2026-07-02", 98000, "machine"),
		a("Microsoft SQL Server 2022 (64-bit)", "16.0.1000.6", "Microsoft Corporation", "2025-11-20", 0, "machine"),
		a("PostgreSQL 16", "16.4", "PostgreSQL Global Development Group", "2026-08-12", 520000, "machine"),
		a("Spotify", "1.2.46.462", "Spotify AB", "2026-09-10", 310000, "user"),
		a("Discord", "1.0.9164", "Discord Inc.", "2026-09-15", 95000, "user"),
		a("NVIDIA Graphics Driver 560.94", "560.94", "NVIDIA Corporation", "2026-08-22", 1200000, "machine"),
		a("Microsoft Visual C++ 2015-2022 Redistributable (x86)", "14.40.33810.0", "Microsoft Corporation", "2026-05-01", 20000, "machine-x86"),
	}, nil
}

func (s *demoSW) ListUpgrades(ctx context.Context) ([]model.Upgrade, string, error) {
	select {
	case <-time.After(1500 * time.Millisecond): // winget is slow; mimic it
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Upgrade, len(s.ups))
	copy(out, s.ups)
	return out, "v1.8.1911 (demo)", nil
}

func (s *demoSW) RunUpgrade(ctx context.Context, id string) (string, error) {
	select {
	case <-time.After(4 * time.Second):
	case <-ctx.Done():
		return "", ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.ups {
		if u.ID == id {
			s.ups = append(s.ups[:i], s.ups[i+1:]...)
			return fmt.Sprintf("Found %s [%s] Version %s\nDownloading...\nSuccessfully installed (demo)", u.Name, u.ID, u.Available), nil
		}
	}
	return "", errors.New("No available upgrade found.")
}

func main() {
	addr := flag.String("addr", "127.0.0.1:9099", "listen address (loopback only)")
	preview := flag.String("preview", "", "also expose the dashboard through a reverse proxy on this address (e.g. 0.0.0.0:8080) for remote review")
	synthetic := flag.Bool("synthetic", false, "serve simulated telemetry instead of this host's real data (UI development only)")
	selfTest := flag.Bool("enable-selftest", false, "allow the synthetic radar self-test button")
	noResolve := flag.Bool("no-resolve", false, "disable NetBIOS / mDNS / DNS name resolution of LAN devices")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := checkLoopback(*addr); err != nil {
		log.Error("refusing to start", "err", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var h *hub.Hub
	var srv *server.Server
	if *synthetic {
		h, srv = syntheticStack(ctx, log, *addr)
	} else {
		var err error
		h, srv, err = liveStack(ctx, log, *addr, *selfTest, *noResolve)
		if err != nil {
			log.Error("live host telemetry unavailable on this OS; use -synthetic for simulated data", "err", err)
			os.Exit(2)
		}
	}
	go h.Run(ctx)
	if *preview != "" {
		go func() {
			if err := servePreview(*preview, *addr, log); err != nil {
				log.Error("preview proxy stopped", "err", err)
			}
		}()
	}
	mode := "live host telemetry"
	if *synthetic {
		mode = "SYNTHETIC data"
	}
	err := srv.ListenAndServe(ctx, func(url string) { log.Info("dashboard ready", "url", url, "mode", mode) })
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

// syntheticStack wires the deterministic simulators (UI development only).
// The dashboard shows a "SIMULATED DATA" badge in this mode.
func syntheticStack(ctx context.Context, log *slog.Logger, addr string) (*hub.Hub, *server.Server) {
	procs := newProcs()
	pm := procmon.New(procs, 4)
	nd := newNet(procs)
	tracker := netmon.NewTracker(nd.Source, pm.Resolve)
	sm := sysmon.New(newPlat(), 300)
	h := hub.New(hub.Config{MetricsEvery: time.Second, NetEvery: time.Second, EventsEvery: 5 * time.Second,
		Channels: []string{"System", "Application"}, SelfTest: true, NoResolve: true}, log, sm, pm, tracker, newEvents())
	h.SetRadarPlatform(demoRadarPlat{})
	h.SetAuditSource(newDemoAudit())
	srv := server.New(h, newSW(), log, addr)
	srv.Synthetic, srv.Platform = true, "synthetic"
	go runDemoTraffic(ctx, h)
	return h, srv
}
