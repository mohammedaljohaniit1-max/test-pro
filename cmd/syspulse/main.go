//go:build windows

// Command syspulse (5.0) is a Windows system diagnostics and observability
// dashboard: live sockets, processes, system resources, event log
// reliability analysis and software updates via winget, served from an
// embedded web UI on http://localhost:9099.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/eventlog"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/hub"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/ifstats"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/netmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/netnames"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/procmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/radar"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/server"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/services"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/software"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/sysmon"
)

// sw adapts the Windows software package to server.SoftwareBackend.
type sw struct{}

func (sw) Inventory() ([]model.App, error) { return software.Inventory() }
func (sw) ListUpgrades(ctx context.Context) ([]model.Upgrade, string, error) {
	return software.ListUpgrades(ctx)
}
func (sw) RunUpgrade(ctx context.Context, id string) (string, error) {
	return software.RunUpgrade(ctx, id)
}

// eventSource adapts eventlog.Reader to hub.EventSource.
type eventSource struct{ r *eventlog.Reader }

func (e eventSource) Query(ch string, since time.Time, max, lvl int, after uint64) ([]model.Event, error) {
	return e.r.Query(ch, since, max, lvl, after)
}
func (e eventSource) QueryXPath(ch, xpath string, max int, format bool) ([]model.Event, error) {
	return e.r.QueryXPath(ch, xpath, max, format)
}

// auditSource adapts eventlog.Reader to audit.Source.
type auditSource struct{ r *eventlog.Reader }

func (a auditSource) QueryXPath(ch, xpath string, max int, format bool) ([]model.Event, error) {
	return a.r.QueryXPath(ch, xpath, max, format)
}

func isElevated() bool {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return false
	}
	defer tok.Close()
	return tok.IsElevated()
}

func openBrowser(url string) {
	// rundll32 avoids cmd.exe quoting pitfalls and opens the default browser.
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Start()
}

func setConsoleTitle(s string) {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return
	}
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("SetConsoleTitleW")
	proc.Call(uintptr(unsafePointer(p)))
}

func main() {
	var (
		addr        = flag.String("addr", "127.0.0.1:9099", "listen address (loopback only)")
		noBrowse    = flag.Bool("no-browser", false, "do not open the dashboard in the default browser")
		window      = flag.Duration("events-window", 7*24*time.Hour, "how far back to read the event log")
		maxEv       = flag.Int("events-max", 2000, "maximum events retained per channel")
		interval    = flag.Duration("interval", 4*time.Second, "foreground system/process/network sampling interval (idle browsers throttle automatically)")
		radarWin    = flag.Duration("radar-window", 5*time.Second, "connection-sweep detection window")
		radarThr    = flag.Int("radar-threshold", 10, "flag a remote IP that contacts more than this many distinct ports within -radar-window")
		radarCD     = flag.Duration("radar-cooldown", 60*time.Second, "quiet time after which a sweep incident is closed")
		radarAll    = flag.String("radar-allow", "", "comma-separated remote IPs never flagged (e.g. authorised vulnerability scanners)")
		noRaw       = flag.Bool("no-raw-capture", false, "disable the raw SYN sensor (SIO_RCVALL); use the TCP table only")
		selfTest    = flag.Bool("enable-selftest", false, "allow the synthetic radar self-test (off by default: the dashboard shows only real host telemetry)")
		clients     = flag.String("radar-client-procs", "", "extra comma-separated outbound-only process names ignored by the TCP-table sensor (browsers and updaters are built in)")
		noRes       = flag.Bool("no-resolve", false, "disable NetBIOS / mDNS / reverse-DNS name resolution of LAN devices")
		rulesF      = flag.String("rules-file", defaultRulesFile(), "JSON file that stores the alert rules (empty = keep rules in memory only)")
		svcEvery    = flag.Duration("services-interval", 30*time.Second, "Windows service enumeration interval")
		canaryPorts = flag.String("canary-ports", "21,23,8080,8443", "comma-separated TCP decoy ports; binds on all IPv4 interfaces (empty disables)")
		verbose     = flag.Bool("v", false, "verbose logging")
		version     = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()
	if *version {
		fmt.Println("syspulse", server.Version)
		return
	}
	lvl := slog.LevelInfo
	if *verbose {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	if err := checkLoopback(*addr); err != nil {
		log.Error("refusing to start", "err", err)
		os.Exit(2)
	}

	elevated := isElevated()
	pm := procmon.New(procmon.NewSystemReader(), 0)
	tracker := netmon.NewTracker(netmon.NewSystemSource(), pm.Resolve)
	sm := sysmon.New(sysmon.NewSystemPlatform(), 300)
	er := eventlog.NewReader()
	defer er.Close()

	h := hub.New(hub.Config{
		MetricsEvery: *interval, NetEvery: *interval, EventsEvery: 15 * time.Second,
		EventWindow: *window, MaxEvents: *maxEv, Channels: []string{"System", "Application"},
		RadarWindow: *radarWin, RadarThreshold: *radarThr, RadarCooldown: *radarCD, RadarAllow: splitList(*radarAll),
		SelfTest: *selfTest, ClientProcs: splitList(*clients), NoResolve: *noRes, Resolver: netnames.New(),
		ServicesEvery: *svcEvery, RulesFile: *rulesF,
	}, log, sm, pm, tracker, eventSource{er})
	h.SetInterfaceReader(ifstats.NewSystemReader())
	h.SetServiceLister(services.NewSystemLister())
	rp := radar.NewSystemPlatform()
	h.SetRadarPlatform(rp)
	h.SetGateways(rp.Gateways())
	h.SetAuditSource(auditSource{er})
	srv := server.New(h, sw{}, log, *addr)
	srv.Platform = "windows"
	srv.FlowSampler = &tcpEStats{last: map[string]tcpCounters{}}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	h.Radar().SetSensor(radar.SensorStatus{Name: radar.SensorTable, Active: true, Detail: "new inbound rows of GetExtendedTcpTable (accepted connections, IPv4 + IPv6)"})
	if *noRaw {
		h.Radar().SetSensor(radar.SensorStatus{Name: radar.SensorRaw, Detail: "raw SYN capture (SIO_RCVALL)", Error: "disabled by -no-raw-capture"})
	} else if err := radar.StartRawSensor(ctx, rp, h.ObserveRadar, h.Radar().SetSensor); err != nil {
		log.Info("raw SYN sensor unavailable; sweep radar uses the TCP table only", "reason", err)
	} else {
		log.Info("raw SYN sensor active: every inbound TCP SYN is evaluated by the sweep radar")
	}
	if *canaryPorts != "" {
		var ports []uint16
		for _, raw := range splitList(*canaryPorts) {
			var n uint16
			if _, err := fmt.Sscanf(raw, "%d", &n); err != nil || n == 0 {
				log.Error("invalid canary port", "port", raw)
				os.Exit(2)
			}
			ports = append(ports, n)
		}
		failures := radar.StartCanaries(ctx, ports, h.ObserveCanary)
		for port, err := range failures {
			log.Warn("canary unavailable", "port", port, "err", err)
		}
		if len(failures) == len(ports) {
			h.Radar().SetSensor(radar.SensorStatus{Name: radar.SensorCanary, Error: "no canary ports could be bound"})
		} else {
			h.Radar().SetSensor(radar.SensorStatus{Name: radar.SensorCanary, Active: true, Detail: "passive TCP decoy listeners; firewall-blocked traffic requires raw SYN sensor"})
		}
	}
	go h.Run(ctx)

	setConsoleTitle("SysPulse " + server.Version + " — http://" + *addr)
	fmt.Print(banner(*addr, elevated))
	if !elevated {
		log.Info("running without administrator rights: protected processes show limited details")
	}
	err := srv.ListenAndServe(ctx, func(url string) {
		log.Info("dashboard ready", "url", url)
		if !*noBrowse {
			openBrowser(url)
		}
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Error("server stopped", "err", err)
		fmt.Fprintln(os.Stderr, "\nIs another SysPulse instance already running? Try -addr 127.0.0.1:9100")
		os.Exit(1)
	}
	log.Info("SysPulse stopped")
}

// TCP_ESTATS_DATA_ROD_v0 is 96 bytes on amd64. Only its first, third
// uint64 fields (TCP payload bytes out/in) are used for measured rates.
type tcpDataROD struct {
	OutBytes, OutSegs, InBytes, InSegs, SegsOut, SegsIn uint64
	SoftErrors, SoftReason, SndUna, SndNxt, SndMax      uint32
	ThruAcked                                           uint64
	RcvNxt                                              uint32
	ThruReceived                                        uint64
}
type tcpRow4 struct{ State, LocalAddr, LocalPort, RemoteAddr, RemotePort uint32 }
type tcpRow6 struct {
	State                   uint32
	LocalAddr               [16]byte
	LocalScope, LocalPort   uint32
	RemoteAddr              [16]byte
	RemoteScope, RemotePort uint32
}
type tcpCounters struct {
	at      time.Time
	in, out uint64
}
type tcpEStats struct {
	mu   sync.Mutex
	last map[string]tcpCounters
}

var tcpDLL = windows.NewLazySystemDLL("iphlpapi.dll")
var get4 = tcpDLL.NewProc("GetPerTcpConnectionEStats")
var set4 = tcpDLL.NewProc("SetPerTcpConnectionEStats")
var get6 = tcpDLL.NewProc("GetPerTcp6ConnectionEStats")
var set6 = tcpDLL.NewProc("SetPerTcp6ConnectionEStats")

func portDWORD(p uint16) uint32 { return uint32(p>>8) | uint32(p&255)<<8 }

func (s *tcpEStats) Sample(conns []model.Connection) map[string]server.FlowRate {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[string]server.FlowRate, len(conns))
	now, seen := time.Now(), make(map[string]bool, len(conns))
	for i, c := range conns {
		if i >= 200 {
			break
		} // bounded on-demand diagnostics
		key := c.Key()
		seen[key] = true
		if c.Proto != "TCP" && c.Proto != "TCP6" {
			result[key] = server.FlowRate{Error: "TCP EStats does not include UDP"}
			continue
		}
		local, remote := net.ParseIP(c.LocalAddr), net.ParseIP(c.RemoteAddr)
		if local == nil || remote == nil {
			result[key] = server.FlowRate{Error: "invalid socket address"}
			continue
		}
		var row uintptr
		var rowOwner any // preserve the Go allocation across syscall.SyscallN
		get, set := get4, set4
		if c.Proto == "TCP6" {
			get, set = get6, set6
			l, r := local.To16(), remote.To16()
			if l == nil || r == nil {
				continue
			}
			v := &tcpRow6{State: 5, LocalPort: portDWORD(c.LocalPort), RemotePort: portDWORD(c.RemotePort)}
			copy(v.LocalAddr[:], l)
			copy(v.RemoteAddr[:], r)
			row = uintptr(unsafe.Pointer(v))
			rowOwner = v
		} else {
			l, r := local.To4(), remote.To4()
			if l == nil || r == nil {
				continue
			}
			v := &tcpRow4{State: 5, LocalAddr: binary.LittleEndian.Uint32(l), LocalPort: portDWORD(c.LocalPort), RemoteAddr: binary.LittleEndian.Uint32(r), RemotePort: portDWORD(c.RemotePort)}
			row = uintptr(unsafe.Pointer(v))
			rowOwner = v
		}
		var enabled uint32
		var data tcpDataROD
		read := func() uintptr {
			rc, _, _ := get.Call(row, 1, uintptr(unsafe.Pointer(&enabled)), 0, 1, 0, 0, 0,
				uintptr(unsafe.Pointer(&data)), 0, unsafe.Sizeof(data))
			runtime.KeepAlive(rowOwner)
			return rc
		}
		if errCode := read(); errCode != 0 {
			result[key] = server.FlowRate{Error: windows.Errno(errCode).Error()}
			continue
		}
		if enabled == 0 {
			flag := byte(1)
			rc, _, _ := set.Call(row, 1, uintptr(unsafe.Pointer(&flag)), 0, 1, 0)
			runtime.KeepAlive(rowOwner)
			if rc != 0 {
				result[key] = server.FlowRate{Error: "EStats requires administrator: " + windows.Errno(rc).Error()}
				continue
			}
			if rc = read(); rc != 0 || enabled == 0 {
				result[key] = server.FlowRate{Error: "EStats not enabled for this connection"}
				continue
			}
		}
		// The API accepts pointers to live MIB rows, not a Go-owned socket.
		runtime.KeepAlive(rowOwner)
		v := server.FlowRate{Error: "collecting baseline"}
		if prev, ok := s.last[key]; ok && now.After(prev.at) && data.InBytes >= prev.in && data.OutBytes >= prev.out {
			dt := now.Sub(prev.at).Seconds()
			if dt > 0 {
				v = server.FlowRate{Available: true, InBps: float64(data.InBytes-prev.in) / dt, OutBps: float64(data.OutBytes-prev.out) / dt}
			}
		}
		s.last[key] = tcpCounters{at: now, in: data.InBytes, out: data.OutBytes}
		result[key] = v
	}
	for key := range s.last {
		if !seen[key] {
			delete(s.last, key)
		}
	}
	return result
}

func banner(addr string, elevated bool) string {
	mode := "standard user"
	if elevated {
		mode = "administrator"
	}
	return fmt.Sprintf(`
   ____            ____        _
  / ___| _   _ ___|  _ \ _   _| |___  ___
  \___ \| | | / __| |_) | | | | / __|/ _ \
   ___) | |_| \__ \  __/| |_| | \__ \  __/
  |____/ \__, |___/_|    \__,_|_|___/\___|
         |___/      %s

  Dashboard : http://%s/
  Privileges: %s
  Shortcuts : Ctrl+K command palette · [ collapse sidebar
  Press Ctrl+C to stop.

`, server.Version, addr, mode)
}

// defaultRulesFile is %LOCALAPPDATA%\SysPulse\rules.json.
func defaultRulesFile() string {
	if d, err := os.UserCacheDir(); err == nil && d != "" {
		return filepath.Join(d, "SysPulse", "rules.json")
	}
	return ""
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
