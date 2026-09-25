//go:build windows

// Command syspulse is a Windows system diagnostics and observability
// dashboard: live sockets, processes, system resources, event log
// reliability analysis and software updates via winget, served from an
// embedded web UI on http://localhost:9099.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/eventlog"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/hub"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/netmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/procmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/server"
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
		addr     = flag.String("addr", "127.0.0.1:9099", "listen address (loopback only)")
		noBrowse = flag.Bool("no-browser", false, "do not open the dashboard in the default browser")
		window   = flag.Duration("events-window", 7*24*time.Hour, "how far back to read the event log")
		maxEv    = flag.Int("events-max", 2000, "maximum events retained per channel")
		interval = flag.Duration("interval", time.Second, "system/process/network sampling interval")
		verbose  = flag.Bool("v", false, "verbose logging")
		version  = flag.Bool("version", false, "print version and exit")
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
	}, log, sm, pm, tracker, eventSource{er})
	srv := server.New(h, sw{}, log, *addr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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
  Press Ctrl+C to stop.

`, server.Version, addr, mode)
}
