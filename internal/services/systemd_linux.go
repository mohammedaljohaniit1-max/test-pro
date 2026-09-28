//go:build linux

package services

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// Systemd lists service units with systemctl (Linux preview build only).
type Systemd struct{}

// NewSystemLister returns the systemd lister.
func NewSystemLister() Lister { return Systemd{} }

// List implements Lister. `systemctl show` without unit arguments reports
// the manager itself, so units are enumerated with list-units first and
// then queried in one batched show call.
func (Systemd) List() ([]model.Service, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	lu, err := run(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--full", "--no-pager")
	if err != nil {
		return nil, err
	}
	units := ParseListUnits(lu)
	if len(units) == 0 {
		return nil, nil
	}
	args := append([]string{"show", "--no-pager",
		"--property=Id,Description,ActiveState,SubState,UnitFileState,MainPID,User,ExecStart,Type,ExecMainStatus"}, units...)
	out, err := run(ctx, "systemctl", args...)
	if err != nil {
		return nil, err
	}
	return ParseSystemctlShow(out), nil
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	var stderr strings.Builder
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return "", fmt.Errorf("%s %s: %s", name, args[0], msg)
		}
		return "", fmt.Errorf("%s %s: %w", name, args[0], err)
	}
	return string(out), nil
}

// ParseListUnits extracts unit names from `systemctl list-units --plain
// --no-legend` output (first column; a leading status bullet is skipped).
func ParseListUnits(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) > 0 && (f[0] == "●" || f[0] == "*") {
			f = f[1:]
		}
		if len(f) > 0 && strings.HasSuffix(f[0], ".service") {
			out = append(out, f[0])
		}
	}
	return out
}

// ParseSystemctlShow parses blank-line separated "Key=Value" blocks.
func ParseSystemctlShow(s string) []model.Service {
	var out []model.Service
	for _, block := range strings.Split(s, "\n\n") {
		kv := map[string]string{}
		for _, l := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(l, "="); ok {
				kv[k] = v
			}
		}
		id := kv["Id"]
		if id == "" || kv["UnitFileState"] == "" && kv["ActiveState"] == "inactive" {
			continue // unit referenced but not installed
		}
		sv := model.Service{Name: strings.TrimSuffix(id, ".service"), Display: kv["Description"], Account: kv["User"], Type: kv["Type"]}
		if sv.Display == "" {
			sv.Display = sv.Name
		}
		switch kv["ActiveState"] {
		case "active", "reloading":
			sv.State = model.SvcRunning
			if kv["SubState"] == "exited" {
				sv.State = model.SvcStopped
			}
		case "inactive", "failed":
			sv.State = model.SvcStopped
		case "activating":
			sv.State = model.SvcStarting
		case "deactivating":
			sv.State = model.SvcStopping
		default:
			sv.State = model.SvcOther
		}
		switch kv["UnitFileState"] {
		case "enabled", "enabled-runtime", "static", "alias":
			sv.StartType = model.StartAuto
			if kv["UnitFileState"] == "static" {
				sv.StartType = model.StartManual
			}
		case "disabled", "indirect":
			sv.StartType = model.StartManual
		case "masked", "masked-runtime":
			sv.StartType = model.StartDisabled
		default:
			sv.StartType = model.StartManual
		}
		if pid, err := strconv.ParseUint(kv["MainPID"], 10, 32); err == nil {
			sv.PID = uint32(pid)
		}
		if ex := kv["ExecStart"]; ex != "" {
			if _, rest, ok := strings.Cut(ex, "path="); ok {
				sv.Binary, _, _ = strings.Cut(rest, " ;")
			}
		}
		if code, err := strconv.ParseUint(kv["ExecMainStatus"], 10, 32); err == nil && code != 0 {
			sv.ExitCode = uint32(code)
		}
		if kv["ActiveState"] == "failed" && sv.ExitCode == 0 {
			sv.ExitCode = 1 // failed without an exit status (signal, timeout, start limit)
		}
		out = append(out, sv)
	}
	return out
}
