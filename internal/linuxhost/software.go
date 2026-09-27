//go:build linux

package linuxhost

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/software"
)

// Software implements server.SoftwareBackend from the dpkg database (or
// rpm). Install dates come from the mtime of each package's file list.
// Upgrades are listed from `apt list --upgradable`; nothing is installed.
type Software struct{}

// Inventory returns every installed package.
func (Software) Inventory() ([]model.App, error) {
	if _, err := os.Stat("/var/lib/dpkg/status"); err == nil {
		return dpkg()
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		return rpm()
	}
	return nil, errors.New("no supported package database (dpkg / rpm) found")
}

func dpkg() ([]model.App, error) {
	f, err := os.Open("/var/lib/dpkg/status")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var raw []software.RawEntry
	cur := map[string]string{}
	flush := func() {
		if cur["Package"] != "" && strings.Contains(cur["Status"], "installed") && !strings.Contains(cur["Status"], "not-installed") {
			name := cur["Package"]
			e := software.RawEntry{Key: "dpkg:" + name, KeyName: name, Scope: "machine", DisplayName: name,
				DisplayVersion: cur["Version"], Publisher: maintainer(cur["Maintainer"]), Arch: cur["Architecture"],
				Comments: cur["Description"], URLInfoAbout: cur["Homepage"], Source: "dpkg",
				UninstallString: "sudo apt remove " + name}
			if kb, err := strconv.ParseUint(cur["Installed-Size"], 10, 64); err == nil {
				e.EstimatedSizeKB = kb
			}
			for _, p := range []string{"/var/lib/dpkg/info/" + name + ".list", "/var/lib/dpkg/info/" + name + ":" + cur["Architecture"] + ".list"} {
				if st, err := os.Stat(p); err == nil {
					e.InstallDate = st.ModTime().Format("20060102")
					break
				}
			}
			raw = append(raw, e)
		}
		cur = map[string]string{}
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		l := sc.Text()
		if l == "" {
			flush()
			continue
		}
		if l[0] == ' ' || l[0] == '\t' {
			continue // continuation (long description)
		}
		k, v, ok := strings.Cut(l, ":")
		if ok {
			cur[k] = strings.TrimSpace(v)
		}
	}
	flush()
	return software.FilterAll(raw), nil
}

func maintainer(s string) string {
	if i := strings.Index(s, "<"); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func rpm() ([]model.App, error) {
	out, err := exec.Command("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{INSTALLTIME}\t%{SIZE}\t%{ARCH}\t%{URL}\n").Output()
	if err != nil {
		return nil, err
	}
	var raw []software.RawEntry
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Split(l, "\t")
		if len(f) < 7 {
			continue
		}
		e := software.RawEntry{Key: "rpm:" + f[0], KeyName: f[0], Scope: "machine", DisplayName: f[0], DisplayVersion: f[1],
			Publisher: f[2], Arch: f[5], URLInfoAbout: f[6], Source: "rpm"}
		if ts, err := strconv.ParseInt(f[3], 10, 64); err == nil {
			e.InstallDate = time.Unix(ts, 0).Format("20060102")
		}
		if sz, err := strconv.ParseUint(f[4], 10, 64); err == nil {
			e.EstimatedSizeKB = sz / 1024
		}
		raw = append(raw, e)
	}
	return software.FilterAll(raw), nil
}

// ListUpgrades parses `apt list --upgradable` (read-only; no package lists
// are refreshed).
func (Software) ListUpgrades(ctx context.Context) ([]model.Upgrade, string, error) {
	if _, err := exec.LookPath("apt"); err != nil {
		return nil, "", errors.New("apt not available on this host")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "apt", "list", "--upgradable").Output()
	if err != nil && len(out) == 0 {
		return nil, "", err
	}
	var ups []model.Upgrade
	for _, l := range strings.Split(string(out), "\n") {
		// name/suite version arch [upgradable from: old]
		name, rest, ok := strings.Cut(l, "/")
		if !ok || !strings.Contains(rest, "upgradable from:") {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 2 {
			continue
		}
		old := strings.TrimSuffix(l[strings.LastIndex(l, ":")+1:], "]")
		ups = append(ups, model.Upgrade{Name: name, ID: name, Version: strings.TrimSpace(old), Available: f[1], Source: "apt",
			Command: "sudo apt install --only-upgrade " + name})
	}
	return ups, "apt", nil
}

// RunUpgrade is refused: the Linux preview is strictly read-only.
func (Software) RunUpgrade(ctx context.Context, id string) (string, error) {
	return "", errors.New("package upgrades are disabled in the Linux preview (read-only); run the shown apt command yourself")
}
