//go:build windows

package software

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

type hive struct {
	root  registry.Key
	rootS string
	path  string
	scope string
	flags uint32
}

var hives = []hive{
	{registry.LOCAL_MACHINE, `HKLM`, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "machine", registry.WOW64_64KEY},
	{registry.LOCAL_MACHINE, `HKLM`, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "machine-x86", registry.WOW64_32KEY},
	{registry.CURRENT_USER, `HKCU`, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "user", 0},
}

// Inventory reads every uninstall key in HKLM (64- and 32-bit views) and HKCU.
func Inventory() ([]model.App, error) {
	var raw []RawEntry
	var firstErr error
	for _, h := range hives {
		k, err := registry.OpenKey(h.root, h.path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|h.flags)
		if err != nil {
			if firstErr == nil && !errors.Is(err, registry.ErrNotExist) {
				firstErr = err
			}
			continue
		}
		names, _ := k.ReadSubKeyNames(-1)
		for _, n := range names {
			sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE|h.flags)
			if err != nil {
				continue
			}
			str := func(v string) string { s, _, _ := sk.GetStringValue(v); return s }
			dword := func(v string) uint64 { d, _, _ := sk.GetIntegerValue(v); return d }
			raw = append(raw, RawEntry{
				Key: h.rootS + `\` + h.path + `\` + n, Scope: h.scope,
				DisplayName: str("DisplayName"), DisplayVersion: str("DisplayVersion"),
				Publisher: str("Publisher"), InstallDate: str("InstallDate"),
				InstallLocation: str("InstallLocation"), EstimatedSizeKB: dword("EstimatedSize"),
				SystemComponent: dword("SystemComponent"), ParentKeyName: str("ParentKeyName"),
				ReleaseType: str("ReleaseType"),
			})
			sk.Close()
		}
		k.Close()
	}
	apps := Filter(raw)
	if len(apps) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return apps, nil
}

func wingetPath() (string, error) {
	p, err := exec.LookPath("winget.exe")
	if err != nil {
		return "", ErrNoWinget
	}
	return p, nil
}

func run(ctx context.Context, args []string) (string, error) {
	p, err := wingetPath()
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, p, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	return out.String(), err
}

// ListUpgrades runs `winget upgrade` and parses the table. winget exits
// non-zero when there is nothing to upgrade on some versions, so the output
// is parsed regardless of the exit code.
func ListUpgrades(ctx context.Context) ([]model.Upgrade, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	out, err := run(ctx, ListArgs)
	if errors.Is(err, ErrNoWinget) {
		return nil, "", err
	}
	ups := ParseUpgrade(out)
	if ctx.Err() != nil {
		return ups, out, ctx.Err()
	}
	return ups, out, nil
}

// RunUpgrade upgrades one package silently and returns winget's output.
func RunUpgrade(ctx context.Context, id string) (string, error) {
	args, err := UpgradeArgs(id)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	return run(ctx, args)
}
