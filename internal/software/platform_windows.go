//go:build windows

package software

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

type hive struct {
	root  registry.Key
	rootS string
	path  string
	scope string
	arch  string
	flags uint32
	sid   string
}

const uninstallPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

// hives lists every standard uninstall location:
//
//	HKLM 64-bit view, HKLM 32-bit view (WOW6432Node),
//	HKCU 64-bit and 32-bit views (per-user installers such as VS Code,
//	Spotify, Discord), plus every other loaded user profile under HKU.
func hives() []hive {
	hs := []hive{
		{registry.LOCAL_MACHINE, `HKLM`, uninstallPath, "machine", "x64", registry.WOW64_64KEY, ""},
		{registry.LOCAL_MACHINE, `HKLM`, uninstallPath, "machine-x86", "x86", registry.WOW64_32KEY, ""},
		{registry.CURRENT_USER, `HKCU`, uninstallPath, "user", "", registry.WOW64_64KEY, ""},
		{registry.CURRENT_USER, `HKCU`, uninstallPath, "user-x86", "x86", registry.WOW64_32KEY, ""},
	}
	// Other signed-in users' hives (HKU\S-1-5-21-…). Reading them needs no
	// elevation for the current user and administrator rights for others;
	// failures are skipped silently.
	if k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS); err == nil {
		sids, _ := k.ReadSubKeyNames(-1)
		k.Close()
		cur := currentSID()
		for _, sid := range sids {
			if !strings.HasPrefix(sid, "S-1-5-21-") || strings.HasSuffix(sid, "_Classes") || sid == cur {
				continue
			}
			hs = append(hs, hive{registry.USERS, `HKU\` + sid, sid + `\` + uninstallPath, "other-user", "", registry.WOW64_64KEY, sid})
		}
	}
	return hs
}

func currentSID() string {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	return u.User.Sid.String()
}

// Inventory deep-scans every uninstall key in HKLM (64- and 32-bit views),
// HKCU (both views) and other loaded user hives, and returns only the
// entries "Apps & features" would show.
func Inventory() ([]model.App, error) {
	all, err := InventoryAll()
	var out []model.App
	for _, a := range all {
		if !a.Hidden {
			out = append(out, a)
		}
	}
	return out, err
}

// InventoryAll returns every uninstall entry including system components
// and updates (marked Hidden).
func InventoryAll() ([]model.App, error) {
	var raw []RawEntry
	var firstErr error
	seenKeys := map[string]bool{}
	for _, h := range hives() {
		k, err := registry.OpenKey(h.root, h.path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|h.flags)
		if err != nil {
			if firstErr == nil && !errors.Is(err, registry.ErrNotExist) && h.sid == "" {
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
			e := RawEntry{
				Key: h.rootS + `\` + uninstallPath + `\` + n, KeyName: n, Scope: h.scope, Arch: h.arch, UserSID: h.sid,
				DisplayName: str("DisplayName"), DisplayVersion: str("DisplayVersion"),
				Publisher: str("Publisher"), InstallDate: str("InstallDate"),
				InstallLocation: str("InstallLocation"), InstallSource: str("InstallSource"),
				EstimatedSizeKB: dword("EstimatedSize"), SystemComponent: dword("SystemComponent"),
				WindowsInstaller: dword("WindowsInstaller"), ParentKeyName: str("ParentKeyName"),
				ReleaseType: str("ReleaseType"), UninstallString: str("UninstallString"),
				QuietUninstall: str("QuietUninstallString"), URLInfoAbout: str("URLInfoAbout"),
				HelpLink: str("HelpLink"), Comments: str("Comments"), DisplayIcon: str("DisplayIcon"),
				Source: "registry",
			}
			if l := dword("Language"); l != 0 {
				e.Language = strconv.FormatUint(l, 10)
			}
			if h.arch == "x64" && strings.Contains(strings.ToLower(e.InstallLocation), `program files (x86)`) {
				e.Arch = "x86"
			}
			if ki, err := sk.Stat(); err == nil {
				e.KeyWritten = ki.ModTime()
			}
			sk.Close()
			// HKCU 32/64 views are shared on modern Windows: skip exact repeats.
			id := e.Key + "|" + e.DisplayName
			if seenKeys[id] {
				continue
			}
			seenKeys[id] = true
			raw = append(raw, e)
		}
		k.Close()
	}
	apps := FilterAll(raw)
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
