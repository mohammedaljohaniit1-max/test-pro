//go:build windows

package software

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

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
	apps = append(apps, scanPortable(apps)...)
	if len(apps) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return apps, nil
}

// scanPortable performs a bounded, on-demand, read-only scan of known
// executable locations. Reparse points are not traversed; no binary runs.
func scanPortable(indexed []model.App) []model.App {
	roots := []string{
		filepath.Join(os.Getenv("USERPROFILE"), "Downloads"),
		filepath.Join(os.Getenv("APPDATA"), "Programs"),
		`C:\Tools`,
	}
	seen := map[string]bool{}
	for _, a := range indexed {
		if a.InstallLocation != "" {
			seen[strings.ToLower(filepath.Clean(a.InstallLocation))] = true
		}
	}
	var out []model.App
	visited := 0
	var walk func(string, int)
	walk = func(dir string, depth int) {
		if visited >= 500 || len(out) >= 150 || depth > 2 {
			return
		}
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if visited >= 500 || len(out) >= 150 {
				return
			}
			visited++
			if e.Type()&os.ModeSymlink != 0 {
				continue
			}
			path := filepath.Join(dir, e.Name())
			if e.IsDir() {
				walk(path, depth+1)
				continue
			}
			if !strings.EqualFold(filepath.Ext(e.Name()), ".exe") {
				continue
			}
			if meta, err := os.Lstat(path); err != nil || !meta.Mode().IsRegular() || meta.Size() > 1<<30 {
				continue
			}
			v, name, publisher, err := executableVersion(path)
			if err != nil || v == "" {
				continue
			} // no real PE resource: do not infer a version
			if name == "" {
				name = strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
			}
			key := strings.ToLower(filepath.Clean(path))
			if seen[key] {
				continue
			}
			seen[key] = true
			scope := "user"
			if strings.HasPrefix(strings.ToLower(path), `c:\tools\`) {
				scope = "machine"
			}
			out = append(out, model.App{Name: name, Version: v, Publisher: publisher, Scope: scope,
				UninstallKey: "portable:" + path, InstallLocation: filepath.Dir(path), DisplayIcon: path,
				Kind: "app", Source: "portable-pe"})
		}
	}
	for _, root := range roots {
		// An unset env var must never turn a broad relative path into a scan.
		if !filepath.IsAbs(root) {
			continue
		}
		walk(root, 0)
	}
	return out
}

// executableVersion retrieves the version and publisher from the signed or
// unsigned PE's actual VERSIONINFO resource (not its filename).
func executableVersion(path string) (version, name, publisher string, err error) {
	var unused windows.Handle
	size, err := windows.GetFileVersionInfoSize(path, &unused)
	if err != nil || size == 0 || size > 1<<20 {
		return "", "", "", fmt.Errorf("no bounded PE version resource: %v", err)
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return "", "", "", err
	}
	var fixed *windows.VS_FIXEDFILEINFO
	var length uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\`, unsafe.Pointer(&fixed), &length); err != nil || fixed == nil ||
		length < uint32(unsafe.Sizeof(*fixed)) || fixed.Signature != 0xfeef04bd {
		return "", "", "", errors.New("invalid VS_FIXEDFILEINFO")
	}
	vms, vls := fixed.FileVersionMS, fixed.FileVersionLS
	version = fmt.Sprintf("%d.%d.%d.%d", vms>>16, vms&0xffff, vls>>16, vls&0xffff)
	var translation *byte
	if windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&translation), &length) != nil || translation == nil || length < 4 {
		return version, "", "", nil
	}
	lang, codePage := *(*uint16)(unsafe.Pointer(translation)), *(*uint16)(unsafe.Add(unsafe.Pointer(translation), 2))
	query := func(key string) string {
		sub := fmt.Sprintf(`\StringFileInfo\%04X%04X\%s`, lang, codePage, key)
		var text *uint16
		var n uint32
		if windows.VerQueryValue(unsafe.Pointer(&buf[0]), sub, unsafe.Pointer(&text), &n) != nil || text == nil || n == 0 || n > 256 {
			return ""
		}
		return strings.TrimSpace(windows.UTF16ToString(unsafe.Slice(text, n)))
	}
	return version, query("ProductName"), query("CompanyName"), nil
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
