package software

import (
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// RawEntry is one registry uninstall key as read by the platform layer.
type RawEntry struct {
	Key              string
	KeyName          string // last path element (MSI product code for Windows Installer entries)
	Scope            string
	DisplayName      string
	DisplayVersion   string
	Publisher        string
	InstallDate      string
	InstallLocation  string
	InstallSource    string
	EstimatedSizeKB  uint64
	SystemComponent  uint64
	WindowsInstaller uint64
	ParentKeyName    string
	ReleaseType      string
	UninstallString  string
	QuietUninstall   string
	URLInfoAbout     string
	HelpLink         string
	Comments         string
	DisplayIcon      string
	Language         string
	UserSID          string
	Arch             string
	Source           string
	KeyWritten       time.Time // registry key last-write time (fallback install date)
}

// Filter applies the same rules as "Apps & features": skip entries without
// a DisplayName, system components, and child updates/hotfixes. Duplicates
// (same name+version in several hives) are collapsed, preferring machine
// scope.
func Filter(raw []RawEntry) []model.App {
	var out []model.App
	for _, a := range FilterAll(raw) {
		if !a.Hidden {
			out = append(out, a)
		}
	}
	return out
}

var productCode = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

// FilterAll is the deep inventory: every uninstall entry with a
// DisplayName, with system components, updates and child entries kept but
// marked Hidden and classified by Kind. InstallDate falls back to the
// registry key's last-write time when the InstallDate value is missing.
func FilterAll(raw []RawEntry) []model.App {
	seen := map[string]int{}
	var out []model.App
	for _, r := range raw {
		name := strings.TrimSpace(r.DisplayName)
		if name == "" {
			continue
		}
		kind := "app"
		switch strings.ToLower(r.ReleaseType) {
		case "update", "hotfix", "security update", "service pack":
			kind = "update"
		}
		if kind == "app" && r.ParentKeyName != "" {
			kind = "update"
		}
		if kind == "app" && r.SystemComponent == 1 {
			kind = "system-component"
		}
		if r.Source != "" && r.Source != "registry" {
			kind = "package"
		}
		a := model.App{
			Name: name, Version: strings.TrimSpace(r.DisplayVersion), Publisher: strings.TrimSpace(r.Publisher),
			InstallDate: formatDate(r.InstallDate), InstallLocation: strings.TrimSpace(r.InstallLocation),
			SizeKB: r.EstimatedSizeKB, Scope: r.Scope, UninstallKey: r.Key,
			Hidden: kind == "update" || kind == "system-component", Kind: kind, Arch: r.Arch,
			MSI:        r.WindowsInstaller == 1 || productCode.MatchString(r.KeyName),
			InstallSrc: strings.TrimSpace(r.InstallSource), Comments: strings.TrimSpace(r.Comments),
			DisplayIcon: strings.TrimSpace(r.DisplayIcon), Language: r.Language, UserSID: r.UserSID,
			Source: r.Source,
		}
		if a.Source == "" {
			a.Source = "registry"
		}
		a.Uninstall = strings.TrimSpace(r.QuietUninstall)
		if a.Uninstall == "" {
			a.Uninstall = strings.TrimSpace(r.UninstallString)
		}
		a.URL = strings.TrimSpace(r.URLInfoAbout)
		if a.URL == "" {
			a.URL = strings.TrimSpace(r.HelpLink)
		}
		if a.InstallDate != "" {
			a.DateSource = "registry"
			if r.Source == "dpkg" || r.Source == "rpm" {
				a.DateSource = "package-db"
			}
		} else if !r.KeyWritten.IsZero() && r.KeyWritten.Year() > 1990 {
			a.InstallDate = r.KeyWritten.Local().Format("2006-01-02")
			a.DateSource = "key-write-time"
		}
		k := strings.ToLower(a.Name) + "\x00" + a.Version
		if i, dup := seen[k]; dup {
			if out[i].Scope == "user" && a.Scope != "user" {
				a.Hidden = a.Hidden && out[i].Hidden
				out[i] = a
			}
			continue
		}
		seen[k] = len(out)
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// formatDate converts the registry's YYYYMMDD InstallDate to YYYY-MM-DD.
func formatDate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 8 {
		if _, ok := num(s); ok {
			return s[:4] + "-" + s[4:6] + "-" + s[6:]
		}
	}
	return s
}
