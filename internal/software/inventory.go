package software

import (
	"sort"
	"strings"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// RawEntry is one registry uninstall key as read by the platform layer.
type RawEntry struct {
	Key             string
	Scope           string
	DisplayName     string
	DisplayVersion  string
	Publisher       string
	InstallDate     string
	InstallLocation string
	EstimatedSizeKB uint64
	SystemComponent uint64
	ParentKeyName   string
	ReleaseType     string
}

// Filter applies the same rules as "Apps & features": skip entries without
// a DisplayName, system components, and child updates/hotfixes. Duplicates
// (same name+version in several hives) are collapsed, preferring machine
// scope.
func Filter(raw []RawEntry) []model.App {
	seen := map[string]int{}
	var out []model.App
	for _, r := range raw {
		name := strings.TrimSpace(r.DisplayName)
		if name == "" || r.SystemComponent == 1 || r.ParentKeyName != "" {
			continue
		}
		switch strings.ToLower(r.ReleaseType) {
		case "update", "hotfix", "security update":
			continue
		}
		a := model.App{
			Name: name, Version: strings.TrimSpace(r.DisplayVersion), Publisher: strings.TrimSpace(r.Publisher),
			InstallDate: formatDate(r.InstallDate), InstallLocation: strings.TrimSpace(r.InstallLocation),
			SizeKB: r.EstimatedSizeKB, Scope: r.Scope, UninstallKey: r.Key,
		}
		k := strings.ToLower(a.Name) + "\x00" + a.Version
		if i, dup := seen[k]; dup {
			if out[i].Scope == "user" && a.Scope != "user" {
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
