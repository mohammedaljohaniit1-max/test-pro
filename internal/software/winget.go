// Package software inventories installed applications (registry uninstall
// keys) and wraps the Windows Package Manager CLI (winget) to discover and
// apply upgrades.
package software

import (
	"errors"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// ErrNoWinget is returned when winget.exe is not installed or not on PATH.
var ErrNoWinget = errors.New("winget is not installed (install 'App Installer' from the Microsoft Store)")

// wingetIDPattern restricts package IDs passed to `winget upgrade --id` so
// user input can never inject extra arguments.
var wingetIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$`)

// ValidID reports whether id is a syntactically valid winget package ID.
func ValidID(id string) bool { return wingetIDPattern.MatchString(id) }

// UpgradeArgs builds the argument list for a silent upgrade of one package.
func UpgradeArgs(id string) ([]string, error) {
	if !ValidID(id) {
		return nil, errors.New("invalid winget package id")
	}
	return []string{"upgrade", "--id", id, "--exact", "--silent",
		"--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity"}, nil
}

// ListArgs is the argument list used to query available upgrades.
var ListArgs = []string{"upgrade", "--include-unknown", "--accept-source-agreements", "--disable-interactivity"}

// cleanOutput removes the progress spinner / bar noise winget writes before
// the table (carriage-return overwritten lines and block characters).
func cleanOutput(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if i := strings.LastIndexByte(l, '\r'); i >= 0 {
			l = l[i+1:]
		}
		l = strings.TrimRight(l, " ")
		t := strings.TrimSpace(l)
		if t == "" || t == "-" || t == "\\" || t == "|" || t == "/" {
			continue
		}
		if strings.ContainsAny(t, "█▒") {
			continue
		}
		lines = append(lines, l)
	}
	return lines
}

// column describes one table column by rune offset.
type column struct {
	name  string
	start int
}

// ParseUpgrade parses the human-readable table printed by `winget upgrade`.
// Columns are located from the header line (Name, Id, Version, Available,
// Source) and cut by *display rune offsets*, which handles names containing
// spaces. Header names are matched case-insensitively and by position, so
// localised headers still work as long as the order is standard.
func ParseUpgrade(out string) []model.Upgrade {
	lines := cleanOutput(out)
	sep := -1
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if len(t) >= 10 && strings.Trim(t, "-") == "" {
			sep = i
			break
		}
	}
	if sep < 1 {
		return nil
	}
	header := []rune(lines[sep-1])
	cols := headerColumns(header)
	if len(cols) < 4 {
		return nil
	}
	var res []model.Upgrade
	for _, l := range lines[sep+1:] {
		r := []rune(l)
		// Footer lines ("3 upgrades available.", pinned notes) are shorter
		// than the Available column start or do not fill the ID column.
		if len(r) < cols[3].start {
			continue
		}
		get := func(i int) string {
			start := cols[i].start
			end := len(r)
			if i+1 < len(cols) {
				end = cols[i+1].start
			}
			if start >= len(r) {
				return ""
			}
			if end > len(r) {
				end = len(r)
			}
			return strings.TrimSpace(string(r[start:end]))
		}
		u := model.Upgrade{Name: get(0), ID: get(1), Version: get(2), Available: get(3)}
		if len(cols) > 4 {
			u.Source = get(4)
		}
		// Names longer than their column push the rest right (and short
		// footer lines never fit the grid). Validate the row structurally and
		// fall back to a whitespace re-split of the tail.
		hasSource := len(cols) > 4
		if !rowValid(u, hasSource) {
			fixed, ok := resplit(string(r), hasSource)
			if !ok || !rowValid(fixed, hasSource) {
				continue
			}
			u = fixed
		}
		if u.Available == "" || u.Available == u.Version {
			continue
		}
		u.Command = "winget " + strings.Join(mustArgs(u.ID), " ")
		res = append(res, u)
	}
	sort.Slice(res, func(i, j int) bool { return strings.ToLower(res[i].Name) < strings.ToLower(res[j].Name) })
	return res
}

// knownSources are winget's built-in source names.
var knownSources = map[string]bool{"winget": true, "msstore": true}

func versionLike(v string) bool {
	if v == "" || strings.ContainsAny(v, " \t") {
		return false
	}
	if strings.EqualFold(v, "unknown") {
		return true
	}
	return strings.ContainsAny(v, "0123456789")
}

func rowValid(u model.Upgrade, hasSource bool) bool {
	if !ValidID(u.ID) || !versionLike(u.Version) || !versionLike(u.Available) {
		return false
	}
	if hasSource && !knownSources[strings.ToLower(u.Source)] {
		return false
	}
	return true
}

func mustArgs(id string) []string {
	a, _ := UpgradeArgs(id)
	return a
}

func headerColumns(h []rune) []column {
	var cols []column
	in := false
	for i, c := range h {
		if c != ' ' && !in {
			// Start of a word; a column starts after ≥1 space.
			if i == 0 || h[i-1] == ' ' {
				j := i
				for j < len(h) && h[j] != ' ' {
					j++
				}
				cols = append(cols, column{name: strings.ToLower(string(h[i:j])), start: i})
			}
			in = true
		} else if c == ' ' {
			in = false
		}
	}
	return cols
}

// resplit handles rows whose Name overflowed: the last whitespace-separated
// fields are Id, Version, Available[, Source].
func resplit(line string, hasSource bool) (model.Upgrade, bool) {
	f := strings.Fields(line)
	src := ""
	if hasSource {
		if len(f) == 0 || !knownSources[strings.ToLower(f[len(f)-1])] {
			return model.Upgrade{}, false
		}
		src = f[len(f)-1]
		f = f[:len(f)-1]
	}
	if len(f) < 4 {
		return model.Upgrade{}, false
	}
	n := len(f)
	return model.Upgrade{Name: strings.Join(f[:n-3], " "), ID: f[n-3], Version: f[n-2], Available: f[n-1], Source: src}, true
}

// Normalize makes names comparable across registry and winget output
// (winget truncates long names with "…").
func Normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, "…")
	var b strings.Builder
	for len(s) > 0 {
		r, n := utf8.DecodeRuneInString(s)
		s = s[n:]
		if r == ' ' || r == '-' || r == '_' || r == '.' || r == '(' || r == ')' || r == ',' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Merge annotates apps with available upgrades, matching by normalised name
// (prefix match to handle winget's truncation) and installed version.
func Merge(apps []model.App, ups []model.Upgrade) []model.App {
	out := append([]model.App(nil), apps...)
	for _, u := range ups {
		un := Normalize(u.Name)
		if un == "" {
			continue
		}
		best := -1
		for i := range out {
			an := Normalize(out[i].Name)
			if an == un || (len(un) >= 8 && strings.HasPrefix(an, un)) {
				if best < 0 || out[i].Version == u.Version {
					best = i
				}
			}
		}
		if best >= 0 {
			out[best].AvailableVersion = u.Available
			out[best].WingetID = u.ID
		}
	}
	return out
}

// CompareVersions compares dotted versions numerically segment by segment
// ("10.2" > "9.9", "1.0.0" == "1"). Non-numeric segments compare as strings.
func CompareVersions(a, b string) int {
	pa, pb := splitVer(a), splitVer(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y string
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if c := cmpSeg(x, y); c != 0 {
			return c
		}
	}
	return 0
}

func splitVer(v string) []string {
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(v, "v"), "< "))
	return strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' || r == '+' || r == ' ' })
}

func cmpSeg(x, y string) int {
	xn, xok := num(x)
	yn, yok := num(y)
	switch {
	case xok && yok:
		switch {
		case xn < yn:
			return -1
		case xn > yn:
			return 1
		}
		return 0
	case x == "" && yok:
		if yn == 0 {
			return 0
		}
		return -1
	case y == "" && xok:
		if xn == 0 {
			return 0
		}
		return 1
	}
	return strings.Compare(x, y)
}

func num(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint64(c-'0')
	}
	return n, true
}
