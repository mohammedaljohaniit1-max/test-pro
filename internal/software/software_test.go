package software

import (
	"strings"
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// Representative `winget upgrade` output including the progress spinner that
// winget prints before the table (overwritten with \r), a long name that
// was truncated with "…", and footer lines.
const wingetOut = "   - \r   \\ \r   | \r   / \r" +
	"  ██████████████████████████████  1.40 MB / 1.40 MB\r\n" +
	"Name                              Id                          Version        Available      Source\r\n" +
	"----------------------------------------------------------------------------------------------------\r\n" +
	"Mozilla Firefox (x64 en-US)       Mozilla.Firefox             129.0.1        130.0          winget\r\n" +
	"Microsoft Visual Studio Code      Microsoft.VisualStudioCode  1.92.0         1.93.1         winget\r\n" +
	"7-Zip 23.01 (x64)                 7zip.7zip                   23.01          24.08          winget\r\n" +
	"Microsoft Visual C++ 2015-2022 R… Microsoft.VCRedist.2015+.x64 14.38.33135.0 14.40.33810.0 winget\r\n" +
	"Same Version App                  Vendor.Same                 1.0            1.0            winget\r\n" +
	"4 upgrades available.\r\n" +
	"1 package(s) have version numbers that cannot be determined. Use --include-unknown to see all results.\r\n"

func TestParseUpgrade(t *testing.T) {
	ups := ParseUpgrade(wingetOut)
	if len(ups) != 4 {
		for _, u := range ups {
			t.Logf("%+v", u)
		}
		t.Fatalf("got %d upgrades", len(ups))
	}
	byID := map[string]model.Upgrade{}
	for _, u := range ups {
		byID[u.ID] = u
	}
	ff := byID["Mozilla.Firefox"]
	if ff.Name != "Mozilla Firefox (x64 en-US)" || ff.Version != "129.0.1" || ff.Available != "130.0" || ff.Source != "winget" {
		t.Fatalf("firefox %+v", ff)
	}
	vc := byID["Microsoft.VCRedist.2015+.x64"]
	if vc.Version != "14.38.33135.0" || vc.Available != "14.40.33810.0" {
		t.Fatalf("overflowing row not re-split: %+v", vc)
	}
	if !strings.HasPrefix(ff.Command, "winget upgrade --id Mozilla.Firefox --exact --silent") {
		t.Fatalf("command %q", ff.Command)
	}
	if ups[0].Name != "7-Zip 23.01 (x64)" { // sorted by name
		t.Fatalf("order %q", ups[0].Name)
	}
	if ParseUpgrade("No installed package found matching input criteria.") != nil {
		t.Fatal("no table must yield nil")
	}
}

func TestValidIDRejectsInjection(t *testing.T) {
	for _, bad := range []string{"", "--all", "a b", "x;calc", "x&y", "x|y", `x"y`, strings.Repeat("a", 200), "-x"} {
		if ValidID(bad) {
			t.Errorf("accepted %q", bad)
		}
		if _, err := UpgradeArgs(bad); err == nil {
			t.Errorf("UpgradeArgs accepted %q", bad)
		}
	}
	for _, ok := range []string{"Mozilla.Firefox", "7zip.7zip", "Microsoft.VCRedist.2015+.x64", "Git.Git", "9NBLGGH4NNS1"} {
		if !ValidID(ok) {
			t.Errorf("rejected %q", ok)
		}
	}
}

func TestFilterInventory(t *testing.T) {
	raw := []RawEntry{
		{Key: "k1", Scope: "user", DisplayName: "Git", DisplayVersion: "2.45.1", InstallDate: "20240511"},
		{Key: "k2", Scope: "machine", DisplayName: "Git", DisplayVersion: "2.45.1"},
		{Key: "k3", Scope: "machine", DisplayName: ""},
		{Key: "k4", Scope: "machine", DisplayName: "Hidden", SystemComponent: 1},
		{Key: "k5", Scope: "machine", DisplayName: "KB5030219", ParentKeyName: "Office"},
		{Key: "k6", Scope: "machine", DisplayName: "Security Update", ReleaseType: "Security Update"},
		{Key: "k7", Scope: "machine-x86", DisplayName: "7-Zip", DisplayVersion: "23.01", EstimatedSizeKB: 5000},
	}
	apps := Filter(raw)
	if len(apps) != 2 || apps[0].Name != "7-Zip" || apps[1].Name != "Git" {
		t.Fatalf("%+v", apps)
	}
	if apps[1].Scope != "machine" || apps[1].UninstallKey != "k2" {
		t.Fatalf("dedupe must prefer machine scope: %+v", apps[1])
	}
	if formatDate("20240511") != "2024-05-11" || formatDate("5/11/2024") != "5/11/2024" {
		t.Fatal("date format")
	}
}

func TestMerge(t *testing.T) {
	apps := []model.App{
		{Name: "Mozilla Firefox (x64 en-US)", Version: "129.0.1"},
		{Name: "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33135", Version: "14.38.33135.0"},
		{Name: "Notepad++", Version: "8.6"},
	}
	merged := Merge(apps, ParseUpgrade(wingetOut))
	if merged[0].AvailableVersion != "130.0" || merged[0].WingetID != "Mozilla.Firefox" {
		t.Fatalf("firefox %+v", merged[0])
	}
	if merged[1].WingetID != "Microsoft.VCRedist.2015+.x64" {
		t.Fatalf("truncated-name prefix match failed: %+v", merged[1])
	}
	if merged[2].AvailableVersion != "" {
		t.Fatal("unmatched app annotated")
	}
	if apps[0].AvailableVersion != "" {
		t.Fatal("Merge must not mutate its input")
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"10.2", "9.9", 1}, {"1.0.0", "1", 0}, {"1.0.1", "1", 1}, {"2.45.1", "2.45.10", -1},
		{"v1.2", "1.2", 0}, {"14.38.33135.0", "14.40.33810.0", -1}, {"1.0-beta", "1.0-alpha", 1}, {"", "", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestFilterAllDeepInventory(t *testing.T) {
	kw := time.Date(2025, 3, 4, 12, 0, 0, 0, time.UTC)
	raw := []RawEntry{
		{Key: "k1", KeyName: "{23170F69-40C1-2702-2301-000001000000}", Scope: "machine", DisplayName: "7-Zip", DisplayVersion: "23.01", UninstallString: "MsiExec.exe /X{…}"},
		{Key: "k2", Scope: "machine", DisplayName: "Hidden runtime", SystemComponent: 1, KeyWritten: kw},
		{Key: "k3", Scope: "machine", DisplayName: "KB5030219", ParentKeyName: "Office"},
		{Key: "k4", Scope: "user", DisplayName: "Spotify", QuietUninstall: "spotify /uninstall /silent", URLInfoAbout: "https://spotify.com", UserSID: "S-1-5-21-1"},
	}
	all := FilterAll(raw)
	if len(all) != 4 {
		t.Fatalf("%+v", all)
	}
	by := map[string]model.App{}
	for _, a := range all {
		by[a.Name] = a
	}
	if !by["7-Zip"].MSI || by["7-Zip"].Hidden || by["7-Zip"].Kind != "app" {
		t.Fatalf("msi: %+v", by["7-Zip"])
	}
	if h := by["Hidden runtime"]; !h.Hidden || h.Kind != "system-component" || h.InstallDate != "2025-03-04" || h.DateSource != "key-write-time" {
		t.Fatalf("hidden: %+v", h)
	}
	if u := by["KB5030219"]; u.Kind != "update" || !u.Hidden {
		t.Fatalf("update: %+v", u)
	}
	if s := by["Spotify"]; s.Uninstall != "spotify /uninstall /silent" || s.URL == "" || s.UserSID == "" {
		t.Fatalf("spotify: %+v", s)
	}
	if len(Filter(raw)) != 2 {
		t.Fatal("Filter must keep hiding system components and updates")
	}
}
