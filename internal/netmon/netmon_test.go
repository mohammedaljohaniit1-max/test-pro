package netmon

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

func le(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

// nport encodes a port the way Windows stores it: network order in the low
// 16 bits of a DWORD.
func nport(p uint16) []byte { return []byte{byte(p >> 8), byte(p), 0, 0} }

func TestParseTCP4(t *testing.T) {
	buf := le(2)
	// ESTABLISHED 192.168.1.10:50123 -> 93.184.216.34:443 pid 4242
	buf = append(buf, le(5)...)
	buf = append(buf, 192, 168, 1, 10)
	buf = append(buf, nport(50123)...)
	buf = append(buf, 93, 184, 216, 34)
	buf = append(buf, nport(443)...)
	buf = append(buf, le(4242)...)
	// LISTEN 0.0.0.0:445 pid 4 (remote must be blanked)
	buf = append(buf, le(2)...)
	buf = append(buf, 0, 0, 0, 0)
	buf = append(buf, nport(445)...)
	buf = append(buf, 0, 0, 0, 0)
	buf = append(buf, nport(0)...)
	buf = append(buf, le(4)...)
	got, err := ParseTCP4(buf)
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	c := got[0]
	if c.State != "ESTABLISHED" || c.LocalAddr != "192.168.1.10" || c.LocalPort != 50123 ||
		c.RemoteAddr != "93.184.216.34" || c.RemotePort != 443 || c.PID != 4242 || c.Proto != "TCP" {
		t.Fatalf("row0 %+v", c)
	}
	if got[1].State != "LISTEN" || got[1].LocalPort != 445 || got[1].RemoteAddr != "" || got[1].PID != 4 {
		t.Fatalf("row1 %+v", got[1])
	}
	if _, err := ParseTCP4(buf[:30]); err == nil {
		t.Fatal("truncated table accepted")
	}
}

func TestParseTCP6AndUDP(t *testing.T) {
	loop6 := make([]byte, 16)
	loop6[15] = 1
	buf := le(1)
	buf = append(buf, loop6...)
	buf = append(buf, le(0)...) // scope
	buf = append(buf, nport(8080)...)
	buf = append(buf, loop6...)
	buf = append(buf, le(0)...)
	buf = append(buf, nport(55555)...)
	buf = append(buf, le(5)...)
	buf = append(buf, le(99)...)
	got, err := ParseTCP6(buf)
	if err != nil || len(got) != 1 || got[0].LocalAddr != "::1" || got[0].LocalPort != 8080 ||
		got[0].RemotePort != 55555 || got[0].PID != 99 || got[0].Proto != "TCP6" {
		t.Fatalf("%+v %v", got, err)
	}

	u := le(1)
	u = append(u, 127, 0, 0, 1)
	u = append(u, nport(53)...)
	u = append(u, le(1234)...)
	ug, err := ParseUDP4(u)
	if err != nil || ug[0].LocalPort != 53 || ug[0].PID != 1234 || ug[0].State != "-" {
		t.Fatalf("%+v %v", ug, err)
	}

	u6 := le(1)
	u6 = append(u6, loop6...)
	u6 = append(u6, le(0)...)
	u6 = append(u6, nport(5353)...)
	u6 = append(u6, le(7)...)
	u6g, err := ParseUDP6(u6)
	if err != nil || u6g[0].LocalPort != 5353 || u6g[0].PID != 7 || u6g[0].Proto != "UDP6" {
		t.Fatalf("%+v %v", u6g, err)
	}
}

func TestTrackerDiffAndStats(t *testing.T) {
	now := time.Unix(1000, 0)
	snaps := [][]model.Connection{
		{
			{Proto: "TCP", LocalAddr: "10.0.0.1", LocalPort: 5000, RemoteAddr: "1.1.1.1", RemotePort: 443, State: "SYN_SENT", PID: 10},
			{Proto: "TCP", LocalAddr: "0.0.0.0", LocalPort: 80, State: "LISTEN", PID: 20},
		},
		{
			{Proto: "TCP", LocalAddr: "10.0.0.1", LocalPort: 5000, RemoteAddr: "1.1.1.1", RemotePort: 443, State: "ESTABLISHED", PID: 10},
			{Proto: "TCP", LocalAddr: "10.0.0.1", LocalPort: 5001, RemoteAddr: "1.1.1.1", RemotePort: 443, State: "ESTABLISHED", PID: 10},
			{Proto: "UDP", LocalAddr: "0.0.0.0", LocalPort: 53, State: "-", PID: 30},
		},
	}
	i := 0
	resolved := 0
	tr := NewTracker(func() ([]model.Connection, error) { s := snaps[i]; i++; return s, nil },
		func(pid uint32) (string, string) {
			resolved++
			return map[uint32]string{10: "chrome.exe", 20: "httpd.exe", 30: "dns.exe"}[pid], `C:\x.exe`
		})
	tr.now = func() time.Time { return now }

	d, _ := tr.Poll()
	if len(d.Added) != 2 || len(d.Removed) != 0 {
		t.Fatalf("first poll %+v", d)
	}
	now = now.Add(2 * time.Second)
	d, _ = tr.Poll()
	if len(d.Added) != 2 || len(d.Removed) != 1 || len(d.Changed) != 1 || d.Changed[0].State != "ESTABLISHED" {
		t.Fatalf("second poll %+v", d)
	}
	if d.Changed[0].ProcessName != "chrome.exe" || d.Changed[0].FirstSeen != time.Unix(1000, 0).UnixMilli() {
		t.Fatalf("carried-over fields lost: %+v", d.Changed[0])
	}
	if resolved != 4 {
		t.Fatalf("resolver must only run for new sockets; ran %d times", resolved)
	}
	s := tr.Stats()
	if s.Total != 3 || s.ByState["ESTABLISHED"] != 2 || s.ByProto["UDP"] != 1 || s.ByState["-"] != 0 {
		t.Fatalf("stats %+v", s)
	}
	if s.NewPerSec != 1.0 { // 2 new sockets over 2 seconds (first snapshot excluded)
		t.Fatalf("rate %v", s.NewPerSec)
	}
	if s.TopProcs[0].Name != "chrome.exe" || s.TopProcs[0].Count != 2 || s.TopRemotes[0].Name != "1.1.1.1" {
		t.Fatalf("top %+v %+v", s.TopProcs, s.TopRemotes)
	}
	if snap := tr.Snapshot(); len(snap) != 3 || snap[0].Proto != "TCP" || snap[2].Proto != "UDP" {
		t.Fatalf("snapshot order %+v", snap)
	}
}

func TestPlaceholderNamesAreRetried(t *testing.T) {
	conn := []model.Connection{{Proto: "TCP", LocalAddr: "0.0.0.0", LocalPort: 80, State: "LISTEN", PID: 42}}
	known := false
	tr := NewTracker(func() ([]model.Connection, error) { return conn, nil }, func(pid uint32) (string, string) {
		if known {
			return "svc.exe", `C:\svc.exe`
		}
		return "pid 42", ""
	})
	tr.Poll()
	if tr.Snapshot()[0].ProcessName != "pid 42" {
		t.Fatal("expected placeholder")
	}
	known = true
	d, _ := tr.Poll()
	if tr.Snapshot()[0].ProcessName != "svc.exe" || len(d.Changed) != 1 {
		t.Fatalf("placeholder not re-resolved: %+v %+v", tr.Snapshot()[0], d)
	}
}
