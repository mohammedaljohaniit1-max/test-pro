package radar

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

func obs(t0 time.Time, ip string, port uint16, dt time.Duration) Observation {
	return Observation{Time: t0.Add(dt), RemoteIP: ip, RemotePort: 50000, LocalIP: "192.168.1.42", LocalPort: port, Sensor: SensorRaw}
}

func TestSweepRuleExactlyAboveTen(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	d := New(Config{})
	d.SetClock(func() time.Time { return t0.Add(5 * time.Second) })
	d.SetNeighbors([]Neighbor{{IP: "192.168.1.66", MAC: "00-0C-29-7D-E4-A0", IfIndex: 12, Interface: "Ethernet"}})
	// 10 distinct ports within 5 s: at the limit, not above it.
	for p := uint16(1); p <= 10; p++ {
		if incs := d.Observe(obs(t0, "192.168.1.66", p, time.Duration(p)*100*time.Millisecond)); len(incs) != 0 {
			t.Fatalf("flagged at %d ports", p)
		}
	}
	// Repeating a port does not widen the breadth.
	if incs := d.Observe(obs(t0, "192.168.1.66", 5, 1200*time.Millisecond)); len(incs) != 0 {
		t.Fatal("repeat port flagged")
	}
	incs := d.Observe(obs(t0, "192.168.1.66", 11, 1300*time.Millisecond))
	if len(incs) != 1 {
		t.Fatalf("11th distinct port not flagged: %v", incs)
	}
	inc := incs[0]
	if !inc.New || inc.RemoteIP != "192.168.1.66" || inc.DistinctPorts != 11 || inc.PortMin != 1 || inc.PortMax != 11 ||
		inc.PortRange != "1-11" || inc.MAC != "00-0C-29-7D-E4-A0" || inc.Interface != "Ethernet" || !inc.OnLink || !inc.Active {
		t.Fatalf("incident %+v", inc)
	}
	// Further ports update the same incident, New is reported only once.
	incs = d.Observe(obs(t0, "192.168.1.66", 443, 1400*time.Millisecond))
	if len(incs) != 1 || incs[0].New || incs[0].ID != inc.ID || incs[0].PortRange != "1-11, 443" {
		t.Fatalf("update %+v", incs)
	}
}

func TestSlowScanOutsideWindowNotFlagged(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	d := New(Config{})
	d.SetClock(func() time.Time { return t0 })
	// 30 ports but one every second: never more than 6 inside 5 s.
	for p := uint16(1); p <= 30; p++ {
		if incs := d.Observe(obs(t0, "10.0.0.9", p, time.Duration(p)*time.Second)); len(incs) != 0 {
			t.Fatalf("slow scan flagged at port %d", p)
		}
	}
}

func TestIgnoredAndAllowList(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	d := New(Config{Allow: []string{"192.168.1.200"}})
	for _, ip := range []string{"127.0.0.1", "::1", "0.0.0.0", "192.168.1.200", "224.0.0.251"} {
		for p := uint16(1); p <= 30; p++ {
			if incs := d.Observe(obs(t0, ip, p, 0)); len(incs) != 0 {
				t.Fatalf("%s flagged", ip)
			}
		}
	}
	if st := d.Snapshot(0); st.Tracked != 0 {
		t.Fatalf("ignored hosts tracked: %d", st.Tracked)
	}
}

func TestCooldownExpiryAndSnapshot(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	now := t0
	d := New(Config{Cooldown: 10 * time.Second})
	d.SetClock(func() time.Time { return now })
	var batch []Observation
	for p := uint16(100); p < 120; p++ {
		batch = append(batch, obs(t0, "203.0.113.45", p, 0))
	}
	incs := d.Observe(batch...)
	if len(incs) != 1 || incs[0].Attempts != 20 {
		t.Fatalf("batch %+v", incs)
	}
	st := d.Snapshot(10)
	if st.Active != 1 || len(st.Hosts) != 1 || !st.Hosts[0].Flagged || st.Hosts[0].PortsWindow != 20 || st.Threshold != 10 {
		t.Fatalf("snapshot %+v", st)
	}
	now = t0.Add(11 * time.Second)
	if ex := d.Expire(); len(ex) != 1 || ex[0].Active {
		t.Fatalf("expire %+v", ex)
	}
	// A new sweep after cooldown opens a new incident.
	batch = batch[:0]
	for p := uint16(200); p < 215; p++ {
		batch = append(batch, obs(t0, "203.0.113.45", p, 12*time.Second))
	}
	incs = d.Observe(batch...)
	if len(incs) != 1 || !incs[0].New || incs[0].ID == "SWP-0001" {
		t.Fatalf("second incident %+v", incs)
	}
	if got := len(d.Incidents()); got != 2 {
		t.Fatalf("incidents %d", got)
	}
}

func TestAttribute(t *testing.T) {
	d := New(Config{})
	var batch []Observation
	for p := uint16(1); p <= 12; p++ {
		batch = append(batch, obs(time.Now(), "8.8.4.4", p, 0))
	}
	inc := d.Observe(batch...)[0]
	upd, ok := d.Attribute(inc.ID, Neighbor{MAC: "3C-84-6A-12-9F-01", Interface: "Ethernet", Gateway: "192.168.1.1"}, false, nil)
	if !ok || upd.MAC != "3C-84-6A-12-9F-01" || upd.OnLink || upd.Gateway != "192.168.1.1" {
		t.Fatalf("attribute %+v", upd)
	}
}

func TestCompressPorts(t *testing.T) {
	cases := map[string][]uint16{
		"":                  nil,
		"80":                {80},
		"21-23, 80, 443":    {21, 22, 23, 80, 443},
		"1, 3, 5 (+2 more)": {1, 3, 5, 7, 9},
		"8000-8003, 9000":   {8000, 8001, 8002, 8003, 9000},
	}
	for want, in := range cases {
		max := 0
		if want == "1, 3, 5 (+2 more)" {
			max = 3
		}
		if got := CompressPorts(in, max); got != want {
			t.Errorf("%v: got %q want %q", in, got, want)
		}
	}
}

func TestParseIpNetTable(t *testing.T) {
	t.Run("layout", func(t *testing.T) {
		b := make([]byte, 4+ipNetRowSize)
		binary.LittleEndian.PutUint32(b, 1)
		r := b[4:]
		binary.LittleEndian.PutUint32(r[0:], 12)
		binary.LittleEndian.PutUint32(r[4:], 6)
		copy(r[8:14], []byte{0x3c, 0x84, 0x6a, 0x12, 0x9f, 0x01})
		copy(r[16:20], []byte{192, 168, 1, 1})
		binary.LittleEndian.PutUint32(r[20:], 3)
		ns, err := ParseIpNetTable(b, func(i uint32) string { return "Ethernet" })
		if err != nil || len(ns) != 1 {
			t.Fatalf("%v %v", ns, err)
		}
		if n := ns[0]; n.IP != "192.168.1.1" || n.MAC != "3C-84-6A-12-9F-01" || n.IfIndex != 12 || n.Interface != "Ethernet" || n.Type != "dynamic" {
			t.Fatalf("%+v", n)
		}
	})
	t.Run("skips invalid and incomplete", func(t *testing.T) {
		b := make([]byte, 4+2*ipNetRowSize)
		binary.LittleEndian.PutUint32(b, 2)
		r := b[4 : 4+ipNetRowSize] // all-zero MAC (incomplete)
		binary.LittleEndian.PutUint32(r[4:], 6)
		binary.LittleEndian.PutUint32(r[20:], 3)
		r = b[4+ipNetRowSize:] // type 2 = invalid
		binary.LittleEndian.PutUint32(r[4:], 6)
		r[8] = 0xaa
		binary.LittleEndian.PutUint32(r[20:], 2)
		if ns, err := ParseIpNetTable(b, nil); err != nil || len(ns) != 0 {
			t.Fatalf("%v %v", ns, err)
		}
	})
	if _, err := ParseIpNetTable([]byte{5, 0, 0, 0, 1}, nil); err == nil {
		t.Fatal("truncated table accepted")
	}
}

func synPacket(src, dst net.IP, sport, dport uint16, flags byte) []byte {
	p := make([]byte, 40)
	p[0] = 0x45
	p[9] = 6
	copy(p[12:16], src.To4())
	copy(p[16:20], dst.To4())
	binary.BigEndian.PutUint16(p[20:], sport)
	binary.BigEndian.PutUint16(p[22:], dport)
	p[33] = flags
	return p
}

func TestParseInboundSYN(t *testing.T) {
	local := net.ParseIP("192.168.1.42").To4()
	remote := net.ParseIP("192.168.1.66")
	src, sp, dst, dp, err := ParseInboundSYN(synPacket(remote, local, 51000, 445, tcpSYN), local)
	if err != nil || !src.Equal(remote) || sp != 51000 || !dst.Equal(local) || dp != 445 {
		t.Fatalf("%v %v %v %v %v", src, sp, dst, dp, err)
	}
	for name, pkt := range map[string][]byte{
		"syn-ack":  synPacket(remote, local, 51000, 445, tcpSYN|tcpACK),
		"rst":      synPacket(remote, local, 51000, 445, tcpRST),
		"outbound": synPacket(local, remote, 51000, 445, tcpSYN),
		"short":    {0x45, 0},
		"ipv6":     append([]byte{0x60}, make([]byte, 50)...),
	} {
		if _, _, _, _, err := ParseInboundSYN(pkt, local); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestFromConnections(t *testing.T) {
	listen := map[string][]model.Listener{
		ListenKey("TCP", 445):   {{Addr: "0.0.0.0", PID: 4}},
		ListenKey("TCP6", 3389): {{Addr: "::", PID: 900}},
		ListenKey("TCP", 51500): {{Addr: "127.0.0.1", PID: 777}}, // loopback-only IPC listener
	}
	added := []model.Connection{
		{Proto: "TCP", LocalAddr: "192.168.1.42", LocalPort: 445, RemoteAddr: "192.168.1.66", RemotePort: 51000, State: "ESTABLISHED", PID: 4, FirstSeen: 1},
		{Proto: "TCP6", LocalAddr: "fe80::1", LocalPort: 3389, RemoteAddr: "fe80::9", RemotePort: 51001, State: "ESTABLISHED", PID: 900},
		{Proto: "TCP", LocalAddr: "192.168.1.42", LocalPort: 7777, RemoteAddr: "192.168.1.66", RemotePort: 51002, State: "SYN_RECEIVED"},
		{Proto: "TCP", LocalAddr: "192.168.1.42", LocalPort: 52000, RemoteAddr: "142.250.1.1", RemotePort: 443, State: "ESTABLISHED"}, // outbound
		{Proto: "TCP", LocalAddr: "0.0.0.0", LocalPort: 445, State: "LISTEN"},
		{Proto: "UDP", LocalAddr: "0.0.0.0", LocalPort: 53},
		// Browser ephemeral port colliding with a loopback-only listener: not inbound.
		{Proto: "TCP", LocalAddr: "192.168.1.42", LocalPort: 51500, RemoteAddr: "151.101.1.69", RemotePort: 8443, State: "ESTABLISHED", PID: 4012, ProcessName: "chrome.exe"},
		// Same collision from an unknown process: address mismatch keeps it out.
		{Proto: "TCP", LocalAddr: "192.168.1.42", LocalPort: 51500, RemoteAddr: "10.0.0.5", RemotePort: 7000, State: "ESTABLISHED", PID: 12},
		// A browser row in SYN_RECEIVED is still dropped (client process).
		{Proto: "TCP", LocalAddr: "192.168.1.42", LocalPort: 9222, RemoteAddr: "10.0.0.5", RemotePort: 7001, State: "SYN_RECEIVED", ProcessName: "Chrome.exe"},
	}
	got := FromConnections(added, listen, NewTableOptions())
	if len(got) != 3 || got[0].LocalPort != 445 || got[0].Sensor != SensorTable || got[2].LocalPort != 7777 {
		t.Fatalf("%+v", got)
	}
}

// A browser with dozens of tabs opens many outbound sockets in a burst; the
// table sensor must never turn them into observations.
func TestBrowserBurstNeverObserved(t *testing.T) {
	listen := map[string][]model.Listener{}
	var added []model.Connection
	for i := 0; i < 200; i++ {
		added = append(added, model.Connection{Proto: "TCP", LocalAddr: "192.168.1.42", LocalPort: uint16(50000 + i),
			RemoteAddr: "142.250.185.78", RemotePort: uint16([]int{443, 80, 8443, 5228}[i%4]), State: "SYN_SENT", PID: 4012, ProcessName: "msedge.exe"})
		listen[ListenKey("TCP", uint16(50000+i))] = []model.Listener{{Addr: "127.0.0.1", PID: 99}}
	}
	if got := FromConnections(added, listen, NewTableOptions()); len(got) != 0 {
		t.Fatalf("browser burst produced %d observations", len(got))
	}
}
