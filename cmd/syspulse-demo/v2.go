package main

// Synthetic sources for the SysPulse 2.0 features: ARP table, inbound
// connection traffic (benign clients plus an occasional LAN port sweep) and
// Security / System / Application events for the one-click audits.

import (
	"context"
	"math/rand"
	"strings"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/hub"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/radar"
)

// ---- ARP / routing ----

type demoRadarPlat struct{}

var demoARP = []radar.Neighbor{
	{IP: "192.168.1.1", MAC: "3C-84-6A-12-9F-01", IfIndex: 12, Interface: "Ethernet", Type: "dynamic"},
	{IP: "192.168.1.20", MAC: "D4-5D-64-A1-22-7C", IfIndex: 12, Interface: "Ethernet", Type: "dynamic"},
	{IP: "192.168.1.35", MAC: "B8-27-EB-4C-19-D2", IfIndex: 12, Interface: "Ethernet", Type: "dynamic"},
	{IP: "192.168.1.57", MAC: "F0-2F-74-8E-03-5B", IfIndex: 12, Interface: "Ethernet", Type: "dynamic"},
	{IP: "192.168.1.66", MAC: "00-0C-29-7D-E4-A0", IfIndex: 12, Interface: "Ethernet", Type: "dynamic"},
	{IP: "192.168.1.104", MAC: "A4-83-E7-5B-C2-11", IfIndex: 12, Interface: "Ethernet", Type: "dynamic"},
	{IP: "10.8.0.1", MAC: "02-50-F2-00-00-01", IfIndex: 19, Interface: "WireGuard Tunnel", Type: "static"},
}

func (demoRadarPlat) Neighbors() ([]radar.Neighbor, error) { return demoARP, nil }

func (demoRadarPlat) Resolve(ip string) (radar.Neighbor, bool, error) {
	for _, n := range demoARP {
		if n.IP == ip {
			return n, true, nil
		}
	}
	if strings.HasPrefix(ip, "192.168.1.") {
		time.Sleep(300 * time.Millisecond) // SendARP round trip
		return radar.Neighbor{IP: ip, MAC: "00-1A-2B-3C-4D-5E", IfIndex: 12, Interface: "Ethernet", Type: "resolved"}, true, nil
	}
	// Off-link: attribute to the default gateway.
	return radar.Neighbor{IP: ip, MAC: demoARP[0].MAC, IfIndex: 12, Interface: "Ethernet", Type: "resolved", Gateway: "192.168.1.1"}, false, nil
}

// ---- inbound traffic ----

var benignClients = []struct {
	ip    string
	ports []uint16
}{
	{"192.168.1.20", []uint16{5432, 445}},
	{"192.168.1.35", []uint16{80, 443}},
	{"192.168.1.104", []uint16{3389}},
	{"10.8.0.1", []uint16{22, 1433}},
	{"2001:db8::51", []uint16{443}},
}

// sweepPorts returns a scanner-like port list (well-known services first).
func sweepPorts(n int) []uint16 {
	common := []uint16{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 8080, 8443}
	out := append([]uint16(nil), common...)
	for p := uint16(1000); len(out) < n; p += uint16(1 + rand.Intn(3)) {
		out = append(out, p)
	}
	return out[:n]
}

func runDemoTraffic(ctx context.Context, h *hub.Hub) {
	h.Radar().SetSensor(radar.SensorStatus{Name: radar.SensorTable, Active: true, Detail: "new inbound rows of GetExtendedTcpTable (demo)"})
	h.Radar().SetSensor(radar.SensorStatus{Name: radar.SensorRaw, Active: true, Detail: "raw SYN capture (SIO_RCVALL) — simulated", Adapters: []string{"192.168.1.42 (Ethernet)"}})
	t := time.NewTicker(700 * time.Millisecond)
	defer t.Stop()
	sweepers := []string{"192.168.1.66", "192.168.1.57", "203.0.113.45"}
	next := time.Now().Add(25 * time.Second)
	n := 0
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			var obs []radar.Observation
			for _, c := range benignClients {
				if rand.Float64() < 0.35 {
					obs = append(obs, radar.Observation{Time: now, RemoteIP: c.ip, RemotePort: uint16(49152 + rand.Intn(16000)),
						LocalIP: "192.168.1.42", LocalPort: c.ports[rand.Intn(len(c.ports))], Sensor: radar.SensorRaw})
				}
			}
			// A noisy-but-legitimate host touching a few ports (stays under the limit).
			if rand.Float64() < 0.25 {
				for _, p := range []uint16{80, 443, 8080, 8443, 9000, 9090} {
					if rand.Float64() < 0.5 {
						obs = append(obs, radar.Observation{Time: now, RemoteIP: "192.168.1.1", RemotePort: uint16(40000 + rand.Intn(9000)),
							LocalIP: "192.168.1.42", LocalPort: p, Sensor: radar.SensorRaw})
					}
				}
			}
			h.ObserveRadar(obs...)
			if now.After(next) {
				ip := sweepers[n%len(sweepers)]
				n++
				next = now.Add(time.Duration(80+rand.Intn(60)) * time.Second)
				go func(ip string) {
					for i, p := range sweepPorts(18 + rand.Intn(40)) {
						select {
						case <-ctx.Done():
							return
						case <-time.After(time.Duration(40+rand.Intn(80)) * time.Millisecond):
						}
						h.ObserveRadar(radar.Observation{Time: time.Now(), RemoteIP: ip, RemotePort: uint16(51000 + i),
							LocalIP: "192.168.1.42", LocalPort: p, Sensor: radar.SensorRaw})
					}
				}(ip)
			}
		}
	}
}
