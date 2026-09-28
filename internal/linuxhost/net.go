//go:build linux

package linuxhost

import (
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/radar"
)

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECEIVED", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
	"06": "TIME_WAIT", "07": "CLOSED", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

// ParseProcNetAddr decodes "0100007F:1F90" (IPv4) or the 32-hex-digit IPv6
// form used by /proc/net/{tcp,udp}{,6}. The kernel prints each 32-bit word
// in host (little-endian) byte order.
func ParseProcNetAddr(s string) (string, uint16, error) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, errors.New("bad address")
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return "", 0, err
	}
	raw, err := hex.DecodeString(a)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, errors.New("bad address")
	}
	ip := make(net.IP, len(raw))
	for w := 0; w < len(raw); w += 4 {
		ip[w], ip[w+1], ip[w+2], ip[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	if v4 := ip.To4(); v4 != nil && len(raw) == 16 {
		return v4.String(), uint16(port), nil // IPv4-mapped
	}
	return ip.String(), uint16(port), nil
}

// inodePIDs maps socket inodes to owning PIDs by scanning /proc/*/fd.
func inodePIDs() map[string]uint32 {
	m := map[string]uint32{}
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		dir := "/proc/" + e.Name() + "/fd/"
		fds, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			l, err := os.Readlink(dir + fd.Name())
			if err == nil && strings.HasPrefix(l, "socket:[") {
				m[l[8:len(l)-1]] = uint32(pid)
			}
		}
	}
	return m
}

// Sockets implements netmon.Source from /proc/net.
func Sockets() ([]model.Connection, error) {
	inodes := inodePIDs()
	var out []model.Connection
	var firstErr error
	for _, t := range []struct{ file, proto string }{{"tcp", "TCP"}, {"tcp6", "TCP6"}, {"udp", "UDP"}, {"udp6", "UDP6"}} {
		b, err := os.ReadFile("/proc/net/" + t.file)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		lines := strings.Split(string(b), "\n")
		for _, l := range lines[1:] {
			f := strings.Fields(l)
			if len(f) < 10 {
				continue
			}
			la, lp, err1 := ParseProcNetAddr(f[1])
			ra, rp, err2 := ParseProcNetAddr(f[2])
			if err1 != nil || err2 != nil {
				continue
			}
			c := model.Connection{Proto: t.proto, LocalAddr: la, LocalPort: lp, PID: inodes[f[9]]}
			if strings.HasPrefix(t.proto, "UDP") {
				c.State = "-"
				if rp != 0 {
					c.RemoteAddr, c.RemotePort = ra, rp
				}
			} else {
				c.State = tcpStates[f[3]]
				if c.State == "" {
					c.State = "UNKNOWN"
				}
				if c.State != "LISTEN" {
					c.RemoteAddr, c.RemotePort = ra, rp
				}
			}
			out = append(out, c)
		}
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// Neighbors implements radar.Platform (and radar.LocalLister) from
// /proc/net/arp and the kernel routing table.
type Neighbors struct{}

// Neighbors parses /proc/net/arp.
func (Neighbors) Neighbors() ([]radar.Neighbor, error) {
	b, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	var out []radar.Neighbor
	for _, l := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(l)
		if len(f) < 6 || f[3] == "00:00:00:00:00:00" {
			continue
		}
		flags, _ := strconv.ParseUint(strings.TrimPrefix(f[2], "0x"), 16, 32)
		if flags&0x2 == 0 { // ATF_COM: incomplete entry
			continue
		}
		typ := "dynamic"
		if flags&0x4 != 0 {
			typ = "static"
		}
		idx := uint32(0)
		if ifc, err := net.InterfaceByName(f[5]); err == nil {
			idx = uint32(ifc.Index)
		}
		out = append(out, radar.Neighbor{IP: f[0], MAC: strings.ToUpper(strings.ReplaceAll(f[3], ":", "-")), IfIndex: idx, Interface: f[5], Type: typ})
	}
	return out, nil
}

// Resolve looks ip up in the ARP cache; off-link hosts are attributed to
// the default gateway.
func (n Neighbors) Resolve(ip string) (radar.Neighbor, bool, error) {
	ns, _ := n.Neighbors()
	for _, x := range ns {
		if x.IP == ip {
			return x, true, nil
		}
	}
	if gw := Gateways(); len(gw) > 0 {
		for _, x := range ns {
			if x.IP == gw[0] {
				x.Gateway, x.IP, x.Type = gw[0], ip, "resolved"
				return x, false, nil
			}
		}
	}
	time.Sleep(10 * time.Millisecond)
	return radar.Neighbor{IP: ip}, false, errors.New("not in the ARP cache")
}

// LocalIPv4 lists this host's IPv4 addresses.
func (Neighbors) LocalIPv4() []radar.LocalAddr {
	var out []radar.LocalAddr
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
				out = append(out, radar.LocalAddr{IP: ipn.IP.String(), IfIndex: uint32(ifc.Index), Interface: ifc.Name})
			}
		}
	}
	return out
}

// Gateways returns default-route next hops from /proc/net/route.
func Gateways() []string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(l)
		if len(f) > 2 && f[1] == "00000000" && f[2] != "00000000" {
			if ip, _, err := ParseProcNetAddr(f[2] + ":0"); err == nil {
				out = append(out, ip)
			}
		}
	}
	return out
}
