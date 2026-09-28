//go:build linux

package ifstats

import (
	"encoding/hex"
	"os"
	"strconv"
	"strings"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// SystemReader reads /proc/net/dev plus /sys/class/net metadata. It exists
// for the Linux preview binary; syspulse.exe uses GetIfTable2.
type SystemReader struct{ Root string }

// NewSystemReader returns the Linux interface reader.
func NewSystemReader() Reader { return SystemReader{} }

func (r SystemReader) path(p string) string { return r.Root + p }

func (r SystemReader) sys(name, f string) string {
	b, err := os.ReadFile(r.path("/sys/class/net/" + name + "/" + f))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Read implements Reader.
func (r SystemReader) Read() ([]Counter, error) {
	b, err := os.ReadFile(r.path("/proc/net/dev"))
	if err != nil {
		return nil, err
	}
	cs := ParseProcNetDev(string(b))
	for i := range cs {
		c := &cs[i]
		n := c.Name
		if v, err := strconv.ParseUint(r.sys(n, "ifindex"), 10, 32); err == nil {
			c.Index = uint32(v)
		}
		st := r.sys(n, "operstate")
		c.Up = st == "up" || st == "unknown" && (c.InOctets > 0 || c.OutOctets > 0)
		if mbps, err := strconv.ParseInt(r.sys(n, "speed"), 10, 64); err == nil && mbps > 0 {
			c.SpeedBps = uint64(mbps) * 1_000_000
		}
		if v, err := strconv.ParseUint(r.sys(n, "mtu"), 10, 32); err == nil {
			c.MTU = uint32(v)
		}
		if mac := strings.ReplaceAll(r.sys(n, "address"), ":", ""); len(mac) == 12 {
			if raw, err := hex.DecodeString(mac); err == nil {
				c.MAC = FormatMAC(raw)
			}
		}
		_, errDev := os.Stat(r.path("/sys/class/net/" + n + "/device"))
		c.Physical = errDev == nil
		switch {
		case n == "lo":
			c.Kind = model.IfLoopback
		case dirExists(r.path("/sys/class/net/" + n + "/wireless")):
			c.Kind = model.IfWiFi
		case strings.HasPrefix(n, "tun") || strings.HasPrefix(n, "wg") || strings.HasPrefix(n, "tap"):
			c.Kind = model.IfTunnel
		case c.Physical:
			c.Kind = model.IfEthernet
		default:
			c.Kind = model.IfVirtual
		}
		c.Desc = c.Kind
		if drv := r.sys(n, "device/uevent"); drv != "" {
			for _, l := range strings.Split(drv, "\n") {
				if v, ok := strings.CutPrefix(l, "DRIVER="); ok {
					c.Desc = v
				}
			}
		}
	}
	return cs, nil
}

func dirExists(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

// ParseProcNetDev parses /proc/net/dev. Index is a 1-based line ordinal until
// the caller fills in the kernel ifindex.
func ParseProcNetDev(s string) []Counter {
	var out []Counter
	for _, line := range strings.Split(s, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if name == "" || len(f) < 16 {
			continue
		}
		u := func(i int) uint64 { v, _ := strconv.ParseUint(f[i], 10, 64); return v }
		out = append(out, Counter{Index: uint32(len(out) + 1), Name: name,
			InOctets: u(0), InPkts: u(1), OutOctets: u(8), OutPkts: u(9),
			Errors: u(2) + u(10), Discards: u(3) + u(11)})
	}
	return out
}
