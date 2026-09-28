// Package oui maps hardware (MAC) addresses to their manufacturer using an
// embedded copy of the IEEE Registration Authority database.
//
// All three public registries are included — MA-L (24-bit OUI), MA-M
// (28-bit) and MA-S (36-bit) — and lookups use longest-prefix match, so a
// MAC from a small MA-S block resolves to the block owner rather than to
// the "IEEE Registration Authority" umbrella entry.
//
// The table is regenerated with gen_oui.go from the official CSV exports and
// is decompressed lazily on first use (~55k prefixes, a few MB of heap).
package oui

//go:generate go run gen_oui.go oui.csv mam.csv oui36.csv

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strconv"
	"strings"
	"sync"
)

//go:embed oui.tsv.gz
var dbGz []byte

// Vendor is the result of a lookup.
type Vendor struct {
	Name     string `json:"name"`               // organisation name as registered
	Short    string `json:"short,omitempty"`    // brand (e.g. "Apple", "Samsung")
	Prefix   string `json:"prefix,omitempty"`   // matched prefix, e.g. "F0-2F-74" or "70-B3-D5-1"
	Registry string `json:"registry,omitempty"` // MA-L, MA-M, MA-S
	Class    string `json:"class,omitempty"`    // device-class hint: pc, mobile, network, printer, iot, tv, console, vm, sbc
	Random   bool   `json:"random,omitempty"`   // locally administered (randomised / private) address
}

var (
	once sync.Once
	l24  map[uint32]string // top 24 bits
	l28  map[uint32]string // top 28 bits
	l36  map[uint64]string // top 36 bits
	size int
)

func load() {
	l24, l28, l36 = map[uint32]string{}, map[uint32]string{}, map[uint64]string{}
	zr, err := gzip.NewReader(bytes.NewReader(dbGz))
	if err != nil {
		return
	}
	defer zr.Close()
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		tab := strings.IndexByte(line, '\t')
		if tab <= 0 {
			continue
		}
		p, name := line[:tab], line[tab+1:]
		v, err := strconv.ParseUint(p, 16, 64)
		if err != nil {
			continue
		}
		switch len(p) {
		case 6:
			l24[uint32(v)] = name
		case 7:
			l28[uint32(v)] = name
		case 9:
			l36[v] = name
		default:
			continue
		}
		size++
	}
}

// Size returns the number of prefixes in the embedded database.
func Size() int {
	once.Do(load)
	return size
}

// ParseMAC accepts AA-BB-CC-DD-EE-FF, aa:bb:cc:dd:ee:ff, aabb.ccdd.eeff and
// bare hex, and returns the first six octets.
func ParseMAC(s string) ([6]byte, bool) {
	var out [6]byte
	hex := make([]byte, 0, 12)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			hex = append(hex, c)
		case c == '-' || c == ':' || c == '.' || c == ' ':
		default:
			return out, false
		}
	}
	if len(hex) < 12 {
		return out, false
	}
	for i := 0; i < 6; i++ {
		b, err := strconv.ParseUint(string(hex[2*i:2*i+2]), 16, 8)
		if err != nil {
			return out, false
		}
		out[i] = byte(b)
	}
	return out, true
}

// Lookup resolves the manufacturer of mac. ok is false when the address is
// malformed or not registered. Locally administered addresses (phones and
// laptops with "private Wi-Fi address" enabled, containers, VPN adapters)
// return ok=true with Random set and no Name, except for well-known
// hypervisor ranges.
func Lookup(mac string) (Vendor, bool) {
	b, ok := ParseMAC(mac)
	if !ok {
		return Vendor{}, false
	}
	once.Do(load)
	if b == [6]byte{} || b == [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} {
		return Vendor{}, false
	}
	u := uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 | uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
	if b[0]&0x02 != 0 {
		// Locally administered. A few hypervisors use fixed LAA ranges.
		switch {
		case b[0] == 0x52 && b[1] == 0x54 && b[2] == 0x00:
			return Vendor{Name: "QEMU / KVM virtual NIC", Short: "QEMU/KVM", Prefix: "52-54-00", Class: "vm", Random: true}, true
		case b[0] == 0x02 && b[1] == 0x42:
			return Vendor{Name: "Docker container interface", Short: "Docker", Prefix: "02-42", Class: "vm", Random: true}, true
		case b[0] == 0x02 && b[1] == 0x50 && b[2] == 0xF2:
			return Vendor{Name: "Microsoft virtual adapter (WireGuard / Wintun)", Short: "Virtual adapter", Prefix: "02-50-F2", Class: "vm", Random: true}, true
		}
		return Vendor{Random: true, Class: "mobile"}, true
	}
	if n, ok := l36[u>>12]; ok {
		return decorate(Vendor{Name: n, Prefix: fmtPrefix(u>>12, 9), Registry: "MA-S"}), true
	}
	if n, ok := l28[uint32(u>>20)]; ok {
		return decorate(Vendor{Name: n, Prefix: fmtPrefix(u>>20, 7), Registry: "MA-M"}), true
	}
	if n, ok := l24[uint32(u>>24)]; ok {
		return decorate(Vendor{Name: n, Prefix: fmtPrefix(u>>24, 6), Registry: "MA-L"}), true
	}
	return Vendor{}, false
}

// fmtPrefix renders n hex nibbles as AA-BB-CC[-D…].
func fmtPrefix(v uint64, nibbles int) string {
	h := strings.ToUpper(strconv.FormatUint(v, 16))
	for len(h) < nibbles {
		h = "0" + h
	}
	var sb strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte('-')
		}
		end := i + 2
		if end > len(h) {
			end = len(h)
		}
		sb.WriteString(h[i:end])
	}
	return sb.String()
}

// brand rules: first matching lower-case substring wins. Order matters
// (more specific entries first).
var brands = []struct{ key, short, class string }{
	{"raspberry pi", "Raspberry Pi", "sbc"},
	{"espressif", "Espressif (ESP32/ESP8266)", "iot"},
	{"apple", "Apple", "mobile"},
	{"samsung", "Samsung", "mobile"},
	{"xiaomi", "Xiaomi", "mobile"},
	{"huawei", "Huawei", "mobile"},
	{"honor device", "Honor", "mobile"},
	{"oneplus", "OnePlus", "mobile"},
	{"oppo", "OPPO", "mobile"},
	{"vivo mobile", "vivo", "mobile"},
	{"motorola mobility", "Motorola", "mobile"},
	{"guangdong oppo", "OPPO", "mobile"},
	{"realme", "realme", "mobile"},
	{"nothing technology", "Nothing", "mobile"},
	{"google", "Google", "iot"},
	{"amazon", "Amazon", "iot"},
	{"sonos", "Sonos", "iot"},
	{"philips lighting", "Philips Hue", "iot"},
	{"signify", "Philips Hue", "iot"},
	{"tuya", "Tuya", "iot"},
	{"shelly", "Shelly", "iot"},
	{"ring llc", "Ring", "iot"},
	{"ecobee", "ecobee", "iot"},
	{"nest labs", "Google Nest", "iot"},
	{"hikvision", "Hikvision", "iot"},
	{"dahua", "Dahua", "iot"},
	{"microsoft", "Microsoft", "pc"},
	{"dell", "Dell", "pc"},
	{"lenovo", "Lenovo", "pc"},
	{"hewlett packard enterprise", "HPE", "network"},
	{"hp inc", "HP", "pc"},
	{"hewlett packard", "HP", "pc"},
	{"intel corporate", "Intel", "pc"},
	{"intel", "Intel", "pc"},
	{"realtek", "Realtek", "pc"},
	{"asustek", "ASUS", "pc"},
	{"giga-byte", "GIGABYTE", "pc"},
	{"micro-star", "MSI", "pc"},
	{"acer", "Acer", "pc"},
	{"liteon", "Lite-On", "pc"},
	{"azurewave", "AzureWave", "pc"},
	{"murata", "Murata", "pc"},
	{"qualcomm", "Qualcomm", "pc"},
	{"mediatek", "MediaTek", "pc"},
	{"broadcom", "Broadcom", "pc"},
	{"nvidia", "NVIDIA", "pc"},
	{"advanced micro devices", "AMD", "pc"},
	{"vmware", "VMware", "vm"},
	{"parallels", "Parallels", "vm"},
	{"xensource", "Xen", "vm"},
	{"oracle", "Oracle (VirtualBox)", "vm"},
	{"pcs systemtechnik", "VirtualBox", "vm"},
	{"cisco", "Cisco", "network"},
	{"tp-link", "TP-Link", "network"},
	{"netgear", "NETGEAR", "network"},
	{"ubiquiti", "Ubiquiti", "network"},
	{"aruba", "Aruba", "network"},
	{"juniper", "Juniper", "network"},
	{"mikrotik", "MikroTik", "network"},
	{"routerboard", "MikroTik", "network"},
	{"d-link", "D-Link", "network"},
	{"zyxel", "Zyxel", "network"},
	{"linksys", "Linksys", "network"},
	{"belkin", "Belkin", "network"},
	{"arris", "ARRIS", "network"},
	{"technicolor", "Technicolor", "network"},
	{"sagemcom", "Sagemcom", "network"},
	{"avm audiovisuelles", "AVM FRITZ!Box", "network"},
	{"fortinet", "Fortinet", "network"},
	{"palo alto", "Palo Alto Networks", "network"},
	{"sophos", "Sophos", "network"},
	{"synology", "Synology", "network"},
	{"qnap", "QNAP", "network"},
	{"eero", "eero", "network"},
	{"tenda", "Tenda", "network"},
	{"canon", "Canon", "printer"},
	{"seiko epson", "Epson", "printer"},
	{"brother industries", "Brother", "printer"},
	{"xerox", "Xerox", "printer"},
	{"lexmark", "Lexmark", "printer"},
	{"kyocera", "Kyocera", "printer"},
	{"ricoh", "Ricoh", "printer"},
	{"lg electronics", "LG", "tv"},
	{"sony interactive", "PlayStation", "console"},
	{"sony", "Sony", "tv"},
	{"nintendo", "Nintendo", "console"},
	{"roku", "Roku", "tv"},
	{"hisense", "Hisense", "tv"},
	{"tcl", "TCL", "tv"},
	{"vizio", "VIZIO", "tv"},
	{"panasonic", "Panasonic", "tv"},
	{"sharp", "Sharp", "tv"},
}

func decorate(v Vendor) Vendor {
	low := strings.ToLower(v.Name)
	for _, b := range brands {
		if strings.Contains(low, b.key) {
			v.Short, v.Class = b.short, b.class
			// Microsoft + game console range.
			if b.short == "Microsoft" && strings.Contains(low, "xbox") {
				v.Class = "console"
			}
			return v
		}
	}
	v.Short = shortName(v.Name)
	return v
}

// shortName strips legal suffixes: "Foo Technology Co.,Ltd." → "Foo Technology".
func shortName(n string) string {
	s := n
	for _, cut := range []string{",", " Co.", " Co ", " Inc", " Ltd", " LLC", " GmbH", " Corporation", " Corp", " S.A.", " AG", " B.V.", " Limited", " Pty", " SRL"} {
		if i := strings.Index(s, cut); i > 2 {
			s = s[:i]
		}
	}
	return strings.TrimSpace(s)
}
