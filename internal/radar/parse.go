package radar

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// ---------------------------------------------------------------------------
// ARP table (iphlpapi!GetIpNetTable → MIB_IPNETTABLE)
// ---------------------------------------------------------------------------

// MIB_IPNETROW layout (24 bytes):
//
//	DWORD dwIndex; DWORD dwPhysAddrLen; BYTE bPhysAddr[8]; DWORD dwAddr; DWORD dwType;
const ipNetRowSize = 24

// ParseIpNetTable decodes a MIB_IPNETTABLE buffer. ifName maps interface
// indexes to friendly names and may be nil. Invalid and incomplete rows
// (no hardware address) are skipped.
func ParseIpNetTable(buf []byte, ifName func(uint32) string) ([]Neighbor, error) {
	if len(buf) < 4 {
		return nil, errors.New("radar: ARP table buffer too small")
	}
	n := binary.LittleEndian.Uint32(buf[:4])
	if uint64(n)*ipNetRowSize+4 > uint64(len(buf)) {
		return nil, fmt.Errorf("radar: ARP table claims %d rows but buffer holds %d bytes", n, len(buf))
	}
	out := make([]Neighbor, 0, n)
	for i := uint32(0); i < n; i++ {
		r := buf[4+i*ipNetRowSize : 4+(i+1)*ipNetRowSize]
		idx := binary.LittleEndian.Uint32(r[0:4])
		alen := binary.LittleEndian.Uint32(r[4:8])
		typ := binary.LittleEndian.Uint32(r[20:24])
		if alen > 8 {
			alen = 8
		}
		if typ == 2 || alen == 0 || allZero(r[8:8+alen]) {
			continue // invalid / incomplete
		}
		ip := net.IPv4(r[16], r[17], r[18], r[19]).String()
		nb := Neighbor{IP: ip, MAC: FormatMAC(r[8 : 8+alen]), IfIndex: idx, Type: arpType(typ)}
		if ifName != nil {
			nb.Interface = ifName(idx)
		}
		out = append(out, nb)
	}
	return out, nil
}

func arpType(t uint32) string {
	switch t {
	case 3:
		return "dynamic"
	case 4:
		return "static"
	case 2:
		return "invalid"
	}
	return "other"
}

// FormatMAC renders a hardware address as AA-BB-CC-DD-EE-FF (Windows style).
func FormatMAC(b []byte) string {
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte('-')
		}
		fmt.Fprintf(&sb, "%02X", x)
	}
	return sb.String()
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Raw IPv4 / TCP packets (SIO_RCVALL delivers IP datagrams, no L2 header)
// ---------------------------------------------------------------------------

// TCP flag bits.
const (
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

// ErrNotSYN is returned by ParseInboundSYN for packets that are not an
// inbound TCP connection attempt.
var ErrNotSYN = errors.New("radar: not an inbound TCP SYN")

// ParseInboundSYN extracts a connection attempt from a raw IPv4 datagram:
// TCP with SYN set and ACK clear (i.e. the first packet of a handshake,
// not a SYN/ACK reply). local is the address the capturing socket is bound
// to; datagrams whose destination differs (our own outbound SYNs) are
// rejected so only inbound attempts are counted.
func ParseInboundSYN(pkt []byte, local net.IP) (src net.IP, srcPort uint16, dst net.IP, dstPort uint16, err error) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil, 0, nil, 0, ErrNotSYN
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+14 {
		return nil, 0, nil, 0, ErrNotSYN
	}
	if pkt[9] != 6 { // IPPROTO_TCP
		return nil, 0, nil, 0, ErrNotSYN
	}
	// Only the first fragment carries the TCP header.
	if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
		return nil, 0, nil, 0, ErrNotSYN
	}
	src = net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15]).To4()
	dst = net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19]).To4()
	if local != nil && !dst.Equal(local) {
		return nil, 0, nil, 0, ErrNotSYN
	}
	tcp := pkt[ihl:]
	flags := tcp[13]
	if flags&tcpSYN == 0 || flags&(tcpACK|tcpRST) != 0 {
		return nil, 0, nil, 0, ErrNotSYN
	}
	return src, binary.BigEndian.Uint16(tcp[0:2]), dst, binary.BigEndian.Uint16(tcp[2:4]), nil
}

// ---------------------------------------------------------------------------
// Socket-table sensor
// ---------------------------------------------------------------------------

// TableOptions tunes how the socket-table sensor classifies new rows.
type TableOptions struct {
	// ClientProcs are lower-case process image names that only make
	// outbound connections (browsers, updaters, sync clients). Their rows are
	// never treated as inbound attempts.
	ClientProcs map[string]bool
}

// DefaultClientProcs lists common multi-connection client applications.
// A browser with many tabs opens hundreds of short-lived outbound sockets
// per minute; none of them are inbound probes.
var DefaultClientProcs = []string{
	"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "opera_gx.exe", "vivaldi.exe", "iexplore.exe",
	"msedgewebview2.exe", "arc.exe", "chrome", "chromium", "chromium-browse", "firefox", "firefox-bin", "brave", "opera", "vivaldi-bin",
	"teams.exe", "ms-teams.exe", "slack.exe", "discord.exe", "zoom.exe", "spotify.exe", "onedrive.exe", "dropbox.exe",
	"googledrivefs.exe", "outlook.exe", "olk.exe", "thunderbird.exe", "whatsapp.exe", "telegram.exe", "signal.exe",
	"code.exe", "code", "slack", "discord", "spotify", "zoom", "teams", "thunderbird",
	"googleupdate.exe", "microsoftedgeupdate.exe", "msedgeupdate.exe", "updater.exe", "update.exe", "wuauclt.exe",
	"usoclient.exe", "mousocoreworker.exe", "backgroundtaskhost.exe", "searchapp.exe", "searchhost.exe",
	"steam.exe", "steamwebhelper.exe", "epicgameslauncher.exe", "officeclicktorun.exe",
	"apt", "apt-get", "packagekitd", "snapd", "unattended-upgr", "fwupd",
}

// NewTableOptions builds options from DefaultClientProcs plus extra names.
func NewTableOptions(extra ...string) TableOptions {
	o := TableOptions{ClientProcs: map[string]bool{}}
	for _, n := range append(append([]string(nil), DefaultClientProcs...), extra...) {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
			o.ClientProcs[n] = true
		}
	}
	return o
}

// ephemeralStart is the lowest port treated as ephemeral (client) port:
// Linux uses 32768-60999, Windows 49152-65535.
const ephemeralStart = 32768

// servicePorts are remote ports that identify the peer as a server.
var servicePorts = map[uint16]bool{
	1433: true, 1521: true, 3306: true, 3389: true, 3478: true, 5222: true, 5223: true, 5228: true, 5349: true,
	5432: true, 5938: true, 6379: true, 8008: true, 8080: true, 8443: true, 8883: true, 9000: true, 9443: true, 19302: true,
}

// LooksOutbound reports whether a socket is almost certainly a client
// connection: an ephemeral local port talking to a well-known service port.
func LooksOutbound(c model.Connection) bool {
	return c.RemotePort != 0 && c.LocalPort >= ephemeralStart && (c.RemotePort < 1024 || servicePorts[c.RemotePort])
}

// FromConnections turns newly observed sockets (netmon Diff.Added) into
// inbound observations. A TCP row is inbound only when it is SYN_RECEIVED,
// or when a listener exists for the same protocol and port whose bound
// address is the wildcard or the row's local address and which is owned by
// the same process (or the kernel, PID 0/4, e.g. http.sys). Rows owned by
// known client applications, and rows that look like outbound client
// connections, are never counted — this keeps multi-tab browsers and
// background updaters from producing false sweep alerts.
func FromConnections(added []model.Connection, listening map[string][]model.Listener, opt TableOptions) []Observation {
	var out []Observation
	for _, c := range added {
		if c.Proto != "TCP" && c.Proto != "TCP6" {
			continue
		}
		if c.State == "LISTEN" || c.RemoteAddr == "" || c.RemotePort == 0 {
			continue
		}
		if opt.ClientProcs[strings.ToLower(c.ProcessName)] {
			continue
		}
		if c.State != "SYN_RECEIVED" {
			if LooksOutbound(c) || !acceptedBy(c, listening[ListenKey(c.Proto, c.LocalPort)]) {
				continue
			}
		}
		out = append(out, Observation{
			Time: time.UnixMilli(c.FirstSeen), RemoteIP: c.RemoteAddr, RemotePort: c.RemotePort,
			LocalIP: c.LocalAddr, LocalPort: c.LocalPort, Sensor: SensorTable,
		})
	}
	return out
}

func acceptedBy(c model.Connection, ls []model.Listener) bool {
	for _, l := range ls {
		addrOK := l.Addr == "" || l.Addr == "0.0.0.0" || l.Addr == "::" || l.Addr == c.LocalAddr
		pidOK := l.PID == c.PID || l.PID == 0 || l.PID == 4 || c.PID == 0 || c.PID == 4
		if addrOK && pidOK {
			return true
		}
	}
	return false
}

// ListenKey identifies a listening port per address family.
func ListenKey(proto string, port uint16) string {
	return proto + ":" + fmt.Sprint(port)
}
