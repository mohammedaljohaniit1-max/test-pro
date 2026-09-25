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

// FromConnections turns newly observed sockets (netmon Diff.Added) into
// inbound observations. A TCP row is inbound when its local port is one
// the machine listens on (listening[port]) or when it is in SYN_RECEIVED.
// Outbound connections, UDP, LISTEN rows and loopback peers are ignored.
func FromConnections(added []model.Connection, listening map[string]bool) []Observation {
	var out []Observation
	for _, c := range added {
		if c.Proto != "TCP" && c.Proto != "TCP6" {
			continue
		}
		if c.State == "LISTEN" || c.RemoteAddr == "" || c.RemotePort == 0 {
			continue
		}
		if c.State != "SYN_RECEIVED" && !listening[ListenKey(c.Proto, c.LocalPort)] {
			continue
		}
		out = append(out, Observation{
			Time: time.UnixMilli(c.FirstSeen), RemoteIP: c.RemoteAddr, RemotePort: c.RemotePort,
			LocalIP: c.LocalAddr, LocalPort: c.LocalPort, Sensor: SensorTable,
		})
	}
	return out
}

// ListenKey identifies a listening port per address family.
func ListenKey(proto string, port uint16) string {
	return proto + ":" + fmt.Sprint(port)
}
