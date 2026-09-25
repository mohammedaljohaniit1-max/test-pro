// Package netmon enumerates TCP/UDP sockets with their owning PIDs and
// tracks connection churn between snapshots.
//
// On Windows the raw tables come from iphlpapi!GetExtendedTcpTable and
// GetExtendedUdpTable (TCP_TABLE_OWNER_PID_ALL / UDP_TABLE_OWNER_PID) for both
// AF_INET and AF_INET6. The binary layouts are decoded here, platform-
// independently, so they can be unit tested anywhere.
package netmon

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// MIB_TCP_STATE values.
var tcpStates = map[uint32]string{
	1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RECEIVED", 5: "ESTABLISHED",
	6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK",
	11: "TIME_WAIT", 12: "DELETE_TCB",
}

// TCPState returns the name of a MIB_TCP_STATE value.
func TCPState(s uint32) string {
	if n, ok := tcpStates[s]; ok {
		return n
	}
	return "UNKNOWN"
}

// Row sizes (bytes) of the owner-PID table rows.
const (
	tcp4Row = 24 // MIB_TCPROW_OWNER_PID
	tcp6Row = 56 // MIB_TCP6ROW_OWNER_PID
	udp4Row = 12 // MIB_UDPROW_OWNER_PID
	udp6Row = 28 // MIB_UDP6ROW_OWNER_PID
)

var errShort = errors.New("netmon: table buffer truncated")

// Ports are stored in network byte order in the low 16 bits of a DWORD.
func port(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

func ip4(b []byte) string { return netip.AddrFrom4([4]byte(b[:4])).String() }

func ip6(b []byte) string { return netip.AddrFrom16([16]byte(b[:16])).String() }

func header(buf []byte, row int) (int, error) {
	if len(buf) < 4 {
		return 0, errShort
	}
	n := int(binary.LittleEndian.Uint32(buf))
	if 4+n*row > len(buf) {
		return 0, errShort
	}
	return n, nil
}

// ParseTCP4 decodes MIB_TCPTABLE_OWNER_PID.
//
//	DWORD dwNumEntries; { dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort, dwOwningPid }[]
func ParseTCP4(buf []byte) ([]model.Connection, error) {
	n, err := header(buf, tcp4Row)
	if err != nil {
		return nil, err
	}
	out := make([]model.Connection, 0, n)
	for i := 0; i < n; i++ {
		r := buf[4+i*tcp4Row:]
		st := binary.LittleEndian.Uint32(r[0:])
		c := model.Connection{
			Proto: "TCP", State: TCPState(st),
			LocalAddr: ip4(r[4:]), LocalPort: port(r[8:]),
			PID: binary.LittleEndian.Uint32(r[20:]),
		}
		if st != 2 { // LISTEN sockets have no meaningful remote endpoint
			c.RemoteAddr, c.RemotePort = ip4(r[12:]), port(r[16:])
		}
		out = append(out, c)
	}
	return out, nil
}

// ParseTCP6 decodes MIB_TCP6TABLE_OWNER_PID.
//
//	{ ucLocalAddr[16], dwLocalScopeId, dwLocalPort, ucRemoteAddr[16], dwRemoteScopeId, dwRemotePort, dwState, dwOwningPid }
func ParseTCP6(buf []byte) ([]model.Connection, error) {
	n, err := header(buf, tcp6Row)
	if err != nil {
		return nil, err
	}
	out := make([]model.Connection, 0, n)
	for i := 0; i < n; i++ {
		r := buf[4+i*tcp6Row:]
		st := binary.LittleEndian.Uint32(r[48:])
		c := model.Connection{
			Proto: "TCP6", State: TCPState(st),
			LocalAddr: ip6(r[0:]), LocalPort: port(r[20:]),
			PID: binary.LittleEndian.Uint32(r[52:]),
		}
		if st != 2 {
			c.RemoteAddr, c.RemotePort = ip6(r[24:]), port(r[44:])
		}
		out = append(out, c)
	}
	return out, nil
}

// ParseUDP4 decodes MIB_UDPTABLE_OWNER_PID: { dwLocalAddr, dwLocalPort, dwOwningPid }.
func ParseUDP4(buf []byte) ([]model.Connection, error) {
	n, err := header(buf, udp4Row)
	if err != nil {
		return nil, err
	}
	out := make([]model.Connection, 0, n)
	for i := 0; i < n; i++ {
		r := buf[4+i*udp4Row:]
		out = append(out, model.Connection{
			Proto: "UDP", State: "-",
			LocalAddr: ip4(r[0:]), LocalPort: port(r[4:]),
			PID: binary.LittleEndian.Uint32(r[8:]),
		})
	}
	return out, nil
}

// ParseUDP6 decodes MIB_UDP6TABLE_OWNER_PID: { ucLocalAddr[16], dwLocalScopeId, dwLocalPort, dwOwningPid }.
func ParseUDP6(buf []byte) ([]model.Connection, error) {
	n, err := header(buf, udp6Row)
	if err != nil {
		return nil, err
	}
	out := make([]model.Connection, 0, n)
	for i := 0; i < n; i++ {
		r := buf[4+i*udp6Row:]
		out = append(out, model.Connection{
			Proto: "UDP6", State: "-",
			LocalAddr: ip6(r[0:]), LocalPort: port(r[20:]),
			PID: binary.LittleEndian.Uint32(r[24:]),
		})
	}
	return out, nil
}
