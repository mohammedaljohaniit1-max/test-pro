//go:build windows

package netmon

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPIDAll = 5 // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPID    = 1 // UDP_TABLE_OWNER_PID
	errInsufficient     = 122
)

// fetch calls a GetExtended*Table function, growing the buffer until it fits.
// Tables can grow between the sizing call and the real call, so it retries.
func fetch(p *windows.LazyProc, family, class uint32) ([]byte, error) {
	size := uint32(16 << 10)
	for attempt := 0; attempt < 8; attempt++ {
		buf := make([]byte, size)
		r, _, _ := p.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0, // unsorted: we sort ourselves
			uintptr(family),
			uintptr(class),
			0,
		)
		switch r {
		case 0:
			return buf[:size], nil
		case errInsufficient:
			size += 4 << 10 // headroom for growth between calls
			continue
		default:
			return nil, fmt.Errorf("netmon: %s failed: %w", p.Name, windows.Errno(r))
		}
	}
	return nil, fmt.Errorf("netmon: %s: table kept growing", p.Name)
}

// NewSystemSource returns a Source reading the live Windows socket tables.
func NewSystemSource() Source {
	return func() ([]model.Connection, error) {
		var all []model.Connection
		type spec struct {
			p      *windows.LazyProc
			family uint32
			class  uint32
			parse  func([]byte) ([]model.Connection, error)
		}
		for _, s := range []spec{
			{procGetExtendedTcpTable, windows.AF_INET, tcpTableOwnerPIDAll, ParseTCP4},
			{procGetExtendedTcpTable, windows.AF_INET6, tcpTableOwnerPIDAll, ParseTCP6},
			{procGetExtendedUdpTable, windows.AF_INET, udpTableOwnerPID, ParseUDP4},
			{procGetExtendedUdpTable, windows.AF_INET6, udpTableOwnerPID, ParseUDP6},
		} {
			buf, err := fetch(s.p, s.family, s.class)
			if err != nil {
				return nil, err
			}
			conns, err := s.parse(buf)
			if err != nil {
				return nil, err
			}
			all = append(all, conns...)
		}
		return all, nil
	}
}
