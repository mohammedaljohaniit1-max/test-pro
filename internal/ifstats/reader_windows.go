//go:build windows

package ifstats

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

var (
	iphlpapi         = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIfTable2  = iphlpapi.NewProc("GetIfTable2")
	procFreeMibTable = iphlpapi.NewProc("FreeMibTable")
)

// InterfaceAndOperStatusFlags bits (MIB_IF_ROW2).
const (
	flagHardware  = 1 << 0
	flagFilter    = 1 << 1
	flagConnector = 1 << 2
)

const ifOperStatusUp = 1

// SystemReader reads MIB_IF_ROW2 counters with GetIfTable2. It keeps real
// adapters (physical NICs, Hyper-V / WSL vEthernet, VPN and TAP adapters,
// loopback) and drops NDIS filter-driver shadows ("WFP Native MAC Layer
// LightWeight Filter", "QoS Packet Scheduler"…) and never-connected
// pseudo-interfaces such as the WAN Miniports, which would otherwise duplicate
// every byte several times.
type SystemReader struct{}

// NewSystemReader returns the Windows interface reader.
func NewSystemReader() Reader { return SystemReader{} }

// Read implements Reader.
func (SystemReader) Read() ([]Counter, error) {
	if unsafe.Sizeof(windows.MibIfRow2{}) != 1352 {
		return nil, fmt.Errorf("unexpected MIB_IF_ROW2 size %d", unsafe.Sizeof(windows.MibIfRow2{}))
	}
	var table unsafe.Pointer
	if r, _, _ := procGetIfTable2.Call(uintptr(unsafe.Pointer(&table))); r != 0 {
		return nil, fmt.Errorf("GetIfTable2: error %d", r)
	}
	if table == nil {
		return nil, fmt.Errorf("GetIfTable2 returned no table")
	}
	defer procFreeMibTable.Call(uintptr(table))
	n := *(*uint32)(table)
	// MIB_IF_TABLE2 { ULONG NumEntries; MIB_IF_ROW2 Table[]; } — rows are
	// 8-byte aligned because MIB_IF_ROW2 starts with a ULONG64.
	rows := unsafe.Slice((*windows.MibIfRow2)(unsafe.Add(table, 8)), n)
	out := make([]Counter, 0, 16)
	for i := range rows {
		r := &rows[i]
		fl := r.InterfaceAndOperStatusFlags
		if fl&flagFilter != 0 {
			continue
		}
		up := r.OperStatus == ifOperStatusUp
		kind := KindFromIfType(r.Type)
		name := windows.UTF16ToString(r.Alias[:])
		desc := windows.UTF16ToString(r.Description[:])
		physical := fl&flagHardware != 0
		if !up && !(physical && fl&flagConnector != 0) {
			continue // down pseudo adapters (Teredo, 6to4, WAN Miniport, Kernel Debug…)
		}
		if name == "" || strings.HasPrefix(desc, "WAN Miniport") || strings.Contains(desc, "Kernel Debug") {
			continue // RAS/VPN miniport shims report "up" but never carry their own traffic
		}
		if r.TunnelType != 0 && kind != model.IfLoopback {
			kind = model.IfTunnel
		}
		if !physical && kind == model.IfEthernet {
			kind = model.IfVirtual // vEthernet (Hyper-V / WSL), TAP, VPN clients
		}
		plen := r.PhysicalAddressLength
		if plen > uint32(len(r.PhysicalAddress)) {
			plen = uint32(len(r.PhysicalAddress))
		}
		speed := r.ReceiveLinkSpeed
		if r.TransmitLinkSpeed > speed {
			speed = r.TransmitLinkSpeed
		}
		if speed == ^uint64(0) {
			speed = 0
		}
		out = append(out, Counter{
			Index: r.InterfaceIndex, Name: name, Desc: desc, Kind: kind, Physical: physical, Up: up,
			MAC: FormatMAC(r.PhysicalAddress[:plen]), SpeedBps: speed, MTU: r.Mtu,
			InOctets: r.InOctets, OutOctets: r.OutOctets,
			InPkts: r.InUcastPkts + r.InNUcastPkts, OutPkts: r.OutUcastPkts + r.OutNUcastPkts,
			Errors: r.InErrors + r.OutErrors, Discards: r.InDiscards + r.OutDiscards,
		})
	}
	return out, nil
}
