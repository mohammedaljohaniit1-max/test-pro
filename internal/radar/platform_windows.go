//go:build windows

package radar

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi         = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpNet     = iphlpapi.NewProc("GetIpNetTable")
	procSendARP      = iphlpapi.NewProc("SendARP")
	procGetBestRoute = iphlpapi.NewProc("GetBestRoute")
)

const (
	errInsufficientBuffer = 122
	errNoData             = 232
	wsaeTimedOut          = 10060
	sioRcvAll             = 0x98000001 // _WSAIOW(IOC_VENDOR, 1)
	rcvAllOn              = 1
	rcvAllIPLevel         = 3 // RCVALL_IPLEVEL (Windows 8+): this host's traffic only, NIC not promiscuous
)

var wsaOnce sync.Once

func wsaInit() {
	wsaOnce.Do(func() {
		var d windows.WSAData
		_ = windows.WSAStartup(0x0202, &d)
	})
}

// SystemPlatform reads the Windows ARP and routing tables.
type SystemPlatform struct {
	mu     sync.Mutex
	names  map[uint32]string
	addrs  []adapterAddr
	loaded time.Time
}

type adapterAddr struct {
	ip      net.IP
	ifIndex uint32
	name    string
}

// NewSystemPlatform returns the Windows implementation of Platform.
func NewSystemPlatform() *SystemPlatform { return &SystemPlatform{names: map[uint32]string{}} }

// refresh reloads adapter names and IPv4 unicast addresses (cached 30 s).
func (p *SystemPlatform) refresh(force bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !force && time.Since(p.loaded) < 30*time.Second && len(p.names) > 0 {
		return
	}
	size := uint32(16 << 10)
	var buf []byte
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		buf = make([]byte, size)
		err = windows.GetAdaptersAddresses(windows.AF_INET,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil || err != windows.ERROR_BUFFER_OVERFLOW {
			break
		}
	}
	if err != nil {
		return
	}
	names := map[uint32]string{}
	var addrs []adapterAddr
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		name := windows.UTF16PtrToString(a.FriendlyName)
		if name == "" {
			name = windows.UTF16PtrToString(a.Description)
		}
		names[a.IfIndex] = name
		for u := a.FirstUnicastAddress; u != nil; u = u.Next {
			if ip := u.Address.IP(); ip != nil && ip.To4() != nil {
				addrs = append(addrs, adapterAddr{ip: ip.To4(), ifIndex: a.IfIndex, name: name})
			}
		}
	}
	p.names, p.addrs, p.loaded = names, addrs, time.Now()
}

func (p *SystemPlatform) ifName(idx uint32) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n, ok := p.names[idx]; ok {
		return n
	}
	return fmt.Sprintf("interface #%d", idx)
}

// LocalIPv4 returns the machine's IPv4 unicast addresses (excluding loopback).
func (p *SystemPlatform) LocalIPv4() []LocalAddr {
	p.refresh(false)
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []LocalAddr
	for _, a := range p.addrs {
		if !a.ip.IsLoopback() && !a.ip.IsLinkLocalUnicast() {
			out = append(out, LocalAddr{IP: a.ip.String(), IfIndex: a.ifIndex, Interface: a.name})
		}
	}
	return out
}

// Gateways returns the default-gateway addresses of every IPv4 adapter
// (the next hop GetBestRoute picks for 0.0.0.0 / a public address).
func (p *SystemPlatform) Gateways() []string {
	var row [14]uint32
	dst := net.IPv4(8, 8, 8, 8).To4()
	if r, _, _ := procGetBestRoute.Call(uintptr(ipv4ToDword(dst)), 0, uintptr(unsafe.Pointer(&row[0]))); r != 0 {
		return nil
	}
	var nh [4]byte
	binary.LittleEndian.PutUint32(nh[:], row[3])
	gw := net.IPv4(nh[0], nh[1], nh[2], nh[3]).To4()
	if gw.Equal(net.IPv4zero) {
		return nil
	}
	return []string{gw.String()}
}

// Neighbors reads the IPv4 ARP cache with GetIpNetTable.
func (p *SystemPlatform) Neighbors() ([]Neighbor, error) {
	p.refresh(false)
	size := uint32(8 << 10)
	for attempt := 0; attempt < 6; attempt++ {
		buf := make([]byte, size)
		r, _, _ := procGetIpNet.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1)
		switch r {
		case 0:
			return ParseIpNetTable(buf[:size], p.ifName)
		case errNoData:
			return nil, nil
		case errInsufficientBuffer:
			size += 2 << 10
			continue
		default:
			return nil, fmt.Errorf("GetIpNetTable: %w", windows.Errno(r))
		}
	}
	return nil, errors.New("GetIpNetTable: table kept growing")
}

// ipv4ToDword converts an IPv4 address to the in-memory IPAddr DWORD
// (network byte order stored as-is).
func ipv4ToDword(ip net.IP) uint32 { return binary.LittleEndian.Uint32(ip.To4()) }

// Resolve attributes ip to a MAC address and interface. It consults the
// ARP cache first; otherwise it asks the routing table which interface and
// next hop reach ip. On-link hosts are resolved with SendARP; off-link
// hosts are attributed to the gateway's MAC (the remote host's own MAC is
// not visible across a router).
func (p *SystemPlatform) Resolve(ip string) (Neighbor, bool, error) {
	dst := net.ParseIP(ip).To4()
	if dst == nil {
		return Neighbor{IP: ip}, false, errors.New("MAC attribution is available for IPv4 only (IPv6 uses NDP)")
	}
	ns, _ := p.Neighbors()
	find := func(addr string) (Neighbor, bool) {
		for _, n := range ns {
			if n.IP == addr {
				return n, true
			}
		}
		return Neighbor{}, false
	}
	if n, ok := find(ip); ok {
		return n, true, nil
	}
	var row [14]uint32 // MIB_IPFORWARDROW
	if r, _, _ := procGetBestRoute.Call(uintptr(ipv4ToDword(dst)), 0, uintptr(unsafe.Pointer(&row[0]))); r != 0 {
		return Neighbor{IP: ip}, false, fmt.Errorf("GetBestRoute: %w", windows.Errno(r))
	}
	ifIndex := row[4]
	var nh [4]byte
	binary.LittleEndian.PutUint32(nh[:], row[3])
	nextHop := net.IPv4(nh[0], nh[1], nh[2], nh[3]).To4()
	n := Neighbor{IP: ip, IfIndex: ifIndex, Interface: p.ifName(ifIndex), Type: "resolved"}
	offLink := !nextHop.Equal(net.IPv4zero) && !nextHop.Equal(dst) && !p.isLocal(nextHop)
	target := dst
	if offLink {
		n.Gateway = nextHop.String()
		if g, ok := find(n.Gateway); ok {
			n.MAC = g.MAC
			return n, false, nil
		}
		target = nextHop
	}
	mac, err := sendARP(target)
	if err != nil {
		return n, false, err
	}
	n.MAC = mac
	return n, !offLink, nil
}

func (p *SystemPlatform) isLocal(ip net.IP) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, a := range p.addrs {
		if a.ip.Equal(ip) {
			return true
		}
	}
	return false
}

func sendARP(ip net.IP) (string, error) {
	var mac [8]byte
	l := uint32(len(mac))
	r, _, _ := procSendARP.Call(uintptr(ipv4ToDword(ip)), 0, uintptr(unsafe.Pointer(&mac[0])), uintptr(unsafe.Pointer(&l)))
	if r != 0 {
		return "", fmt.Errorf("SendARP(%s): %w", ip, windows.Errno(r))
	}
	if l == 0 || l > 8 || allZero(mac[:l]) {
		return "", fmt.Errorf("SendARP(%s): no hardware address", ip)
	}
	return FormatMAC(mac[:l]), nil
}

// StartRawSensor opens one SOCK_RAW / SIO_RCVALL capture per local IPv4
// address and feeds every inbound TCP SYN to sink. It needs administrator
// rights; the returned error explains why capture could not start, in
// which case the socket-table sensor remains the only source. status is
// called whenever the sensor state changes.
func StartRawSensor(ctx context.Context, p *SystemPlatform, sink func(...Observation), status func(SensorStatus)) error {
	wsaInit()
	p.refresh(true)
	locals := p.LocalIPv4()
	if len(locals) == 0 {
		err := errors.New("no IPv4 interface to capture on")
		status(SensorStatus{Name: SensorRaw, Detail: "raw SYN capture (SIO_RCVALL)", Error: err.Error()})
		return err
	}
	var socks []windows.Handle
	var names []string
	var firstErr error
	for _, l := range locals {
		s, err := openRaw(net.ParseIP(l.IP).To4())
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		socks = append(socks, s)
		names = append(names, l.IP+" ("+l.Interface+")")
		go capture(ctx, s, net.ParseIP(l.IP).To4(), sink)
	}
	if len(socks) == 0 {
		msg := firstErr.Error()
		if errors.Is(firstErr, windows.WSAEACCES) || errors.Is(firstErr, windows.ERROR_ACCESS_DENIED) {
			msg = "raw capture needs administrator rights (" + msg + ")"
		}
		status(SensorStatus{Name: SensorRaw, Detail: "raw SYN capture (SIO_RCVALL)", Error: msg})
		return errors.New(msg)
	}
	status(SensorStatus{Name: SensorRaw, Active: true, Detail: "raw SYN capture (SIO_RCVALL, RCVALL_IPLEVEL)", Adapters: names})
	go func() {
		<-ctx.Done()
		for _, s := range socks {
			_ = windows.Closesocket(s)
		}
	}()
	return nil
}

func openRaw(ip net.IP) (windows.Handle, error) {
	s, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("socket(SOCK_RAW): %w", err)
	}
	sa := &windows.SockaddrInet4{}
	copy(sa.Addr[:], ip)
	if err := windows.Bind(s, sa); err != nil {
		windows.Closesocket(s)
		return windows.InvalidHandle, fmt.Errorf("bind %s: %w", ip, err)
	}
	var ret uint32
	mode := uint32(rcvAllIPLevel)
	err = windows.WSAIoctl(s, sioRcvAll, (*byte)(unsafe.Pointer(&mode)), 4, nil, 0, &ret, nil, 0)
	if err != nil { // pre-Windows 8: fall back to RCVALL_ON
		mode = rcvAllOn
		err = windows.WSAIoctl(s, sioRcvAll, (*byte)(unsafe.Pointer(&mode)), 4, nil, 0, &ret, nil, 0)
	}
	if err != nil {
		windows.Closesocket(s)
		return windows.InvalidHandle, fmt.Errorf("SIO_RCVALL on %s: %w", ip, err)
	}
	// 1 s receive timeout so the loop notices cancellation.
	_ = windows.SetsockoptInt(s, windows.SOL_SOCKET, windows.SO_RCVTIMEO, 1000)
	_ = windows.SetsockoptInt(s, windows.SOL_SOCKET, windows.SO_RCVBUF, 4<<20)
	return s, nil
}

func capture(ctx context.Context, s windows.Handle, local net.IP, sink func(...Observation)) {
	buf := make([]byte, 65535)
	batch := make([]Observation, 0, 64)
	lastFlush := time.Now()
	flush := func() {
		if len(batch) > 0 {
			sink(batch...)
			batch = batch[:0]
		}
		lastFlush = time.Now()
	}
	for ctx.Err() == nil {
		n, _, err := windows.Recvfrom(s, buf, 0)
		if err != nil {
			if errors.Is(err, windows.Errno(wsaeTimedOut)) {
				flush()
				continue
			}
			if ctx.Err() != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		src, sport, dst, dport, perr := ParseInboundSYN(buf[:n], local)
		if perr == nil {
			batch = append(batch, Observation{Time: time.Now(), RemoteIP: src.String(), RemotePort: sport,
				LocalIP: dst.String(), LocalPort: dport, Sensor: SensorRaw})
		}
		if len(batch) >= 64 || time.Since(lastFlush) > 200*time.Millisecond {
			flush()
		}
	}
}
