package hub

// SysPulse 3.0: local network device inventory. Every ARP / neighbour-table
// refresh is merged into a device list enriched with the IEEE OUI vendor and
// with host names resolved via NetBIOS, mDNS and reverse DNS.

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/netnames"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/oui"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/radar"
)

// NameResolver resolves a LAN host name (netnames.Resolver in production).
type NameResolver interface {
	Resolve(ctx context.Context, ip string) netnames.Result
}

const (
	deviceTTL     = 30 * time.Minute // forget devices absent from ARP this long
	resolveEvery  = 10 * time.Minute // re-resolve names
	resolveFailed = 3 * time.Minute  // retry sooner when nothing was found
	maxResolvers  = 8
)

type devices struct {
	mu   sync.Mutex
	m    map[string]*model.Device
	sem  chan struct{}
	gw   map[string]bool
	self map[string]bool
}

func newDevices() *devices {
	return &devices{m: map[string]*model.Device{}, sem: make(chan struct{}, maxResolvers), gw: map[string]bool{}, self: map[string]bool{}}
}

// Devices returns the LAN device inventory sorted by IP.
func (h *Hub) Devices() []model.Device {
	d := h.devices
	d.mu.Lock()
	out := make([]model.Device, 0, len(d.m))
	for _, v := range d.m {
		c := *v
		if v.Names != nil {
			c.Names = make(map[string]string, len(v.Names))
			for k, n := range v.Names {
				c.Names[k] = n
			}
		}
		out = append(out, c)
	}
	d.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i].IP, out[j].IP) })
	return out
}

// SetGateways marks default-gateway addresses (shown with a router badge).
func (h *Hub) SetGateways(ips []string) {
	h.devices.mu.Lock()
	h.devices.gw = map[string]bool{}
	for _, ip := range ips {
		h.devices.gw[ip] = true
	}
	h.devices.mu.Unlock()
}

// updateDevices merges an ARP snapshot and schedules name resolution.
func (h *Hub) updateDevices(ns []radar.Neighbor) {
	now := time.Now()
	d := h.devices
	var todo []string
	d.mu.Lock()
	for _, n := range ns {
		ip := net.ParseIP(n.IP)
		if ip == nil || ip.IsMulticast() || ip.Equal(net.IPv4bcast) || n.MAC == "" {
			continue
		}
		// Skip subnet-directed broadcasts (x.x.x.255 with FF MAC) and multicast MACs.
		if mb, ok := oui.ParseMAC(n.MAC); !ok || mb[0]&0x01 != 0 {
			continue
		}
		dev := d.m[n.IP]
		if dev == nil {
			dev = &model.Device{IP: n.IP, FirstSeen: now.UnixMilli()}
			d.m[n.IP] = dev
		}
		if dev.MAC != n.MAC {
			dev.MAC = n.MAC
			dev.Vendor, dev.VendorFull, dev.OUI, dev.Registry, dev.Class, dev.RandomMAC = "", "", "", "", "", false
			if v, ok := oui.Lookup(n.MAC); ok {
				dev.Vendor, dev.VendorFull, dev.OUI, dev.Registry, dev.Class, dev.RandomMAC = v.Short, v.Name, v.Prefix, v.Registry, v.Class, v.Random
			}
		}
		dev.Interface, dev.IfIndex, dev.Type = n.Interface, n.IfIndex, n.Type
		dev.Gateway = d.gw[n.IP]
		if dev.Gateway && dev.Class != "vm" {
			dev.Class = "network"
		}
		dev.LastSeen = now.UnixMilli()
		due := resolveEvery
		if dev.Hostname == "" {
			due = resolveFailed
		}
		if !h.cfg.NoResolve && !dev.Resolving && now.Sub(time.UnixMilli(dev.Resolved)) > due {
			dev.Resolving = true
			todo = append(todo, n.IP)
		}
	}
	for ip, dev := range d.m {
		if now.Sub(time.UnixMilli(dev.LastSeen)) > deviceTTL {
			delete(d.m, ip)
		}
	}
	d.mu.Unlock()
	res := h.cfg.Resolver
	if res == nil {
		return
	}
	for _, ip := range todo {
		go h.resolveDevice(res, ip)
	}
}

func (h *Hub) resolveDevice(res NameResolver, ip string) {
	d := h.devices
	d.sem <- struct{}{}
	defer func() { <-d.sem }()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	r := res.Resolve(ctx, ip)
	cancel()
	d.mu.Lock()
	dev := d.m[ip]
	if dev != nil {
		dev.Resolving = false
		dev.Resolved = time.Now().UnixMilli()
		if r.Name != "" {
			dev.Hostname, dev.NameSource, dev.Names = r.Name, r.Source, r.Names
		}
		if r.Workgroup != "" {
			dev.Workgroup = r.Workgroup
		}
	}
	d.mu.Unlock()
	if dev != nil && r.Name != "" && h.Subscribers() > 0 {
		h.Broadcast("devices", h.Devices())
	}
}

// ResolveDevices forces an immediate name refresh for every known device.
func (h *Hub) ResolveDevices() int {
	if h.cfg.Resolver == nil || h.cfg.NoResolve {
		return 0
	}
	d := h.devices
	var ips []string
	d.mu.Lock()
	for ip, dev := range d.m {
		if !dev.Resolving {
			dev.Resolving = true
			ips = append(ips, ip)
		}
	}
	d.mu.Unlock()
	for _, ip := range ips {
		go h.resolveDevice(h.cfg.Resolver, ip)
	}
	return len(ips)
}

func ipLess(a, b string) bool {
	x, y := net.ParseIP(a), net.ParseIP(b)
	if x == nil || y == nil {
		return a < b
	}
	x16, y16 := x.To16(), y.To16()
	for i := range x16 {
		if x16[i] != y16[i] {
			return x16[i] < y16[i]
		}
	}
	return false
}
