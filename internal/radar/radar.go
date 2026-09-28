// Package radar implements the Multi-Port Connection Sweep & Network Anomaly
// Radar.
//
// It tracks inbound TCP connection attempts per remote IP and flags a
// "High-Frequency Connection Sweep (Traffic Anomaly)" when one remote
// address touches more than Threshold distinct local ports inside Window
// (default: >10 ports in 5 s).
//
// Observations come from two sensors:
//
//   - the raw SYN sensor (Windows, administrator): a SOCK_RAW socket in
//     SIO_RCVALL mode on every local IPv4 interface sees every inbound SYN,
//     including probes to closed or firewalled ports;
//   - the socket-table sensor (always on): new inbound rows of the TCP
//     table (GetExtendedTcpTable) — only accepted connections to listening
//     ports, but works without elevation and covers IPv6.
//
// Detected incidents are enriched with the physical MAC address and
// network interface from the ARP table (GetIpNetTable). Everything in this
// file is platform-independent and unit-tested; Win32 access lives in the
// *_windows.go files.
package radar

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/oui"
)

// Sensor identifiers.
const (
	SensorRaw      = "raw-syn"
	SensorTable    = "tcp-table"
	SensorSelfTest = "self-test"
)

// Observation is one inbound TCP connection attempt.
type Observation struct {
	Time       time.Time
	RemoteIP   string
	RemotePort uint16
	LocalIP    string
	LocalPort  uint16
	Sensor     string
}

// Neighbor is one row of the ARP (IPv4 neighbour) table.
type Neighbor struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	IfIndex   uint32 `json:"ifIndex"`
	Interface string `json:"interface"`
	Type      string `json:"type"`              // dynamic, static, resolved, other
	Gateway   string `json:"gateway,omitempty"` // set when ip is off-link and MAC is the router's
}

// LocalAddr is one IPv4 address of this machine.
type LocalAddr struct {
	IP        string `json:"ip"`
	IfIndex   uint32 `json:"ifIndex"`
	Interface string `json:"interface"`
}

// Platform provides hardware attribution (ARP table, route lookup).
// The Windows implementation is SystemPlatform; tests and the demo use fakes.
type Platform interface {
	// Neighbors returns the IPv4 ARP cache (GetIpNetTable).
	Neighbors() ([]Neighbor, error)
	// Resolve maps ip to a MAC and interface. onLink is false when the MAC
	// belongs to the next-hop gateway instead of the host itself.
	Resolve(ip string) (n Neighbor, onLink bool, err error)
}

// Incident is one detected connection sweep.
type Incident struct {
	ID            string    `json:"id"`
	RemoteIP      string    `json:"remoteIp"`
	MAC           string    `json:"mac"`
	Vendor        string    `json:"vendor,omitempty"`
	Interface     string    `json:"interface"`
	IfIndex       uint32    `json:"ifIndex"`
	OnLink        bool      `json:"onLink"` // MAC belongs to the host itself (same L2 segment)
	Gateway       string    `json:"gateway,omitempty"`
	AttrError     string    `json:"attrError,omitempty"`
	Targets       []string  `json:"targets"`
	Ports         []uint16  `json:"ports"`
	DistinctPorts int       `json:"distinctPorts"`
	PortMin       uint16    `json:"portMin"`
	PortMax       uint16    `json:"portMax"`
	PortRange     string    `json:"portRange"`
	PortsInWindow int       `json:"portsInWindow"` // distinct ports at the moment of detection
	Attempts      int       `json:"attempts"`
	FirstSeen     time.Time `json:"firstSeen"`
	Detected      time.Time `json:"detected"`
	LastSeen      time.Time `json:"lastSeen"`
	Sensor        string    `json:"sensor"`
	Active        bool      `json:"active"`
	Test          bool      `json:"test"`
	New           bool      `json:"new"` // true only on the first publication
}

// Config tunes the detector.
type Config struct {
	Window    time.Duration // sliding window for the port-breadth rule
	Threshold int           // flag when distinct ports > Threshold
	Cooldown  time.Duration // quiet time after which an incident closes
	Allow     []string      // remote IPs never flagged (authorised scanners)
	MaxHosts  int           // tracked remote IPs (LRU eviction)
}

func (c *Config) defaults() {
	if c.Window <= 0 {
		c.Window = 5 * time.Second
	}
	if c.Threshold <= 0 {
		c.Threshold = 10
	}
	if c.Cooldown <= 0 {
		c.Cooldown = 60 * time.Second
	}
	if c.MaxHosts <= 0 {
		c.MaxHosts = 4096
	}
}

type hit struct {
	t    time.Time
	port uint16
}

type host struct {
	ip        string
	hits      []hit // last statsSpan of observations, oldest first
	total     int
	ports     map[uint16]struct{} // lifetime distinct ports (capped)
	firstSeen time.Time
	lastSeen  time.Time
	peak      int // max distinct ports ever seen within Window
	incident  *Incident
	lastLocal string
	sensors   map[string]bool
}

const (
	statsSpan    = 60 * time.Second
	maxPortsKept = 4096
	maxIncidents = 200
	maxHits      = 20000
)

// Detector is safe for concurrent use: the raw sensor goroutines and the
// hub's socket-table poller feed it simultaneously.
type Detector struct {
	cfg   Config
	allow map[string]bool

	mu        sync.Mutex
	hosts     map[string]*host
	incidents []*Incident // newest first
	seq       int
	neighbors map[string]Neighbor
	obsCount  []obsBucket
	sensors   map[string]SensorStatus
	local     map[string]bool // this machine's own addresses (never a sweeper)
	now       func() time.Time
}

// LocalLister is implemented by platforms that can enumerate this host's
// IPv4 addresses (used to exclude self-traffic from the radar).
type LocalLister interface {
	LocalIPv4() []LocalAddr
}

// SetLocal replaces the set of this machine's own addresses. Connections
// between two local addresses (e.g. a browser talking to a local proxy over
// the LAN IP) are never evaluated.
func (d *Detector) SetLocal(ips []string) {
	m := make(map[string]bool, len(ips))
	for _, ip := range ips {
		m[normIP(ip)] = true
	}
	d.mu.Lock()
	d.local = m
	d.mu.Unlock()
}

type obsBucket struct {
	sec int64
	n   int
}

// SensorStatus describes one observation source.
type SensorStatus struct {
	Name     string    `json:"name"`
	Active   bool      `json:"active"`
	Detail   string    `json:"detail"`
	Error    string    `json:"error,omitempty"`
	Seen     uint64    `json:"seen"`
	Since    time.Time `json:"since"`
	Adapters []string  `json:"adapters,omitempty"`
}

// New creates a detector.
func New(cfg Config) *Detector {
	cfg.defaults()
	d := &Detector{cfg: cfg, allow: map[string]bool{}, hosts: map[string]*host{},
		neighbors: map[string]Neighbor{}, sensors: map[string]SensorStatus{}, now: time.Now}
	for _, a := range cfg.Allow {
		if ip := net.ParseIP(strings.TrimSpace(a)); ip != nil {
			d.allow[ip.String()] = true
		}
	}
	return d
}

// Config returns the effective configuration.
func (d *Detector) Config() Config { return d.cfg }

// SetClock overrides the time source (tests / demo).
func (d *Detector) SetClock(now func() time.Time) {
	d.mu.Lock()
	d.now = now
	d.mu.Unlock()
}

// SetSensor records the status of an observation source.
func (d *Detector) SetSensor(s SensorStatus) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if old, ok := d.sensors[s.Name]; ok {
		s.Seen = old.Seen
		if s.Since.IsZero() {
			s.Since = old.Since
		}
	}
	if s.Since.IsZero() {
		s.Since = d.now()
	}
	d.sensors[s.Name] = s
}

// SensorActive reports whether the named sensor is currently capturing.
func (d *Detector) SensorActive(name string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sensors[name].Active
}

// SetNeighbors replaces the cached ARP table (used for MAC attribution in
// the live statistics; incidents are resolved on demand as well).
func (d *Detector) SetNeighbors(ns []Neighbor) {
	m := make(map[string]Neighbor, len(ns))
	for _, n := range ns {
		m[n.IP] = n
	}
	d.mu.Lock()
	d.neighbors = m
	d.mu.Unlock()
}

// Neighbor returns the cached ARP entry for ip.
func (d *Detector) Neighbor(ip string) (Neighbor, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n, ok := d.neighbors[ip]
	return n, ok
}

// Neighbors returns the cached ARP table sorted by interface then IP.
func (d *Detector) Neighbors() []Neighbor {
	d.mu.Lock()
	out := make([]Neighbor, 0, len(d.neighbors))
	for _, n := range d.neighbors {
		out = append(out, n)
	}
	d.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].IfIndex != out[j].IfIndex {
			return out[i].IfIndex < out[j].IfIndex
		}
		return ipLess(out[i].IP, out[j].IP)
	})
	return out
}

// Ignored reports whether observations from ip are never evaluated
// (loopback, unspecified, multicast, broadcast, or explicitly allowed).
func (d *Detector) Ignored(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil || p.IsLoopback() || p.IsUnspecified() || p.IsMulticast() || p.Equal(net.IPv4bcast) {
		return true
	}
	return d.allow[p.String()] || d.local[normIP(ip)]
}

// Observe records connection attempts and returns incidents that were
// opened or updated by them. New incidents have New=true exactly once.
func (d *Detector) Observe(obs ...Observation) []Incident {
	d.mu.Lock()
	defer d.mu.Unlock()
	changed := map[*Incident]bool{}
	for _, o := range obs {
		if d.Ignored(o.RemoteIP) {
			continue
		}
		if o.Time.IsZero() {
			o.Time = d.now()
		}
		ip := normIP(o.RemoteIP)
		h := d.hosts[ip]
		if h == nil {
			if len(d.hosts) >= d.cfg.MaxHosts {
				d.evictLocked()
			}
			h = &host{ip: ip, ports: map[uint16]struct{}{}, firstSeen: o.Time, sensors: map[string]bool{}}
			d.hosts[ip] = h
		}
		d.countLocked(o.Time)
		if s, ok := d.sensors[o.Sensor]; ok {
			s.Seen++
			d.sensors[o.Sensor] = s
		}
		h.hits = append(h.hits, hit{o.Time, o.LocalPort})
		if len(h.hits) > maxHits {
			h.hits = h.hits[len(h.hits)-maxHits:]
		}
		h.total++
		h.sensors[o.Sensor] = true
		if len(h.ports) < maxPortsKept {
			h.ports[o.LocalPort] = struct{}{}
		}
		if o.Time.After(h.lastSeen) {
			h.lastSeen = o.Time
		}
		if o.LocalIP != "" {
			h.lastLocal = o.LocalIP
		}
		h.trim(o.Time.Add(-statsSpan))
		inWin := h.distinctSince(o.Time.Add(-d.cfg.Window))
		if inWin > h.peak {
			h.peak = inWin
		}
		inc := h.incident
		if inc != nil && inc.Active && o.Time.Sub(inc.LastSeen) > d.cfg.Cooldown {
			inc.Active = false // quiet for too long: next sweep is a new incident
			h.incident = nil
			inc = nil
		}
		if inc == nil {
			if inWin <= d.cfg.Threshold {
				continue
			}
			d.seq++
			inc = &Incident{
				ID: "SWP-" + pad(d.seq), RemoteIP: ip, Detected: o.Time, Sensor: o.Sensor,
				Active: true, New: true, Test: o.Sensor == SensorSelfTest, PortsInWindow: inWin,
			}
			// Seed the incident with everything seen inside the window.
			cut := o.Time.Add(-d.cfg.Window)
			for _, x := range h.hits {
				if !x.t.Before(cut) {
					inc.addPort(x.port, x.t)
					inc.Attempts++
				}
			}
			if n, ok := d.neighbors[ip]; ok {
				inc.MAC, inc.Interface, inc.IfIndex, inc.OnLink = n.MAC, n.Interface, n.IfIndex, true
			}
			h.incident = inc
			d.incidents = append([]*Incident{inc}, d.incidents...)
			if len(d.incidents) > maxIncidents {
				d.incidents = d.incidents[:maxIncidents]
			}
		} else {
			inc.addPort(o.LocalPort, o.Time)
			inc.Attempts++
			if inWin > inc.PortsInWindow {
				inc.PortsInWindow = inWin
			}
		}
		if o.LocalIP != "" && !contains(inc.Targets, o.LocalIP) && len(inc.Targets) < 16 {
			inc.Targets = append(inc.Targets, o.LocalIP)
		}
		changed[inc] = true
	}
	out := make([]Incident, 0, len(changed))
	for inc := range changed {
		inc.finish()
		out = append(out, inc.clone())
		inc.New = false
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Attribute stores hardware attribution for an incident (resolved
// asynchronously because SendARP may block) and returns the updated copy.
func (d *Detector) Attribute(id string, n Neighbor, onLink bool, err error) (Incident, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, inc := range d.incidents {
		if inc.ID == id {
			if n.MAC != "" {
				inc.MAC = n.MAC
			}
			if n.Interface != "" {
				inc.Interface, inc.IfIndex = n.Interface, n.IfIndex
			}
			inc.OnLink, inc.Gateway = onLink, n.Gateway
			inc.AttrError = ""
			if err != nil && inc.MAC == "" {
				inc.AttrError = err.Error()
			}
			inc.Vendor = VendorOf(inc.MAC)
			c := inc.clone()
			c.New = false
			return c, true
		}
	}
	return Incident{}, false
}

// Expire closes incidents that have been quiet for Cooldown and returns
// the ones that changed state.
func (d *Detector) Expire() []Incident {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	var out []Incident
	for _, h := range d.hosts {
		if inc := h.incident; inc != nil && inc.Active && now.Sub(inc.LastSeen) > d.cfg.Cooldown {
			inc.Active = false
			h.incident = nil
			out = append(out, inc.clone())
		}
	}
	for ip, h := range d.hosts {
		if h.incident == nil && now.Sub(h.lastSeen) > 15*time.Minute {
			delete(d.hosts, ip)
		}
	}
	return out
}

// Forget drops all state for ip (used by the self-test so it can be
// repeated immediately).
func (d *Detector) Forget(ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if h := d.hosts[normIP(ip)]; h != nil && h.incident != nil {
		h.incident.Active = false
	}
	delete(d.hosts, normIP(ip))
}

// Incidents returns recent incidents, newest first.
func (d *Detector) Incidents() []Incident {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Incident, len(d.incidents))
	for i, inc := range d.incidents {
		out[i] = inc.clone()
		out[i].New = false
	}
	return out
}

// HostStat is the per-remote-IP connection frequency / port breadth row.
type HostStat struct {
	IP            string   `json:"ip"`
	MAC           string   `json:"mac,omitempty"`
	Vendor        string   `json:"vendor,omitempty"`
	Interface     string   `json:"interface,omitempty"`
	ConnsWindow   int      `json:"connsWindow"` // attempts in the detection window
	PortsWindow   int      `json:"portsWindow"` // distinct ports in the detection window
	Conns60       int      `json:"conns60"`
	Rate          float64  `json:"rate"` // attempts per second over the last 60 s
	Total         int      `json:"total"`
	DistinctPorts int      `json:"distinctPorts"`
	Peak          int      `json:"peak"`
	FirstSeen     int64    `json:"firstSeen"`
	LastSeen      int64    `json:"lastSeen"`
	Flagged       bool     `json:"flagged"`
	Target        string   `json:"target,omitempty"`
	Sensors       []string `json:"sensors"`
	Pressure      float64  `json:"pressure"` // PortsWindow / Threshold (1.0 = at the limit)
}

// State is the radar payload for the dashboard.
type State struct {
	Window     float64        `json:"windowSec"`
	Threshold  int            `json:"threshold"`
	Cooldown   float64        `json:"cooldownSec"`
	Hosts      []HostStat     `json:"hosts"`
	Tracked    int            `json:"tracked"`
	ObsPerSec  float64        `json:"obsPerSec"`
	Series     []int          `json:"series"` // observations per second, last 60 s (oldest first)
	Incidents  []Incident     `json:"incidents"`
	Active     int            `json:"active"`
	Sensors    []SensorStatus `json:"sensors"`
	Neighbors  int            `json:"neighbors"`
	SampledAt  int64          `json:"sampledAt"`
	AllowCount int            `json:"allowCount"`
}

// Snapshot builds the dashboard state; limit bounds the host table.
func (d *Detector) Snapshot(limit int) State {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	st := State{Window: d.cfg.Window.Seconds(), Threshold: d.cfg.Threshold, Cooldown: d.cfg.Cooldown.Seconds(),
		Tracked: len(d.hosts), Neighbors: len(d.neighbors), SampledAt: now.UnixMilli(), AllowCount: len(d.allow)}
	for _, h := range d.hosts {
		h.trim(now.Add(-statsSpan))
		hs := HostStat{IP: h.ip, Total: h.total, DistinctPorts: len(h.ports), Peak: h.peak,
			FirstSeen: h.firstSeen.UnixMilli(), LastSeen: h.lastSeen.UnixMilli(),
			Flagged: h.incident != nil && h.incident.Active, Target: h.lastLocal}
		cut := now.Add(-d.cfg.Window)
		for _, x := range h.hits {
			if !x.t.Before(cut) {
				hs.ConnsWindow++
			}
		}
		hs.Conns60 = len(h.hits)
		hs.Rate = float64(hs.Conns60) / statsSpan.Seconds()
		hs.PortsWindow = h.distinctSince(cut)
		hs.Pressure = float64(hs.PortsWindow) / float64(d.cfg.Threshold)
		if n, ok := d.neighbors[h.ip]; ok {
			hs.MAC, hs.Interface = n.MAC, n.Interface
		} else if h.incident != nil && h.incident.MAC != "" {
			hs.MAC, hs.Interface = h.incident.MAC, h.incident.Interface
		}
		for s := range h.sensors {
			hs.Sensors = append(hs.Sensors, s)
		}
		sort.Strings(hs.Sensors)
		hs.Vendor = VendorOf(hs.MAC)
		st.Hosts = append(st.Hosts, hs)
	}
	sort.Slice(st.Hosts, func(i, j int) bool {
		a, b := st.Hosts[i], st.Hosts[j]
		if a.Flagged != b.Flagged {
			return a.Flagged
		}
		if a.PortsWindow != b.PortsWindow {
			return a.PortsWindow > b.PortsWindow
		}
		if a.Conns60 != b.Conns60 {
			return a.Conns60 > b.Conns60
		}
		return a.LastSeen > b.LastSeen
	})
	if limit > 0 && len(st.Hosts) > limit {
		st.Hosts = st.Hosts[:limit]
	}
	st.Series = make([]int, 60)
	base := now.Unix() - 59
	total := 0
	for _, b := range d.obsCount {
		if i := b.sec - base; i >= 0 && i < 60 {
			st.Series[i] += b.n
			total += b.n
		}
	}
	st.ObsPerSec = float64(total) / 60
	n := len(d.incidents)
	if n > 50 {
		n = 50
	}
	for _, inc := range d.incidents[:n] {
		c := inc.clone()
		c.New = false
		st.Incidents = append(st.Incidents, c)
	}
	for _, inc := range d.incidents {
		if inc.Active {
			st.Active++
		}
	}
	for _, s := range d.sensors {
		st.Sensors = append(st.Sensors, s)
	}
	sort.Slice(st.Sensors, func(i, j int) bool { return st.Sensors[i].Name < st.Sensors[j].Name })
	return st
}

func (d *Detector) countLocked(t time.Time) {
	sec := t.Unix()
	if n := len(d.obsCount); n > 0 && d.obsCount[n-1].sec == sec {
		d.obsCount[n-1].n++
	} else {
		d.obsCount = append(d.obsCount, obsBucket{sec, 1})
	}
	cut := d.now().Unix() - 60
	i := 0
	for i < len(d.obsCount) && d.obsCount[i].sec < cut {
		i++
	}
	d.obsCount = d.obsCount[i:]
}

func (d *Detector) evictLocked() {
	var oldest *host
	for _, h := range d.hosts {
		if h.incident != nil {
			continue
		}
		if oldest == nil || h.lastSeen.Before(oldest.lastSeen) {
			oldest = h
		}
	}
	if oldest != nil {
		delete(d.hosts, oldest.ip)
	}
}

func (h *host) trim(cut time.Time) {
	i := 0
	for i < len(h.hits) && h.hits[i].t.Before(cut) {
		i++
	}
	if i > 0 {
		h.hits = append(h.hits[:0], h.hits[i:]...)
	}
}

func (h *host) distinctSince(cut time.Time) int {
	seen := map[uint16]struct{}{}
	for i := len(h.hits) - 1; i >= 0; i-- {
		if h.hits[i].t.Before(cut) {
			// hits are appended in arrival order; sensors can deliver
			// slightly out of order, so keep scanning a little.
			continue
		}
		seen[h.hits[i].port] = struct{}{}
	}
	return len(seen)
}

func (inc *Incident) addPort(p uint16, t time.Time) {
	if inc.FirstSeen.IsZero() || t.Before(inc.FirstSeen) {
		inc.FirstSeen = t
	}
	if t.After(inc.LastSeen) {
		inc.LastSeen = t
	}
	i := sort.Search(len(inc.Ports), func(i int) bool { return inc.Ports[i] >= p })
	if i < len(inc.Ports) && inc.Ports[i] == p {
		return
	}
	inc.DistinctPorts++
	if len(inc.Ports) >= maxPortsKept {
		return
	}
	inc.Ports = append(inc.Ports, 0)
	copy(inc.Ports[i+1:], inc.Ports[i:])
	inc.Ports[i] = p
}

// VendorOf returns the manufacturer brand for mac from the embedded IEEE
// OUI database ("" when unknown; "private address" for randomised MACs).
func VendorOf(mac string) string {
	if mac == "" {
		return ""
	}
	v, ok := oui.Lookup(mac)
	switch {
	case !ok:
		return ""
	case v.Short != "":
		return v.Short
	case v.Random:
		return "private address"
	}
	return v.Name
}

func (inc *Incident) finish() {
	inc.Vendor = VendorOf(inc.MAC)
	if len(inc.Ports) > 0 {
		inc.PortMin, inc.PortMax = inc.Ports[0], inc.Ports[len(inc.Ports)-1]
	}
	inc.PortRange = CompressPorts(inc.Ports, 12)
}

func (inc *Incident) clone() Incident {
	c := *inc
	c.Ports = append([]uint16(nil), inc.Ports...)
	c.Targets = append([]string(nil), inc.Targets...)
	return c
}

// CompressPorts renders sorted ports as "21-23, 80, 443, 8000-8010",
// showing at most maxGroups groups followed by "(+N more)".
func CompressPorts(ports []uint16, maxGroups int) string {
	if len(ports) == 0 {
		return ""
	}
	var groups []string
	start, prev := ports[0], ports[0]
	flush := func() {
		if start == prev {
			groups = append(groups, strconv.Itoa(int(start)))
		} else {
			groups = append(groups, strconv.Itoa(int(start))+"-"+strconv.Itoa(int(prev)))
		}
	}
	for _, p := range ports[1:] {
		if p == prev {
			continue
		}
		if p == prev+1 {
			prev = p
			continue
		}
		flush()
		start, prev = p, p
	}
	flush()
	if maxGroups > 0 && len(groups) > maxGroups {
		more := len(groups) - maxGroups
		return strings.Join(groups[:maxGroups], ", ") + " (+" + strconv.Itoa(more) + " more)"
	}
	return strings.Join(groups, ", ")
}

func normIP(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return s
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

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func pad(n int) string {
	s := strconv.Itoa(n)
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}

// ActiveCount returns the number of currently active sweep incidents.
func (d *Detector) ActiveCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, inc := range d.incidents {
		if inc.Active {
			n++
		}
	}
	return n
}
