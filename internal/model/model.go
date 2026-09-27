// Package model defines the data transfer objects shared by the collectors,
// the hub and the HTTP/WebSocket API. All types are JSON-serialisable.
package model

import "time"

// Connection is one TCP or UDP socket owned by a process.
type Connection struct {
	Proto       string `json:"proto"` // TCP, TCP6, UDP, UDP6
	LocalAddr   string `json:"localAddr"`
	LocalPort   uint16 `json:"localPort"`
	RemoteAddr  string `json:"remoteAddr,omitempty"`
	RemotePort  uint16 `json:"remotePort,omitempty"`
	State       string `json:"state"` // ESTABLISHED, LISTEN, ... ("-" for UDP)
	PID         uint32 `json:"pid"`
	ProcessName string `json:"processName"`
	ProcessPath string `json:"processPath,omitempty"`
	FirstSeen   int64  `json:"firstSeen"` // unix ms
}

// Key uniquely identifies a socket for diffing between snapshots.
func (c *Connection) Key() string {
	return c.Proto + "|" + c.LocalAddr + "|" + itoa(int(c.LocalPort)) + "|" +
		c.RemoteAddr + "|" + itoa(int(c.RemotePort)) + "|" + itoa(int(c.PID))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// NetStats summarises a connection snapshot.
type NetStats struct {
	Total       int            `json:"total"`
	ByState     map[string]int `json:"byState"`
	ByProto     map[string]int `json:"byProto"`
	NewPerSec   float64        `json:"newPerSec"`
	TopProcs    []ProcCount    `json:"topProcs"`
	TopRemotes  []ProcCount    `json:"topRemotes"`
	SampledAtMs int64          `json:"sampledAt"`
}

// ProcCount is a (label, count) pair used for top-N lists.
type ProcCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Process is one running process with resource usage.
type Process struct {
	PID        uint32  `json:"pid"`
	PPID       uint32  `json:"ppid"`
	Name       string  `json:"name"`
	Path       string  `json:"path,omitempty"`
	Threads    uint32  `json:"threads"`
	CPUPercent float64 `json:"cpu"`        // share of total machine CPU, 0-100
	WorkingSet uint64  `json:"workingSet"` // bytes (RSS)
	PrivateB   uint64  `json:"private"`    // private bytes (commit)
	StartedMs  int64   `json:"started,omitempty"`
	Access     bool    `json:"access"` // false if details could not be read (protected process)
}

// SystemMetrics is a point-in-time system snapshot.
type SystemMetrics struct {
	Timestamp   int64       `json:"ts"`
	CPUPercent  float64     `json:"cpu"`
	CPUCores    int         `json:"cores"`
	MemTotal    uint64      `json:"memTotal"`
	MemUsed     uint64      `json:"memUsed"`
	MemPercent  float64     `json:"memPercent"`
	CommitTotal uint64      `json:"commitTotal"`
	CommitUsed  uint64      `json:"commitUsed"`
	UptimeSec   uint64      `json:"uptime"`
	Processes   int         `json:"processes"`
	Threads     int         `json:"threads"`
	Disks       []DiskUsage `json:"disks"`
	Hostname    string      `json:"hostname"`
	OS          string      `json:"os"`
}

// DiskUsage describes one logical volume.
type DiskUsage struct {
	Mount   string  `json:"mount"`
	Type    string  `json:"type"`
	Total   uint64  `json:"total"`
	Free    uint64  `json:"free"`
	Used    uint64  `json:"used"`
	Percent float64 `json:"percent"`
}

// Event categories.
const (
	CatServiceCrash     = "service-crash"
	CatAppFault         = "app-fault"
	CatUnexpectedShutdn = "unexpected-shutdown"
	CatDriver           = "driver"
	CatDisk             = "disk"
	CatUpdate           = "windows-update"
	CatPower            = "power"
	CatOther            = "other"
)

// Event is one Windows event log record.
type Event struct {
	Channel  string    `json:"channel"`
	RecordID uint64    `json:"recordId"`
	EventID  uint32    `json:"eventId"`
	Level    int       `json:"level"` // 1 critical, 2 error, 3 warning, 4 info
	LevelStr string    `json:"levelStr"`
	Provider string    `json:"provider"`
	Time     time.Time `json:"time"`
	Computer string    `json:"computer,omitempty"`
	Message  string    `json:"message"`
	Category string    `json:"category"`
	// Data holds the EventData / UserData fields (named, plus positional
	// keys "#0", "#1", …). It is used by the diagnostic audits and is not
	// sent to the dashboard with the live event stream.
	Data map[string]string `json:"-"`
}

// App is one installed application from the registry.
type App struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Publisher       string `json:"publisher,omitempty"`
	InstallDate     string `json:"installDate,omitempty"`
	InstallLocation string `json:"installLocation,omitempty"`
	SizeKB          uint64 `json:"sizeKB,omitempty"`
	Scope           string `json:"scope"` // machine, machine-x86, user
	UninstallKey    string `json:"key"`
	// Filled in when a winget upgrade is known for this app.
	AvailableVersion string `json:"available,omitempty"`
	WingetID         string `json:"wingetId,omitempty"`

	// SysPulse 3.0 deep inventory fields.
	Hidden       bool   `json:"hidden,omitempty"`     // not shown in "Apps & features" (system component, update, child entry)
	Kind         string `json:"kind,omitempty"`       // app, system-component, update, package
	DateSource   string `json:"dateSource,omitempty"` // registry (InstallDate value), key-write-time, package-db
	Arch         string `json:"arch,omitempty"`       // x64, x86, arm64, all…
	MSI          bool   `json:"msi,omitempty"`        // Windows Installer product (key name is a product code)
	Uninstall    string `json:"uninstall,omitempty"`  // UninstallString / QuietUninstallString
	URL          string `json:"url,omitempty"`        // URLInfoAbout / Homepage
	InstallSrc   string `json:"installSource,omitempty"`
	Comments     string `json:"comments,omitempty"`
	Source       string `json:"source,omitempty"` // registry, dpkg, rpm
	UserSID      string `json:"userSid,omitempty"`
	DisplayIcon  string `json:"icon,omitempty"`
	Language     string `json:"language,omitempty"`
	EstimatedRaw uint64 `json:"-"`
}

// Listener is one listening TCP socket (bound address and owning PID). The
// radar's socket-table sensor uses it to decide whether a new row is an
// accepted inbound connection.
type Listener struct {
	Addr string `json:"addr"`
	PID  uint32 `json:"pid"`
}

// Device is one host discovered on the local network (ARP / neighbour table)
// enriched with its hardware vendor and resolved host name.
type Device struct {
	IP         string            `json:"ip"`
	MAC        string            `json:"mac"`
	Vendor     string            `json:"vendor,omitempty"`     // brand, e.g. "Apple"
	VendorFull string            `json:"vendorFull,omitempty"` // registered organisation name
	OUI        string            `json:"oui,omitempty"`        // matched prefix
	Registry   string            `json:"registry,omitempty"`   // MA-L / MA-M / MA-S
	Class      string            `json:"class,omitempty"`      // pc, mobile, network, printer, iot, tv, console, vm, sbc
	RandomMAC  bool              `json:"randomMac,omitempty"`  // locally administered / private address
	Hostname   string            `json:"hostname,omitempty"`
	NameSource string            `json:"nameSource,omitempty"` // netbios, mdns, dns
	Names      map[string]string `json:"names,omitempty"`      // every name found, keyed by source
	Workgroup  string            `json:"workgroup,omitempty"`
	Interface  string            `json:"interface,omitempty"`
	IfIndex    uint32            `json:"ifIndex,omitempty"`
	Type       string            `json:"type,omitempty"` // dynamic, static, …
	Gateway    bool              `json:"gateway,omitempty"`
	Self       bool              `json:"self,omitempty"`
	FirstSeen  int64             `json:"firstSeen"`
	LastSeen   int64             `json:"lastSeen"`
	Resolved   int64             `json:"resolved,omitempty"` // unix ms of the last name lookup
	Resolving  bool              `json:"resolving,omitempty"`
}

// ProcessDetail is the on-demand deep inspection of one process.
type ProcessDetail struct {
	Process
	CommandLine string            `json:"commandLine,omitempty"`
	User        string            `json:"user,omitempty"`
	Handles     uint32            `json:"handles,omitempty"` // Windows handles / Linux open file descriptors
	Priority    string            `json:"priority,omitempty"`
	Cwd         string            `json:"cwd,omitempty"`
	ParentName  string            `json:"parentName,omitempty"`
	Children    []Process         `json:"children,omitempty"`
	Sockets     []Connection      `json:"sockets,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`
	Errors      []string          `json:"errors,omitempty"`
}

// Upgrade is one row of `winget upgrade`.
type Upgrade struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	Version   string `json:"version"`
	Available string `json:"available"`
	Source    string `json:"source"`
	Command   string `json:"command"`
}

// Text is a bilingual (English / Arabic) string. The dashboard picks the
// active language; reports and exports can include both.
type Text struct {
	En string `json:"en"`
	Ar string `json:"ar"`
}

// T builds a Text.
func T(en, ar string) Text { return Text{En: en, Ar: ar} }

// Get returns the text in lang ("ar" or anything else for English).
func (t Text) Get(lang string) string {
	if lang == "ar" && t.Ar != "" {
		return t.Ar
	}
	return t.En
}

// Severity levels used by alerts and audit findings.
const (
	SevCritical = "critical"
	SevWarning  = "warning"
	SevInfo     = "info"
)

// SeverityRank orders severities (critical first).
func SeverityRank(s string) int {
	switch s {
	case SevCritical:
		return 0
	case SevWarning:
		return 1
	}
	return 2
}

// Alert categories.
const (
	AlertNetworkSweep = "network-sweep"
	AlertAuth         = "authentication"
	AlertReliability  = "reliability"
	AlertResource     = "resource"
	AlertSystem       = "system"
)

// Alert is one entry in the Alerts & Incidents stream.
type Alert struct {
	ID       string            `json:"id"`
	Time     time.Time         `json:"time"`
	Severity string            `json:"severity"` // critical, warning, info
	Category string            `json:"category"`
	Title    Text              `json:"title"`
	Detail   Text              `json:"detail"`
	Source   string            `json:"source"` // radar, eventlog, audit, metrics, syspulse
	Fields   map[string]string `json:"fields,omitempty"`
	Count    int               `json:"count"` // occurrences folded into this alert
	Updated  time.Time         `json:"updated"`
	Acked    bool              `json:"acked"`
}

// Finding is one diagnosed issue produced by an event-log audit.
type Finding struct {
	ID        string            `json:"id"`
	Kind      string            `json:"kind"` // failed-logon, privileged-logon, service-crash, app-fault, bugcheck, unexpected-shutdown
	Severity  string            `json:"severity"`
	Title     Text              `json:"title"`
	Subject   string            `json:"subject"` // account, service, application, stop code…
	EventIDs  []uint32          `json:"eventIds"`
	Count     int               `json:"count"`
	First     time.Time         `json:"first"`
	Last      time.Time         `json:"last"`
	Details   map[string]string `json:"details,omitempty"`
	Diagnosis Text              `json:"diagnosis"`
	Fix       Text              `json:"fix"`
	Samples   []string          `json:"samples,omitempty"`
}

// AuditReport is the result of one diagnostic button press.
type AuditReport struct {
	Kind      string         `json:"kind"` // auth, reliability
	Started   time.Time      `json:"started"`
	Finished  time.Time      `json:"finished"`
	WindowH   int            `json:"windowHours"`
	Scanned   int            `json:"scanned"`
	ByEventID map[string]int `json:"byEventId"`
	BySev     map[string]int `json:"bySeverity"`
	Findings  []Finding      `json:"findings"`
	Errors    []string       `json:"errors,omitempty"`
	Notes     []Text         `json:"notes,omitempty"`
}

// Message is the WebSocket envelope.
type Message struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}
