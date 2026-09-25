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

// Message is the WebSocket envelope.
type Message struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}
