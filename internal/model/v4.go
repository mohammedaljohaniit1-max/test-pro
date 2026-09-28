package model

// SysPulse 4.0 telemetry types: per-core CPU, memory composition, network
// interface throughput, Windows services, configurable alert rules and the
// executive health score.

// MemDetail is the memory composition reported alongside SystemMetrics.
// On Windows it comes from GlobalMemoryStatusEx + GetPerformanceInfo.
type MemDetail struct {
	Available      uint64 `json:"available"`      // bytes immediately usable (free + standby)
	Cached         uint64 `json:"cached"`         // system file cache (standby + modified + cache WS)
	KernelPaged    uint64 `json:"kernelPaged"`    // paged pool
	KernelNonpaged uint64 `json:"kernelNonpaged"` // non-paged pool
	CommitPeak     uint64 `json:"commitPeak"`
	PageFileTotal  uint64 `json:"pageFileTotal"`
	Handles        uint32 `json:"handles"`
}

// Interface kinds.
const (
	IfEthernet = "ethernet"
	IfWiFi     = "wifi"
	IfLoopback = "loopback"
	IfTunnel   = "tunnel"
	IfVirtual  = "virtual"
	IfCellular = "cellular"
	IfOther    = "other"
)

// IfStat is the live throughput of one network interface.
type IfStat struct {
	Index    uint32  `json:"index"`
	Name     string  `json:"name"` // friendly name / alias ("Wi-Fi", "Ethernet 2")
	Desc     string  `json:"desc,omitempty"`
	Kind     string  `json:"kind"`
	Physical bool    `json:"physical"`
	Up       bool    `json:"up"`
	MAC      string  `json:"mac,omitempty"`
	SpeedBps uint64  `json:"speed"` // link speed, bits per second (0 = unknown)
	MTU      uint32  `json:"mtu,omitempty"`
	InBps    float64 `json:"inBps"`  // bytes per second received
	OutBps   float64 `json:"outBps"` // bytes per second sent
	InTotal  uint64  `json:"inTotal"`
	OutTotal uint64  `json:"outTotal"`
	InPkts   float64 `json:"inPps"`
	OutPkts  float64 `json:"outPps"`
	Errors   uint64  `json:"errors"`   // cumulative in+out errors
	Discards uint64  `json:"discards"` // cumulative in+out discards
	Util     float64 `json:"util"`     // % of link speed used by max(in, out)
}

// IfHistory holds recent per-interface samples for the sparklines.
type IfHistory struct {
	Name string    `json:"name"`
	In   []float64 `json:"in"`
	Out  []float64 `json:"out"`
}

// Service states and start types (Service Control Manager vocabulary).
const (
	SvcRunning  = "running"
	SvcStopped  = "stopped"
	SvcStarting = "start-pending"
	SvcStopping = "stop-pending"
	SvcPaused   = "paused"
	SvcOther    = "other"

	StartAuto     = "auto"
	StartDelayed  = "auto-delayed"
	StartManual   = "manual"
	StartDisabled = "disabled"
	StartBoot     = "boot"
	StartSystem   = "system"
)

// Service is one Windows service (or systemd unit in the preview build).
type Service struct {
	Name        string `json:"name"`
	Display     string `json:"display"`
	State       string `json:"state"`
	StartType   string `json:"startType"`
	PID         uint32 `json:"pid,omitempty"`
	Type        string `json:"type,omitempty"` // own-process, share-process, driver…
	Account     string `json:"account,omitempty"`
	Binary      string `json:"binary,omitempty"`
	Description string `json:"description,omitempty"`
	ExitCode    uint32 `json:"exitCode,omitempty"`
}

// ServiceSummary aggregates service states for badges and health.
type ServiceSummary struct {
	Total       int    `json:"total"`
	Running     int    `json:"running"`
	Stopped     int    `json:"stopped"`
	AutoStopped int    `json:"autoStopped"` // auto-start services that are not running (includes benign trigger-start exits)
	AutoFailed  int    `json:"autoFailed"`  // auto-start services stopped with a failure exit code
	Disabled    int    `json:"disabled"`
	Error       string `json:"error,omitempty"`
	Updated     int64  `json:"updated"`
}

// ProcNode is one node of the process hierarchy.
type ProcNode struct {
	Process
	Depth       int         `json:"depth"`
	SubCPU      float64     `json:"subCpu"` // CPU of the node plus all descendants
	SubWS       uint64      `json:"subWs"`
	Descendants int         `json:"descendants"`
	Services    []string    `json:"services,omitempty"`
	Children    []*ProcNode `json:"children,omitempty"`
}

// HealthFactor explains one deduction from the health score.
type HealthFactor struct {
	Key     string  `json:"key"`
	Penalty float64 `json:"penalty"`
	Value   float64 `json:"value"`
	Detail  Text    `json:"detail"`
}

// Health is the executive host health score (0-100).
type Health struct {
	Score   float64        `json:"score"`
	Grade   string         `json:"grade"` // excellent, good, degraded, critical
	Factors []HealthFactor `json:"factors"`
	At      int64          `json:"at"`
}
