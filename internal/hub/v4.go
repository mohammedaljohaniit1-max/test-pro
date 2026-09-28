package hub

// SysPulse 4.0 hub extensions: per-interface throughput, the Windows
// services monitor, the configurable threshold rules engine (which replaces
// the hard-coded resource alerts of 2.x/3.x), the process hierarchy
// metadata and the executive health score.

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/ifstats"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/rules"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/services"
)

type v4 struct {
	rules *rules.Engine
	ifmon *ifstats.Monitor
	svc   *services.Monitor

	v4mu      sync.RWMutex
	health    model.Health
	sockByPID map[uint32]int
	ifPrevErr map[uint32]uint64
	ifPrevAt  time.Time
	metaTick  int
	svcTick   int
}

// ProcMeta enriches the process list for the hierarchy view.
type ProcMeta struct {
	Services map[uint32][]string `json:"services"`
	Sockets  map[uint32]int      `json:"sockets"`
}

// InterfacesState is the payload of the "ifstats" message.
type InterfacesState struct {
	Interfaces []model.IfStat             `json:"interfaces"`
	History    map[uint32]model.IfHistory `json:"history,omitempty"`
	TotalIn    float64                    `json:"totalIn"`
	TotalOut   float64                    `json:"totalOut"`
	Error      string                     `json:"error,omitempty"`
	Available  bool                       `json:"available"`
	At         int64                      `json:"at"`
}

// ServicesState is the payload of the "services" message.
type ServicesState struct {
	Services  []model.Service      `json:"services,omitempty"`
	Summary   model.ServiceSummary `json:"summary"`
	Available bool                 `json:"available"`
}

// RulesState is the payload of the "rules" message and GET /api/rules.
type RulesState struct {
	Rules   []rules.Rule      `json:"rules"`
	States  []rules.RuleState `json:"states"`
	Catalog []rules.Metric    `json:"catalog"`
	File    string            `json:"file,omitempty"`
}

func (h *Hub) initV4() {
	h.rules = rules.New(h.cfg.RulesFile)
	h.sockByPID = map[uint32]int{}
	h.ifPrevErr = map[uint32]uint64{}
}

// SetInterfaceReader enables per-NIC throughput telemetry.
func (h *Hub) SetInterfaceReader(r ifstats.Reader) { h.ifmon = ifstats.New(r, 60) }

// SetServiceLister enables the services monitor.
func (h *Hub) SetServiceLister(l services.Lister) { h.svc = services.New(l) }

// Rules exposes the rules engine (HTTP CRUD).
func (h *Hub) Rules() *rules.Engine { return h.rules }

// RulesState returns rules, runtime states and the metric catalog.
func (h *Hub) RulesState() RulesState {
	return RulesState{Rules: h.rules.List(), States: h.rules.States(), Catalog: rules.Catalog, File: h.rules.File()}
}

// BroadcastRules pushes the rule set after a change.
func (h *Hub) BroadcastRules() {
	if h.Subscribers() > 0 {
		h.Broadcast("rules", h.RulesState())
	}
}

// Interfaces returns the latest interface throughput.
func (h *Hub) Interfaces() InterfacesState {
	if h.ifmon == nil {
		return InterfacesState{Error: "interface counters are not available on this platform"}
	}
	s := h.ifmon.Last()
	in, out := ifstats.Totals(s)
	return InterfacesState{Interfaces: s, History: h.ifmon.History(), TotalIn: in, TotalOut: out, Error: h.ifmon.Err(), Available: true, At: h.now().UnixMilli()}
}

// Services returns the latest service list and summary.
func (h *Hub) Services() ServicesState {
	if h.svc == nil {
		return ServicesState{Summary: model.ServiceSummary{Error: "the services monitor is not available on this platform"}}
	}
	return ServicesState{Services: h.svc.List(), Summary: h.svc.Summary(), Available: true}
}

// Health returns the latest health score.
func (h *Hub) Health() model.Health {
	h.v4mu.RLock()
	defer h.v4mu.RUnlock()
	return h.health
}

// ProcMeta returns service-host and socket counts per PID.
func (h *Hub) ProcMeta() ProcMeta {
	m := ProcMeta{Services: map[uint32][]string{}, Sockets: map[uint32]int{}}
	if h.svc != nil {
		m.Services = h.svc.ByPID()
	}
	h.v4mu.RLock()
	for k, v := range h.sockByPID {
		m.Sockets[k] = v
	}
	h.v4mu.RUnlock()
	return m
}

// ProcessTree builds the parent/child hierarchy of the latest sample.
func (h *Hub) ProcessTree() []*model.ProcNode {
	meta := h.ProcMeta()
	return BuildTree(h.procs.Last(), meta.Services)
}

// runV4 registers the SysPulse 4.0 collectors.
func (h *Hub) runV4(loop func(time.Duration, func())) {
	if h.ifmon != nil {
		loop(h.cfg.NetEvery, h.collectInterfaces)
	}
	if h.svc != nil {
		loop(h.cfg.ServicesEvery, h.collectServices)
	}
}

// ---------------------------------------------------------------------------
// Rule evaluation → alerts
// ---------------------------------------------------------------------------

func (h *Hub) fire(fs []rules.Firing) {
	for _, f := range fs {
		title, detail := rules.Describe(f)
		m, _ := rules.CatalogByKey(f.Rule.Metric)
		key := f.Key()
		val := strconv.FormatFloat(f.Value, 'f', 2, 64)
		if f.Resolved {
			h.alerts.Update(key, func(a *model.Alert) {
				a.Detail = model.T(a.Detail.En+" "+detail.En, a.Detail.Ar+" "+detail.Ar)
				if a.Fields == nil {
					a.Fields = map[string]string{}
				}
				a.Fields["resolved"] = h.now().UTC().Format(time.RFC3339)
				a.Fields["recoveredAt"] = val
			})
			continue
		}
		fields := map[string]string{"rule": f.Rule.ID, "metric": f.Rule.Metric, "value": val,
			"condition": f.Rule.Op + " " + strconv.FormatFloat(f.Rule.Threshold, 'f', -1, 64) + " " + m.Unit,
			"for":       strconv.Itoa(f.Rule.ForSec) + "s"}
		if f.Instance != "" {
			fields["instance"] = f.Instance
		}
		h.alerts.Raise(key, model.Alert{Severity: f.Rule.Severity, Category: m.Category, Source: "rules",
			Title: title, Detail: detail, Fields: fields})
	}
}

func (h *Hub) eval(metric string, obs ...rules.Obs) { h.fire(h.rules.Evaluate(metric, obs)) }

// evalHostRules runs on every metrics sample.
func (h *Hub) evalHostRules(m model.SystemMetrics, ps []model.Process) {
	h.eval(rules.MetricCPU, rules.Obs{Value: m.CPUPercent})
	h.eval(rules.MetricCPUKernel, rules.Obs{Value: m.KernelPct})
	if len(m.PerCore) > 0 {
		max, idx := 0.0, 0
		for i, v := range m.PerCore {
			if v > max {
				max, idx = v, i
			}
		}
		h.eval(rules.MetricCPUCoreMax, rules.Obs{Value: max, Label: "CPU " + strconv.Itoa(idx)})
	}
	h.eval(rules.MetricMem, rules.Obs{Value: m.MemPercent})
	if m.CommitTotal > 0 {
		h.eval(rules.MetricCommit, rules.Obs{Value: float64(m.CommitUsed) / float64(m.CommitTotal) * 100})
	}
	if m.Mem != nil && m.Mem.Handles > 0 {
		h.eval(rules.MetricHandles, rules.Obs{Value: float64(m.Mem.Handles)})
	}
	disks := make([]rules.Obs, 0, len(m.Disks))
	for _, d := range m.Disks {
		disks = append(disks, rules.Obs{Instance: d.Mount, Value: d.Percent})
	}
	h.eval(rules.MetricDisk, disks...)

	// Per-process rules aggregate by image name (the worst instance wins) so a
	// scope such as "chrome.exe" tracks the heaviest Chrome process.
	type agg struct {
		cpu, mem, thr float64
		pid           uint32
	}
	by := map[string]*agg{}
	for _, p := range ps {
		if !p.Access || p.PID == 0 {
			continue
		}
		k := strings.ToLower(p.Name)
		a := by[k]
		if a == nil {
			a = &agg{}
			by[k] = a
		}
		if p.CPUPercent >= a.cpu {
			a.cpu, a.pid = p.CPUPercent, p.PID
		}
		if v := float64(p.WorkingSet) / (1 << 20); v > a.mem {
			a.mem = v
		}
		if v := float64(p.Threads); v > a.thr {
			a.thr = v
		}
	}
	cpuO, memO, thrO := make([]rules.Obs, 0, len(by)), make([]rules.Obs, 0, len(by)), make([]rules.Obs, 0, len(by))
	for k, a := range by {
		lbl := k + " (PID " + strconv.FormatUint(uint64(a.pid), 10) + ")"
		cpuO = append(cpuO, rules.Obs{Instance: k, Value: a.cpu, Label: lbl})
		memO = append(memO, rules.Obs{Instance: k, Value: a.mem, Label: k})
		thrO = append(thrO, rules.Obs{Instance: k, Value: a.thr, Label: k})
	}
	h.eval(rules.MetricProcCPU, cpuO...)
	h.eval(rules.MetricProcMem, memO...)
	h.eval(rules.MetricProcThreads, thrO...)

	hl := h.computeHealth(m)
	h.v4mu.Lock()
	h.health = hl
	h.v4mu.Unlock()
	h.eval(rules.MetricHealth, rules.Obs{Value: hl.Score})
}

// evalNetRules runs on every connection-table poll.
func (h *Hub) evalNetRules(st model.NetStats, conns []model.Connection) {
	h.eval(rules.MetricSocketsNew, rules.Obs{Value: st.NewPerSec})
	h.eval(rules.MetricSocketsTotal, rules.Obs{Value: float64(st.Total)})
	h.eval(rules.MetricEstablished, rules.Obs{Value: float64(st.ByState["ESTABLISHED"])})
	by := make(map[uint32]int, 64)
	for _, c := range conns {
		by[c.PID]++
	}
	h.v4mu.Lock()
	h.sockByPID = by
	h.v4mu.Unlock()
}

func (h *Hub) collectInterfaces() {
	s, err := h.ifmon.Sample()
	if err != nil {
		h.log.Debug("interface counters failed", "err", err)
	}
	now := h.now()
	h.v4mu.Lock()
	dt := now.Sub(h.ifPrevAt).Seconds()
	prev := h.ifPrevErr
	next := make(map[uint32]uint64, len(s))
	h.v4mu.Unlock()
	in, out, util, errs := make([]rules.Obs, 0, len(s)), make([]rules.Obs, 0, len(s)), make([]rules.Obs, 0, len(s)), make([]rules.Obs, 0, len(s))
	for _, x := range s {
		if x.Kind == model.IfLoopback || !x.Up {
			continue
		}
		in = append(in, rules.Obs{Instance: x.Name, Value: x.InBps / 1e6})
		out = append(out, rules.Obs{Instance: x.Name, Value: x.OutBps / 1e6})
		if x.SpeedBps > 0 {
			util = append(util, rules.Obs{Instance: x.Name, Value: x.Util})
		}
		tot := x.Errors + x.Discards
		next[x.Index] = tot
		if p, ok := prev[x.Index]; ok && dt > 0 && tot >= p {
			errs = append(errs, rules.Obs{Instance: x.Name, Value: float64(tot-p) / dt})
		}
	}
	h.v4mu.Lock()
	h.ifPrevErr, h.ifPrevAt = next, now
	h.v4mu.Unlock()
	h.eval(rules.MetricNetIn, in...)
	h.eval(rules.MetricNetOut, out...)
	h.eval(rules.MetricIfUtil, util...)
	h.eval(rules.MetricIfErrors, errs...)
	if h.Subscribers() == 0 {
		return
	}
	st := h.Interfaces()
	st.History = nil // clients keep their own rings after the snapshot
	h.Broadcast("ifstats", st)
}

func (h *Hub) collectServices() {
	changes, err := h.svc.Refresh()
	if err != nil {
		h.log.Debug("service enumeration failed", "err", err)
	}
	list := h.svc.List()
	sum := h.svc.Summary()
	if err == nil {
		h.eval(rules.MetricSvcAutoStopped, rules.Obs{Value: float64(sum.AutoFailed)})
		obs := make([]rules.Obs, 0, len(list))
		for _, s := range list {
			v := 0.0
			if s.State == model.SvcStopped {
				v = 1
			}
			obs = append(obs, rules.Obs{Instance: s.Name, Value: v, Label: s.Display})
		}
		h.eval(rules.MetricSvcDown, obs...)
	}
	for _, c := range changes {
		// An automatic service that stopped with a non-zero exit code is a
		// reliability signal on its own, independent of user rules.
		if services.IsAuto(c.Service.StartType) && services.Failed(c.Service) {
			h.alerts.Raise("svc:"+c.Service.Name, model.Alert{Severity: model.SevWarning, Category: model.AlertReliability, Source: "services",
				Title: model.T("Automatic service stopped: "+c.Service.Display, "توقفت خدمة تلقائية: "+c.Service.Display),
				Detail: model.T("The service "+c.Service.Name+" (start type "+c.Service.StartType+") went from "+c.From+" to stopped with exit code "+strconv.FormatUint(uint64(c.Service.ExitCode), 10)+".",
					"انتقلت الخدمة "+c.Service.Name+" (نوع البدء "+c.Service.StartType+") من "+c.From+" إلى متوقفة برمز خروج "+strconv.FormatUint(uint64(c.Service.ExitCode), 10)+"."),
				Fields: map[string]string{"service": c.Service.Name, "exitCode": strconv.FormatUint(uint64(c.Service.ExitCode), 10), "from": c.From}})
		}
	}
	if h.Subscribers() == 0 {
		return
	}
	h.svcTick++
	st := ServicesState{Summary: sum, Available: true}
	if len(changes) > 0 || h.svcTick%6 == 1 {
		st.Services = list
	}
	h.Broadcast("services", st)
}

// broadcastV4 runs after every metrics sample.
func (h *Hub) broadcastV4() {
	h.Broadcast("health", h.Health())
	h.Broadcast("rulestate", h.rules.States())
	h.metaTick++
	if h.metaTick%3 == 1 {
		h.Broadcast("procmeta", h.ProcMeta())
	}
}

// ---------------------------------------------------------------------------
// Health score
// ---------------------------------------------------------------------------

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// computeHealth derives a 0-100 score from resource pressure, open alerts,
// active sweeps and stopped automatic services. Every deduction is listed.
func (h *Hub) computeHealth(m model.SystemMetrics) model.Health {
	var fs []model.HealthFactor
	add := func(key string, pen, val float64, en, ar string) {
		if pen > 0.05 {
			fs = append(fs, model.HealthFactor{Key: key, Penalty: round1(pen), Value: round1(val), Detail: model.T(en, ar)})
		}
	}
	add("cpu", clamp((m.CPUPercent-70)*0.6, 0, 18), m.CPUPercent, "Processor load above 70%", "حمل المعالج أعلى من 70%")
	add("memory", clamp((m.MemPercent-75)*0.8, 0, 20), m.MemPercent, "Physical memory above 75%", "الذاكرة الفعلية أعلى من 75%")
	if m.CommitTotal > 0 {
		c := float64(m.CommitUsed) / float64(m.CommitTotal) * 100
		add("commit", clamp((c-80)*0.8, 0, 15), c, "Commit charge above 80% of the limit", "الذاكرة الملتزمة أعلى من 80% من الحد")
	}
	worst := 0.0
	for _, d := range m.Disks {
		if d.Percent > worst {
			worst = d.Percent
		}
	}
	add("disk", clamp((worst-85)*1.5, 0, 20), worst, "Fullest volume above 85%", "أكثر وحدات التخزين امتلاءً أعلى من 85%")
	crit, warn := 0, 0
	for _, a := range h.alerts.List(alertsFilter(500)) {
		if a.Acked || a.Fields["resolved"] != "" {
			continue
		}
		switch a.Severity {
		case model.SevCritical:
			crit++
		case model.SevWarning:
			warn++
		}
	}
	add("alerts-critical", clamp(float64(crit)*8, 0, 24), float64(crit), "Unacknowledged critical alerts", "تنبيهات حرجة غير مُقرّ بها")
	add("alerts-warning", clamp(float64(warn)*1.5, 0, 9), float64(warn), "Unacknowledged warnings", "تحذيرات غير مُقرّ بها")
	if n := h.radar.ActiveCount(); n > 0 {
		add("radar", clamp(float64(n)*15, 0, 30), float64(n), "Active connection sweeps", "عمليات مسح اتصال نشطة")
	}
	if h.svc != nil {
		if s := h.svc.Summary(); s.AutoFailed > 0 {
			add("services", clamp(float64(s.AutoFailed)*3, 0, 12), float64(s.AutoFailed), "Automatic services stopped with an error", "خدمات تلقائية متوقفة بخطأ")
		}
	}
	score := 100.0
	for _, f := range fs {
		score -= f.Penalty
	}
	score = round1(clamp(score, 0, 100))
	grade := "excellent"
	switch {
	case score < 50:
		grade = "critical"
	case score < 75:
		grade = "degraded"
	case score < 90:
		grade = "good"
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].Penalty > fs[j].Penalty })
	return model.Health{Score: score, Grade: grade, Factors: fs, At: h.now().UnixMilli()}
}

func round1(v float64) float64 {
	if v < 0 {
		return -round1(-v)
	}
	return float64(int64(v*10+0.5)) / 10
}

// ---------------------------------------------------------------------------
// Process hierarchy
// ---------------------------------------------------------------------------

// BuildTree links processes by PPID. A process whose parent is missing or
// was started after it (PID reuse on Windows) becomes a root. Subtree CPU and
// working set are aggregated; siblings are ordered by subtree CPU.
func BuildTree(ps []model.Process, svcByPID map[uint32][]string) []*model.ProcNode {
	nodes := make(map[uint32]*model.ProcNode, len(ps))
	for _, p := range ps {
		n := &model.ProcNode{Process: p}
		if s := svcByPID[p.PID]; len(s) > 0 {
			n.Services = append([]string(nil), s...)
			sort.Strings(n.Services)
		}
		nodes[p.PID] = n
	}
	var roots []*model.ProcNode
	for _, p := range ps {
		n := nodes[p.PID]
		par, ok := nodes[p.PPID]
		if !ok || p.PPID == p.PID || p.PID == 0 || (par.StartedMs != 0 && p.StartedMs != 0 && par.StartedMs > p.StartedMs) {
			roots = append(roots, n)
			continue
		}
		par.Children = append(par.Children, n)
	}
	var walk func(n *model.ProcNode, depth int, guard map[uint32]bool)
	walk = func(n *model.ProcNode, depth int, guard map[uint32]bool) {
		guard[n.PID] = true
		n.Depth = depth
		n.SubCPU, n.SubWS, n.Descendants = n.CPUPercent, n.WorkingSet, 0
		kids := n.Children[:0]
		for _, c := range n.Children {
			if guard[c.PID] {
				continue // defensive: PPID cycle
			}
			walk(c, depth+1, guard)
			n.SubCPU += c.SubCPU
			n.SubWS += c.SubWS
			n.Descendants += 1 + c.Descendants
			kids = append(kids, c)
		}
		n.Children = kids
		sortNodes(n.Children)
	}
	guard := map[uint32]bool{}
	for _, r := range roots {
		walk(r, 0, guard)
	}
	sortNodes(roots)
	return roots
}

func sortNodes(ns []*model.ProcNode) {
	sort.Slice(ns, func(i, j int) bool {
		if ns[i].SubCPU != ns[j].SubCPU {
			return ns[i].SubCPU > ns[j].SubCPU
		}
		if ns[i].SubWS != ns[j].SubWS {
			return ns[i].SubWS > ns[j].SubWS
		}
		return ns[i].PID < ns[j].PID
	})
}
