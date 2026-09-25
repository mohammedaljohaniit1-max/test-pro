package hub

// SysPulse 2.0 hub extensions: the network anomaly radar, the Alerts &
// Incidents store, resource alerts and the one-click event-log audits.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/alerts"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/audit"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/netmon"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/radar"
)

// SelfTestIP is the documentation address (RFC 5737 TEST-NET-2) used by the
// radar self-test. It can never be a real peer.
const SelfTestIP = "198.51.100.77"

// SelfTestMAC is from the IANA documentation MAC range (RFC 7042).
const SelfTestMAC = "00-00-5E-00-53-01"

type v2 struct {
	radar    *radar.Detector
	rplat    radar.Platform
	alerts   *alerts.Store
	auditSrc audit.Source

	netPolls  int
	evPrimed  bool
	lastARP   time.Time
	resMu     sync.Mutex
	resHigh   map[string]int  // consecutive samples over the threshold
	resActive map[string]bool // currently alerted

	auditMu      sync.Mutex
	audits       map[string]model.AuditReport
	auditRunning map[string]bool
	radarTick    int
}

func (h *Hub) initV2() {
	h.radar = radar.New(radar.Config{Window: h.cfg.RadarWindow, Threshold: h.cfg.RadarThreshold,
		Cooldown: h.cfg.RadarCooldown, Allow: h.cfg.RadarAllow})
	h.alerts = alerts.New(h.cfg.AlertsMax, 10*time.Minute)
	h.resHigh = map[string]int{}
	h.resActive = map[string]bool{}
	h.audits = map[string]model.AuditReport{}
	h.auditRunning = map[string]bool{}
	h.alerts.OnChange(func(a model.Alert, isNew bool) {
		if h.Subscribers() == 0 {
			return
		}
		h.Broadcast("alert", map[string]any{"alert": a, "new": isNew})
		h.Broadcast("alertcounts", h.alerts.Counts())
	})
}

// Radar returns the connection-sweep detector.
func (h *Hub) Radar() *radar.Detector { return h.radar }

// Alerts returns the Alerts & Incidents store.
func (h *Hub) Alerts() *alerts.Store { return h.alerts }

// SetRadarPlatform enables ARP-table polling and MAC attribution.
func (h *Hub) SetRadarPlatform(p radar.Platform) { h.rplat = p }

// SetAuditSource enables the one-click event-log audits.
func (h *Hub) SetAuditSource(s audit.Source) { h.auditSrc = s }

// AuditAvailable reports whether audits can run.
func (h *Hub) AuditAvailable() bool { return h.auditSrc != nil }

// ---------------------------------------------------------------------------
// Radar
// ---------------------------------------------------------------------------

// ObserveRadar feeds connection attempts to the detector (called by the raw
// SYN sensor goroutines and by the socket-table sensor).
func (h *Hub) ObserveRadar(obs ...radar.Observation) {
	if len(obs) == 0 {
		return
	}
	h.handleIncidents(h.radar.Observe(obs...))
}

func (h *Hub) handleIncidents(incs []radar.Incident) {
	for _, inc := range incs {
		key := "sweep:" + inc.ID
		if inc.New {
			h.log.Warn("connection sweep detected", "id", inc.ID, "remote", inc.RemoteIP, "ports", inc.DistinctPorts, "range", inc.PortRange, "sensor", inc.Sensor)
			h.alerts.Raise(key, sweepAlert(inc))
			if h.Subscribers() > 0 {
				h.Broadcast("sweep", inc)
			}
			go h.attribute(inc)
			continue
		}
		h.alerts.Update(key, func(a *model.Alert) {
			a.Updated = inc.LastSeen
			a.Count = inc.Attempts
			a.Detail = sweepDetail(inc)
			a.Fields = sweepFields(inc)
		})
	}
}

// attribute resolves the MAC / interface of a sweeping host. It runs on its
// own goroutine because SendARP can block for a few seconds.
func (h *Hub) attribute(inc radar.Incident) {
	var n radar.Neighbor
	var onLink bool
	var err error
	switch {
	case inc.Test:
		n = radar.Neighbor{IP: inc.RemoteIP, MAC: SelfTestMAC, Interface: "self-test (synthetic)"}
		onLink = true
	case inc.MAC != "" && inc.OnLink:
		return // already attributed from the cached ARP table
	case h.rplat == nil:
		err = errors.New("hardware attribution unavailable on this platform")
	default:
		done := make(chan struct{})
		go func() {
			n, onLink, err = h.rplat.Resolve(inc.RemoteIP)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			err = errors.New("ARP resolution timed out")
		}
	}
	upd, ok := h.radar.Attribute(inc.ID, n, onLink, err)
	if !ok {
		return
	}
	h.alerts.Update("sweep:"+inc.ID, func(a *model.Alert) {
		a.Detail = sweepDetail(upd)
		a.Fields = sweepFields(upd)
	})
	if h.Subscribers() > 0 {
		h.Broadcast("sweep", upd)
	}
}

func sweepAlert(inc radar.Incident) model.Alert {
	title := model.T("High-Frequency Connection Sweep (Traffic Anomaly)", "مسح اتصالات عالي التردد (شذوذ في حركة المرور)")
	if inc.Test {
		title = model.T("[TEST] High-Frequency Connection Sweep (Traffic Anomaly)", "[اختبار] مسح اتصالات عالي التردد (شذوذ في حركة المرور)")
	}
	return model.Alert{Time: inc.Detected, Severity: model.SevCritical, Category: model.AlertNetworkSweep,
		Title: title, Detail: sweepDetail(inc), Source: "radar", Fields: sweepFields(inc), Count: inc.Attempts}
}

func sweepDetail(inc radar.Incident) model.Text {
	mac := inc.MAC
	macAr := inc.MAC
	if mac == "" {
		mac, macAr = "resolving…", "جارٍ التحديد…"
		if inc.AttrError != "" {
			mac, macAr = "unknown ("+inc.AttrError+")", "غير معروف ("+inc.AttrError+")"
		}
	} else if !inc.OnLink && inc.Gateway != "" {
		mac += " (via gateway " + inc.Gateway + ")"
		macAr += " (عبر البوابة " + inc.Gateway + ")"
	}
	return model.T(
		fmt.Sprintf("Remote host %s [MAC %s] contacted %d distinct local ports (%s) — %d within %s. Port range: %s.",
			inc.RemoteIP, mac, inc.DistinctPorts, strconv.Itoa(inc.Attempts)+" attempts", inc.PortsInWindow, "the detection window", inc.PortRange),
		fmt.Sprintf("المضيف البعيد %s [عنوان MAC ‏%s] اتصل بـ %d منفذًا محليًا مختلفًا (%d محاولة) — منها %d خلال نافذة الكشف. نطاق المنافذ: %s.",
			inc.RemoteIP, macAr, inc.DistinctPorts, inc.Attempts, inc.PortsInWindow, inc.PortRange))
}

func sweepFields(inc radar.Incident) map[string]string {
	f := map[string]string{
		"incident": inc.ID, "remoteIp": inc.RemoteIP, "mac": inc.MAC, "interface": inc.Interface,
		"portRange": inc.PortRange, "distinctPorts": strconv.Itoa(inc.DistinctPorts),
		"portMin": strconv.Itoa(int(inc.PortMin)), "portMax": strconv.Itoa(int(inc.PortMax)),
		"attempts": strconv.Itoa(inc.Attempts), "sensor": inc.Sensor,
		"detected": inc.Detected.UTC().Format(time.RFC3339Nano), "targets": strings.Join(inc.Targets, ","),
	}
	if inc.Gateway != "" {
		f["gateway"] = inc.Gateway
	}
	if inc.Test {
		f["test"] = "true"
	}
	return f
}

// feedTableSensor converts newly seen inbound TCP rows into observations.
// The very first poll lists every pre-existing socket and is skipped. When
// the raw SYN sensor is running it already sees every IPv4 attempt, so only
// IPv6 rows are taken from the table to avoid double counting.
func (h *Hub) feedTableSensor(d netmon.Diff, listening map[string]bool) {
	h.netPolls++
	if h.netPolls <= 1 || len(d.Added) == 0 {
		return
	}
	obs := radar.FromConnections(d.Added, listening)
	if h.radar.SensorActive(radar.SensorRaw) {
		kept := obs[:0]
		for _, o := range obs {
			if strings.Contains(o.RemoteIP, ":") {
				kept = append(kept, o)
			}
		}
		obs = kept
	}
	h.ObserveRadar(obs...)
}

// radarTickFn runs on the network cadence: closes quiet incidents, refreshes
// the ARP cache every 10 s and publishes the radar state.
func (h *Hub) radarTickFn() {
	for _, inc := range h.radar.Expire() {
		h.alerts.Update("sweep:"+inc.ID, func(a *model.Alert) { a.Fields = sweepFields(inc) })
	}
	if h.rplat != nil && time.Since(h.lastARP) > 10*time.Second {
		h.lastARP = time.Now()
		if ns, err := h.rplat.Neighbors(); err == nil {
			h.radar.SetNeighbors(ns)
		} else {
			h.log.Debug("ARP table read failed", "err", err)
		}
	}
	if h.Subscribers() > 0 {
		h.Broadcast("radar", h.radar.Snapshot(100))
	}
}

// RadarSelfTest injects a synthetic sweep from SelfTestIP through the full
// pipeline (detector → alert → dashboard banner and chime → attribution).
// ports is the number of distinct ports to "touch" (default 24).
func (h *Hub) RadarSelfTest(ports int) radar.Incident {
	if ports <= h.radar.Config().Threshold {
		ports = h.radar.Config().Threshold + 14
	}
	if ports > 1024 {
		ports = 1024
	}
	h.radar.Forget(SelfTestIP)
	now := time.Now()
	obs := make([]radar.Observation, 0, ports)
	for i := 0; i < ports; i++ {
		obs = append(obs, radar.Observation{Time: now.Add(time.Duration(i) * 40 * time.Millisecond / time.Duration(ports)),
			RemoteIP: SelfTestIP, RemotePort: uint16(40000 + i), LocalIP: "self-test", LocalPort: uint16(20 + i), Sensor: radar.SensorSelfTest})
	}
	incs := h.radar.Observe(obs...)
	h.handleIncidents(incs)
	for _, inc := range incs {
		return inc
	}
	return radar.Incident{}
}

// ---------------------------------------------------------------------------
// Alerts from other collectors
// ---------------------------------------------------------------------------

// eventAlerts raises alerts for fresh reliability events. The initial
// 7-day load only produces one informational summary.
func (h *Hub) eventAlerts(fresh []model.Event) {
	if !h.evPrimed {
		h.evPrimed = true
		crit, errs := 0, 0
		for _, e := range fresh {
			switch e.Level {
			case 1:
				crit++
			case 2:
				errs++
			}
		}
		h.alerts.Raise("", model.Alert{Severity: model.SevInfo, Category: model.AlertSystem, Source: "eventlog",
			Title: model.T("Event log baseline loaded", "تم تحميل خط الأساس لسجل الأحداث"),
			Detail: model.T(fmt.Sprintf("%d events read from %s: %d critical, %d errors. New events will raise alerts in real time.", len(fresh), strings.Join(h.cfg.Channels, " + "), crit, errs),
				fmt.Sprintf("تمت قراءة %d حدثًا من %s: %d حرج و %d خطأ. ستُنشئ الأحداث الجديدة تنبيهات فورية.", len(fresh), strings.Join(h.cfg.Channels, " + "), crit, errs)),
			Fields: map[string]string{"events": strconv.Itoa(len(fresh)), "critical": strconv.Itoa(crit), "errors": strconv.Itoa(errs)}})
		return
	}
	for _, e := range fresh {
		sev := ""
		switch {
		case e.Level == 1:
			sev = model.SevCritical
		case e.Level == 2 && e.Category != model.CatOther:
			sev = model.SevWarning
		case e.Level == 2:
			sev = model.SevInfo
		case e.Level == 3 && e.Category != model.CatOther:
			sev = model.SevInfo
		default:
			continue
		}
		cat := model.AlertReliability
		if e.Category == model.CatOther {
			cat = model.AlertSystem
		}
		msg := e.Message
		if len(msg) > 400 {
			msg = msg[:400] + "…"
		}
		h.alerts.Raise(fmt.Sprintf("ev:%s:%d", strings.ToLower(e.Provider), e.EventID), model.Alert{
			Time: e.Time, Severity: sev, Category: cat, Source: "eventlog",
			Title:  model.T(fmt.Sprintf("%s — event %d (%s)", e.Provider, e.EventID, e.LevelStr), fmt.Sprintf("%s — الحدث %d (%s)", e.Provider, e.EventID, levelAr(e.LevelStr))),
			Detail: model.T(msg, msg),
			Fields: map[string]string{"channel": e.Channel, "eventId": strconv.Itoa(int(e.EventID)), "provider": e.Provider, "category": e.Category, "recordId": strconv.FormatUint(e.RecordID, 10)},
		})
	}
}

func levelAr(l string) string {
	switch l {
	case "critical":
		return "حرج"
	case "error":
		return "خطأ"
	case "warning":
		return "تحذير"
	}
	return "معلومات"
}

// resourceAlerts applies hysteresis: an alert is raised after `need`
// consecutive samples above the limit and re-armed once the value drops
// 5 points below it.
func (h *Hub) resourceAlerts(m model.SystemMetrics) {
	type chk struct {
		key       string
		val, lim  float64
		need      int
		sev       string
		titleEn   string
		titleAr   string
		detailEn  string
		detailAr  string
		fieldName string
	}
	checks := []chk{
		{"cpu", m.CPUPercent, 90, 30, model.SevWarning, "Sustained high CPU usage", "استخدام مرتفع ومستمر للمعالج",
			fmt.Sprintf("CPU has been above 90%% for 30 samples (now %.1f%%). Check the Processes tab for the top consumer.", m.CPUPercent),
			fmt.Sprintf("تجاوز استخدام المعالج 90%% لمدة 30 عينة (حاليًا %.1f%%). راجع تبويب العمليات لمعرفة الأكثر استهلاكًا.", m.CPUPercent), "cpu"},
		{"mem", m.MemPercent, 92, 15, model.SevWarning, "Memory pressure", "ضغط على الذاكرة",
			fmt.Sprintf("Physical memory usage is %.1f%%. Applications may slow down as Windows pages to disk.", m.MemPercent),
			fmt.Sprintf("استخدام الذاكرة الفعلية %.1f%%. قد تتباطأ التطبيقات لأن Windows يبدأ بالترحيل إلى القرص.", m.MemPercent), "memory"},
	}
	for _, d := range m.Disks {
		sev := model.SevWarning
		if d.Percent >= 97 {
			sev = model.SevCritical
		}
		checks = append(checks, chk{"disk:" + d.Mount, d.Percent, 92, 1, sev, "Low disk space on " + d.Mount, "مساحة منخفضة على القرص " + d.Mount,
			fmt.Sprintf("%s is %.1f%% full. Free space below 8%% can break Windows Update and cause crashes. Run cleanmgr or Storage Sense.", d.Mount, d.Percent),
			fmt.Sprintf("القرص %s ممتلئ بنسبة %.1f%%. انخفاض المساحة الحرة عن 8%% قد يعطّل تحديثات Windows ويسبب أعطالًا. شغّل cleanmgr أو «استشعار التخزين».", d.Mount, d.Percent), "disk"})
	}
	h.resMu.Lock()
	var raise []chk
	for _, c := range checks {
		if c.val >= c.lim {
			h.resHigh[c.key]++
			if h.resHigh[c.key] >= c.need && !h.resActive[c.key] {
				h.resActive[c.key] = true
				raise = append(raise, c)
			}
		} else {
			h.resHigh[c.key] = 0
			if c.val < c.lim-5 {
				h.resActive[c.key] = false
			}
		}
	}
	h.resMu.Unlock()
	for _, c := range raise {
		h.alerts.Raise("res:"+c.key, model.Alert{Severity: c.sev, Category: model.AlertResource, Source: "metrics",
			Title: model.T(c.titleEn, c.titleAr), Detail: model.T(c.detailEn, c.detailAr),
			Fields: map[string]string{c.fieldName: strconv.FormatFloat(c.val, 'f', 1, 64), "threshold": strconv.FormatFloat(c.lim, 'f', 0, 64)}})
	}
}

// ---------------------------------------------------------------------------
// Audits
// ---------------------------------------------------------------------------

// ErrAuditBusy is returned when the same audit is already running.
var ErrAuditBusy = errors.New("audit already running")

// ErrAuditUnavailable is returned when no event source is configured.
var ErrAuditUnavailable = errors.New("event log audits are only available on Windows")

// RunAudit executes one audit kind, stores and broadcasts the report and
// raises alerts for critical / warning findings.
func (h *Hub) RunAudit(ctx context.Context, kind string, window time.Duration) (model.AuditReport, error) {
	if h.auditSrc == nil {
		return model.AuditReport{}, ErrAuditUnavailable
	}
	if kind != audit.KindAuth && kind != audit.KindReliability {
		return model.AuditReport{}, fmt.Errorf("unknown audit kind %q", kind)
	}
	h.auditMu.Lock()
	if h.auditRunning[kind] {
		h.auditMu.Unlock()
		return model.AuditReport{}, ErrAuditBusy
	}
	h.auditRunning[kind] = true
	h.auditMu.Unlock()
	if h.Subscribers() > 0 {
		h.Broadcast("auditstate", h.AuditState())
	}
	rep, err := audit.Run(ctx, h.auditSrc, kind, audit.Options{Window: window}, h.now())
	h.auditMu.Lock()
	delete(h.auditRunning, kind)
	if err == nil {
		h.audits[kind] = rep
	}
	h.auditMu.Unlock()
	if err != nil {
		if h.Subscribers() > 0 {
			h.Broadcast("auditstate", h.AuditState())
		}
		return rep, err
	}
	cat := model.AlertReliability
	if kind == audit.KindAuth {
		cat = model.AlertAuth
	}
	for _, f := range rep.Findings {
		if f.Severity == model.SevInfo {
			continue
		}
		h.alerts.Raise("audit:"+kind+":"+f.Kind+":"+strings.ToLower(f.Subject), model.Alert{
			Severity: f.Severity, Category: cat, Source: "audit", Title: f.Title, Detail: f.Diagnosis, Count: f.Count,
			Fields: map[string]string{"finding": f.ID, "kind": f.Kind, "subject": f.Subject, "count": strconv.Itoa(f.Count),
				"eventIds": joinIDs(f.EventIDs), "fix_en": f.Fix.En, "fix_ar": f.Fix.Ar},
		})
	}
	h.log.Info("audit finished", "kind", kind, "scanned", rep.Scanned, "findings", len(rep.Findings), "errors", len(rep.Errors))
	if h.Subscribers() > 0 {
		h.Broadcast("audit", rep)
		h.Broadcast("auditstate", h.AuditState())
	}
	return rep, nil
}

func joinIDs(ids []uint32) string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = strconv.Itoa(int(id))
	}
	return strings.Join(s, ",")
}

// AuditState lists the last report per kind and which audits are running.
type AuditState struct {
	Available bool                         `json:"available"`
	Running   []string                     `json:"running"`
	Reports   map[string]model.AuditReport `json:"reports"`
}

// AuditState returns the current audit state.
func (h *Hub) AuditState() AuditState {
	h.auditMu.Lock()
	defer h.auditMu.Unlock()
	st := AuditState{Available: h.auditSrc != nil, Running: []string{}, Reports: map[string]model.AuditReport{}}
	for k := range h.auditRunning {
		st.Running = append(st.Running, k)
	}
	sort.Strings(st.Running)
	for k, v := range h.audits {
		st.Reports[k] = v
	}
	return st
}

func alertsFilter(limit int) alerts.Filter { return alerts.Filter{Limit: limit} }

// Metrics returns the latest system sample.
func (h *Hub) Metrics() model.SystemMetrics { return h.sys.Last() }
