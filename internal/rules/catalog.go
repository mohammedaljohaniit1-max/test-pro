package rules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// Metric keys.
const (
	MetricCPU            = "cpu"
	MetricCPUCoreMax     = "cpu_core_max"
	MetricCPUKernel      = "cpu_kernel"
	MetricMem            = "mem"
	MetricCommit         = "commit"
	MetricDisk           = "disk"
	MetricProcCPU        = "proc_cpu"
	MetricProcMem        = "proc_mem"
	MetricProcThreads    = "proc_threads"
	MetricSocketsNew     = "sockets_new"
	MetricSocketsTotal   = "sockets_total"
	MetricEstablished    = "established"
	MetricNetIn          = "net_in"
	MetricNetOut         = "net_out"
	MetricIfUtil         = "if_util"
	MetricIfErrors       = "if_errors"
	MetricSvcAutoStopped = "svc_auto_stopped"
	MetricSvcDown        = "svc_down"
	MetricHandles        = "handles"
	MetricHealth         = "health"
)

// Metric describes an alertable signal.
type Metric struct {
	Key        string     `json:"key"`
	Label      model.Text `json:"label"`
	Unit       string     `json:"unit"` // %, MB, MB/s, /s, count, score
	Group      string     `json:"group"`
	Scoped     bool       `json:"scoped"`
	ScopeHint  model.Text `json:"scopeHint,omitempty"`
	Min        float64    `json:"min"`
	Max        float64    `json:"max"`
	Hysteresis float64    `json:"hysteresis"`
	Category   string     `json:"category"` // alert category
}

// Catalog lists every metric the engine can evaluate.
var Catalog = []Metric{
	{Key: MetricCPU, Label: model.T("Total CPU utilisation", "إجمالي استخدام المعالج"), Unit: "%", Group: "cpu", Max: 100, Hysteresis: 5, Category: model.AlertResource},
	{Key: MetricCPUCoreMax, Label: model.T("Busiest logical core", "أكثر نواة منطقية انشغالًا"), Unit: "%", Group: "cpu", Max: 100, Hysteresis: 5, Category: model.AlertResource},
	{Key: MetricCPUKernel, Label: model.T("Kernel (privileged) CPU time", "وقت المعالج في النواة (المميز)"), Unit: "%", Group: "cpu", Max: 100, Hysteresis: 5, Category: model.AlertResource},
	{Key: MetricMem, Label: model.T("Physical memory in use", "الذاكرة الفعلية المستخدمة"), Unit: "%", Group: "memory", Max: 100, Hysteresis: 3, Category: model.AlertResource},
	{Key: MetricCommit, Label: model.T("Commit charge of limit", "الذاكرة الملتزمة من الحد"), Unit: "%", Group: "memory", Max: 100, Hysteresis: 3, Category: model.AlertResource},
	{Key: MetricHandles, Label: model.T("System handle count", "عدد المقابض في النظام"), Unit: "count", Group: "memory", Max: 1e8, Hysteresis: 1000, Category: model.AlertResource},
	{Key: MetricDisk, Label: model.T("Volume space used", "المساحة المستخدمة من وحدة التخزين"), Unit: "%", Group: "storage", Scoped: true, ScopeHint: model.T(`volume, e.g. C:\`, `وحدة تخزين، مثل C:\`), Max: 100, Hysteresis: 2, Category: model.AlertResource},
	{Key: MetricProcCPU, Label: model.T("Single-process CPU", "معالج عملية واحدة"), Unit: "%", Group: "process", Scoped: true, ScopeHint: model.T("process name, e.g. chrome.exe or msedge*", "اسم العملية، مثل chrome.exe أو msedge*"), Max: 100, Hysteresis: 5, Category: model.AlertResource},
	{Key: MetricProcMem, Label: model.T("Single-process working set", "مجموعة العمل لعملية واحدة"), Unit: "MB", Group: "process", Scoped: true, ScopeHint: model.T("process name glob", "نمط اسم العملية"), Max: 1 << 22, Hysteresis: 64, Category: model.AlertResource},
	{Key: MetricProcThreads, Label: model.T("Single-process thread count", "عدد خيوط عملية واحدة"), Unit: "count", Group: "process", Scoped: true, ScopeHint: model.T("process name glob", "نمط اسم العملية"), Max: 1e6, Hysteresis: 10, Category: model.AlertResource},
	{Key: MetricSocketsNew, Label: model.T("New sockets per second (burst)", "المقابس الجديدة في الثانية (اندفاع)"), Unit: "/s", Group: "network", Max: 1e6, Hysteresis: 10, Category: model.AlertNetwork},
	{Key: MetricSocketsTotal, Label: model.T("Open sockets", "المقابس المفتوحة"), Unit: "count", Group: "network", Max: 1e7, Hysteresis: 50, Category: model.AlertNetwork},
	{Key: MetricEstablished, Label: model.T("Established TCP connections", "اتصالات TCP القائمة"), Unit: "count", Group: "network", Max: 1e7, Hysteresis: 20, Category: model.AlertNetwork},
	{Key: MetricNetIn, Label: model.T("Interface receive rate", "معدل الاستقبال على الواجهة"), Unit: "MB/s", Group: "network", Scoped: true, ScopeHint: model.T("interface, e.g. Wi-Fi or Ethernet*", "الواجهة، مثل Wi-Fi أو Ethernet*"), Max: 1e5, Hysteresis: 0.5, Category: model.AlertNetwork},
	{Key: MetricNetOut, Label: model.T("Interface send rate", "معدل الإرسال على الواجهة"), Unit: "MB/s", Group: "network", Scoped: true, ScopeHint: model.T("interface name glob", "نمط اسم الواجهة"), Max: 1e5, Hysteresis: 0.5, Category: model.AlertNetwork},
	{Key: MetricIfUtil, Label: model.T("Interface link utilisation", "استخدام سعة رابط الواجهة"), Unit: "%", Group: "network", Scoped: true, ScopeHint: model.T("interface name glob", "نمط اسم الواجهة"), Max: 100, Hysteresis: 10, Category: model.AlertNetwork},
	{Key: MetricIfErrors, Label: model.T("Interface errors + discards per second", "أخطاء ومهملات الواجهة في الثانية"), Unit: "/s", Group: "network", Scoped: true, ScopeHint: model.T("interface name glob", "نمط اسم الواجهة"), Max: 1e6, Hysteresis: 1, Category: model.AlertNetwork},
	{Key: MetricSvcAutoStopped, Label: model.T("Automatic services stopped with an error", "خدمات تلقائية متوقفة بخطأ"), Unit: "count", Group: "services", Max: 1e4, Category: model.AlertReliability},
	{Key: MetricSvcDown, Label: model.T("Specific service stopped (1 = stopped)", "خدمة محددة متوقفة (1 = متوقفة)"), Unit: "state", Group: "services", Scoped: true, ScopeHint: model.T("service name, e.g. Spooler, WinDefend", "اسم الخدمة، مثل Spooler أو WinDefend"), Max: 1, Category: model.AlertReliability},
	{Key: MetricHealth, Label: model.T("Host health score", "درجة صحة الجهاز"), Unit: "score", Group: "health", Max: 100, Hysteresis: 5, Category: model.AlertSystem},
}

// CatalogByKey finds a metric.
func CatalogByKey(k string) (Metric, bool) {
	for _, m := range Catalog {
		if m.Key == k {
			return m, true
		}
	}
	return Metric{}, false
}

func fmtVal(v float64, unit string) string {
	s := strconv.FormatFloat(v, 'f', 1, 64)
	s = strings.TrimSuffix(s, ".0")
	switch unit {
	case "%":
		return s + "%"
	case "count", "state", "score":
		return s
	}
	return s + " " + unit
}

// Describe builds the bilingual alert title and detail of a firing.
func Describe(f Firing) (title, detail model.Text) {
	m, _ := CatalogByKey(f.Rule.Metric)
	title = model.T(f.Rule.Name, f.Rule.NameAr)
	if title.Ar == "" {
		title.Ar = f.Rule.Name
	}
	who := f.Label
	if who == "" {
		who = f.Instance
	}
	whoEn, whoAr := "", ""
	if who != "" {
		whoEn, whoAr = " on "+who, " على "+who
		title.En += " — " + who
		title.Ar += " — " + who
	}
	val, thr := fmtVal(f.Value, m.Unit), fmtVal(f.Rule.Threshold, m.Unit)
	dur := ""
	durAr := ""
	if f.Rule.ForSec > 0 {
		dur = fmt.Sprintf(" for at least %d s", f.Rule.ForSec)
		durAr = fmt.Sprintf(" لمدة %d ث على الأقل", f.Rule.ForSec)
	}
	if f.Resolved {
		detail = model.T(fmt.Sprintf("Recovered: %s%s is back to %s (rule %s %s).", m.Label.En, whoEn, val, f.Rule.Op, thr),
			fmt.Sprintf("تعافٍ: %s%s عاد إلى %s (القاعدة %s %s).", m.Label.Ar, whoAr, val, f.Rule.Op, thr))
		return
	}
	detail = model.T(fmt.Sprintf("%s%s is %s — rule condition %s %s held%s.", m.Label.En, whoEn, val, f.Rule.Op, thr, dur),
		fmt.Sprintf("%s%s يساوي %s — تحقق شرط القاعدة %s %s%s.", m.Label.Ar, whoAr, val, f.Rule.Op, thr, durAr))
	return
}
