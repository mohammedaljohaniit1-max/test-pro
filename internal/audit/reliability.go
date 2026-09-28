package audit

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

type stopInfo struct {
	name string
	diag model.Text
	fix  model.Text
}

// Well-known bugcheck (stop) codes.
var stopCodes = map[uint64]stopInfo{
	0x0a: {"IRQL_NOT_LESS_OR_EQUAL", model.T("a driver accessed memory it was not allowed to", "برنامج تشغيل (Driver) حاول الوصول إلى ذاكرة غير مسموح بها"),
		model.T("Update or roll back recently installed drivers (Device Manager), then run 'verifier' only if the crash repeats.", "حدّث برامج التشغيل المثبتة حديثًا أو أرجعها لإصدار سابق (إدارة الأجهزة)، واستخدم أداة verifier فقط إذا تكرر الانهيار.")},
	0x1a: {"MEMORY_MANAGEMENT", model.T("the memory manager found corrupted data — often faulty RAM", "مدير الذاكرة وجد بيانات تالفة — غالبًا بسبب عطل في الذاكرة RAM"),
		model.T("Run Windows Memory Diagnostic (mdsched.exe) or MemTest86, reseat RAM modules and disable XMP/overclocking.", "شغّل أداة تشخيص ذاكرة Windows ‏(mdsched.exe) أو MemTest86، وأعد تركيب شرائح الذاكرة وعطّل XMP أو كسر السرعة.")},
	0x3b: {"SYSTEM_SERVICE_EXCEPTION", model.T("a system call crashed inside a driver or kernel component", "استدعاء نظام انهار داخل برنامج تشغيل أو مكوّن في النواة"),
		model.T("Update graphics, antivirus and storage drivers; run 'sfc /scannow' and 'DISM /Online /Cleanup-Image /RestoreHealth'.", "حدّث برامج تشغيل الرسوميات ومكافحة الفيروسات والتخزين؛ ثم نفّذ 'sfc /scannow' و 'DISM /Online /Cleanup-Image /RestoreHealth'.")},
	0x50: {"PAGE_FAULT_IN_NONPAGED_AREA", model.T("invalid memory was referenced — bad driver, antivirus or RAM", "تمت الإشارة إلى ذاكرة غير صالحة — بسبب برنامج تشغيل أو برنامج حماية أو ذاكرة معطوبة"),
		model.T("Uninstall recently added software/drivers, test RAM with mdsched.exe and check the disk with 'chkdsk /scan'.", "أزل البرامج أو برامج التشغيل المضافة حديثًا، واختبر الذاكرة بـ mdsched.exe وافحص القرص بـ 'chkdsk /scan'.")},
	0x7e: {"SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", model.T("a system thread raised an error nobody handled — usually a driver", "خيط نظام أطلق خطأً لم تتم معالجته — غالبًا برنامج تشغيل"),
		model.T("Open the dump (C:\\Windows\\Minidump) with WinDbg '!analyze -v' to name the driver, then update or remove it.", "افتح ملف التفريغ (C:\\Windows\\Minidump) بأداة WinDbg والأمر '!analyze -v' لمعرفة برنامج التشغيل، ثم حدّثه أو أزله.")},
	0x7f: {"UNEXPECTED_KERNEL_MODE_TRAP", model.T("the CPU raised a trap the kernel could not handle — hardware or overclocking", "المعالج أطلق استثناءً لم تستطع النواة معالجته — عتاد أو كسر سرعة"),
		model.T("Reset BIOS/UEFI to defaults, remove overclocks, check CPU temperatures and test RAM.", "أعد إعدادات BIOS/UEFI للوضع الافتراضي، وألغِ كسر السرعة، وتحقّق من حرارة المعالج واختبر الذاكرة.")},
	0x9f: {"DRIVER_POWER_STATE_FAILURE", model.T("a driver did not finish a sleep/wake transition in time", "برنامج تشغيل لم يُكمل الانتقال إلى وضع السكون أو الاستيقاظ في الوقت المحدد"),
		model.T("Update chipset, network and graphics drivers and the BIOS; as a workaround disable 'Fast startup' and USB selective suspend.", "حدّث برامج تشغيل الشرائح والشبكة والرسوميات وBIOS؛ وكحل مؤقت عطّل «بدء التشغيل السريع» وتعليق USB الانتقائي.")},
	0xd1: {"DRIVER_IRQL_NOT_LESS_OR_EQUAL", model.T("a driver used an invalid memory address — very often a network or storage driver", "برنامج تشغيل استخدم عنوان ذاكرة غير صالح — غالبًا برنامج تشغيل شبكة أو تخزين"),
		model.T("Update or reinstall network (Wi-Fi/Ethernet/VPN) and storage drivers from the hardware vendor's site.", "حدّث أو أعد تثبيت برامج تشغيل الشبكة (Wi-Fi/Ethernet/VPN) والتخزين من موقع الشركة المصنّعة.")},
	0xef: {"CRITICAL_PROCESS_DIED", model.T("a process Windows cannot live without stopped", "توقفت عملية لا يمكن لـ Windows العمل بدونها"),
		model.T("Run 'sfc /scannow' and 'DISM /Online /Cleanup-Image /RestoreHealth', check the disk with 'chkdsk C: /f', and scan for malware.", "نفّذ 'sfc /scannow' و 'DISM /Online /Cleanup-Image /RestoreHealth'، وافحص القرص بـ 'chkdsk C: /f'، وافحص الجهاز من البرمجيات الخبيثة.")},
	0x124: {"WHEA_UNCORRECTABLE_ERROR", model.T("the hardware reported an uncorrectable fault (CPU, RAM, power or overheating)", "أبلغ العتاد عن عطل غير قابل للتصحيح (المعالج أو الذاكرة أو الطاقة أو الحرارة)"),
		model.T("Remove overclocks, check temperatures and the power supply, update BIOS, and review WHEA-Logger events for the failing component.", "ألغِ كسر السرعة، وتحقّق من الحرارة ومزوّد الطاقة، وحدّث BIOS، وراجع أحداث WHEA-Logger لمعرفة المكوّن المعطوب.")},
	0x133: {"DPC_WATCHDOG_VIOLATION", model.T("a driver kept the CPU busy for too long — often storage (SSD) firmware or drivers", "برنامج تشغيل أبقى المعالج مشغولًا مدة طويلة — غالبًا برنامج تشغيل أو برنامج ثابت لقرص SSD"),
		model.T("Update SSD firmware and the SATA/NVMe (storahci/stornvme) driver, plus chipset drivers.", "حدّث البرنامج الثابت لقرص SSD وبرنامج تشغيل SATA/NVMe ‏(storahci/stornvme) وبرامج تشغيل الشرائح.")},
	0x139: {"KERNEL_SECURITY_CHECK_FAILURE", model.T("the kernel detected corrupted internal data — driver bug or memory corruption", "اكتشفت النواة تلفًا في بياناتها الداخلية — خلل في برنامج تشغيل أو تلف في الذاكرة"),
		model.T("Update all drivers, run mdsched.exe and 'sfc /scannow'.", "حدّث جميع برامج التشغيل، وشغّل mdsched.exe و 'sfc /scannow'.")},
	0x1e: {"KMODE_EXCEPTION_NOT_HANDLED", model.T("a kernel-mode program generated an error that was not handled", "برنامج في وضع النواة أطلق خطأً لم تتم معالجته"),
		model.T("Identify the driver from the minidump and update or remove it; test RAM if no driver is named.", "حدّد برنامج التشغيل من ملف التفريغ وحدّثه أو أزله؛ واختبر الذاكرة إن لم يظهر اسم برنامج تشغيل.")},
	0x19: {"BAD_POOL_HEADER", model.T("kernel memory pool corruption — typically a faulty driver", "تلف في مجمّع ذاكرة النواة — غالبًا بسبب برنامج تشغيل معطوب"),
		model.T("Update drivers (especially antivirus, VPN and storage) and test RAM.", "حدّث برامج التشغيل (خصوصًا الحماية وVPN والتخزين) واختبر الذاكرة.")},
	0xc2: {"BAD_POOL_CALLER", model.T("a driver made an invalid memory pool request", "برنامج تشغيل طلب ذاكرة بطريقة غير صحيحة"),
		model.T("Update or uninstall recently added drivers and security software.", "حدّث أو أزل برامج التشغيل وبرامج الحماية المضافة حديثًا.")},
	0x116: {"VIDEO_TDR_FAILURE", model.T("the graphics driver stopped responding and could not be recovered", "توقف برنامج تشغيل الرسوميات عن الاستجابة ولم يمكن استعادته"),
		model.T("Clean-install the latest GPU driver (DDU), check GPU temperature and remove GPU overclocks.", "ثبّت أحدث برنامج تشغيل للرسوميات تثبيتًا نظيفًا (DDU)، وتحقّق من حرارة المعالج الرسومي وألغِ كسر سرعته.")},
	0x7a: {"KERNEL_DATA_INPAGE_ERROR", model.T("Windows could not read kernel data from the disk (page file) — disk or cable problem", "لم يستطع Windows قراءة بيانات النواة من القرص (ملف الترحيل) — مشكلة في القرص أو الكابل"),
		model.T("Check disk health (SMART, 'chkdsk C: /r'), reseat SATA cables and back up your data now.", "افحص صحة القرص (SMART و 'chkdsk C: /r')، وأعد تركيب كابلات SATA، وخذ نسخة احتياطية من بياناتك الآن.")},
	0xc000021a: {"STATUS_SYSTEM_PROCESS_TERMINATED", model.T("a critical user-mode subsystem (winlogon/csrss) failed", "فشل نظام فرعي حرج في وضع المستخدم (winlogon/csrss)"),
		model.T("Boot into Windows Recovery, run Startup Repair, 'sfc /scannow /offbootdir=C:\\ /offwindir=C:\\Windows' and uninstall the latest update if needed.", "ادخل إلى بيئة استرداد Windows، وشغّل إصلاح بدء التشغيل و 'sfc /scannow /offbootdir=C:\\ /offwindir=C:\\Windows'، وأزل آخر تحديث إذا لزم.")},
}

// ParseStopCode extracts the bugcheck code from a WER 1001 "param1" string
// such as "0x0000009f (0x0000000000000003, …)" or a decimal Kernel-Power 41
// BugcheckCode such as "159".
func ParseStopCode(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if i := strings.IndexAny(s, " (,"); i > 0 {
		s = s[:i]
	}
	var v uint64
	var err error
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		v, err = strconv.ParseUint(s[2:], 16, 64)
	} else {
		v, err = strconv.ParseUint(s, 10, 64)
	}
	if err != nil || v == 0 {
		return 0, false
	}
	return v, true
}

// StopName formats a stop code as "0x0000009F DRIVER_POWER_STATE_FAILURE".
func StopName(code uint64) string {
	s := fmt.Sprintf("0x%08X", code)
	if i, ok := stopCodes[code]; ok {
		s += " " + i.name
	}
	return s
}

// Windows exception codes seen in Application Error 1000.
var exceptionCodes = map[string]model.Text{
	"c0000005": model.T("access violation (the program used memory it does not own)", "انتهاك وصول (البرنامج استخدم ذاكرة لا يملكها)"),
	"c0000409": model.T("stack buffer overrun / fail-fast (the program deliberately aborted after detecting corruption)", "تجاوز مخزن المكدس / إنهاء سريع (أوقف البرنامج نفسه بعد اكتشاف تلف)"),
	"c0000374": model.T("heap corruption", "تلف في ذاكرة الكومة (Heap)"),
	"c00000fd": model.T("stack overflow (endless recursion)", "فيض المكدس (استدعاء ذاتي لا ينتهي)"),
	"c000001d": model.T("illegal CPU instruction", "تعليمة معالج غير صالحة"),
	"c0000094": model.T("integer division by zero", "قسمة عدد صحيح على صفر"),
	"e0434352": model.T("unhandled .NET exception", "استثناء ‎.NET غير معالج"),
	"e06d7363": model.T("unhandled C++ exception", "استثناء C++ غير معالج"),
	"80000003": model.T("breakpoint (debug build or assertion)", "نقطة توقف (إصدار تجريبي أو فحص تأكيد)"),
	"c0000602": model.T("unknown fail-fast exception", "استثناء إنهاء سريع غير معروف"),
	"c06d007e": model.T("a required DLL could not be loaded", "تعذّر تحميل مكتبة DLL مطلوبة"),
	"40000015": model.T("fatal application exit", "خروج قاتل للتطبيق"),
}

func normHex(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "0x")
	return s
}

var systemModules = map[string]bool{"ntdll.dll": true, "kernelbase.dll": true, "kernel32.dll": true, "ucrtbase.dll": true,
	"msvcrt.dll": true, "combase.dll": true, "user32.dll": true, "clr.dll": true, "coreclr.dll": true, "vcruntime140.dll": true}

// AnalyzeReliability categorises System/Application reliability events.
func AnalyzeReliability(evs []model.Event, rep model.AuditReport) model.AuditReport {
	svc := map[string]*group{}
	apps := map[string]*group{}
	hangs := map[string]*group{}
	bugs := map[uint64]*group{}
	var shut *group
	bugTimes := []time.Time{}

	for _, e := range evs {
		prov := strings.ToLower(e.Provider)
		switch {
		case (e.EventID == 7031 || e.EventID == 7034) && (prov == "" || strings.Contains(prov, "service control manager")):
			name := field(e, "param1", "#0")
			if name == "" {
				name = "(unknown service)"
			}
			g := svc[strings.ToLower(name)]
			if g == nil {
				g = &group{f: model.Finding{Kind: FServiceCrash, Subject: name}}
				svc[strings.ToLower(name)] = g
			}
			g.add(e, e.Message)
			if e.EventID == 7031 {
				g.note("action", field(e, "param5", "#4"))
			}
			g.note("times", field(e, "param2", "#1"))
		case e.EventID == 1000 && (prov == "" || strings.Contains(prov, "application error")):
			app := field(e, "AppName", "#0")
			if app == "" {
				app = "(unknown application)"
			}
			g := apps[strings.ToLower(app)]
			if g == nil {
				g = &group{f: model.Finding{Kind: FAppFault, Subject: app}}
				apps[strings.ToLower(app)] = g
			}
			mod := field(e, "ModuleName", "#3")
			exc := normHex(field(e, "ExceptionCode", "#6"))
			g.add(e, fmt.Sprintf("%s crashed in %s (0x%s)", app, orDash(mod), exc))
			g.note("module", mod)
			g.note("exception", exc)
			g.note("version", field(e, "AppVersion", "#1"))
			g.note("path", field(e, "AppPath", "#10"))
		case e.EventID == 1002 && (prov == "" || strings.Contains(prov, "application hang")):
			app := field(e, "AppName", "#0")
			if app == "" {
				app = "(unknown application)"
			}
			g := hangs[strings.ToLower(app)]
			if g == nil {
				g = &group{f: model.Finding{Kind: FAppHang, Subject: app}}
				hangs[strings.ToLower(app)] = g
			}
			g.add(e, app+" stopped responding")
			g.note("version", field(e, "AppVersion", "#1"))
		case e.EventID == 1001 && (strings.Contains(prov, "systemerrorreporting") || strings.Contains(prov, "bugcheck")):
			code, ok := ParseStopCode(field(e, "param1", "#0"))
			if !ok {
				code, ok = parseStopFromMessage(e.Message)
			}
			if !ok {
				continue
			}
			g := bugs[code]
			if g == nil {
				g = &group{f: model.Finding{Kind: FBugcheck, Subject: StopName(code)}}
				bugs[code] = g
			}
			g.add(e, "Bugcheck "+field(e, "param1", "#0"))
			g.note("dump", field(e, "param2", "#1"))
			bugTimes = append(bugTimes, e.Time)
		case e.EventID == 41 && strings.Contains(prov, "kernel-power"):
			if code, ok := ParseStopCode(field(e, "BugcheckCode")); ok {
				g := bugs[code]
				if g == nil {
					g = &group{f: model.Finding{Kind: FBugcheck, Subject: StopName(code)}}
					bugs[code] = g
				}
				g.add(e, "Kernel-Power 41 with bugcheck "+StopName(code))
				bugTimes = append(bugTimes, e.Time)
				continue
			}
			fallthrough
		case e.EventID == 6008 && (e.EventID == 41 || prov == "" || prov == "eventlog"):
			if shut == nil {
				shut = &group{f: model.Finding{Kind: FUnexpectedShut, Subject: "System"}}
			}
			shut.add(e, e.Message)
			if e.EventID == 41 {
				shut.note("power", field(e, "PowerButtonTimestamp"))
			}
		}
	}

	var out []model.Finding
	for _, g := range svc {
		g.detail("recoveryAction", g.values("action"))
		f := g.f
		f.Severity = model.SevWarning
		if f.Count >= 3 {
			f.Severity = model.SevCritical
		}
		f.Title = model.T("Service crashed: "+f.Subject, "انهيار خدمة: "+f.Subject)
		f.Diagnosis = model.T(
			fmt.Sprintf("The Windows service \"%s\" stopped unexpectedly %d time(s) between %s and %s. A service that keeps crashing can make features stop working (printing, search, updates, networking…).",
				f.Subject, f.Count, day(f.First), day(f.Last)),
			fmt.Sprintf("توقفت خدمة Windows ‏«%s» بشكل غير متوقع %d مرة بين %s و %s. الخدمة التي تنهار باستمرار قد تعطّل ميزات مثل الطباعة أو البحث أو التحديثات أو الشبكة.",
				f.Subject, f.Count, day(f.First), day(f.Last)))
		f.Fix = model.T(
			"Open services.msc → \""+f.Subject+"\" → Recovery and make sure 'Restart the service' is set. Check the Application log for a matching 'Application Error' (1000) around the same time to find the crashing DLL, update the software that installed the service, and run 'sfc /scannow' if it is a Windows service.",
			"افتح services.msc ← «"+f.Subject+"» ← الاسترداد وتأكّد من ضبط «إعادة تشغيل الخدمة». افحص سجل التطبيقات بحثًا عن حدث «Application Error» ‏(1000) في الوقت نفسه لمعرفة المكتبة المسببة، وحدّث البرنامج الذي ثبّت الخدمة، ونفّذ 'sfc /scannow' إن كانت خدمة من Windows.")
		out = append(out, f)
	}

	for _, g := range apps {
		mods := g.values("module")
		excs := g.values("exception")
		g.detail("faultingModule", mods)
		g.detail("exceptionCode", prefixAll(excs, "0x"))
		g.detail("version", g.values("version"))
		g.detail("path", g.values("path"))
		f := g.f
		f.Severity = model.SevWarning
		if f.Count >= 5 {
			f.Severity = model.SevCritical
		} else if f.Count == 1 {
			f.Severity = model.SevInfo
		}
		excEn, excAr := "an unknown error", "خطأ غير معروف"
		for _, x := range excs {
			if t, ok := exceptionCodes[x]; ok {
				excEn, excAr = t.En, t.Ar
				break
			}
		}
		mod := first(mods)
		f.Title = model.T("Application crash: "+f.Subject, "انهيار تطبيق: "+f.Subject)
		f.Diagnosis = model.T(
			fmt.Sprintf("%s closed unexpectedly %d time(s). The crash happened in %s because of %s.", f.Subject, f.Count, orDash(mod), excEn),
			fmt.Sprintf("أُغلق التطبيق %s بشكل غير متوقع %d مرة. وقع الانهيار في %s بسبب %s.", f.Subject, f.Count, orDash(mod), excAr))
		switch {
		case mod != "" && strings.EqualFold(mod, f.Subject):
			f.Fix = model.T(
				"The bug is inside the application itself. Update "+f.Subject+" to the latest version (see the Software tab), or reinstall it; if it persists, report the crash to the vendor with the exception code.",
				"الخلل داخل التطبيق نفسه. حدّث "+f.Subject+" إلى أحدث إصدار (راجع تبويب البرامج) أو أعد تثبيته؛ وإن استمر فأبلغ الشركة المطوّرة مع رمز الاستثناء.")
		case systemModules[strings.ToLower(mod)]:
			f.Fix = model.T(
				"The crash surfaced in a core Windows library ("+mod+"), which usually means the application passed it bad data. Update or repair "+f.Subject+", update Visual C++ / .NET runtimes, and run 'sfc /scannow' plus 'DISM /Online /Cleanup-Image /RestoreHealth' if several apps crash in the same module.",
				"ظهر الانهيار في مكتبة أساسية من Windows ‏("+mod+")، وغالبًا يعني ذلك أن التطبيق مرّر لها بيانات خاطئة. حدّث "+f.Subject+" أو أصلحه، وحدّث حزم Visual C++ و ‎.NET، ونفّذ 'sfc /scannow' و 'DISM /Online /Cleanup-Image /RestoreHealth' إذا انهارت عدة تطبيقات في المكتبة نفسها.")
		default:
			f.Fix = model.T(
				"The faulting module "+orDash(mod)+" is a plug-in or third-party component loaded into "+f.Subject+". Update or remove the add-in/driver that ships this DLL (graphics overlay, antivirus hook, shell extension), then update the application.",
				"الوحدة المسببة "+orDash(mod)+" إضافة أو مكوّن من طرف ثالث محمّل داخل "+f.Subject+". حدّث أو أزل الإضافة أو برنامج التشغيل الذي يحتوي هذه المكتبة (طبقة رسوميات، برنامج حماية، امتداد لمستكشف الملفات)، ثم حدّث التطبيق.")
		}
		out = append(out, f)
	}

	for _, g := range hangs {
		g.detail("version", g.values("version"))
		f := g.f
		f.Severity = model.SevInfo
		if f.Count >= 3 {
			f.Severity = model.SevWarning
		}
		f.Title = model.T("Application stopped responding: "+f.Subject, "تطبيق توقف عن الاستجابة: "+f.Subject)
		f.Diagnosis = model.T(
			fmt.Sprintf("%s froze and was closed %d time(s). Freezes usually come from waiting on a slow disk, network share or a stuck add-in.", f.Subject, f.Count),
			fmt.Sprintf("تجمّد التطبيق %s وتم إغلاقه %d مرة. غالبًا ينتج التجمّد عن انتظار قرص بطيء أو مجلد شبكة أو إضافة عالقة.", f.Subject, f.Count))
		f.Fix = model.T(
			"Update the application, disable its add-ins, check free disk space and disk health (Overview tab), and remove unreachable mapped network drives.",
			"حدّث التطبيق، وعطّل إضافاته، وتحقّق من المساحة الحرة وصحة القرص (تبويب النظرة العامة)، وأزل محركات الشبكة المعيّنة غير المتاحة.")
		out = append(out, f)
	}

	for code, g := range bugs {
		g.detail("dumpFile", g.values("dump"))
		f := g.f
		f.Severity = model.SevCritical
		info, known := stopCodes[code]
		f.Title = model.T("System crash (bugcheck / blue screen): "+f.Subject, "انهيار النظام (شاشة زرقاء): "+f.Subject)
		if known {
			f.Diagnosis = model.T(
				fmt.Sprintf("Windows crashed with a blue screen %d time(s) with stop code %s: %s.", f.Count, f.Subject, info.diag.En),
				fmt.Sprintf("انهار Windows بشاشة زرقاء %d مرة برمز الإيقاف %s: %s.", f.Count, f.Subject, info.diag.Ar))
			f.Fix = model.T(info.fix.En+" The crash dump is in C:\\Windows\\Minidump.", info.fix.Ar+" ملف التفريغ موجود في C:\\Windows\\Minidump.")
		} else {
			f.Diagnosis = model.T(
				fmt.Sprintf("Windows crashed with a blue screen %d time(s) with stop code %s.", f.Count, f.Subject),
				fmt.Sprintf("انهار Windows بشاشة زرقاء %d مرة برمز الإيقاف %s.", f.Count, f.Subject))
			f.Fix = model.T(
				"Analyse the dump in C:\\Windows\\Minidump with WinDbg ('!analyze -v') to identify the driver, update drivers and BIOS, and test RAM (mdsched.exe).",
				"حلّل ملف التفريغ في C:\\Windows\\Minidump باستخدام WinDbg ‏('!analyze -v') لتحديد برنامج التشغيل، وحدّث برامج التشغيل وBIOS، واختبر الذاكرة (mdsched.exe).")
		}
		out = append(out, f)
	}

	if shut != nil {
		f := shut.f
		// Kernel-Power 41 + EventLog 6008 describe the same reboot; count reboots, not records.
		reboots := dedupeWithin(shut.times, 5*time.Minute)
		f.Count = reboots
		pressed := len(shut.values("power")) > 0 && !(len(shut.values("power")) == 1 && shut.values("power")[0] == "0")
		f.Severity = model.SevWarning
		if reboots >= 3 {
			f.Severity = model.SevCritical
		}
		f.Title = model.T("Unexpected shutdowns / power loss", "إيقاف تشغيل غير متوقع / انقطاع الطاقة")
		f.Diagnosis = model.T(
			fmt.Sprintf("The computer restarted %d time(s) without shutting down cleanly and without a blue-screen record. Typical causes: power cut, holding the power button, overheating, or a failing power supply.", reboots),
			fmt.Sprintf("أُعيد تشغيل الجهاز %d مرة دون إيقاف سليم ودون تسجيل شاشة زرقاء. الأسباب المعتادة: انقطاع الكهرباء، أو الضغط المطوّل على زر التشغيل، أو ارتفاع الحرارة، أو عطل في مزوّد الطاقة.", reboots))
		if pressed {
			f.Diagnosis.En += " The power button was pressed during at least one of these events."
			f.Diagnosis.Ar += " تم الضغط على زر التشغيل أثناء واحد على الأقل من هذه الأحداث."
		}
		f.Fix = model.T(
			"Check the power source (UPS, cable, power strip), clean dust and monitor temperatures, and in Control Panel → System → Advanced → Startup and Recovery enable 'Write a small memory dump' so the next crash is recorded. If the PC froze first, update chipset and graphics drivers.",
			"تحقّق من مصدر الطاقة (UPS، الكابل، الموزّع)، ونظّف الغبار وراقب درجات الحرارة، ومن لوحة التحكم ← النظام ← خيارات متقدمة ← بدء التشغيل والاسترداد فعّل «كتابة تفريغ ذاكرة صغير» ليُسجَّل الانهيار التالي. إذا تجمّد الجهاز أولًا فحدّث برامج تشغيل الشرائح والرسوميات.")
		out = append(out, f)
	}
	_ = bugTimes
	return finalize(rep, out, evs)
}

func parseStopFromMessage(msg string) (uint64, bool) {
	l := strings.ToLower(msg)
	i := strings.Index(l, "bugcheck was: ")
	if i < 0 {
		return 0, false
	}
	return ParseStopCode(msg[i+len("bugcheck was: "):])
}

func dedupeWithin(ts []time.Time, d time.Duration) int {
	if len(ts) == 0 {
		return 0
	}
	s := append([]time.Time(nil), ts...)
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].Before(s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	n, last := 1, s[0]
	for _, t := range s[1:] {
		if t.Sub(last) > d {
			n++
		}
		last = t
	}
	return n
}

func prefixAll(xs []string, p string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = p + x
	}
	return out
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02 15:04Z") }
