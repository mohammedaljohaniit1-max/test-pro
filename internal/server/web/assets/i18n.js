/* SysPulse 2.0 — bilingual dictionary (English / Arabic).
 * Static markup uses data-i18n (textContent), data-i18n-ph (placeholder) and
 * data-i18n-title (title). Dynamic strings use I18N.t(key, vars).
 * Interpolation: "{name}" is replaced by vars.name. */
(() => {
  "use strict";
  const D = {
    en: {
      "tab.overview": "Overview", "tab.network": "Network", "tab.radar": "Anomaly Radar", "tab.processes": "Processes",
      "tab.events": "Event Log", "tab.diagnostics": "Diagnostics", "tab.alerts": "Alerts & Incidents", "tab.software": "Software",
      "tab.guide": "User Guide / دليل الاستخدام",
      "sound.toggle": "Alert sound on/off", "sound.on": "Alert sound enabled", "sound.off": "Alert sound muted",
      "conn.connecting": "connecting…", "conn.live": "live", "conn.retry": "disconnected — retrying",

      "ov.cpu": "CPU", "ov.memory": "Memory", "ov.commit": "Commit", "ov.processes": "Processes", "ov.sockets": "Sockets",
      "ov.uptime": "Uptime", "ov.sinceBoot": "since last boot", "ov.radar": "Sweep radar", "ov.alerts": "Open alerts",
      "ov.chart": "CPU & memory — last 5 minutes", "ov.cpuPct": "CPU %", "ov.memPct": "Memory %", "ov.disks": "Disks",
      "ov.topProcs": "Top processes by CPU", "ov.recent": "Recent errors & warnings",
      "ov.cores": "{n} logical processors", "ov.threads": "{n} threads", "ov.rate": "{r} new/s · {e} established",
      "ov.radarSub": "{t} remote IPs tracked", "ov.radarActive": "{n} ACTIVE", "ov.radarClear": "clear",
      "ov.alertsSub": "{c} critical · {w} warning", "ov.noVolumes": "No volumes", "ov.free": "{f} free of {t}",
      "ov.noErrors": "No recent errors or warnings 🎉",

      "net.states": "Connection states", "net.topProcs": "Top processes by sockets", "net.topRemotes": "Top remote hosts (established)",
      "net.active": "Active sockets", "net.filter": "Filter by process, address, port, state…", "net.allProto": "All protocols",
      "net.allStates": "All states", "net.hideLoop": "hide loopback",
      "net.foot": "{n} of {total} sockets", "net.first2000": " (first 2000 shown)", "net.error": " · error: {e}",

      "radar.rule": "Detection rule",
      "radar.ruleText": "Flag a remote IP that contacts more than {thr} distinct ports within {win} s",
      "radar.active": "Active sweeps", "radar.tracked": "Tracked remote IPs", "radar.rate": "Inbound attempts / s", "radar.arp": "ARP neighbours",
      "radar.selftest": "Run safe self-test", "radar.showArp": "ARP table",
      "radar.chart": "Inbound connection attempts — last 60 s", "radar.incidents": "Sweep incidents",
      "radar.hosts": "Connection frequency & port breadth per remote IP", "radar.filter": "Filter by IP or MAC…",
      "radar.noIncidents": "No connection sweeps detected. The radar is watching every inbound TCP connection attempt.",
      "radar.noHosts": "No inbound connection attempts observed yet.",
      "radar.foot": "{n} remote IPs shown of {t} tracked · allow-listed: {a}",
      "radar.sensorOn": "active", "radar.sensorOff": "inactive",
      "radar.sensor.raw-syn": "Raw SYN sensor", "radar.sensor.tcp-table": "TCP-table sensor", "radar.sensor.self-test": "Self-test",
      "radar.flagged": "SWEEP", "radar.activeBadge": "active", "radar.closedBadge": "closed", "radar.testBadge": "test",
      "radar.incPorts": "{n} ports", "radar.incAttempts": "{n} attempts", "radar.via": "via gateway {g}",
      "radar.resolving": "resolving…", "radar.unknownMac": "unknown",
      "radar.testConfirm": "This injects a synthetic sweep from the documentation address {ip} (RFC 5737) through the full detection pipeline. No packets are sent on the network. Continue?",
      "radar.testDone": "Self-test incident {id} created — the banner and chime should appear now.",
      "radar.arpTitle": "ARP table (GetIpNetTable)", "radar.arpEmpty": "The ARP cache is empty.",

      "sweep.title": "High-Frequency Connection Sweep (Traffic Anomaly)",
      "sweep.titleTest": "[TEST] High-Frequency Connection Sweep (Traffic Anomaly)",
      "sweep.remoteIp": "Remote IP", "sweep.mac": "MAC address", "sweep.iface": "Interface", "sweep.ports": "Target port range",
      "sweep.distinct": "Distinct ports", "sweep.time": "Timestamp", "sweep.view": "View in radar", "sweep.dismiss": "Dismiss",
      "sweep.more": "+{n} more active",

      "proc.title": "Processes", "proc.filter": "Filter by name, PID or path…",
      "proc.foot": "{n} of {total} processes · processes marked n/a are protected and require elevation to inspect",
      "proc.na": "n/a", "proc.denied": "access denied (protected process)",

      "ev.volume": "Event volume — last 7 days", "ev.buckets": "(3-hour buckets)", "ev.title": "Events",
      "ev.search": "Search source or message…", "ev.allLevels": "All levels", "ev.allCats": "All categories",
      "ev.foot": "{n} of {total} events", "ev.first1500": " (first 1500 shown)", "ev.err": "Event log: {e}",
      "cat.service-crash": "Service crashes", "cat.app-fault": "Application faults", "cat.unexpected-shutdown": "Unexpected shutdowns",
      "cat.driver": "Driver issues", "cat.disk": "Disk / storage", "cat.windows-update": "Windows Update", "cat.power": "Power",
      "lvl.critical": "Critical", "lvl.error": "Error", "lvl.warning": "Warning", "lvl.info": "Info", "lvl.verbose": "Verbose",

      "diag.authTitle": "Audit Authentication & Access Logs",
      "diag.authDesc": "Reads the Security log: repeated failed logons (4625), lockouts (4740) and administrative privilege assignments (4672).",
      "diag.authBtn": "Audit Authentication & Access Logs",
      "diag.relTitle": "Audit System Reliability & Faults",
      "diag.relDesc": "Reads the System and Application logs: service crashes (7034/7031), application faults (1000), hangs (1002), bugchecks and unexpected shutdowns.",
      "diag.relBtn": "Audit System Reliability & Faults",
      "diag.window": "Look back", "diag.h24": "24 hours", "diag.d7": "7 days", "diag.d30": "30 days",
      "diag.unavailable": "Event-log audits need the Windows build of SysPulse.",
      "diag.running": "Analysing event logs…",
      "diag.report.auth": "Authentication & Access audit", "diag.report.reliability": "System Reliability & Faults audit",
      "diag.meta": "{n} events scanned · window {h} h · finished {t} · took {d}",
      "diag.none": "No issues found in this period. ✔",
      "diag.byEvent": "Events by ID:",
      "diag.findingsCount": "{n} findings",
      "diag.export": "Export:",
      "diag.done": "{kind} finished: {n} findings",
      "diag.failed": "Audit failed: {e}",
      "diag.details": "Details", "diag.samples": "Sample occurrences",
      "col.finding": "Finding", "col.subject": "Account / component", "col.events": "Event IDs", "col.window": "First → last",
      "col.diagnosis": "Plain-Language Diagnosis", "col.fix": "Recommended Fix",
      "kind.failed-logon": "Failed logons", "kind.password-spray": "Password spraying", "kind.account-lockout": "Account lockout",
      "kind.privileged-logon": "Privileged logon", "kind.service-crash": "Service crash", "kind.app-fault": "Application fault",
      "kind.app-hang": "Application hang", "kind.bugcheck": "Bugcheck (BSOD)", "kind.unexpected-shutdown": "Unexpected shutdown",

      "sev.critical": "Critical", "sev.warning": "Warning", "sev.info": "Informational",
      "alerts.title": "Alerts & Incidents", "alerts.all": "All", "alerts.allCats": "All categories", "alerts.search": "Search alerts…",
      "alerts.onlyUnacked": "only unacknowledged", "alerts.unacked": "Unacknowledged", "alerts.last24": "Last 24 h",
      "alerts.ackAll": "Acknowledge all", "alerts.clear": "Clear", "alerts.exportLbl": "Export (current filter):",
      "alerts.ack": "Ack", "alerts.acked": "acknowledged", "alerts.none": "No alerts match the current filter.",
      "alerts.foot": "{n} of {total} alerts", "alerts.clearConfirm": "Remove all alerts from the list? Exports made earlier are not affected.",
      "alerts.details": "Alert details", "alerts.fields": "Fields",
      "acat.network-sweep": "Network sweep", "acat.authentication": "Authentication", "acat.reliability": "Reliability",
      "acat.resource": "Resources", "acat.system": "System",
      "src.radar": "Radar", "src.eventlog": "Event log", "src.audit": "Audit", "src.metrics": "Metrics", "src.syspulse": "SysPulse",

      "col.proto": "Proto", "col.process": "Process", "col.pid": "PID", "col.localAddr": "Local address", "col.port": "Port",
      "col.remoteAddr": "Remote address", "col.state": "State", "col.firstSeen": "First seen", "col.remoteIp": "Remote IP",
      "col.mac": "MAC address", "col.iface": "Interface", "col.portsWindow": "Ports / window", "col.pressure": "Rule pressure",
      "col.connsWindow": "Attempts / window", "col.rate": "Rate (60 s)", "col.distinct": "Distinct ports", "col.total": "Total",
      "col.lastSeen": "Last seen", "col.sensor": "Sensor", "col.name": "Name", "col.parent": "Parent", "col.cpu": "CPU %",
      "col.ws": "Working set", "col.private": "Private", "col.threads": "Threads", "col.started": "Started", "col.path": "Path",
      "col.time": "Time", "col.level": "Level", "col.category": "Category", "col.source": "Source", "col.id": "ID",
      "col.channel": "Channel", "col.message": "Message", "col.severity": "Severity", "col.alert": "Alert", "col.details": "Details",
      "col.count": "Count", "col.sourceMod": "Source", "col.pkg": "Package ID", "col.installed": "Installed", "col.available": "Available",
      "col.command": "Command", "col.version": "Version", "col.update": "Update", "col.publisher": "Publisher",
      "col.installedOn": "Installed", "col.size": "Size", "col.scope": "Scope", "col.type": "Type",

      "sw.upgrades": "Available upgrades", "sw.check": "Check for updates", "sw.checking": "Checking…", "sw.apps": "Installed applications",
      "sw.filter": "Filter by name or publisher…", "sw.onlyUpd": "only with updates", "sw.checked": "· checked {t}",
      "sw.notChecked": "· not checked yet", "sw.upgrade": "Upgrade", "sw.upgrading": "upgrading…", "sw.runningWinget": "Running winget…",
      "sw.upToDate": "Everything is up to date.", "sw.pressCheck": "Press “Check for updates” to query winget.",
      "sw.count": "({n} of {total})", "sw.copy": "Click to copy", "sw.copied": "Command copied to clipboard",
      "sw.confirm": "Upgrade {id} silently with winget?", "sw.started": "Upgrading {id}…", "sw.failed": "Upgrade failed: {e}",
      "sw.refreshFailed": "Refresh failed: {e}", "sw.checkingToast": "Checking for updates with winget…", "sw.invFailed": "Software inventory failed: {e}",

      "ago.s": "{n}s ago", "ago.m": "{n}m ago", "ago.h": "{n}h ago", "ago.d": "{n}d ago",
      "btn.ok": "OK", "btn.cancel": "Cancel", "btn.close": "Close", "btn.confirm": "Confirm",
      "err.generic": "Request failed: {e}",
    },

    ar: {
      "tab.overview": "نظرة عامة", "tab.network": "الشبكة", "tab.radar": "رادار الشذوذ", "tab.processes": "العمليات",
      "tab.events": "سجل الأحداث", "tab.diagnostics": "التشخيص", "tab.alerts": "التنبيهات والحوادث", "tab.software": "البرامج",
      "tab.guide": "دليل الاستخدام / User Guide",
      "sound.toggle": "تشغيل/كتم صوت التنبيه", "sound.on": "تم تفعيل صوت التنبيه", "sound.off": "تم كتم صوت التنبيه",
      "conn.connecting": "جارٍ الاتصال…", "conn.live": "مباشر", "conn.retry": "انقطع الاتصال — إعادة المحاولة",

      "ov.cpu": "المعالج", "ov.memory": "الذاكرة", "ov.commit": "الذاكرة الملتزمة", "ov.processes": "العمليات", "ov.sockets": "المقابس",
      "ov.uptime": "مدة التشغيل", "ov.sinceBoot": "منذ آخر إقلاع", "ov.radar": "رادار المسح", "ov.alerts": "التنبيهات المفتوحة",
      "ov.chart": "المعالج والذاكرة — آخر 5 دقائق", "ov.cpuPct": "المعالج %", "ov.memPct": "الذاكرة %", "ov.disks": "الأقراص",
      "ov.topProcs": "أعلى العمليات استهلاكًا للمعالج", "ov.recent": "أحدث الأخطاء والتحذيرات",
      "ov.cores": "{n} معالج منطقي", "ov.threads": "{n} خيط", "ov.rate": "{r} جديد/ث · {e} متصل",
      "ov.radarSub": "{t} عنوان بعيد قيد المراقبة", "ov.radarActive": "{n} نشط", "ov.radarClear": "سليم",
      "ov.alertsSub": "{c} حرج · {w} تحذير", "ov.noVolumes": "لا توجد أقراص", "ov.free": "{f} متاح من {t}",
      "ov.noErrors": "لا توجد أخطاء أو تحذيرات حديثة 🎉",

      "net.states": "حالات الاتصال", "net.topProcs": "أكثر العمليات استخدامًا للمقابس", "net.topRemotes": "أكثر المضيفين البعيدين (اتصالات قائمة)",
      "net.active": "المقابس النشطة", "net.filter": "تصفية حسب العملية أو العنوان أو المنفذ أو الحالة…", "net.allProto": "كل البروتوكولات",
      "net.allStates": "كل الحالات", "net.hideLoop": "إخفاء الاتصالات المحلية",
      "net.foot": "{n} من {total} مقبس", "net.first2000": " (عرض أول 2000)", "net.error": " · خطأ: {e}",

      "radar.rule": "قاعدة الكشف",
      "radar.ruleText": "يُعلَّم أي عنوان بعيد يتصل بأكثر من {thr} منفذًا مختلفًا خلال {win} ثوانٍ",
      "radar.active": "عمليات مسح نشطة", "radar.tracked": "عناوين بعيدة مراقَبة", "radar.rate": "محاولات واردة / ثانية", "radar.arp": "جيران ARP",
      "radar.selftest": "تشغيل اختبار ذاتي آمن", "radar.showArp": "جدول ARP",
      "radar.chart": "محاولات الاتصال الواردة — آخر 60 ثانية", "radar.incidents": "حوادث المسح",
      "radar.hosts": "تردد الاتصال واتساع المنافذ لكل عنوان بعيد", "radar.filter": "تصفية حسب العنوان أو MAC…",
      "radar.noIncidents": "لم يُكتشف أي مسح للاتصالات. الرادار يراقب كل محاولة اتصال TCP واردة.",
      "radar.noHosts": "لم تُرصد أي محاولات اتصال واردة بعد.",
      "radar.foot": "عرض {n} عنوان من أصل {t} مراقَب · القائمة المسموح بها: {a}",
      "radar.sensorOn": "نشط", "radar.sensorOff": "غير نشط",
      "radar.sensor.raw-syn": "مستشعر SYN الخام", "radar.sensor.tcp-table": "مستشعر جدول TCP", "radar.sensor.self-test": "اختبار ذاتي",
      "radar.flagged": "مسح", "radar.activeBadge": "نشط", "radar.closedBadge": "مغلق", "radar.testBadge": "اختبار",
      "radar.incPorts": "{n} منفذ", "radar.incAttempts": "{n} محاولة", "radar.via": "عبر البوابة {g}",
      "radar.resolving": "جارٍ التحديد…", "radar.unknownMac": "غير معروف",
      "radar.testConfirm": "سيحقن هذا الاختبار مسحًا اصطناعيًا من عنوان التوثيق {ip} (RFC 5737) عبر مسار الكشف كاملًا. لن تُرسل أي حزم على الشبكة. هل تريد المتابعة؟",
      "radar.testDone": "تم إنشاء حادثة الاختبار {id} — يجب أن يظهر الشريط الأحمر والتنبيه الصوتي الآن.",
      "radar.arpTitle": "جدول ARP ‏(GetIpNetTable)", "radar.arpEmpty": "ذاكرة ARP المؤقتة فارغة.",

      "sweep.title": "مسح اتصالات عالي التردد (شذوذ في حركة المرور)",
      "sweep.titleTest": "[اختبار] مسح اتصالات عالي التردد (شذوذ في حركة المرور)",
      "sweep.remoteIp": "العنوان البعيد", "sweep.mac": "عنوان MAC", "sweep.iface": "واجهة الشبكة", "sweep.ports": "نطاق المنافذ المستهدفة",
      "sweep.distinct": "عدد المنافذ المختلفة", "sweep.time": "الوقت", "sweep.view": "عرض في الرادار", "sweep.dismiss": "إخفاء",
      "sweep.more": "+{n} نشط آخر",

      "proc.title": "العمليات", "proc.filter": "تصفية حسب الاسم أو المعرّف أو المسار…",
      "proc.foot": "{n} من {total} عملية · العمليات المعلّمة بـ «غ/م» محمية وتحتاج صلاحيات المسؤول لفحصها",
      "proc.na": "غ/م", "proc.denied": "تم رفض الوصول (عملية محمية)",

      "ev.volume": "حجم الأحداث — آخر 7 أيام", "ev.buckets": "(فترات من 3 ساعات)", "ev.title": "الأحداث",
      "ev.search": "ابحث في المصدر أو الرسالة…", "ev.allLevels": "كل المستويات", "ev.allCats": "كل الفئات",
      "ev.foot": "{n} من {total} حدث", "ev.first1500": " (عرض أول 1500)", "ev.err": "سجل الأحداث: {e}",
      "cat.service-crash": "انهيار الخدمات", "cat.app-fault": "أعطال التطبيقات", "cat.unexpected-shutdown": "إيقاف غير متوقع",
      "cat.driver": "مشكلات برامج التشغيل", "cat.disk": "الأقراص / التخزين", "cat.windows-update": "تحديثات Windows", "cat.power": "الطاقة",
      "lvl.critical": "حرج", "lvl.error": "خطأ", "lvl.warning": "تحذير", "lvl.info": "معلومات", "lvl.verbose": "تفصيلي",

      "diag.authTitle": "تدقيق سجلات المصادقة والوصول",
      "diag.authDesc": "يقرأ سجل الأمان: محاولات الدخول الفاشلة المتكررة (4625)، وقفل الحسابات (4740)، ومنح الصلاحيات الإدارية (4672).",
      "diag.authBtn": "تدقيق سجلات المصادقة والوصول",
      "diag.relTitle": "تدقيق موثوقية النظام والأعطال",
      "diag.relDesc": "يقرأ سجلي النظام والتطبيقات: انهيار الخدمات (7034/7031)، وأعطال التطبيقات (1000)، والتجمّد (1002)، والشاشات الزرقاء، والإيقاف غير المتوقع.",
      "diag.relBtn": "تدقيق موثوقية النظام والأعطال",
      "diag.window": "الفترة", "diag.h24": "24 ساعة", "diag.d7": "7 أيام", "diag.d30": "30 يومًا",
      "diag.unavailable": "تتطلب عمليات تدقيق سجل الأحداث إصدار SysPulse الخاص بنظام Windows.",
      "diag.running": "جارٍ تحليل سجلات الأحداث…",
      "diag.report.auth": "تدقيق المصادقة والوصول", "diag.report.reliability": "تدقيق موثوقية النظام والأعطال",
      "diag.meta": "تم فحص {n} حدث · الفترة {h} ساعة · انتهى {t} · استغرق {d}",
      "diag.none": "لم تُكتشف مشكلات في هذه الفترة. ✔",
      "diag.byEvent": "الأحداث حسب المعرّف:",
      "diag.findingsCount": "{n} نتيجة",
      "diag.export": "تصدير:",
      "diag.done": "اكتمل {kind}: {n} نتيجة",
      "diag.failed": "فشل التدقيق: {e}",
      "diag.details": "التفاصيل", "diag.samples": "نماذج من الحالات",
      "col.finding": "النتيجة", "col.subject": "الحساب / المكوّن", "col.events": "أرقام الأحداث", "col.window": "أول ← آخر ظهور",
      "col.diagnosis": "التشخيص بلغة مبسّطة", "col.fix": "الإصلاح المقترح",
      "kind.failed-logon": "دخول فاشل", "kind.password-spray": "رشّ كلمات المرور", "kind.account-lockout": "قفل حساب",
      "kind.privileged-logon": "دخول بصلاحيات عالية", "kind.service-crash": "انهيار خدمة", "kind.app-fault": "عطل تطبيق",
      "kind.app-hang": "تجمّد تطبيق", "kind.bugcheck": "شاشة زرقاء", "kind.unexpected-shutdown": "إيقاف غير متوقع",

      "sev.critical": "حرج", "sev.warning": "تحذير", "sev.info": "معلوماتي",
      "alerts.title": "التنبيهات والحوادث", "alerts.all": "الكل", "alerts.allCats": "كل الفئات", "alerts.search": "ابحث في التنبيهات…",
      "alerts.onlyUnacked": "غير المراجَعة فقط", "alerts.unacked": "غير مراجَعة", "alerts.last24": "آخر 24 ساعة",
      "alerts.ackAll": "مراجعة الكل", "alerts.clear": "مسح", "alerts.exportLbl": "تصدير (حسب التصفية الحالية):",
      "alerts.ack": "مراجعة", "alerts.acked": "تمت المراجعة", "alerts.none": "لا توجد تنبيهات مطابقة للتصفية الحالية.",
      "alerts.foot": "{n} من {total} تنبيه", "alerts.clearConfirm": "هل تريد حذف جميع التنبيهات من القائمة؟ لن تتأثر التقارير المصدّرة سابقًا.",
      "alerts.details": "تفاصيل التنبيه", "alerts.fields": "الحقول",
      "acat.network-sweep": "مسح الشبكة", "acat.authentication": "المصادقة", "acat.reliability": "الموثوقية",
      "acat.resource": "الموارد", "acat.system": "النظام",
      "src.radar": "الرادار", "src.eventlog": "سجل الأحداث", "src.audit": "التدقيق", "src.metrics": "القياسات", "src.syspulse": "SysPulse",

      "col.proto": "البروتوكول", "col.process": "العملية", "col.pid": "المعرّف", "col.localAddr": "العنوان المحلي", "col.port": "المنفذ",
      "col.remoteAddr": "العنوان البعيد", "col.state": "الحالة", "col.firstSeen": "أول ظهور", "col.remoteIp": "العنوان البعيد",
      "col.mac": "عنوان MAC", "col.iface": "الواجهة", "col.portsWindow": "منافذ / نافذة", "col.pressure": "الاقتراب من الحد",
      "col.connsWindow": "محاولات / نافذة", "col.rate": "المعدل (60 ث)", "col.distinct": "منافذ مختلفة", "col.total": "الإجمالي",
      "col.lastSeen": "آخر ظهور", "col.sensor": "المستشعر", "col.name": "الاسم", "col.parent": "الأب", "col.cpu": "المعالج %",
      "col.ws": "مجموعة العمل", "col.private": "الخاصة", "col.threads": "الخيوط", "col.started": "وقت البدء", "col.path": "المسار",
      "col.time": "الوقت", "col.level": "المستوى", "col.category": "الفئة", "col.source": "المصدر", "col.id": "المعرّف",
      "col.channel": "القناة", "col.message": "الرسالة", "col.severity": "الخطورة", "col.alert": "التنبيه", "col.details": "التفاصيل",
      "col.count": "التكرار", "col.sourceMod": "المصدر", "col.pkg": "معرّف الحزمة", "col.installed": "المثبّت", "col.available": "المتاح",
      "col.command": "الأمر", "col.version": "الإصدار", "col.update": "التحديث", "col.publisher": "الناشر",
      "col.installedOn": "تاريخ التثبيت", "col.size": "الحجم", "col.scope": "النطاق", "col.type": "النوع",

      "sw.upgrades": "الترقيات المتاحة", "sw.check": "التحقق من التحديثات", "sw.checking": "جارٍ التحقق…", "sw.apps": "التطبيقات المثبّتة",
      "sw.filter": "تصفية حسب الاسم أو الناشر…", "sw.onlyUpd": "التي لها تحديثات فقط", "sw.checked": "· آخر تحقق {t}",
      "sw.notChecked": "· لم يتم التحقق بعد", "sw.upgrade": "ترقية", "sw.upgrading": "جارٍ الترقية…", "sw.runningWinget": "جارٍ تشغيل winget…",
      "sw.upToDate": "كل البرامج محدّثة.", "sw.pressCheck": "اضغط «التحقق من التحديثات» للاستعلام من winget.",
      "sw.count": "({n} من {total})", "sw.copy": "انقر للنسخ", "sw.copied": "تم نسخ الأمر",
      "sw.confirm": "ترقية {id} بصمت باستخدام winget؟", "sw.started": "جارٍ ترقية {id}…", "sw.failed": "فشلت الترقية: {e}",
      "sw.refreshFailed": "فشل التحديث: {e}", "sw.checkingToast": "جارٍ التحقق من التحديثات عبر winget…", "sw.invFailed": "فشل جرد البرامج: {e}",

      "ago.s": "قبل {n} ث", "ago.m": "قبل {n} د", "ago.h": "قبل {n} س", "ago.d": "قبل {n} يوم",
      "btn.ok": "موافق", "btn.cancel": "إلغاء", "btn.close": "إغلاق", "btn.confirm": "تأكيد",
      "err.generic": "فشل الطلب: {e}",
    },
  };

  let lang = "en";
  try { const s = localStorage.getItem("syspulse.lang"); if (s === "ar" || s === "en") lang = s; } catch (_) { /* storage disabled */ }

  const t = (key, vars) => {
    let s = (D[lang] && D[lang][key]) ?? D.en[key] ?? key;
    if (vars) s = s.replace(/\{(\w+)\}/g, (m, k) => (vars[k] ?? m));
    return s;
  };
  // Pick the active language from a bilingual {en, ar} object sent by the server.
  const tx = (o) => (o ? (lang === "ar" && o.ar ? o.ar : o.en || "") : "");

  function apply(root) {
    const r = root || document;
    r.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
    r.querySelectorAll("[data-i18n-ph]").forEach((el) => { el.placeholder = t(el.dataset.i18nPh); });
    r.querySelectorAll("[data-i18n-title]").forEach((el) => { el.title = t(el.dataset.i18nTitle); });
  }

  const listeners = [];
  function set(l) {
    lang = l === "ar" ? "ar" : "en";
    try { localStorage.setItem("syspulse.lang", lang); } catch (_) { /* ignore */ }
    const html = document.documentElement;
    html.lang = lang;
    html.dir = lang === "ar" ? "rtl" : "ltr";
    document.body.classList.toggle("rtl", lang === "ar");
    document.title = lang === "ar" ? "SysPulse 2.0 — لوحة مراقبة وموثوقية Windows" : "SysPulse 2.0 — Windows Observability & Reliability Cockpit";
    apply();
    listeners.forEach((fn) => fn(lang));
  }

  window.I18N = {
    t, tx, apply, set, dict: D,
    get lang() { return lang; },
    locale: () => (lang === "ar" ? "ar-u-nu-latn" : undefined),
    onChange: (fn) => listeners.push(fn),
  };
})();
