/* SysPulse 3.0 — integrated User Guide & System Manual (English / Arabic).
 * Content is structured data rendered into tables by renderGuide(); all text
 * is escaped, so it is safe under the strict CSP. */
(() => {
  "use strict";
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  // `code` spans: text between backticks is rendered monospace.
  // Minimal inline markup on already-escaped text: `code`, **bold**, *italic*.
  const rich = (s) => esc(s)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>")
    .replace(/(^|[\s(«“])\*([^*\s][^*]*)\*/g, "$1<i>$2</i>");

  const G = {
    en: {
      title: "SysPulse 3.0 — User Guide & System Manual",
      intro: "SysPulse is a read-only Windows observability and reliability cockpit. It samples the machine through native Win32 APIs, streams live telemetry to this dashboard over a local WebSocket, detects network connection sweeps, audits the event logs on demand and keeps a searchable, exportable incident stream. Nothing is changed on the machine except the software upgrades you start yourself.",
      toc: "Contents",
      sections: [
        {
          id: "v3", h: "What's new in 3.0",
          table: { cols: ["Feature", "What it does"], rows: [
            ["100% real telemetry", "syspulse.exe runs no synthetic generator. The radar self-test is off unless started with `-enable-selftest`; the header badge shows **LIVE HOST DATA**."],
            ["False-positive hardening", "The TCP-table sensor only counts a row as inbound when a listener for the same address *and* process accepted it. Browsers, sync clients and updaters (Chrome, Edge, Firefox, Teams, OneDrive, winget…) and ephemeral→service-port sockets are never counted. The host's own addresses are ignored. Add names with `-radar-client-procs`."],
            ["LAN device & vendor profiling", "Network → **Local network devices**: every ARP neighbour with its manufacturer from the embedded IEEE OUI registry (≈54 000 MA-L/MA-M/MA-S prefixes, longest-prefix match), device type, and host name from NetBIOS, mDNS or reverse DNS. Randomised (private) MACs are flagged."],
            ["Instant filters", "Event Log and Diagnostics: multi-select severity chips with live counts, category and channel dropdowns, quick ranges (1 h / 24 h / 3 days) and From/To date pickers — all applied as you type, no reloads."],
            ["Deep software inventory", "HKLM 64/32-bit, HKCU 64/32-bit and other users' hives (HKU). Toggle system components and updates, filter by scope/publisher, click a row for uninstall command, registry key, install source and date origin."],
            ["Process actions", "Quick filters (High CPU, High memory, Top 10, Protected) with thresholds, one-click **Copy process diagnostic path**, and an **Inspect details** modal with command line, account, handles, priority, I/O, children and sockets."],
          ] },
        },
        {
          id: "quick", h: "1. Quick start",
          list: [
            "Run `syspulse.exe` from an **elevated** (Run as administrator) prompt for full visibility: protected processes, the Security log and the raw SYN sensor all need elevation.",
            "The dashboard opens at `http://127.0.0.1:9099`. It listens on loopback only and cannot be reached from the network.",
            "Use the **EN / AR** switch in the top bar to change language. Arabic switches the whole interface to right-to-left.",
            "The 🔔 button mutes or enables the audible chime for critical network alerts.",
          ],
        },
        {
          id: "tabs", h: "2. Dashboard tabs",
          table: { cols: ["Tab", "What it shows", "Data source (Win32)", "Refresh"], rows: [
            ["Overview", "CPU, memory, commit charge, processes, sockets, uptime, radar and alert status, 5-minute history chart, disks, top CPU processes, latest errors", "GetSystemTimes, GlobalMemoryStatusEx, GetPerformanceInfo, GetDiskFreeSpaceExW", "1 s"],
            ["Network", "Every TCP/UDP socket (IPv4 + IPv6) with owning process, endpoints and state; new sockets flash green", "GetExtendedTcpTable / GetExtendedUdpTable", "1 s"],
            ["Anomaly Radar", "Per-remote-IP connection frequency and distinct-port breadth, sweep incidents, sensor status, ARP attribution", "Raw socket SIO_RCVALL, TCP table, GetIpNetTable, SendARP, GetBestRoute", "1 s"],
            ["Processes", "CPU %, working set, private bytes, threads, start time, image path", "Toolhelp32, GetProcessTimes, GetProcessMemoryInfo", "1 s"],
            ["Event Log", "System + Application events classified by reliability category, 7-day stacked timeline", "wevtapi EvtQuery / EvtRender / EvtFormatMessage", "15 s"],
            ["Diagnostics", "Two one-click audits with plain-language diagnosis and recommended fix per finding", "wevtapi (Security, System, Application)", "on demand"],
            ["Alerts & Incidents", "All alerts with severity badges, quick filters, acknowledgement, JSON/CSV export", "All modules", "real time"],
            ["Software", "Installed programs and winget upgrades with one-click upgrade", "Registry Uninstall keys, winget.exe", "on demand"],
          ] },
        },
        {
          id: "metrics", h: "3. Metric reference",
          table: { cols: ["Metric", "Meaning", "Healthy range", "When to worry"], rows: [
            ["CPU %", "Share of all logical processors busy over the last interval", "< 70% sustained", "> 90% for 30 s raises a warning alert"],
            ["Memory %", "Physical RAM in use (excluding standby cache)", "< 80%", "> 92% raises a memory-pressure alert"],
            ["Commit", "Virtual memory promised to processes vs. RAM + page file limit", "< 80% of limit", "Near 100%: allocations fail, apps crash"],
            ["Working set", "RAM currently mapped by a process (RSS)", "Depends on app", "Steady growth over hours = possible leak"],
            ["Private bytes", "Memory committed exclusively to a process", "Depends on app", "Grows without dropping = leak"],
            ["Sockets / new per s", "Open sockets and new sockets per second (10 s average)", "Stable", "Sudden bursts may mean scanning or a runaway client"],
            ["Disk %", "Used space per volume", "< 85%", "> 92% warning, > 97% critical alert"],
            ["Ports / window", "Distinct local ports one remote IP touched inside the detection window", "≤ 3 for normal clients", "> threshold (10) = sweep"],
            ["Rule pressure", "Ports / window ÷ threshold (100% = at the limit)", "< 30%", "Bar turns amber above 60%, red at 100%"],
            ["Attempts / window", "Inbound connection attempts from the IP inside the window", "Low", "High with few ports = flood or retry loop, not a sweep"],
          ] },
        },
        {
          id: "radar", h: "4. Multi-port connection sweep & network anomaly radar",
          p: [
            "The radar tracks every inbound TCP connection attempt per remote IP. **Rule:** if a single remote IP contacts **more than 10 distinct local ports within 5 seconds**, it is flagged immediately as a **High-Frequency Connection Sweep (Traffic Anomaly)**. The window, threshold and cooldown are configurable with `-radar-window`, `-radar-threshold` and `-radar-cooldown`.",
            "When a sweep is detected SysPulse: (1) opens an incident, (2) looks up the remote IP in the Windows ARP table with `GetIpNetTable` — if absent, it asks `GetBestRoute` which interface reaches it and resolves the MAC with `SendARP`, (3) shows the **red warning banner** with Remote IP, MAC address, interface, target port range and timestamp, (4) plays an audio chime and (5) records a **critical** alert.",
          ],
          table: { cols: ["Sensor", "How it works", "Sees", "Needs"], rows: [
            ["Raw SYN sensor", "A SOCK_RAW socket per local IPv4 address in SIO_RCVALL (RCVALL_IPLEVEL) mode reads every inbound IP packet; TCP packets with SYN set and ACK clear are counted", "All IPv4 attempts, including closed and firewalled ports", "Administrator; Windows Firewall may need to allow syspulse.exe"],
            ["TCP-table sensor", "New inbound rows (to listening ports or SYN_RECEIVED) of GetExtendedTcpTable, polled every second", "Accepted connections, IPv4 and IPv6", "Nothing — always on"],
          ] },
          table2: { cols: ["Field", "Meaning"], rows: [
            ["MAC address", "Hardware address of the sweeping host when it is on the same network segment. For off-link (routed) hosts the MAC shown is the gateway's, marked “via gateway”."],
            ["Interface", "Network adapter (friendly name) through which the host is reached"],
            ["Target port range", "Compressed list of ports touched, e.g. `21-23, 80, 443, 1000-1040`"],
            ["Active / closed", "An incident closes after the host has been quiet for the cooldown (60 s default); a new burst opens a new incident"],
            ["Allow-list", "`-radar-allow 10.0.0.5,10.0.0.6` excludes authorised vulnerability scanners"],
          ] },
        },
        {
          id: "diag", h: "5. One-click event log diagnostics",
          table: { cols: ["Button", "Log", "Event IDs", "What is reported"], rows: [
            ["Audit Authentication & Access Logs", "Security", "4625, 4740, 4672", "Repeated failed logons per account and source (brute force), password spraying (one source, ≥ 5 account names), account lockouts, administrative privilege assignments (with escalation when failures precede them)"],
            ["Audit System Reliability & Faults", "System, Application", "7034, 7031, 1000, 1002, 1001 (BugCheck), 41, 6008", "Service crashes, application faults with faulting module and exception code, hangs, blue screens with decoded stop code, unexpected shutdowns"],
          ] },
          table2: { cols: ["Severity", "Typical trigger"], rows: [
            ["Critical", "≥ 20 failed logons or ≥ 10 in 10 min, password spraying, repeated lockouts, any bugcheck, a service crashing ≥ 3 times, an app crashing ≥ 5 times, ≥ 3 unexpected shutdowns"],
            ["Warning", "≥ 5 failed logons, a lockout, a service crash, repeated application faults, built-in Administrator in use"],
            ["Informational", "Isolated events, normal administrator logons, expected system-account privileges"],
          ] },
          p: ["Every finding has a **Plain-Language Diagnosis** and a **Recommended Fix** column in both languages. Critical and warning findings are also added to Alerts & Incidents. Reports can be exported as JSON or CSV (UTF-8 with BOM, opens correctly in Excel). The Security log requires administrator rights; without them the audit explains how to re-run elevated."],
        },
        {
          id: "alerts", h: "6. Alerts & Incidents",
          table: { cols: ["Badge", "Meaning", "Examples"], rows: [
            ["Critical", "Needs attention now", "Connection sweep, bugcheck, brute-force attack, disk > 97%"],
            ["Warning", "Degradation or risk", "Service crash, memory pressure, sustained CPU, lockout"],
            ["Informational", "For the record", "Baseline loaded, isolated errors, audit notes"],
          ] },
          list: [
            "Repeated occurrences of the same problem are folded into one alert with a **Count** instead of flooding the list.",
            "Quick filters: severity chips, category, free-text search (IP, MAC, account, service…), unacknowledged only.",
            "**Export** downloads exactly what the current filter shows, as JSON (with counts and metadata) or CSV (both languages, spreadsheet-safe).",
            "Click a row to open the full alert with all fields.",
          ],
        },
        {
          id: "verify", h: "7. Verification guide — testing sweep detection safely",
          warn: "Only scan machines you own or are explicitly authorised to test. Port scanning third-party networks may be illegal. The steps below stay inside your own LAN.",
          steps: [
            ["Built-in self-test (no network traffic)", "Start SysPulse with `-enable-selftest` (the button is hidden and the endpoint refused in live mode), open **Anomaly Radar** and press **Run safe self-test**. SysPulse injects a synthetic sweep from the documentation address `198.51.100.77` (RFC 5737). Expected: red banner with MAC `00-00-5E-00-53-01`, chime, a critical “[TEST]” alert, and an incident marked *test*."],
            ["Prepare the target (this PC)", "Start SysPulse as administrator. On the Radar tab confirm **Raw SYN sensor: active**. Note this PC's IPv4 address with `ipconfig` (e.g. `192.168.1.42`)."],
            ["Choose a second machine on the same LAN", "Any Windows, Linux or macOS machine you control. Its IP should appear in the ARP table (**ARP table** button) after it has talked to this PC once (e.g. `ping 192.168.1.42`)."],
            ["Generate a sweep — option A: PowerShell (no tools to install)", "On the second machine run:\n`1..40 | % { $c = New-Object Net.Sockets.TcpClient; $c.BeginConnect('192.168.1.42', $_, $null, $null) | Out-Null; Start-Sleep -Milliseconds 50; $c.Close() }`\nThis touches ports 1–40 in about 2 seconds."],
            ["Generate a sweep — option B: Nmap", "`nmap -sS -p 1-100 -T4 192.168.1.42` (or `-sT` without admin). Nmap is the standard tool for authorised network testing."],
            ["Generate a sweep — option C: netcat (Linux/macOS)", "`nc -z -w1 192.168.1.42 1-60`"],
            ["Verify the result", "Within a second: red banner showing the second machine's IP and MAC, the interface name, a port range such as `1-40`, and the timestamp; a chime plays; the Radar table shows the host flagged with rule pressure ≥ 100%; **Alerts & Incidents** has a critical *Network sweep* alert. Compare the MAC with `ipconfig /all` (Windows) or `ip link` (Linux) on the second machine."],
            ["Negative test", "Connect normally (e.g. open one web page or SMB share) from the second machine — the host appears in the table with low pressure and is **not** flagged. Scan slowly (`nmap -T1`) — spread over more than 5 s per 10 ports, it stays below the rule."],
            ["If nothing is detected", "Without elevation only accepted connections to listening ports are seen: scan ports that are open, or run as administrator. If the raw sensor is active but silent, allow `syspulse.exe` in Windows Defender Firewall (inbound). IPv6 scans are detected by the TCP-table sensor only."],
          ],
        },
        {
          id: "security", h: "8. Security & privacy model",
          table: { cols: ["Control", "Protection"], rows: [
            ["Loopback-only listener", "The dashboard is never reachable from the network; non-loopback -addr values are refused"],
            ["Host header check", "Blocks DNS-rebinding attacks"],
            ["Per-launch session token + same-origin", "Required for WebSocket, every POST (self-test, audits, acknowledgements, upgrades) and every export download"],
            ["Strict Content-Security-Policy", "No inline scripts or styles, no CDNs, no third-party requests"],
            ["Spreadsheet-safe CSV", "Cells starting with = + - @ are neutralised (attacker-controlled user names cannot inject formulas)"],
            ["Read-only telemetry", "Sensors observe only; the raw sensor uses RCVALL_IPLEVEL (no promiscuous mode) and inspects headers only"],
          ] },
        },
        {
          id: "flags", h: "9. Command-line options",
          table: { cols: ["Flag", "Default", "Meaning"], rows: [
            ["-addr", "127.0.0.1:9099", "Listen address (loopback only)"],
            ["-radar-window", "5s", "Sweep detection window"],
            ["-radar-threshold", "10", "Flag when distinct ports exceed this value"],
            ["-radar-cooldown", "60s", "Quiet time before an incident closes"],
            ["-radar-allow", "(none)", "Comma-separated IPs never flagged"],
            ["-no-raw-capture", "false", "Disable the raw SYN sensor"],
            ["-interval", "1s", "Sampling period"],
            ["-events-window / -events-max", "168h / 2000", "Event log look-back and retention"],
            ["-no-browser, -v, -version", "", "UI launch, verbose logging, version"],
          ] },
        },
        {
          id: "faq", h: "10. Troubleshooting",
          table: { cols: ["Symptom", "Cause", "Fix"], rows: [
            ["Raw SYN sensor inactive", "Not elevated, or blocked by policy", "Run as administrator; allow syspulse.exe in the firewall"],
            ["MAC shows “unknown”", "IPv6 peer, or host did not answer ARP", "MAC attribution is IPv4 only; the host may have left the network"],
            ["MAC is the router's", "The scanner is on another subnet or the internet", "Expected: only the gateway MAC is visible across a router"],
            ["Authentication audit shows an access error", "Security log needs admin rights", "Restart SysPulse elevated"],
            ["No 4625 events at all", "Logon failure auditing disabled", "`auditpol /set /subcategory:\"Logon\" /failure:enable`"],
            ["No sound", "Browser blocks audio until you interact", "Click anywhere once; check the 🔔 toggle"],
          ] },
        },
      ],
    },

    ar: {
      title: "SysPulse 3.0 — دليل الاستخدام ودليل النظام",
      intro: "SysPulse لوحة قراءة فقط لمراقبة Windows وموثوقيته. يقرأ حالة الجهاز عبر واجهات Win32 الأصلية، ويبث القياسات الحية إلى هذه اللوحة عبر WebSocket محلي، ويكتشف عمليات مسح المنافذ على الشبكة، ويدقق سجلات الأحداث عند الطلب، ويحفظ سجل حوادث قابلًا للبحث والتصدير. لا يغيّر شيئًا على الجهاز باستثناء ترقيات البرامج التي تبدؤها بنفسك.",
      toc: "المحتويات",
      sections: [
        {
          id: "v3", h: "الجديد في الإصدار 3.0",
          table: { cols: ["الميزة", "ماذا تفعل"], rows: [
            ["بيانات حقيقية 100%", "لا يشغّل syspulse.exe أي مولّد بيانات اصطناعية. الاختبار الذاتي للرادار معطّل ما لم يُشغَّل البرنامج بالخيار `-enable-selftest`، وتعرض الشارة في الأعلى **بيانات حيّة من الجهاز**."],
            ["الحد من الإنذارات الكاذبة", "لا يَعُدّ مستشعر جدول TCP الاتصال واردًا إلا إذا قبله مستمع على العنوان نفسه ومن العملية نفسها. لا تُحتسب أبدًا اتصالات المتصفحات وعملاء المزامنة وبرامج التحديث (Chrome و Edge و Firefox و Teams و OneDrive و winget…) ولا الاتصالات من منفذ مؤقت إلى منفذ خدمة. عناوين الجهاز نفسه مستثناة. أضف أسماء أخرى عبر `-radar-client-procs`."],
            ["تعريف أجهزة الشبكة والمصنّعين", "الشبكة ← **أجهزة الشبكة المحلية**: كل جار في جدول ARP مع الشركة المصنّعة من سجل IEEE OUI المضمّن (نحو 54 ألف بادئة MA-L/MA-M/MA-S بمطابقة أطول بادئة)، ونوع الجهاز، واسمه عبر NetBIOS أو mDNS أو DNS العكسي. تُعلَّم عناوين MAC العشوائية (الخاصة)."],
            ["تصفية فورية", "سجل الأحداث والتشخيص: شرائح خطورة متعددة الاختيار مع أعداد حيّة، وقوائم الفئة والقناة، ونطاقات سريعة (ساعة / 24 ساعة / 3 أيام) ومنتقي تاريخ من/إلى — تُطبَّق أثناء الكتابة دون إعادة تحميل."],
            ["جرد عميق للبرامج", "HKLM بنسختي 64/32 بت، و HKCU بنسختي 64/32 بت، وسجلات المستخدمين الآخرين (HKU). يمكن إظهار مكوّنات النظام والتحديثات، والتصفية حسب النطاق والناشر، والنقر على أي صف لعرض أمر الإزالة ومفتاح السجل ومصدر التثبيت ومصدر التاريخ."],
            ["إجراءات العمليات", "مرشحات سريعة (معالج مرتفع، ذاكرة مرتفعة، أعلى 10، محمية) مع حدود قابلة للضبط، وزر **نسخ مسار العملية التشخيصي**، ونافذة **عرض التفاصيل** مع سطر الأوامر والحساب والمقابض والأولوية والإدخال/الإخراج والعمليات الفرعية والمقابس."],
          ] },
        },
        {
          id: "quick", h: "1. البدء السريع",
          list: [
            "شغّل `syspulse.exe` من نافذة أوامر **بصلاحيات المسؤول** لرؤية كاملة: العمليات المحمية وسجل الأمان ومستشعر SYN الخام كلها تتطلب صلاحيات المسؤول.",
            "تُفتح اللوحة على `http://127.0.0.1:9099`. تستمع على عنوان الحلقة المحلية فقط ولا يمكن الوصول إليها من الشبكة.",
            "استخدم مفتاح **EN / AR** في الشريط العلوي لتغيير اللغة. عند اختيار العربية تتحول الواجهة بالكامل إلى الاتجاه من اليمين إلى اليسار.",
            "زر 🔔 يكتم أو يفعّل الصوت المصاحب لتنبيهات الشبكة الحرجة.",
          ],
        },
        {
          id: "tabs", h: "2. تبويبات اللوحة",
          table: { cols: ["التبويب", "ما يعرضه", "مصدر البيانات (Win32)", "التحديث"], rows: [
            ["نظرة عامة", "المعالج والذاكرة والذاكرة الملتزمة والعمليات والمقابس ومدة التشغيل وحالة الرادار والتنبيهات ومخطط آخر 5 دقائق والأقراص وأعلى العمليات وأحدث الأخطاء", "GetSystemTimes، GlobalMemoryStatusEx، GetPerformanceInfo، GetDiskFreeSpaceExW", "1 ث"],
            ["الشبكة", "كل مقابس TCP/UDP ‏(IPv4 و IPv6) مع العملية المالكة والعناوين والحالة؛ المقابس الجديدة تومض بالأخضر", "GetExtendedTcpTable / GetExtendedUdpTable", "1 ث"],
            ["رادار الشذوذ", "تردد الاتصال واتساع المنافذ لكل عنوان بعيد، وحوادث المسح، وحالة المستشعرات، وتحديد عنوان MAC", "مقبس خام SIO_RCVALL، جدول TCP، GetIpNetTable، SendARP، GetBestRoute", "1 ث"],
            ["العمليات", "نسبة المعالج ومجموعة العمل والذاكرة الخاصة والخيوط ووقت البدء والمسار", "Toolhelp32، GetProcessTimes، GetProcessMemoryInfo", "1 ث"],
            ["سجل الأحداث", "أحداث النظام والتطبيقات مصنفة حسب فئة الموثوقية مع مخطط زمني لسبعة أيام", "wevtapi: EvtQuery / EvtRender / EvtFormatMessage", "15 ث"],
            ["التشخيص", "عمليتا تدقيق بنقرة واحدة مع تشخيص مبسّط وإصلاح مقترح لكل نتيجة", "wevtapi (الأمان، النظام، التطبيقات)", "عند الطلب"],
            ["التنبيهات والحوادث", "كل التنبيهات مع شارات الخطورة والتصفية السريعة والمراجعة والتصدير JSON/CSV", "جميع الوحدات", "فوري"],
            ["البرامج", "البرامج المثبتة وترقيات winget مع ترقية بنقرة واحدة", "مفاتيح التسجيل Uninstall، ‏winget.exe", "عند الطلب"],
          ] },
        },
        {
          id: "metrics", h: "3. مرجع المقاييس",
          table: { cols: ["المقياس", "المعنى", "النطاق السليم", "متى تقلق"], rows: [
            ["المعالج %", "نسبة انشغال جميع المعالجات المنطقية خلال آخر فترة", "أقل من 70% باستمرار", "أكثر من 90% لمدة 30 ثانية يُنشئ تنبيه تحذير"],
            ["الذاكرة %", "الذاكرة الفعلية المستخدمة (دون ذاكرة الاستعداد المؤقتة)", "أقل من 80%", "أكثر من 92% يُنشئ تنبيه ضغط على الذاكرة"],
            ["الذاكرة الملتزمة", "الذاكرة الافتراضية الموعودة للعمليات مقابل حد الذاكرة وملف الترحيل", "أقل من 80% من الحد", "قرب 100%: تفشل عمليات الحجز وتنهار التطبيقات"],
            ["مجموعة العمل", "الذاكرة الفعلية المعيّنة حاليًا للعملية (RSS)", "حسب التطبيق", "نمو مستمر لساعات = احتمال تسرّب ذاكرة"],
            ["الذاكرة الخاصة", "الذاكرة المحجوزة حصريًا للعملية", "حسب التطبيق", "تزداد دون أن تنخفض = تسرّب"],
            ["المقابس / الجديدة في الثانية", "المقابس المفتوحة والجديدة في الثانية (متوسط 10 ث)", "مستقر", "الارتفاع المفاجئ قد يعني مسحًا أو عميلًا خارجًا عن السيطرة"],
            ["القرص %", "المساحة المستخدمة لكل قرص", "أقل من 85%", "أكثر من 92% تحذير، وأكثر من 97% تنبيه حرج"],
            ["منافذ / نافذة", "عدد المنافذ المحلية المختلفة التي لمسها عنوان بعيد واحد داخل نافذة الكشف", "3 أو أقل للعملاء العاديين", "تجاوز الحد (10) = مسح"],
            ["الاقتراب من الحد", "منافذ النافذة ÷ الحد (100% = عند الحد)", "أقل من 30%", "يصبح الشريط برتقاليًا فوق 60% وأحمر عند 100%"],
            ["محاولات / نافذة", "محاولات الاتصال الواردة من العنوان داخل النافذة", "منخفض", "مرتفع مع منافذ قليلة = إغراق أو إعادة محاولات، وليس مسحًا"],
          ] },
        },
        {
          id: "radar", h: "4. رادار مسح المنافذ المتعددة وشذوذ الشبكة",
          p: [
            "يتتبع الرادار كل محاولة اتصال TCP واردة لكل عنوان بعيد. **القاعدة:** إذا اتصل عنوان بعيد واحد بـ **أكثر من 10 منافذ محلية مختلفة خلال 5 ثوانٍ** فإنه يُعلَّم فورًا على أنه **مسح اتصالات عالي التردد (شذوذ في حركة المرور)**. يمكن تعديل النافذة والحد وفترة التهدئة عبر `-radar-window` و `-radar-threshold` و `-radar-cooldown`.",
            "عند اكتشاف المسح يقوم SysPulse بما يلي: (1) يفتح حادثة، (2) يبحث عن العنوان في جدول ARP الخاص بـ Windows عبر `GetIpNetTable` — وإن لم يجده يسأل `GetBestRoute` عن الواجهة التي توصل إليه ثم يحدد عنوان MAC عبر `SendARP`، (3) يعرض **الشريط الأحمر التحذيري** مع العنوان البعيد وعنوان MAC والواجهة ونطاق المنافذ المستهدفة والوقت، (4) يُصدر تنبيهًا صوتيًا، (5) يسجل تنبيهًا **حرجًا**.",
          ],
          table: { cols: ["المستشعر", "طريقة العمل", "ما يرصده", "المتطلبات"], rows: [
            ["مستشعر SYN الخام", "مقبس SOCK_RAW لكل عنوان IPv4 محلي في وضع SIO_RCVALL ‏(RCVALL_IPLEVEL) يقرأ كل حزمة IP واردة؛ وتُحتسب حزم TCP التي تحمل SYN دون ACK", "جميع محاولات IPv4 بما فيها المنافذ المغلقة والمحجوبة بالجدار الناري", "صلاحيات المسؤول؛ وقد يلزم السماح لـ syspulse.exe في جدار حماية Windows"],
            ["مستشعر جدول TCP", "الصفوف الواردة الجديدة (إلى منافذ الاستماع أو بحالة SYN_RECEIVED) في GetExtendedTcpTable كل ثانية", "الاتصالات المقبولة، IPv4 و IPv6", "لا شيء — يعمل دائمًا"],
          ] },
          table2: { cols: ["الحقل", "المعنى"], rows: [
            ["عنوان MAC", "العنوان الفيزيائي للجهاز الذي يجري المسح إن كان في مقطع الشبكة نفسه. للأجهزة خارج الشبكة المحلية يُعرض عنوان MAC الخاص بالبوابة مع عبارة «عبر البوابة»."],
            ["الواجهة", "محول الشبكة (بالاسم المألوف) الذي يتم الوصول عبره إلى الجهاز"],
            ["نطاق المنافذ المستهدفة", "قائمة مختصرة بالمنافذ الملموسة، مثل `21-23, 80, 443, 1000-1040`"],
            ["نشط / مغلق", "تُغلق الحادثة بعد هدوء الجهاز طوال فترة التهدئة (60 ثانية افتراضيًا)؛ وأي دفعة جديدة تفتح حادثة جديدة"],
            ["القائمة المسموح بها", "`-radar-allow 10.0.0.5,10.0.0.6` تستثني أدوات فحص الثغرات المصرّح بها"],
          ] },
        },
        {
          id: "diag", h: "5. تشخيص سجل الأحداث بنقرة واحدة",
          table: { cols: ["الزر", "السجل", "أرقام الأحداث", "ما يتم الإبلاغ عنه"], rows: [
            ["تدقيق سجلات المصادقة والوصول", "الأمان", "4625، 4740، 4672", "محاولات الدخول الفاشلة المتكررة لكل حساب ومصدر (هجوم تخمين)، ورشّ كلمات المرور (مصدر واحد يجرب 5 أسماء أو أكثر)، وقفل الحسابات، ومنح الصلاحيات الإدارية (مع رفع الخطورة إذا سبقتها محاولات فاشلة)"],
            ["تدقيق موثوقية النظام والأعطال", "النظام، التطبيقات", "7034، 7031، 1000، 1002، 1001 (BugCheck)، 41، 6008", "انهيار الخدمات، وأعطال التطبيقات مع الوحدة المسببة ورمز الاستثناء، والتجمّد، والشاشات الزرقاء مع تفسير رمز الإيقاف، والإيقاف غير المتوقع"],
          ] },
          table2: { cols: ["الخطورة", "المسبب المعتاد"], rows: [
            ["حرج", "20 محاولة فاشلة أو أكثر أو 10 خلال 10 دقائق، أو رشّ كلمات المرور، أو قفل متكرر، أو أي شاشة زرقاء، أو انهيار خدمة 3 مرات فأكثر، أو انهيار تطبيق 5 مرات فأكثر، أو 3 إيقافات غير متوقعة فأكثر"],
            ["تحذير", "5 محاولات فاشلة فأكثر، أو قفل حساب، أو انهيار خدمة، أو أعطال تطبيق متكررة، أو استخدام حساب Administrator المدمج"],
            ["معلوماتي", "أحداث منفردة، أو دخول عادي لمسؤول، أو صلاحيات متوقعة لحسابات النظام"],
          ] },
          p: ["لكل نتيجة عمودان: **التشخيص بلغة مبسّطة** و**الإصلاح المقترح** باللغتين. وتُضاف النتائج الحرجة والتحذيرية أيضًا إلى التنبيهات والحوادث. يمكن تصدير التقارير بصيغة JSON أو CSV ‏(UTF-8 مع BOM لتظهر العربية صحيحة في Excel). يتطلب سجل الأمان صلاحيات المسؤول؛ وبدونها يوضح التدقيق كيفية إعادة التشغيل بصلاحيات مرتفعة."],
        },
        {
          id: "alerts", h: "6. التنبيهات والحوادث",
          table: { cols: ["الشارة", "المعنى", "أمثلة"], rows: [
            ["حرج", "يحتاج إلى تدخل فوري", "مسح اتصالات، شاشة زرقاء، هجوم تخمين كلمات المرور، امتلاء القرص فوق 97%"],
            ["تحذير", "تراجع في الأداء أو خطر محتمل", "انهيار خدمة، ضغط على الذاكرة، استخدام مستمر للمعالج، قفل حساب"],
            ["معلوماتي", "للتوثيق", "تحميل خط الأساس، أخطاء منفردة، ملاحظات التدقيق"],
          ] },
          list: [
            "تُدمج تكرارات المشكلة نفسها في تنبيه واحد مع **عدّاد** بدلًا من إغراق القائمة.",
            "تصفية سريعة: شرائح الخطورة، والفئة، والبحث النصي (عنوان IP أو MAC أو حساب أو خدمة…)، وغير المراجَعة فقط.",
            "**التصدير** ينزّل ما تعرضه التصفية الحالية تمامًا، بصيغة JSON (مع الإحصاءات والبيانات الوصفية) أو CSV (باللغتين وآمن لجداول البيانات).",
            "انقر على أي صف لفتح التنبيه كاملًا مع جميع الحقول.",
          ],
        },
        {
          id: "verify", h: "7. دليل التحقق — اختبار كشف المسح بأمان",
          warn: "لا تفحص إلا الأجهزة التي تملكها أو المصرّح لك رسميًا باختبارها. فحص منافذ شبكات الآخرين قد يكون مخالفًا للقانون. الخطوات التالية تبقى داخل شبكتك المحلية.",
          steps: [
            ["الاختبار الذاتي المدمج (دون أي حركة على الشبكة)", "شغّل SysPulse بالخيار `-enable-selftest` (الزر مخفي والطلب مرفوض في الوضع الحي)، ثم افتح **رادار الشذوذ** واضغط **تشغيل اختبار ذاتي آمن**. يحقن SysPulse مسحًا اصطناعيًا من عنوان التوثيق `198.51.100.77` ‏(RFC 5737). النتيجة المتوقعة: شريط أحمر مع عنوان MAC ‏`00-00-5E-00-53-01`، وتنبيه صوتي، وتنبيه حرج يحمل «[اختبار]»، وحادثة معلّمة بـ *اختبار*."],
            ["تجهيز الجهاز المستهدف (هذا الجهاز)", "شغّل SysPulse بصلاحيات المسؤول. في تبويب الرادار تأكد من أن **مستشعر SYN الخام: نشط**. سجّل عنوان IPv4 لهذا الجهاز عبر `ipconfig` (مثل `192.168.1.42`)."],
            ["اختيار جهاز ثانٍ على الشبكة نفسها", "أي جهاز Windows أو Linux أو macOS تملكه. يجب أن يظهر عنوانه في جدول ARP (زر **جدول ARP**) بعد أن يتواصل مع هذا الجهاز مرة واحدة (مثل `ping 192.168.1.42`)."],
            ["توليد مسح — الخيار أ: PowerShell (دون تثبيت أدوات)", "على الجهاز الثاني نفّذ:\n`1..40 | % { $c = New-Object Net.Sockets.TcpClient; $c.BeginConnect('192.168.1.42', $_, $null, $null) | Out-Null; Start-Sleep -Milliseconds 50; $c.Close() }`\nيلمس هذا الأمر المنافذ 1–40 في نحو ثانيتين."],
            ["توليد مسح — الخيار ب: Nmap", "`nmap -sS -p 1-100 -T4 192.168.1.42` (أو `-sT` دون صلاحيات المسؤول). ‏Nmap هي الأداة القياسية لاختبارات الشبكة المصرّح بها."],
            ["توليد مسح — الخيار ج: netcat ‏(Linux/macOS)", "`nc -z -w1 192.168.1.42 1-60`"],
            ["التحقق من النتيجة", "خلال ثانية: شريط أحمر يعرض عنوان IP وعنوان MAC للجهاز الثاني، واسم الواجهة، ونطاق منافذ مثل `1-40`، والوقت؛ ويصدر تنبيه صوتي؛ ويظهر الجهاز في جدول الرادار معلّمًا بنسبة اقتراب 100% أو أكثر؛ ويظهر في **التنبيهات والحوادث** تنبيه حرج من فئة *مسح الشبكة*. قارن عنوان MAC بنتيجة `ipconfig /all` ‏(Windows) أو `ip link` ‏(Linux) على الجهاز الثاني."],
            ["اختبار سلبي", "اتصل بشكل عادي من الجهاز الثاني (افتح صفحة ويب واحدة أو مجلدًا مشتركًا) — يظهر الجهاز في الجدول بنسبة منخفضة **دون** تعليمه. وافحص ببطء (`nmap -T1`) — عند توزيع كل 10 منافذ على أكثر من 5 ثوانٍ يبقى تحت القاعدة."],
            ["إذا لم يُكتشف شيء", "دون صلاحيات المسؤول تُرصد فقط الاتصالات المقبولة على منافذ الاستماع: افحص منافذ مفتوحة أو شغّل البرنامج كمسؤول. إذا كان المستشعر الخام نشطًا لكنه صامت فاسمح لـ `syspulse.exe` في جدار حماية Windows ‏(الاتجاه الوارد). عمليات مسح IPv6 يرصدها مستشعر جدول TCP فقط."],
          ],
        },
        {
          id: "security", h: "8. نموذج الأمان والخصوصية",
          table: { cols: ["الضابط", "الحماية"], rows: [
            ["الاستماع على الحلقة المحلية فقط", "لا يمكن الوصول إلى اللوحة من الشبكة إطلاقًا؛ وتُرفض قيم ‎-addr غير المحلية"],
            ["فحص ترويسة Host", "يمنع هجمات إعادة ربط DNS"],
            ["رمز جلسة لكل تشغيل + نفس المصدر", "مطلوب لاتصال WebSocket ولكل طلب POST (الاختبار الذاتي، التدقيق، المراجعة، الترقيات) ولكل تنزيل تصدير"],
            ["سياسة أمان محتوى صارمة (CSP)", "لا نصوص أو أنماط مضمّنة، ولا شبكات توزيع محتوى، ولا طلبات لأطراف ثالثة"],
            ["ملفات CSV آمنة", "تُعطَّل الخلايا التي تبدأ بـ = + - @ (فلا يمكن لأسماء مستخدمين يتحكم بها مهاجم حقن صيغ)"],
            ["قياسات للقراءة فقط", "المستشعرات تراقب فقط؛ والمستشعر الخام يستخدم RCVALL_IPLEVEL (دون الوضع المختلط) ويفحص الترويسات فقط"],
          ] },
        },
        {
          id: "flags", h: "9. خيارات سطر الأوامر",
          table: { cols: ["الخيار", "الافتراضي", "المعنى"], rows: [
            ["-addr", "127.0.0.1:9099", "عنوان الاستماع (محلي فقط)"],
            ["-radar-window", "5s", "نافذة كشف المسح"],
            ["-radar-threshold", "10", "يُعلَّم العنوان عند تجاوز عدد المنافذ المختلفة لهذه القيمة"],
            ["-radar-cooldown", "60s", "فترة الهدوء قبل إغلاق الحادثة"],
            ["-radar-allow", "(لا شيء)", "عناوين مفصولة بفواصل لا تُعلَّم أبدًا"],
            ["-no-raw-capture", "false", "تعطيل مستشعر SYN الخام"],
            ["-interval", "1s", "فترة أخذ العينات"],
            ["-events-window / -events-max", "168h / 2000", "مدى قراءة سجل الأحداث والاحتفاظ به"],
            ["-no-browser، ‎-v، ‎-version", "", "فتح الواجهة، السجل المفصّل، الإصدار"],
          ] },
        },
        {
          id: "faq", h: "10. حل المشكلات",
          table: { cols: ["العَرَض", "السبب", "الحل"], rows: [
            ["مستشعر SYN الخام غير نشط", "لا توجد صلاحيات مسؤول أو تحجبه سياسة", "شغّل البرنامج كمسؤول واسمح لـ syspulse.exe في جدار الحماية"],
            ["عنوان MAC «غير معروف»", "الجهاز يستخدم IPv6 أو لم يرد على ARP", "تحديد MAC متاح لـ IPv4 فقط؛ وقد يكون الجهاز غادر الشبكة"],
            ["عنوان MAC هو عنوان الموجّه", "الجهاز الماسح في شبكة فرعية أخرى أو على الإنترنت", "هذا متوقع: لا يظهر عبر الموجّه إلا عنوان MAC الخاص بالبوابة"],
            ["تدقيق المصادقة يعرض خطأ وصول", "سجل الأمان يتطلب صلاحيات المسؤول", "أعد تشغيل SysPulse بصلاحيات مرتفعة"],
            ["لا توجد أحداث 4625 إطلاقًا", "تدقيق فشل تسجيل الدخول معطّل", "`auditpol /set /subcategory:\"Logon\" /failure:enable`"],
            ["لا يوجد صوت", "المتصفح يمنع الصوت حتى تتفاعل مع الصفحة", "انقر في أي مكان مرة واحدة وتحقق من زر 🔔"],
          ] },
        },
      ],
    },
  };

  // **bold** and `code` inline markup, applied after escaping.
  const fmt = (s) => rich(s).replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>").replace(/(^|[^*])\*([^*\s][^*]*)\*/g, "$1<i>$2</i>").replace(/\n/g, "<br>");

  function table(tb) {
    return `<div class="tablewrap guide-table"><table class="grid"><thead><tr>${tb.cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead>
      <tbody>${tb.rows.map((r) => `<tr>${r.map((c, i) => `<td class="${i === 0 ? "gk" : ""}">${fmt(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  }

  function renderGuide(lang) {
    const g = G[lang] || G.en;
    const toc = g.sections.map((s) => `<li><a href="#g-${s.id}" data-gid="${s.id}">${esc(s.h)}</a></li>`).join("");
    const body = g.sections.map((s) => {
      let h = `<section class="gsec" id="g-${s.id}"><h2>${esc(s.h)}</h2>`;
      if (s.warn) h += `<div class="note warn-note">⚠ ${fmt(s.warn)}</div>`;
      (s.p || []).forEach((p) => { h += `<p>${fmt(p)}</p>`; });
      if (s.list) h += `<ul>${s.list.map((li) => `<li>${fmt(li)}</li>`).join("")}</ul>`;
      if (s.table) h += table(s.table);
      if (s.table2) h += table(s.table2);
      if (s.steps) h += `<ol class="steps">${s.steps.map(([t, d]) => `<li><div class="st">${fmt(t)}</div><div class="sd">${fmt(d)}</div></li>`).join("")}</ol>`;
      return h + "</section>";
    }).join("");
    return `<div class="guide-head"><h1>${esc(g.title)}</h1><p class="lead">${fmt(g.intro)}</p></div>
      <div class="guide-layout"><nav class="guide-toc"><div class="k">${esc(g.toc)}</div><ol>${toc}</ol></nav><div class="guide-body">${body}</div></div>`;
  }

  window.GUIDE = { render: renderGuide, data: G };
})();
