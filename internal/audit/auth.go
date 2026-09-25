package audit

import (
	"fmt"
	"strings"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// Failure (sub)status codes of event 4625.
var logonStatus = map[string]model.Text{
	"0xc0000064": model.T("the user name does not exist", "اسم المستخدم غير موجود"),
	"0xc000006a": model.T("the user name is correct but the password is wrong", "اسم المستخدم صحيح لكن كلمة المرور خاطئة"),
	"0xc000006d": model.T("bad user name or authentication information", "اسم مستخدم أو بيانات مصادقة غير صحيحة"),
	"0xc0000234": model.T("the account is currently locked out", "الحساب مقفل حاليًا"),
	"0xc0000072": model.T("the account is disabled", "الحساب معطّل"),
	"0xc000006f": model.T("logon outside the allowed hours", "تسجيل دخول خارج الساعات المسموح بها"),
	"0xc0000070": model.T("logon from a workstation that is not allowed", "تسجيل دخول من جهاز غير مسموح به"),
	"0xc0000071": model.T("the password has expired", "انتهت صلاحية كلمة المرور"),
	"0xc0000193": model.T("the account has expired", "انتهت صلاحية الحساب"),
	"0xc0000133": model.T("the clocks of the client and the domain controller are out of sync", "ساعة الجهاز غير متزامنة مع وحدة التحكم بالمجال"),
	"0xc0000224": model.T("the user must change the password at next logon", "يجب على المستخدم تغيير كلمة المرور عند تسجيل الدخول التالي"),
	"0xc000015b": model.T("the user has not been granted this logon type on this computer", "لم يُمنح المستخدم نوع تسجيل الدخول هذا على هذا الجهاز"),
	"0xc0000413": model.T("the authentication firewall blocked the logon", "جدار حماية المصادقة منع تسجيل الدخول"),
	"0xc000005e": model.T("no logon server was available", "لا يتوفر خادم تسجيل دخول"),
}

var logonTypes = map[string]model.Text{
	"2":  model.T("interactive (console)", "تفاعلي (من لوحة المفاتيح)"),
	"3":  model.T("network (SMB / shared folder)", "شبكة (SMB / مجلد مشترك)"),
	"4":  model.T("batch (scheduled task)", "دفعي (مهمة مجدولة)"),
	"5":  model.T("service", "خدمة"),
	"7":  model.T("screen unlock", "إلغاء قفل الشاشة"),
	"8":  model.T("network clear-text (IIS basic auth)", "شبكة بنص واضح (مصادقة أساسية)"),
	"9":  model.T("new credentials (RunAs /netonly)", "بيانات اعتماد جديدة (RunAs)"),
	"10": model.T("remote interactive (Remote Desktop)", "تفاعلي عن بُعد (سطح المكتب البعيد)"),
	"11": model.T("cached interactive", "تفاعلي من الذاكرة المؤقتة"),
}

func statusText(e model.Event) (string, model.Text) {
	for _, k := range []string{"SubStatus", "Status"} {
		v := strings.ToLower(field(e, k))
		if v == "" || v == "0x0" {
			continue
		}
		if t, ok := logonStatus[v]; ok {
			return v, t
		}
	}
	v := strings.ToLower(field(e, "SubStatus", "Status"))
	return v, model.T("unknown failure reason "+v, "سبب فشل غير معروف "+v)
}

// builtinAccount reports accounts that routinely receive special privileges.
func builtinAccount(user, domain string) bool {
	u := strings.ToUpper(user)
	d := strings.ToUpper(domain)
	switch u {
	case "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "LOCAL SYSTEM":
		return true
	}
	if strings.HasSuffix(u, "$") || strings.HasPrefix(u, "DWM-") || strings.HasPrefix(u, "UMFD-") {
		return true
	}
	return d == "NT AUTHORITY" || d == "NT SERVICE" || d == "FONT DRIVER HOST" || d == "WINDOW MANAGER"
}

func acct(user, domain string) string {
	if user == "" {
		user = "(empty)"
	}
	if domain == "" {
		return user
	}
	return domain + `\` + user
}

func isLocalSource(ip string) bool {
	return ip == "" || ip == "127.0.0.1" || ip == "::1" || ip == "-"
}

// AnalyzeAuth categorises Security events 4625 / 4740 / 4672.
func AnalyzeAuth(evs []model.Event, rep model.AuditReport) model.AuditReport {
	failed := map[string]*group{}   // account|source
	bySource := map[string]*group{} // source -> accounts (spray)
	lockouts := map[string]*group{}
	priv := map[string]*group{}
	var builtin *group
	failedAccounts := map[string]int{}

	for _, e := range evs {
		switch e.EventID {
		case 4625:
			user, dom := field(e, "TargetUserName"), field(e, "TargetDomainName")
			a := acct(user, dom)
			src := field(e, "IpAddress")
			ws := field(e, "WorkstationName")
			code, why := statusText(e)
			lt := field(e, "LogonType")
			key := strings.ToLower(a) + "|" + src
			g := failed[key]
			if g == nil {
				g = &group{f: model.Finding{Kind: FFailedLogon, Subject: a}}
				failed[key] = g
			}
			g.add(e, fmt.Sprintf("%s from %s — %s", a, orDash(src), why.En))
			g.note("source", src)
			g.note("workstation", ws)
			g.note("status", code)
			g.note("logonType", lt)
			g.note("process", field(e, "ProcessName"))
			failedAccounts[strings.ToLower(user)]++
			if !isLocalSource(src) {
				s := bySource[src]
				if s == nil {
					s = &group{f: model.Finding{Kind: FPasswordSpray, Subject: src}}
					bySource[src] = s
				}
				s.add(e, a)
				s.note("account", a)
				s.note("logonType", lt)
			}
		case 4740:
			a := acct(field(e, "TargetUserName"), "")
			g := lockouts[strings.ToLower(a)]
			if g == nil {
				g = &group{f: model.Finding{Kind: FLockout, Subject: a}}
				lockouts[strings.ToLower(a)] = g
			}
			caller := field(e, "TargetDomainName", "#1")
			g.add(e, a+" locked out (caller: "+orDash(caller)+")")
			g.note("caller", caller)
		case 4672:
			user, dom := field(e, "SubjectUserName"), field(e, "SubjectDomainName")
			if builtinAccount(user, dom) {
				if builtin == nil {
					builtin = &group{f: model.Finding{Kind: FPrivilegedLogon, Subject: "built-in service accounts"}}
				}
				builtin.add(e, "")
				builtin.note("account", acct(user, dom))
				continue
			}
			a := acct(user, dom)
			g := priv[strings.ToLower(a)]
			if g == nil {
				g = &group{f: model.Finding{Kind: FPrivilegedLogon, Subject: a}}
				priv[strings.ToLower(a)] = g
			}
			g.add(e, a+" received special privileges")
			for _, p := range strings.Fields(field(e, "PrivilegeList")) {
				g.note("privilege", p)
			}
			g.note("user", user)
		}
	}

	var out []model.Finding
	for _, g := range failed {
		f := g.f
		burst := maxBurst(g.times, 10*time.Minute)
		srcs := g.values("source")
		src := strings.Join(srcs, ", ")
		g.detail("sourceIp", srcs)
		g.detail("workstation", g.values("workstation"))
		g.detail("statusCode", g.values("status"))
		g.detail("logonType", g.values("logonType"))
		g.detail("process", g.values("process"))
		if g.f.Details == nil {
			g.f.Details = map[string]string{}
		}
		g.f.Details["burst10m"] = fmt.Sprint(burst)
		f = g.f
		reasonEn, reasonAr := reasons(g.values("status"))
		ltEn, ltAr := logonTypeNames(g.values("logonType"))
		remote := src != "" && !isLocalSource(src)
		switch {
		case f.Count >= 20 || burst >= 10:
			f.Severity = model.SevCritical
		case f.Count >= 5 || burst >= 5:
			f.Severity = model.SevWarning
		default:
			f.Severity = model.SevInfo
		}
		f.Title = model.T(fmt.Sprintf("Repeated failed logons for %s", f.Subject), fmt.Sprintf("محاولات دخول فاشلة متكررة للحساب %s", f.Subject))
		where := model.T("on this computer", "على هذا الجهاز")
		if remote {
			where = model.T("from "+src, "من العنوان "+src)
		}
		f.Diagnosis = model.T(
			fmt.Sprintf("%d failed sign-in attempt(s) for %s %s (peak %d within 10 minutes) using %s logon. Windows reported: %s.",
				f.Count, f.Subject, where.En, burst, ltEn, reasonEn),
			fmt.Sprintf("%d محاولة دخول فاشلة للحساب %s %s (الذروة %d خلال 10 دقائق) عبر تسجيل دخول %s. سبب الرفض حسب Windows: %s.",
				f.Count, f.Subject, where.Ar, burst, ltAr, reasonAr))
		switch {
		case f.Severity == model.SevCritical && remote:
			f.Diagnosis.En += " This volume and speed look like an automated password-guessing (brute-force) attack."
			f.Diagnosis.Ar += " هذا العدد وهذه السرعة يشيران إلى هجوم آلي لتخمين كلمات المرور (Brute-force)."
			f.Fix = model.T(
				"Block "+src+" at the firewall (e.g. New-NetFirewallRule -DisplayName 'Block "+src+"' -Direction Inbound -RemoteAddress "+src+" -Action Block). Do not expose RDP (3389) or SMB (445) to the internet — put them behind a VPN. Enable an account lockout policy (secpol.msc → Account Policies → Account Lockout: 10 attempts / 15 min) and require strong passwords or MFA.",
				"احظر العنوان "+src+" في جدار الحماية (مثال: New-NetFirewallRule -DisplayName 'Block "+src+"' -Direction Inbound -RemoteAddress "+src+" -Action Block). لا تعرّض منفذ RDP ‏(3389) أو SMB ‏(445) للإنترنت واستخدم VPN. فعّل سياسة قفل الحساب (secpol.msc ← سياسات الحساب ← قفل الحساب: 10 محاولات / 15 دقيقة) واستخدم كلمات مرور قوية أو المصادقة متعددة العوامل.")
		case hasStatus(g, "0xc0000064"):
			f.Fix = model.T(
				"Attempts target an account that does not exist — typical of scanners or a stale saved credential. Find the calling process/host in the details, remove old saved credentials (Control Panel → Credential Manager), mapped drives or scheduled tasks using this name. If the source is external, block it at the firewall.",
				"المحاولات تستهدف حسابًا غير موجود — وهذا نمط أدوات المسح أو بيانات اعتماد قديمة محفوظة. حدّد العملية أو الجهاز المصدر من التفاصيل، واحذف بيانات الاعتماد القديمة (لوحة التحكم ← إدارة بيانات الاعتماد) أو محركات الأقراص المعيّنة أو المهام المجدولة التي تستخدم هذا الاسم. إذا كان المصدر خارجيًا فاحظره في جدار الحماية.")
		case hasStatus(g, "0xc0000071", "0xc0000224"):
			f.Fix = model.T(
				"The password expired or must be changed. Sign in interactively once and set a new password, then update it everywhere it is stored (services, scheduled tasks, mapped drives, mobile mail).",
				"انتهت صلاحية كلمة المرور أو يجب تغييرها. سجّل الدخول مرة واحدة تفاعليًا وعيّن كلمة مرور جديدة، ثم حدّثها في كل مكان محفوظة فيه (الخدمات، المهام المجدولة، محركات الأقراص المعيّنة، بريد الهاتف).")
		case hasStatus(g, "0xc0000133"):
			f.Fix = model.T(
				"Synchronise the clock: run 'w32tm /resync' (or check the time source with 'w32tm /query /status'). Kerberos rejects logons when clocks differ by more than 5 minutes.",
				"زامن الساعة: نفّذ 'w32tm /resync' (أو تحقّق من مصدر الوقت عبر 'w32tm /query /status'). يرفض Kerberos تسجيل الدخول عندما يتجاوز فرق الوقت 5 دقائق.")
		case g.values("logonType") != nil && contains(g.values("logonType"), "5", "4"):
			f.Fix = model.T(
				"A service or scheduled task is using an outdated password. Open services.msc / Task Scheduler, find entries running as "+f.Subject+" and re-enter the current password (or switch them to a managed service account).",
				"هناك خدمة أو مهمة مجدولة تستخدم كلمة مرور قديمة. افتح services.msc أو جدولة المهام، وابحث عن العناصر التي تعمل باسم "+f.Subject+" وأعد إدخال كلمة المرور الحالية (أو استخدم حساب خدمة مُدار).")
		default:
			f.Fix = model.T(
				"If this was the user mistyping, no action is needed. Otherwise confirm with the account owner, reset the password if the attempts were not theirs, and check the source workstation/IP in the details. Consider enabling an account lockout threshold.",
				"إذا كان السبب خطأ المستخدم في الكتابة فلا حاجة لأي إجراء. وإلا فتحقّق مع صاحب الحساب، وأعد تعيين كلمة المرور إن لم تكن المحاولات منه، وافحص الجهاز أو العنوان المصدر في التفاصيل. يُنصح بتفعيل حدّ لقفل الحساب.")
		}
		out = append(out, f)
	}

	for src, g := range bySource {
		accts := g.values("account")
		if len(accts) < 5 {
			continue
		}
		g.detail("accounts", accts)
		f := g.f
		f.Severity = model.SevCritical
		f.Title = model.T("Password spraying from "+src, "رشّ كلمات المرور من العنوان "+src)
		f.Diagnosis = model.T(
			fmt.Sprintf("One source (%s) tried %d different account names (%d attempts). Trying many user names with a few common passwords is called password spraying — an attacker is looking for any weak account.", src, len(accts), f.Count),
			fmt.Sprintf("مصدر واحد (%s) جرّب %d اسم حساب مختلف (%d محاولة). تجربة أسماء مستخدمين كثيرة مع كلمات مرور شائعة تُسمّى «رشّ كلمات المرور»، والمهاجم يبحث عن أي حساب ضعيف.", src, len(accts), f.Count))
		f.Fix = model.T(
			"Block "+src+" immediately at the perimeter and Windows firewall, review whether any of the targeted accounts later logged on successfully (event 4624 from the same IP), reset their passwords, rename or disable the built-in Administrator account, and restrict remote logon to a VPN.",
			"احظر العنوان "+src+" فورًا في الجدار الناري للشبكة ولـ Windows، وراجع ما إذا نجح أي من الحسابات المستهدفة في الدخول لاحقًا (الحدث 4624 من العنوان نفسه)، وأعد تعيين كلمات مرورها، وأعد تسمية حساب Administrator المدمج أو عطّله، واقصر الدخول عن بُعد على VPN.")
		out = append(out, f)
	}

	for _, g := range lockouts {
		g.detail("caller", g.values("caller"))
		f := g.f
		f.Severity = model.SevWarning
		if f.Count >= 3 {
			f.Severity = model.SevCritical
		}
		f.Title = model.T("Account locked out: "+f.Subject, "تم قفل الحساب: "+f.Subject)
		f.Diagnosis = model.T(
			fmt.Sprintf("The account %s was locked %d time(s) because too many wrong passwords were entered.", f.Subject, f.Count),
			fmt.Sprintf("تم قفل الحساب %s عدد %d مرة بسبب إدخال كلمات مرور خاطئة كثيرة.", f.Subject, f.Count))
		f.Fix = model.T(
			"Unlock the account (net user "+strings.TrimPrefix(f.Subject, `\`)+" /active:yes, or 'Unlock account' in Active Directory Users and Computers), then find the caller computer listed in the details — usually a phone, mapped drive or service still using an old password.",
			"ألغِ قفل الحساب (net user "+strings.TrimPrefix(f.Subject, `\`)+" /active:yes، أو «إلغاء قفل الحساب» في أداة مستخدمي Active Directory)، ثم ابحث عن الجهاز المتصل المذكور في التفاصيل — غالبًا هاتف أو محرك أقراص معيّن أو خدمة ما زالت تستخدم كلمة مرور قديمة.")
		out = append(out, f)
	}

	for key, g := range priv {
		privs := g.values("privilege")
		g.detail("privileges", privs)
		f := g.f
		user := strings.ToLower(first(g.values("user")))
		fails := failedAccounts[user]
		f.Severity = model.SevInfo
		f.Title = model.T("Administrative privileges assigned to "+f.Subject, "منح صلاحيات إدارية للحساب "+f.Subject)
		f.Diagnosis = model.T(
			fmt.Sprintf("%s signed in %d time(s) with administrator-level rights (%s). This is normal for administrators, but every such logon can change the whole system.", f.Subject, f.Count, shortList(privs, 4)),
			fmt.Sprintf("سجّل الحساب %s الدخول %d مرة بصلاحيات بمستوى المسؤول (%s). هذا طبيعي لحسابات المسؤولين، لكن كل تسجيل دخول كهذا يستطيع تغيير النظام بالكامل.", f.Subject, f.Count, shortList(privs, 4)))
		f.Fix = model.T(
			"Confirm this account is supposed to be an administrator (lusrmgr.msc → Groups → Administrators). Use a separate standard account for daily work and elevate only when needed (UAC).",
			"تأكّد أن هذا الحساب يجب أن يكون مسؤولًا (lusrmgr.msc ← المجموعات ← Administrators). استخدم حسابًا عاديًا منفصلًا للعمل اليومي ولا ترفع الصلاحيات إلا عند الحاجة (UAC).")
		if fails > 0 {
			f.Severity = model.SevWarning
			f.Diagnosis.En += fmt.Sprintf(" The same account also has %d failed logon(s) in this period — a privileged logon after failures can mean the password was guessed.", fails)
			f.Diagnosis.Ar += fmt.Sprintf(" لدى الحساب نفسه أيضًا %d محاولة دخول فاشلة في هذه الفترة — وتسجيل الدخول بصلاحيات عالية بعد محاولات فاشلة قد يعني أن كلمة المرور تم تخمينها.", fails)
			f.Fix.En = "Verify with the account owner that the successful privileged logons were theirs; if not, reset the password immediately, sign out all sessions, and review recent changes (new users, services, scheduled tasks). " + f.Fix.En
			f.Fix.Ar = "تحقّق مع صاحب الحساب أن عمليات الدخول الناجحة بصلاحيات عالية كانت منه؛ وإن لم تكن فأعد تعيين كلمة المرور فورًا وأنهِ جميع الجلسات وراجع التغييرات الأخيرة (مستخدمون جدد، خدمات، مهام مجدولة). " + f.Fix.Ar
		}
		if strings.HasSuffix(key, `\administrator`) || key == "administrator" {
			f.Severity = model.SevWarning
			f.Fix.En = "The built-in Administrator account is in use; it cannot be locked out and is the first target of attackers. Rename or disable it and use a named admin account instead. " + f.Fix.En
			f.Fix.Ar = "حساب Administrator المدمج قيد الاستخدام؛ وهو لا يُقفل تلقائيًا وهو الهدف الأول للمهاجمين. أعد تسميته أو عطّله واستخدم حساب مسؤول باسم شخصي بدلًا منه. " + f.Fix.Ar
		}
		out = append(out, f)
	}

	if builtin != nil {
		accts := builtin.values("account")
		builtin.detail("accounts", accts)
		f := builtin.f
		f.Severity = model.SevInfo
		f.Title = model.T("Special privileges for built-in system accounts", "صلاحيات خاصة لحسابات النظام المدمجة")
		f.Diagnosis = model.T(
			fmt.Sprintf("%d privileged logon(s) by Windows' own accounts (SYSTEM, services, machine account). This is expected background activity.", f.Count),
			fmt.Sprintf("%d تسجيل دخول بصلاحيات خاصة من حسابات Windows نفسها (SYSTEM والخدمات وحساب الجهاز). هذا نشاط خلفي متوقَّع.", f.Count))
		f.Fix = model.T("No action required.", "لا يلزم أي إجراء.")
		out = append(out, f)
	}
	return finalize(rep, out, evs)
}

func reasons(codes []string) (string, string) {
	var en, ar []string
	for _, c := range codes {
		if t, ok := logonStatus[c]; ok {
			en, ar = append(en, t.En), append(ar, t.Ar)
		} else if c != "" {
			en, ar = append(en, "status "+c), append(ar, "الحالة "+c)
		}
	}
	if len(en) == 0 {
		return "no reason recorded", "لم يُسجَّل سبب"
	}
	return strings.Join(en, "; "), strings.Join(ar, "؛ ")
}

func logonTypeNames(types []string) (string, string) {
	var en, ar []string
	for _, t := range types {
		if x, ok := logonTypes[t]; ok {
			en, ar = append(en, x.En), append(ar, x.Ar)
		} else if t != "" {
			en, ar = append(en, "type "+t), append(ar, "النوع "+t)
		}
	}
	if len(en) == 0 {
		return "unknown", "غير معروف"
	}
	return strings.Join(en, " / "), strings.Join(ar, " / ")
}

func hasStatus(g *group, codes ...string) bool {
	for _, v := range g.values("status") {
		for _, c := range codes {
			if v == c {
				return true
			}
		}
	}
	return false
}

func contains(xs []string, want ...string) bool {
	for _, x := range xs {
		for _, w := range want {
			if x == w {
				return true
			}
		}
	}
	return false
}

func first(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return xs[0]
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func shortList(xs []string, n int) string {
	if len(xs) == 0 {
		return "-"
	}
	if len(xs) > n {
		return strings.Join(xs[:n], ", ") + fmt.Sprintf(" +%d", len(xs)-n)
	}
	return strings.Join(xs, ", ")
}
