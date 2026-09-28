package main

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/eventlog"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// demoAudit implements audit.Source with synthetic Security, System and
// Application events that exercise every diagnosis path.
type demoAudit struct {
	mu   sync.Mutex
	evs  map[string][]model.Event
	made time.Time
}

func newDemoAudit() *demoAudit { return &demoAudit{} }

func (d *demoAudit) build() {
	now := time.Now().UTC()
	d.made = now
	d.evs = map[string][]model.Event{}
	r := rand.New(rand.NewSource(7))
	rec := uint64(900000)
	add := func(ch, prov string, id uint32, lvl int, at time.Time, data map[string]string) {
		rec++
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, k+"="+data[k])
		}
		d.evs[ch] = append(d.evs[ch], model.Event{Channel: ch, RecordID: rec, EventID: id, Level: lvl, LevelStr: eventlog.LevelName(lvl),
			Provider: prov, Time: at, Computer: "DEMO-WORKSTATION", Message: strings.Join(parts, "; "), Data: data})
	}
	sec := "Microsoft-Windows-Security-Auditing"
	fail := func(at time.Time, user, dom, ip, ws, lt, sub string) {
		add("Security", sec, 4625, 0, at, map[string]string{"TargetUserName": user, "TargetDomainName": dom, "IpAddress": ip,
			"WorkstationName": ws, "LogonType": lt, "Status": "0xc000006d", "SubStatus": sub, "ProcessName": `C:\Windows\System32\svchost.exe`})
	}
	// RDP brute force from the internet against "administrator".
	base := now.Add(-26 * time.Hour)
	for i := 0; i < 64; i++ {
		fail(base.Add(time.Duration(i)*7*time.Second), "administrator", "DEMO-WORKSTATION", "203.0.113.45", "-", "10", "0xc000006a")
	}
	// Password spraying from one LAN host over many names.
	for i, u := range []string{"admin", "backup", "test", "guest", "sql", "user1", "scanner", "support"} {
		fail(now.Add(-5*time.Hour+time.Duration(i)*20*time.Second), u, "DEMO-WORKSTATION", "192.168.1.66", "KALI", "3", "0xc0000064")
	}
	// A user mistyping twice.
	fail(now.Add(-3*time.Hour), "sara", "CONTOSO", "127.0.0.1", "DEMO-WORKSTATION", "2", "0xc000006a")
	fail(now.Add(-3*time.Hour+40*time.Second), "sara", "CONTOSO", "127.0.0.1", "DEMO-WORKSTATION", "2", "0xc000006a")
	// A service running with an expired password.
	for i := 0; i < 6; i++ {
		add("Security", sec, 4625, 0, now.Add(-time.Duration(20+i*12)*time.Hour), map[string]string{"TargetUserName": "svc_backup", "TargetDomainName": "CONTOSO",
			"IpAddress": "-", "LogonType": "5", "Status": "0xc000006e", "SubStatus": "0xc0000071", "ProcessName": `C:\Windows\System32\services.exe`})
	}
	add("Security", sec, 4740, 0, now.Add(-2*time.Hour), map[string]string{"TargetUserName": "sara", "TargetDomainName": "LAPTOP-SARA", "SubjectUserName": "DC01$"})
	// Privileged logons.
	for i := 0; i < 9; i++ {
		add("Security", sec, 4672, 0, now.Add(-time.Duration(1+r.Intn(160))*time.Hour), map[string]string{"SubjectUserName": "mohammed", "SubjectDomainName": "CONTOSO",
			"PrivilegeList": "SeSecurityPrivilege SeBackupPrivilege SeRestorePrivilege SeTakeOwnershipPrivilege SeDebugPrivilege SeLoadDriverPrivilege SeImpersonatePrivilege"})
	}
	add("Security", sec, 4672, 0, base.Add(8*time.Minute), map[string]string{"SubjectUserName": "Administrator", "SubjectDomainName": "DEMO-WORKSTATION",
		"PrivilegeList": "SeSecurityPrivilege SeBackupPrivilege SeDebugPrivilege SeImpersonatePrivilege"})
	for i := 0; i < 140; i++ {
		add("Security", sec, 4672, 0, now.Add(-time.Duration(1+r.Intn(167*60))*time.Minute), map[string]string{"SubjectUserName": "SYSTEM", "SubjectDomainName": "NT AUTHORITY",
			"PrivilegeList": "SeAssignPrimaryTokenPrivilege SeTcbPrivilege SeSecurityPrivilege"})
	}

	scm := "Service Control Manager"
	for i := 0; i < 4; i++ {
		add("System", scm, 7031, 2, now.Add(-time.Duration(10+i*30)*time.Hour), map[string]string{"param1": "Print Spooler", "param2": fmt.Sprint(i + 1), "param3": "60000", "param4": "1", "param5": "Restart the service"})
	}
	add("System", scm, 7034, 2, now.Add(-50*time.Hour), map[string]string{"param1": "Windows Search", "param2": "1"})
	add("System", scm, 7034, 2, now.Add(-14*time.Hour), map[string]string{"param1": "Windows Search", "param2": "2"})
	add("System", scm, 7034, 2, now.Add(-90*time.Hour), map[string]string{"param1": "Contoso Backup Agent", "param2": "1"})
	wer := "Microsoft-Windows-WER-SystemErrorReporting"
	add("System", wer, 1001, 2, now.Add(-72*time.Hour), map[string]string{"param1": "0x0000009f (0x0000000000000003, 0xffffc40d1a2b3060, 0xfffff80623c6f750, 0xffffc40d1f8e2010)", "param2": `C:\Windows\Minidump\092226-9781-01.dmp`})
	add("System", wer, 1001, 2, now.Add(-30*time.Hour), map[string]string{"param1": "0x000000d1 (0x0000000000000028, 0x0000000000000002, 0x0000000000000000, 0xfffff8062e4a1b2c)", "param2": `C:\Windows\Minidump\092326-8125-01.dmp`})
	kp := "Microsoft-Windows-Kernel-Power"
	add("System", kp, 41, 1, now.Add(-72*time.Hour-2*time.Minute), map[string]string{"BugcheckCode": "159", "PowerButtonTimestamp": "0"})
	add("System", kp, 41, 1, now.Add(-110*time.Hour), map[string]string{"BugcheckCode": "0", "PowerButtonTimestamp": "133712345678901234"})
	add("System", "EventLog", 6008, 2, now.Add(-110*time.Hour+time.Minute), map[string]string{"#0": "02:14:07", "#1": "2026-09-20"})
	add("System", kp, 41, 1, now.Add(-8*time.Hour), map[string]string{"BugcheckCode": "0", "PowerButtonTimestamp": "0"})
	add("System", "EventLog", 6008, 2, now.Add(-8*time.Hour+30*time.Second), map[string]string{"#0": "09:41:55", "#1": "2026-09-25"})

	crash := func(at time.Time, app, ver, mod, exc, path string) {
		add("Application", "Application Error", 1000, 2, at, map[string]string{"AppName": app, "AppVersion": ver, "ModuleName": mod, "ExceptionCode": exc, "AppPath": path})
	}
	for i := 0; i < 6; i++ {
		crash(now.Add(-time.Duration(5+i*17)*time.Hour), "Teams.exe", "1.7.0.1864", "ntdll.dll", "c0000005", `C:\Users\demo\AppData\Local\Microsoft\Teams\current\Teams.exe`)
	}
	crash(now.Add(-40*time.Hour), "explorer.exe", "10.0.22621.4249", "ShellExtHook64.dll", "c0000005", `C:\Windows\explorer.exe`)
	crash(now.Add(-12*time.Hour), "Contoso.Agent.exe", "4.2.1.0", "KERNELBASE.dll", "e0434352", `C:\Program Files\Contoso\Agent\Contoso.Agent.exe`)
	crash(now.Add(-20*time.Hour), "Contoso.Agent.exe", "4.2.1.0", "KERNELBASE.dll", "e0434352", `C:\Program Files\Contoso\Agent\Contoso.Agent.exe`)
	crash(now.Add(-60*time.Hour), "game.exe", "2.3.0.0", "game.exe", "c0000409", `D:\Games\game.exe`)
	for i := 0; i < 3; i++ {
		add("Application", "Application Hang", 1002, 2, now.Add(-time.Duration(9+i*25)*time.Hour), map[string]string{"AppName": "Code.exe", "AppVersion": "1.93.1"})
	}
}

// QueryXPath honours the event-ID list in the XPath from eventlog.AuditXPath.
func (d *demoAudit) QueryXPath(channel, xpath string, max int, _ bool) ([]model.Event, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.evs == nil || time.Since(d.made) > 10*time.Minute {
		d.build()
	}
	time.Sleep(600 * time.Millisecond) // reading the Security log is not instant
	var out []model.Event
	for _, e := range d.evs[channel] {
		tok := fmt.Sprintf("EventID=%d", e.EventID)
		if strings.Contains(xpath, tok+" ") || strings.Contains(xpath, tok+")") {
			out = append(out, e)
			if len(out) >= max {
				break
			}
		}
	}
	return out, nil
}
