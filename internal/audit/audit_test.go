package audit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/eventlog"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

var t0 = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func ev(id uint32, prov string, at time.Duration, data map[string]string) model.Event {
	return model.Event{EventID: id, Provider: prov, Time: t0.Add(at), Data: data}
}

func find(rep model.AuditReport, kind, subject string) *model.Finding {
	for i := range rep.Findings {
		if rep.Findings[i].Kind == kind && (subject == "" || rep.Findings[i].Subject == subject) {
			return &rep.Findings[i]
		}
	}
	return nil
}

func checkBilingual(t *testing.T, f *model.Finding) {
	t.Helper()
	for name, x := range map[string]model.Text{"title": f.Title, "diagnosis": f.Diagnosis, "fix": f.Fix} {
		if x.En == "" || x.Ar == "" {
			t.Errorf("%s %s missing a language: %+v", f.Kind, name, x)
		}
	}
}

func TestAnalyzeAuth(t *testing.T) {
	var evs []model.Event
	sec := "Microsoft-Windows-Security-Auditing"
	for i := 0; i < 25; i++ {
		evs = append(evs, ev(4625, sec, time.Duration(i)*5*time.Second, map[string]string{"TargetUserName": "administrator", "TargetDomainName": "PC",
			"IpAddress": "203.0.113.45", "LogonType": "10", "Status": "0xc000006d", "SubStatus": "0xc000006a"}))
	}
	for i, u := range []string{"a", "b", "c", "d", "e", "f"} {
		evs = append(evs, ev(4625, sec, time.Duration(i)*time.Minute, map[string]string{"TargetUserName": u, "IpAddress": "192.168.1.66", "LogonType": "3", "SubStatus": "0xc0000064"}))
	}
	evs = append(evs,
		ev(4625, sec, time.Hour, map[string]string{"TargetUserName": "sara", "IpAddress": "127.0.0.1", "LogonType": "2", "SubStatus": "0xc000006a"}),
		ev(4740, sec, 2*time.Hour, map[string]string{"TargetUserName": "sara", "TargetDomainName": "LAPTOP"}),
		ev(4672, sec, 3*time.Hour, map[string]string{"SubjectUserName": "mohammed", "SubjectDomainName": "CONTOSO", "PrivilegeList": "SeDebugPrivilege SeBackupPrivilege"}),
		ev(4672, sec, 3*time.Hour, map[string]string{"SubjectUserName": "SYSTEM", "SubjectDomainName": "NT AUTHORITY", "PrivilegeList": "SeTcbPrivilege"}),
		ev(4672, sec, 3*time.Hour, map[string]string{"SubjectUserName": "PC$", "SubjectDomainName": "CONTOSO", "PrivilegeList": "SeTcbPrivilege"}),
	)
	rep := AnalyzeAuth(evs, model.AuditReport{Kind: KindAuth})
	if rep.Scanned != len(evs) || rep.ByEventID["4625"] != 32 || rep.ByEventID["4672"] != 3 {
		t.Fatalf("counters %d %v", rep.Scanned, rep.ByEventID)
	}
	brute := find(rep, FFailedLogon, `PC\administrator`)
	if brute == nil || brute.Severity != model.SevCritical || brute.Count != 25 || !strings.Contains(brute.Fix.En, "203.0.113.45") ||
		!strings.Contains(brute.Diagnosis.En, "brute-force") || brute.Details["sourceIp"] != "203.0.113.45" {
		t.Fatalf("brute force %+v", brute)
	}
	checkBilingual(t, brute)
	spray := find(rep, FPasswordSpray, "192.168.1.66")
	if spray == nil || spray.Severity != model.SevCritical || !strings.Contains(spray.Diagnosis.En, "6 different account") {
		t.Fatalf("spray %+v", spray)
	}
	if f := find(rep, FFailedLogon, "sara"); f == nil || f.Severity != model.SevInfo {
		t.Fatalf("typo %+v", f)
	}
	if f := find(rep, FLockout, "sara"); f == nil || f.Severity != model.SevWarning {
		t.Fatalf("lockout %+v", f)
	}
	priv := find(rep, FPrivilegedLogon, `CONTOSO\mohammed`)
	if priv == nil || priv.Severity != model.SevInfo || !strings.Contains(priv.Details["privileges"], "SeDebugPrivilege") {
		t.Fatalf("priv %+v", priv)
	}
	checkBilingual(t, priv)
	builtin := find(rep, FPrivilegedLogon, "built-in service accounts")
	if builtin == nil || builtin.Count != 2 {
		t.Fatalf("built-in %+v", builtin)
	}
	// Findings are ordered critical first and carry stable IDs.
	if rep.Findings[0].Severity != model.SevCritical || rep.Findings[0].ID != "AUT-001" || rep.BySev[model.SevCritical] < 2 {
		t.Fatalf("order %+v", rep.Findings[0])
	}
}

func TestPrivilegedAfterFailuresEscalates(t *testing.T) {
	sec := "Microsoft-Windows-Security-Auditing"
	evs := []model.Event{
		ev(4625, sec, 0, map[string]string{"TargetUserName": "bob", "IpAddress": "10.0.0.5", "LogonType": "3", "SubStatus": "0xc000006a"}),
		ev(4672, sec, time.Minute, map[string]string{"SubjectUserName": "bob", "SubjectDomainName": "CONTOSO", "PrivilegeList": "SeDebugPrivilege"}),
	}
	rep := AnalyzeAuth(evs, model.AuditReport{Kind: KindAuth})
	if f := find(rep, FPrivilegedLogon, `CONTOSO\bob`); f == nil || f.Severity != model.SevWarning || !strings.Contains(f.Diagnosis.En, "guessed") {
		t.Fatalf("%+v", f)
	}
}

func TestAnalyzeReliability(t *testing.T) {
	scm, wer := "Service Control Manager", "Microsoft-Windows-WER-SystemErrorReporting"
	evs := []model.Event{
		ev(7031, scm, 0, map[string]string{"param1": "Print Spooler", "param2": "1", "param5": "Restart the service"}),
		ev(7031, scm, time.Hour, map[string]string{"param1": "Print Spooler", "param2": "2", "param5": "Restart the service"}),
		ev(7034, scm, 2*time.Hour, map[string]string{"param1": "Print Spooler", "param2": "3"}),
		ev(7034, scm, 3*time.Hour, map[string]string{"#0": "Windows Search", "#1": "1"}),
		ev(1000, "Application Error", 0, map[string]string{"AppName": "Teams.exe", "ModuleName": "ntdll.dll", "ExceptionCode": "c0000005", "AppVersion": "1.7"}),
		ev(1000, "Application Error", time.Hour, map[string]string{"AppName": "Teams.exe", "ModuleName": "ntdll.dll", "ExceptionCode": "0xc0000005"}),
		ev(1000, "Application Error", time.Hour, map[string]string{"AppName": "game.exe", "ModuleName": "game.exe", "ExceptionCode": "c0000409"}),
		ev(1002, "Application Hang", time.Hour, map[string]string{"AppName": "Code.exe"}),
		ev(1001, wer, 4*time.Hour, map[string]string{"param1": "0x0000009f (0x3, 0xffff, 0xffff, 0xffff)", "param2": `C:\Windows\Minidump\a.dmp`}),
		ev(1001, "Windows Error Reporting", 4*time.Hour, map[string]string{"#0": "APPCRASH"}), // not a bugcheck
		ev(41, "Microsoft-Windows-Kernel-Power", 4*time.Hour-time.Minute, map[string]string{"BugcheckCode": "159"}),
		ev(41, "Microsoft-Windows-Kernel-Power", 10*time.Hour, map[string]string{"BugcheckCode": "0", "PowerButtonTimestamp": "0"}),
		ev(6008, "EventLog", 10*time.Hour+time.Minute, nil),
		{EventID: 1001, Provider: "BugCheck", Time: t0, Message: "The computer has rebooted from a bugcheck.  The bugcheck was: 0x000000d1 (0x28, 0x2, 0x0, 0xfff)."},
	}
	rep := AnalyzeReliability(evs, model.AuditReport{Kind: KindReliability})
	sp := find(rep, FServiceCrash, "Print Spooler")
	if sp == nil || sp.Count != 3 || sp.Severity != model.SevCritical || len(sp.EventIDs) != 2 || sp.Details["recoveryAction"] != "Restart the service" {
		t.Fatalf("spooler %+v", sp)
	}
	checkBilingual(t, sp)
	if f := find(rep, FServiceCrash, "Windows Search"); f == nil || f.Severity != model.SevWarning {
		t.Fatalf("positional param %+v", f)
	}
	teams := find(rep, FAppFault, "Teams.exe")
	if teams == nil || teams.Count != 2 || !strings.Contains(teams.Diagnosis.En, "access violation") || !strings.Contains(teams.Fix.En, "core Windows library") {
		t.Fatalf("teams %+v", teams)
	}
	if g := find(rep, FAppFault, "game.exe"); g == nil || !strings.Contains(g.Fix.En, "inside the application itself") || g.Severity != model.SevInfo {
		t.Fatalf("game %+v", g)
	}
	if find(rep, FAppHang, "Code.exe") == nil {
		t.Fatal("hang missing")
	}
	bc := find(rep, FBugcheck, "0x0000009F DRIVER_POWER_STATE_FAILURE")
	if bc == nil || bc.Count != 2 || bc.Severity != model.SevCritical || !strings.Contains(bc.Fix.Ar, "Minidump") {
		t.Fatalf("bugcheck %+v", bc)
	}
	checkBilingual(t, bc)
	if find(rep, FBugcheck, "0x000000D1 DRIVER_IRQL_NOT_LESS_OR_EQUAL") == nil {
		t.Fatal("bugcheck from message text not parsed")
	}
	sh := find(rep, FUnexpectedShut, "")
	if sh == nil || sh.Count != 1 { // 41 + 6008 one minute apart = one reboot
		t.Fatalf("shutdown %+v", sh)
	}
}

func TestParseStopCode(t *testing.T) {
	for in, want := range map[string]uint64{"0x0000009f (0x3, 0x4)": 0x9f, "159": 159, "0x124": 0x124, " 0x000000D1,": 0xd1} {
		if got, ok := ParseStopCode(in); !ok || got != want {
			t.Errorf("%q: %x %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "0", "abc", "0x"} {
		if _, ok := ParseStopCode(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
	if StopName(0xef) != "0x000000EF CRITICAL_PROCESS_DIED" || StopName(0x1234) != "0x00001234" {
		t.Fatal(StopName(0xef), StopName(0x1234))
	}
}

type fakeSource struct {
	calls []string
	evs   map[string][]model.Event
	err   map[string]error
}

func (f *fakeSource) QueryXPath(ch, xpath string, max int, format bool) ([]model.Event, error) {
	f.calls = append(f.calls, ch+" "+xpath)
	if format {
		panic("audits must not format messages")
	}
	return f.evs[ch], f.err[ch]
}

func TestRunQueriesAndPermissionNote(t *testing.T) {
	src := &fakeSource{err: map[string]error{"Security": errors.New("access denied")}}
	rep, err := Run(context.Background(), src, KindAuth, Options{Window: 24 * time.Hour}, t0)
	if err != nil || len(rep.Errors) != 1 || len(rep.Notes) != 1 || rep.Notes[0].Ar == "" || rep.Findings == nil || rep.WindowH != 24 {
		t.Fatalf("%+v %v", rep, err)
	}
	if !strings.Contains(src.calls[0], "EventID=4625") || !strings.Contains(src.calls[0], "EventID=4672") || !strings.Contains(src.calls[0], "86400000") {
		t.Fatalf("xpath %v", src.calls)
	}
	src = &fakeSource{evs: map[string][]model.Event{"System": {ev(7034, "Service Control Manager", 0, map[string]string{"param1": "X"})}}}
	rep, err = Run(context.Background(), src, KindReliability, Options{}, t0)
	if err != nil || len(src.calls) != 2 || !strings.HasPrefix(src.calls[1], "Application") || len(rep.Findings) != 1 {
		t.Fatalf("%v %v %+v", err, src.calls, rep)
	}
	if _, err := Run(context.Background(), src, "bogus", Options{}, t0); err == nil {
		t.Fatal("unknown kind accepted")
	}
}

func TestAuditXPath(t *testing.T) {
	got := eventlog.AuditXPath([]uint32{4625, 4672}, time.Hour)
	want := "*[System[(EventID=4625 or EventID=4672) and TimeCreated[timediff(@SystemTime) <= 3600000]]]"
	if got != want {
		t.Fatalf("%s", got)
	}
}

func TestExportCSVNeutralisesFormulas(t *testing.T) {
	rep := model.AuditReport{Kind: KindAuth, Findings: []model.Finding{{ID: "AUT-001", Severity: model.SevWarning, Kind: FFailedLogon,
		Subject: "=HYPERLINK(\"http://evil\")", Title: model.T("t", "ع"), Diagnosis: model.T("d", "تشخيص"), Fix: model.T("f", "إصلاح"), EventIDs: []uint32{4625}}}}
	b, err := ExportCSV(rep, "ar")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.HasPrefix(s, "\ufeff") || !strings.Contains(s, "التشخيص المبسّط") || !strings.Contains(s, `'=HYPERLINK`) || !strings.Contains(s, "إصلاح") {
		t.Fatalf("%s", s)
	}
}
