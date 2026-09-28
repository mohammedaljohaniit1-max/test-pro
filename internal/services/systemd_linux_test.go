//go:build linux

package services

import (
	"testing"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

func TestParseSystemctlShow(t *testing.T) {
	s := "Type=notify\nId=ssh.service\nDescription=OpenBSD Secure Shell server\nActiveState=active\nSubState=running\nUnitFileState=enabled\nMainPID=812\nUser=\nExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; }\n\n" +
		"Type=simple\nId=cups.service\nDescription=CUPS\nActiveState=failed\nSubState=failed\nUnitFileState=enabled\nMainPID=0\n\n" +
		"Id=ghost.service\nActiveState=inactive\nUnitFileState=\n"
	l := ParseSystemctlShow(s)
	if len(l) != 2 {
		t.Fatalf("%+v", l)
	}
	if l[0].Name != "ssh" || l[0].State != model.SvcRunning || l[0].PID != 812 || l[0].Binary != "/usr/sbin/sshd" || l[0].StartType != model.StartAuto {
		t.Fatalf("%+v", l[0])
	}
	if l[1].State != model.SvcStopped || l[1].ExitCode != 1 {
		t.Fatalf("%+v", l[1])
	}
}

func TestParseListUnits(t *testing.T) {
	s := "ssh.service loaded active running OpenBSD Secure Shell server\n● cups.service loaded failed failed CUPS\nfoo.socket loaded active listening x\n"
	u := ParseListUnits(s)
	if len(u) != 2 || u[0] != "ssh.service" || u[1] != "cups.service" {
		t.Fatalf("%v", u)
	}
}
