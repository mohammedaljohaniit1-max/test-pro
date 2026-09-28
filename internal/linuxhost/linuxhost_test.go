//go:build linux

package linuxhost

import (
	"testing"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

func TestParseProcNetAddr(t *testing.T) {
	ip, p, err := ParseProcNetAddr("0100007F:1F90")
	if err != nil || ip != "127.0.0.1" || p != 8080 {
		t.Fatal(ip, p, err)
	}
	ip, p, err = ParseProcNetAddr("0000000000000000FFFF00000100007F:0050")
	if err != nil || ip != "127.0.0.1" || p != 80 {
		t.Fatal("mapped", ip, p, err)
	}
	ip, _, err = ParseProcNetAddr("B80D0120000000000000000001000000:01BB")
	if err != nil || ip != "2001:db8::1" {
		t.Fatal("v6", ip, err)
	}
}

func TestLiveCollectors(t *testing.T) {
	s := NewSystem()
	if _, err := s.CPUTimes(); err != nil {
		t.Fatal(err)
	}
	if tot, _, _, _, _ := s.Memory(); tot == 0 {
		t.Fatal("no memory")
	}
	ps, err := NewProcs().List()
	if err != nil || len(ps) == 0 {
		t.Fatal("no processes", err)
	}
	if _, err := Sockets(); err != nil {
		t.Fatal(err)
	}
}

func TestClassify(t *testing.T) {
	if Classify("kernel", "", "app[123]: segfault at 0 ip", 2) != model.CatAppFault {
		t.Fatal("segfault")
	}
	if Classify("systemd", "init.scope", "nginx.service: Failed with result 'exit-code'.", 2) != model.CatServiceCrash {
		t.Fatal("service")
	}
}
