package ifstats

import (
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

func TestRatesHistoryAndWrap(t *testing.T) {
	clock := time.Unix(1000, 0)
	var in, out uint64 = 1000, 500
	r := ReaderFunc(func() ([]Counter, error) {
		return []Counter{
			{Index: 7, Name: "Wi-Fi", Kind: model.IfWiFi, Physical: true, Up: true, SpeedBps: 8_000_000, InOctets: in, OutOctets: out},
			{Index: 1, Name: "Loopback", Kind: model.IfLoopback, Up: true},
			{Index: 9, Name: "vEthernet (WSL)", Kind: model.IfVirtual, Up: true},
		}, nil
	})
	m := New(r, 3)
	m.SetClock(func() time.Time { return clock })
	if _, err := m.Sample(); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * time.Second)
	in, out = 1000+2_000_000, 500+400
	s, _ := m.Sample()
	if s[0].Name != "Wi-Fi" || s[len(s)-1].Kind != model.IfLoopback {
		t.Fatalf("order %+v", s)
	}
	if s[0].InBps != 1_000_000 || s[0].OutBps != 200 {
		t.Fatalf("rates %+v", s[0])
	}
	if s[0].Util != 100 { // 1 MB/s = 8 Mbit/s on an 8 Mbit link
		t.Fatalf("util %v", s[0].Util)
	}
	// Counter reset must not produce a huge spike.
	clock = clock.Add(time.Second)
	in = 10
	s, _ = m.Sample()
	if s[0].InBps != 0 {
		t.Fatalf("wrap produced %v", s[0].InBps)
	}
	clock = clock.Add(time.Second)
	m.Sample()
	h := m.History()[7]
	if len(h.In) != 3 || h.Name != "Wi-Fi" {
		t.Fatalf("history %+v", h)
	}
	ti, _ := Totals(s)
	if ti != 0 {
		t.Fatalf("totals %v", ti)
	}
}

func TestHelpers(t *testing.T) {
	if FormatMAC([]byte{0, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e}) != "00-1A-2B-3C-4D-5E" || FormatMAC([]byte{0, 0}) != "" {
		t.Fatal("FormatMAC")
	}
	if KindFromIfType(71) != model.IfWiFi || KindFromIfType(6) != model.IfEthernet || KindFromIfType(24) != model.IfLoopback {
		t.Fatal("KindFromIfType")
	}
}
