package oui

import "testing"

func TestLookupLongestPrefix(t *testing.T) {
	if Size() < 50000 {
		t.Fatalf("embedded database too small: %d", Size())
	}
	cases := []struct{ mac, short, reg, class string }{
		{"B8-27-EB-4C-19-D2", "Raspberry Pi", "MA-L", "sbc"},
		{"00:0c:29:7d:e4:a0", "VMware", "MA-L", "vm"},
		{"00-50-56-C0-00-08", "VMware", "MA-L", "vm"},
		{"F0-18-98-00-00-01", "Apple", "MA-L", "mobile"},
		{"00-15-5D-01-02-03", "Microsoft", "MA-L", "pc"},
		{"3c22.fb00.0001", "Apple", "MA-L", "mobile"},
	}
	for _, c := range cases {
		v, ok := Lookup(c.mac)
		if !ok || v.Short != c.short || v.Registry != c.reg || v.Class != c.class {
			t.Errorf("%s: got %+v ok=%v", c.mac, v, ok)
		}
	}
	// 8C-1F-64 is an IEEE umbrella block split into MA-S assignments: the
	// 36-bit owner must win over the 24-bit registry entry.
	v, ok := Lookup("8C-1F-64-D0-F1-23")
	if !ok || v.Registry != "MA-S" || v.Prefix != "8C-1F-64-D0-F" || v.Name != "Mecco LLC" {
		t.Errorf("MA-S longest prefix: %+v ok=%v", v, ok)
	}
	v, ok = Lookup("C8-5C-E2-71-00-00")
	if !ok || v.Registry != "MA-M" || v.Prefix != "C8-5C-E2-7" {
		t.Errorf("MA-M: %+v ok=%v", v, ok)
	}
}

func TestLookupSpecial(t *testing.T) {
	if _, ok := Lookup("not a mac"); ok {
		t.Error("garbage accepted")
	}
	if _, ok := Lookup("FF-FF-FF-FF-FF-FF"); ok {
		t.Error("broadcast accepted")
	}
	v, ok := Lookup("DA-A1-19-12-34-56") // randomised (private) Wi-Fi address
	if !ok || !v.Random || v.Name != "" {
		t.Errorf("random MAC: %+v", v)
	}
	v, _ = Lookup("52:54:00:12:34:56")
	if v.Short != "QEMU/KVM" || v.Class != "vm" {
		t.Errorf("qemu: %+v", v)
	}
}

func TestShortName(t *testing.T) {
	if s := shortName("Shenzhen Foo Technology Co.,Ltd."); s != "Shenzhen Foo Technology" {
		t.Fatal(s)
	}
}
