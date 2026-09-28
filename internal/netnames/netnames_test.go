package netnames

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func nbReply(id uint16) []byte {
	b := binary.BigEndian.AppendUint16(nil, id)
	b = append(b, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0)
	q := BuildNBSTAT(0)
	b = append(b, q[12:12+34]...) // encoded name
	b = append(b, 0, 0x21, 0, 1, 0, 0, 0, 0)
	names := []struct {
		n     string
		sfx   byte
		group bool
	}{{"DESKTOP-7Q2", 0x00, false}, {"WORKGROUP", 0x00, true}, {"DESKTOP-7Q2", 0x20, false}}
	rd := []byte{byte(len(names))}
	for _, e := range names {
		nm := []byte(e.n + "               ")[:15]
		rd = append(rd, nm...)
		rd = append(rd, e.sfx)
		f := uint16(0x0400)
		if e.group {
			f |= 0x8000
		}
		rd = binary.BigEndian.AppendUint16(rd, f)
	}
	rd = append(rd, 0xF0, 0x2F, 0x74, 0x8E, 0x03, 0x5B)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rd)))
	return append(b, rd...)
}

func TestNBSTAT(t *testing.T) {
	q := BuildNBSTAT(0x1234)
	if len(q) != 50 || q[12] != 32 || string(q[13:15]) != "CK" {
		t.Fatalf("request %x", q)
	}
	st, err := ParseNBSTAT(nbReply(0x1234), 0x1234)
	if err != nil || st.Name != "DESKTOP-7Q2" || st.Group != "WORKGROUP" || st.MAC != "F0-2F-74-8E-03-5B" || len(st.All) != 3 || st.All[2] != "DESKTOP-7Q2<20>" {
		t.Fatalf("%+v %v", st, err)
	}
	if _, err := ParseNBSTAT(nbReply(1), 2); err == nil {
		t.Fatal("wrong id accepted")
	}
	if _, err := ParseNBSTAT([]byte{1, 2, 3}, 1); err == nil {
		t.Fatal("short accepted")
	}
}

func ptrReply(id uint16, q []byte, target string) []byte {
	b := append([]byte(nil), q...)
	b[2], b[3] = 0x84, 0
	b[7] = 1
	b = append(b, 0xc0, 12, 0, 12, 0, 1, 0, 0, 0, 120)
	var rd []byte
	for _, l := range []string{target, "local"} {
		rd = append(rd, byte(len(l)))
		rd = append(rd, l...)
	}
	rd = append(rd, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rd)))
	return append(b, rd...)
}

func TestPTR(t *testing.T) {
	if ReverseName("192.168.1.57") != "57.1.168.192.in-addr.arpa" {
		t.Fatal(ReverseName("192.168.1.57"))
	}
	if r := ReverseName("2001:db8::1"); r[:4] != "1.0." || r[len(r)-8:] != "ip6.arpa" {
		t.Fatal(r)
	}
	q := BuildPTRQuery(7, ReverseName("192.168.1.57"))
	name, err := ParsePTRReply(ptrReply(7, q, "Johns-iPhone"), 7)
	if err != nil || name != "Johns-iPhone.local" {
		t.Fatalf("%q %v", name, err)
	}
}

func TestAppleTXTModels(t *testing.T) {
	if AppleModelName("iPhone15,2") != "iPhone 14 Pro" || AppleModelName("iPhone16,1") != "iPhone 15 Pro" || AppleModelName("MacBookAir10,1") != "MacBook Air (M1)" {
		t.Fatal("incorrect Apple machine identifier mapping")
	}
	q := BuildPTRQuery(17, "_airplay._tcp.local")
	q[2] = 0x84
	q[7] = 1 // answer count
	var name []byte
	for _, part := range []string{"Living Room", "_airplay", "_tcp", "local"} {
		name = append(name, byte(len(part)))
		name = append(name, part...)
	}
	name = append(name, 0)
	item := []byte("model=iPhone16,1")
	packet := append(q, name...)
	packet = append(packet, 0, 16, 0, 1, 0, 0, 0, 10, 0, byte(len(item)+1), byte(len(item)))
	packet = append(packet, item...)
	if v, err := ParseAppleTXT(packet); err != nil || v != "iPhone16,1" {
		t.Fatalf("TXT=%q err=%v", v, err)
	}
	if _, err := ParseAppleTXT(packet[:len(packet)-1]); err == nil {
		t.Fatal("accepted truncated TXT")
	}
	q[7] = 0
	if _, err := ParseAppleTXT(q); err == nil {
		t.Fatal("accepted no TXT")
	}
}

// End to end against a fake NBSTAT responder on loopback.
func TestResolveLoopback(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		n, a, err := pc.ReadFrom(buf)
		if err != nil || n < 2 {
			return
		}
		pc.WriteTo(nbReply(binary.BigEndian.Uint16(buf)), a)
	}()
	id := uint16(99)
	pkt, err := udpExchange(context.Background(), pc.LocalAddr().String(), BuildNBSTAT(id), time.Second, func(b []byte) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if st, err := ParseNBSTAT(pkt, id); err != nil || st.Name != "DESKTOP-7Q2" {
		t.Fatalf("%+v %v", st, err)
	}
}
