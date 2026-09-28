//go:build linux

package ifstats

import "testing"

func TestParseProcNetDev(t *testing.T) {
	const s = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  123456     100    0    0    0     0          0         0   123456     100    0    0    0     0       0          0
  eth0: 9876543    5000    1    2    0     0          0         0  1234567    4000    3    4    0     0       0          0
`
	c := ParseProcNetDev(s)
	if len(c) != 2 || c[1].Name != "eth0" || c[1].InOctets != 9876543 || c[1].OutOctets != 1234567 || c[1].Errors != 4 || c[1].Discards != 6 || c[1].OutPkts != 4000 {
		t.Fatalf("%+v", c)
	}
}
