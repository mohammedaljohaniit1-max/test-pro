package main

import "testing"

func TestCheckLoopback(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:9099", "localhost:9099", "[::1]:9099", "127.0.0.5:1"} {
		if err := checkLoopback(ok); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:9099", ":9099", "192.168.1.5:9099", "example.com:80", "nonsense"} {
		if err := checkLoopback(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
