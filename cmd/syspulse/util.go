package main

import (
	"fmt"
	"net"
	"unsafe"
)

// checkLoopback refuses non-loopback listen addresses: the dashboard exposes
// process and system details and must never be reachable from the network.
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid -addr %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("-addr must be a loopback address (127.0.0.1 or [::1]), got %q", host)
	}
	return nil
}

func unsafePointer(p *uint16) unsafe.Pointer { return unsafe.Pointer(p) }
