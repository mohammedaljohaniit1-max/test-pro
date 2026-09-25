package main

import (
	"fmt"
	"net"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// checkLoopback refuses non-loopback listen addresses.
func checkLoopback(addr string) error {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if h == "localhost" {
		return nil
	}
	ip := net.ParseIP(h)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%q is not a loopback address", addr)
	}
	return nil
}

// assignIDs gives events chronological, channel-unique record IDs once.
func assignIDs(list []model.Event) {
	sortByTime(list)
	var max uint64
	for _, e := range list {
		if e.RecordID > max {
			max = e.RecordID
		}
	}
	for i := range list {
		if list[i].RecordID == 0 {
			max++
			list[i].RecordID = max
		}
	}
}

func sortByTime(list []model.Event) {
	// Insertion sort keeps already-numbered prefixes stable; new events are
	// appended with the current time so this is effectively O(n).
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j].Time.Before(list[j-1].Time) && list[j].RecordID == 0 && list[j-1].RecordID == 0; j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
}
