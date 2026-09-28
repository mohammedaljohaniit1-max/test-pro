package sysmon

import (
	"errors"
	"testing"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

type fakePlatform struct {
	cpu     CPUTimes
	diskErr error
}

func (f *fakePlatform) CPUTimes() (CPUTimes, error) { return f.cpu, nil }
func (f *fakePlatform) Memory() (uint64, uint64, uint64, uint64, error) {
	return 16 << 30, 4 << 30, 10 << 30, 20 << 30, nil
}
func (f *fakePlatform) Disks() ([]model.DiskUsage, error) {
	if f.diskErr != nil {
		return nil, f.diskErr
	}
	return []model.DiskUsage{{Mount: `C:\`, Total: 100, Used: 40, Percent: 40}}, nil
}
func (f *fakePlatform) Uptime() time.Duration  { return 90 * time.Minute }
func (f *fakePlatform) Info() (string, string) { return "HOST", "Windows 11" }
func (f *fakePlatform) Cores() int             { return 8 }

func TestCPUPercent(t *testing.T) {
	a := CPUTimes{Idle: 0, Kernel: 0, User: 0}
	// 10 s of total time (kernel incl. idle 6 s + user 4 s), 3 s idle -> 70% busy.
	b := CPUTimes{Idle: 3 * time.Second, Kernel: 6 * time.Second, User: 4 * time.Second}
	if got := CPUPercent(a, b); got != 70 {
		t.Fatalf("got %v", got)
	}
	if CPUPercent(b, b) != 0 {
		t.Fatal("no elapsed time must be 0")
	}
	if CPUPercent(a, CPUTimes{Idle: 20 * time.Second, Kernel: 5 * time.Second}) != 0 {
		t.Fatal("negative busy must clamp to 0")
	}
}

func TestSampleAndHistory(t *testing.T) {
	f := &fakePlatform{}
	m := New(f, 3)
	s, err := m.Sample(100, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if s.CPUPercent != 0 || s.MemUsed != 12<<30 || s.MemPercent != 75 || s.Processes != 100 ||
		s.UptimeSec != 5400 || s.CPUCores != 8 || s.CommitUsed != 10<<30 || len(s.Disks) != 1 {
		t.Fatalf("%+v", s)
	}
	f.cpu = CPUTimes{Idle: time.Second, Kernel: 3 * time.Second, User: time.Second}
	s, _ = m.Sample(1, 1)
	if s.CPUPercent != 75 {
		t.Fatalf("cpu %v", s.CPUPercent)
	}
	f.diskErr = errors.New("offline")
	s, err = m.Sample(1, 1)
	if err != nil || s.Disks != nil {
		t.Fatal("disk errors must be best-effort")
	}
	m.Sample(1, 1)
	h := m.History()
	if len(h) != 3 || h[2].Timestamp != m.Last().Timestamp {
		t.Fatalf("history bound %d", len(h))
	}
}
