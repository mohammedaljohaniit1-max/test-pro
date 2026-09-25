package procmon

import (
	"sync/atomic"
	"testing"
	"time"
)

type fakeReader struct {
	procs   []RawProcess
	details atomic.Int32
}

func (f *fakeReader) List() ([]RawProcess, error) {
	out := make([]RawProcess, len(f.procs))
	for i, p := range f.procs {
		out[i] = RawProcess{PID: p.PID, PPID: p.PPID, Name: p.Name, Threads: p.Threads}
	}
	return out, nil
}

func (f *fakeReader) Details(p *RawProcess) {
	f.details.Add(1)
	for _, q := range f.procs {
		if q.PID == p.PID {
			p.Path, p.CPUTime, p.WorkingSet, p.Private, p.Started, p.Access = q.Path, q.CPUTime, q.WorkingSet, q.Private, q.Started, q.Access
		}
	}
}

func TestCPUDeltaAndSorting(t *testing.T) {
	start := time.Unix(500, 0)
	f := &fakeReader{procs: []RawProcess{
		{PID: 100, Name: "busy.exe", Path: `C:\busy.exe`, Access: true, Started: start, WorkingSet: 10 << 20},
		{PID: 200, Name: "idle.exe", Access: true, Started: start, WorkingSet: 500 << 20},
		{PID: 300, Name: "protected.exe", Access: false},
	}}
	m := New(f, 4)
	m.cores = 4
	now := time.Unix(1000, 0)
	m.now = func() time.Time { return now }
	first, err := m.Sample()
	if err != nil || len(first) != 3 {
		t.Fatal(err)
	}
	for _, p := range first {
		if p.CPUPercent != 0 {
			t.Fatal("first sample must report 0% CPU")
		}
	}
	if first[0].Name != "idle.exe" { // ties on CPU sort by memory
		t.Fatalf("order %v", first[0].Name)
	}
	// busy.exe consumed 2 s of CPU over 1 s wall on 4 cores = 50%.
	f.procs[0].CPUTime = 2 * time.Second
	now = now.Add(time.Second)
	s, _ := m.Sample()
	if s[0].Name != "busy.exe" || s[0].CPUPercent != 50 {
		t.Fatalf("busy: %+v", s[0])
	}
	if f.details.Load() != 6 {
		t.Fatalf("details calls %d", f.details.Load())
	}
	// PID reuse: a new process with the same PID but a different start time
	// must not inherit the old CPU counter.
	f.procs[0].Started = start.Add(time.Hour)
	f.procs[0].CPUTime = 10 * time.Second
	now = now.Add(time.Second)
	s, _ = m.Sample()
	for _, p := range s {
		if p.PID == 100 && p.CPUPercent != 0 {
			t.Fatalf("PID reuse leaked CPU delta: %v", p.CPUPercent)
		}
	}
}

func TestResolve(t *testing.T) {
	f := &fakeReader{procs: []RawProcess{{PID: 7, Name: "a.exe", Path: `C:\a.exe`, Access: true}}}
	m := New(f, 1)
	if n, _ := m.Resolve(4); n != "System" {
		t.Fatal(n)
	}
	m.Sample()
	if n, p := m.Resolve(7); n != "a.exe" || p != `C:\a.exe` {
		t.Fatal(n, p)
	}
	f.procs = append(f.procs, RawProcess{PID: 9, Path: `D:\tools\new.exe`, Access: true})
	if n, _ := m.Resolve(9); n != "new.exe" {
		t.Fatalf("fallback name %q", n)
	}
	if n, _ := m.Resolve(12345); n != "pid 12345" {
		t.Fatalf("unknown %q", n)
	}
}
