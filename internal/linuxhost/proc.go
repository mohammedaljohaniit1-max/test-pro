//go:build linux

package linuxhost

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/procmon"
)

// Procs implements procmon.Reader and procmon.Inspector from /proc.
type Procs struct {
	boot  time.Time
	once  sync.Once
	users map[string]string
}

// NewProcs returns the Linux process reader.
func NewProcs() *Procs { return &Procs{boot: bootTime()} }

// parseStat splits /proc/<pid>/stat around the parenthesised comm field.
func parseStat(s string) (comm string, f []string, ok bool) {
	i, j := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if i < 0 || j < i {
		return "", nil, false
	}
	return s[i+1 : j], strings.Fields(s[j+1:]), true
}

// List enumerates numeric /proc entries.
func (p *Procs) List() ([]procmon.RawProcess, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := make([]procmon.RawProcess, 0, len(ents))
	for _, e := range ents {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		comm, f, ok := parseStat(string(b))
		if !ok || len(f) < 20 {
			continue
		}
		ppid, _ := strconv.ParseUint(f[1], 10, 32)
		thr, _ := strconv.ParseUint(f[17], 10, 32)
		out = append(out, procmon.RawProcess{PID: uint32(pid), PPID: uint32(ppid), Name: comm, Threads: uint32(thr)})
	}
	return out, nil
}

// Details fills path, CPU time, start time and memory.
func (p *Procs) Details(r *procmon.RawProcess) {
	dir := "/proc/" + strconv.FormatUint(uint64(r.PID), 10)
	b, err := os.ReadFile(dir + "/stat")
	if err != nil {
		return
	}
	comm, f, ok := parseStat(string(b))
	if !ok || len(f) < 22 {
		return
	}
	if r.Name == "" {
		r.Name = comm
	}
	ut, _ := strconv.ParseUint(f[11], 10, 64)
	st, _ := strconv.ParseUint(f[12], 10, 64)
	start, _ := strconv.ParseUint(f[19], 10, 64)
	r.CPUTime = time.Duration(ut+st) * time.Second / clkTck
	if !p.boot.IsZero() {
		r.Started = p.boot.Add(time.Duration(start) * time.Second / clkTck)
	}
	r.Access = true
	if exe, err := os.Readlink(dir + "/exe"); err == nil {
		r.Path = strings.TrimSuffix(exe, " (deleted)")
		if n := filepath.Base(r.Path); n != "" && len(comm) == 15 && strings.HasPrefix(n, comm) {
			r.Name = n // comm is truncated to 15 chars
		}
	}
	if sb, err := os.ReadFile(dir + "/status"); err == nil {
		for _, l := range strings.Split(string(sb), "\n") {
			k, v, _ := strings.Cut(l, ":")
			fs := strings.Fields(v)
			if len(fs) == 0 {
				continue
			}
			n, _ := strconv.ParseUint(fs[0], 10, 64)
			switch k {
			case "VmRSS":
				r.WorkingSet = n * 1024
			case "RssAnon":
				r.Private = n * 1024
			}
		}
	}
}

func (p *Procs) user(uid string) string {
	p.once.Do(func() {
		p.users = map[string]string{}
		b, _ := os.ReadFile("/etc/passwd")
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Split(l, ":")
			if len(f) > 2 {
				p.users[f[2]] = f[0]
			}
		}
	})
	if n, ok := p.users[uid]; ok {
		return n
	}
	return "uid " + uid
}

// Inspect reads command line, owner, open descriptors, cwd and nice value.
func (p *Procs) Inspect(pid uint32) procmon.Inspection {
	var in procmon.Inspection
	dir := "/proc/" + strconv.FormatUint(uint64(pid), 10)
	if b, err := os.ReadFile(dir + "/cmdline"); err == nil {
		in.CommandLine = strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
	} else {
		in.Errors = append(in.Errors, "cmdline: "+err.Error())
	}
	if sb, err := os.ReadFile(dir + "/status"); err == nil {
		for _, l := range strings.Split(string(sb), "\n") {
			if v, ok := strings.CutPrefix(l, "Uid:"); ok {
				if f := strings.Fields(v); len(f) > 0 {
					in.User = p.user(f[0])
				}
			}
		}
	}
	if fds, err := os.ReadDir(dir + "/fd"); err == nil {
		in.Handles = uint32(len(fds))
	} else {
		in.Errors = append(in.Errors, "fd: "+err.Error())
	}
	if cwd, err := os.Readlink(dir + "/cwd"); err == nil {
		in.Cwd = cwd
	}
	if b, err := os.ReadFile(dir + "/stat"); err == nil {
		if _, f, ok := parseStat(string(b)); ok && len(f) > 16 {
			in.Priority = "nice " + f[16]
		}
	}
	if b, err := os.ReadFile(dir + "/io"); err == nil {
		in.Extra = map[string]string{}
		for _, l := range strings.Split(string(b), "\n") {
			k, v, _ := strings.Cut(l, ":")
			switch k {
			case "read_bytes":
				in.Extra["ioReadBytes"] = strings.TrimSpace(v)
			case "write_bytes":
				in.Extra["ioWriteBytes"] = strings.TrimSpace(v)
			}
		}
	}
	return in
}
