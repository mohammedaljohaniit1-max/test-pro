//go:build linux

// Package linuxhost provides genuine host telemetry on Linux for the
// SysPulse preview binary: /proc for CPU, memory, processes and sockets,
// statfs for volumes, /proc/net/arp for neighbours, journald for the event
// log and dpkg / rpm for the software inventory. It lets the dashboard be
// reviewed against real data on non-Windows machines; syspulse.exe uses the
// Win32 collectors instead.
package linuxhost

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/sysmon"
)

const clkTck = 100 // USER_HZ on every mainstream Linux ABI

// System implements sysmon.Platform from /proc.
type System struct {
	host, osName string
}

// NewSystem returns the Linux system platform.
func NewSystem() *System {
	h, _ := os.Hostname()
	return &System{host: h, osName: osRelease()}
}

func osRelease() string {
	name := "Linux"
	if f, err := os.Open("/etc/os-release"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
				name = strings.Trim(v, `"`)
			}
		}
		f.Close()
	}
	var u syscall.Utsname
	if syscall.Uname(&u) == nil {
		name += " · kernel " + cstr(u.Release[:])
	}
	return name
}

func cstr(b []int8) string {
	var sb strings.Builder
	for _, c := range b {
		if c == 0 {
			break
		}
		sb.WriteByte(byte(c))
	}
	return sb.String()
}

// CPUTimes reads the aggregate "cpu" line of /proc/stat. Kernel includes
// idle, matching the Windows GetSystemTimes convention sysmon expects.
func (s *System) CPUTimes() (sysmon.CPUTimes, error) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return sysmon.CPUTimes{}, err
	}
	line, _, _ := strings.Cut(string(b), "\n")
	f := strings.Fields(line)
	v := func(i int) time.Duration {
		if i >= len(f) {
			return 0
		}
		n, _ := strconv.ParseUint(f[i], 10, 64)
		return time.Duration(n) * time.Second / clkTck
	}
	user := v(1) + v(2)              // user + nice
	sys := v(3) + v(6) + v(7) + v(8) // system + irq + softirq + steal
	idle := v(4) + v(5)              // idle + iowait
	return sysmon.CPUTimes{Idle: idle, Kernel: sys + idle, User: user}, nil
}

func meminfo() map[string]uint64 {
	m := map[string]uint64{}
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return m
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) > 0 {
			n, _ := strconv.ParseUint(f[0], 10, 64)
			m[k] = n * 1024
		}
	}
	return m
}

// Memory returns total, available, committed and commit limit.
//
// CommitLimit is only enforced in strict overcommit mode
// (vm.overcommit_memory = 2). In the default heuristic mode Committed_AS
// routinely exceeds it, so reporting it as a limit would show a meaningless
// "commit > 100 %" and trigger false alerts; the limit is then reported as
// 0 (unknown), unlike Windows where the commit limit is always hard.
func (s *System) Memory() (uint64, uint64, uint64, uint64, error) {
	m := meminfo()
	limit := m["CommitLimit"]
	if !strictOvercommit() {
		limit = 0
	}
	return m["MemTotal"], m["MemAvailable"], m["Committed_AS"], limit, nil
}

func strictOvercommit() bool {
	b, err := os.ReadFile("/proc/sys/vm/overcommit_memory")
	return err == nil && strings.TrimSpace(string(b)) == "2"
}

// Disks lists real block-device filesystems from /proc/self/mounts.
func (s *System) Disks() ([]model.DiskUsage, error) {
	b, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []model.DiskUsage
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		dev, mnt, fs := f[0], f[1], f[2]
		if !strings.HasPrefix(dev, "/dev/") && fs != "overlay" && fs != "zfs" && fs != "btrfs" {
			continue
		}
		if seen[dev] || strings.HasPrefix(mnt, "/snap/") || strings.HasPrefix(mnt, "/proc") || strings.HasPrefix(mnt, "/sys") {
			continue
		}
		var st syscall.Statfs_t
		if syscall.Statfs(mnt, &st) != nil || st.Blocks == 0 {
			continue
		}
		seen[dev] = true
		total := st.Blocks * uint64(st.Bsize)
		free := st.Bavail * uint64(st.Bsize)
		used := total - st.Bfree*uint64(st.Bsize)
		out = append(out, model.DiskUsage{Mount: mnt, Type: fs, Total: total, Free: free, Used: used,
			Percent: 100 * float64(used) / float64(used+free)})
		if len(out) >= 12 {
			break
		}
	}
	return out, nil
}

// Uptime reads /proc/uptime.
func (s *System) Uptime() time.Duration {
	b, _ := os.ReadFile("/proc/uptime")
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return time.Duration(v * float64(time.Second))
}

// Info returns host name and distribution.
func (s *System) Info() (string, string) { return s.host, s.osName }

// Cores returns the number of logical CPUs.
func (s *System) Cores() int { return runtime.NumCPU() }

func bootTime() time.Time {
	b, _ := os.ReadFile("/proc/stat")
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "btime "); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			return time.Unix(n, 0)
		}
	}
	return time.Time{}
}

// CoreTimes reads the per-CPU "cpuN" lines of /proc/stat.
func (s *System) CoreTimes() ([]sysmon.CPUTimes, error) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil, err
	}
	var out []sysmon.CPUTimes
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "cpu") || strings.HasPrefix(line, "cpu ") {
			continue
		}
		f := strings.Fields(line)
		v := func(i int) time.Duration {
			if i >= len(f) {
				return 0
			}
			n, _ := strconv.ParseUint(f[i], 10, 64)
			return time.Duration(n) * time.Second / clkTck
		}
		user := v(1) + v(2)
		sys := v(3) + v(6) + v(7) + v(8)
		idle := v(4) + v(5)
		out = append(out, sysmon.CPUTimes{Idle: idle, Kernel: sys + idle, User: user})
	}
	return out, nil
}

// MemDetail reports page cache, slab and swap from /proc/meminfo.
func (s *System) MemDetail() (model.MemDetail, error) {
	m := meminfo()
	return model.MemDetail{Cached: m["Cached"] + m["Buffers"], KernelPaged: m["SReclaimable"], KernelNonpaged: m["SUnreclaim"],
		PageFileTotal: m["SwapTotal"]}, nil
}
