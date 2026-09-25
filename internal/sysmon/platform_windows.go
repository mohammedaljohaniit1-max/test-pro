//go:build windows

package sysmon

import (
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes       = kernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetTickCount64       = kernel32.NewProc("GetTickCount64")
	procGetDiskFreeSpaceExW  = kernel32.NewProc("GetDiskFreeSpaceExW")
	procGetLogicalDrives     = kernel32.NewProc("GetLogicalDrives")

	psapi                  = windows.NewLazySystemDLL("psapi.dll")
	procGetPerformanceInfo = psapi.NewProc("GetPerformanceInfo")
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

type performanceInfo struct {
	CB                uint32
	CommitTotal       uintptr
	CommitLimit       uintptr
	CommitPeak        uintptr
	PhysicalTotal     uintptr
	PhysicalAvailable uintptr
	SystemCache       uintptr
	KernelTotal       uintptr
	KernelPaged       uintptr
	KernelNonpaged    uintptr
	PageSize          uintptr
	HandleCount       uint32
	ProcessCount      uint32
	ThreadCount       uint32
}

// SystemPlatform implements Platform with Win32 APIs.
type SystemPlatform struct {
	host, osName string
}

// NewSystemPlatform returns the Windows platform reader.
func NewSystemPlatform() Platform {
	host, _ := os.Hostname()
	return &SystemPlatform{host: host, osName: osVersion()}
}

func osVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Windows"
	}
	defer k.Close()
	name, _, _ := k.GetStringValue("ProductName")
	disp, _, _ := k.GetStringValue("DisplayVersion")
	build, _, _ := k.GetStringValue("CurrentBuild")
	// Windows 11 still reports "Windows 10" in ProductName; builds ≥ 22000 are 11.
	var b int
	fmt.Sscan(build, &b)
	if b >= 22000 && len(name) >= 10 && name[:10] == "Windows 10" {
		name = "Windows 11" + name[10:]
	}
	s := name
	if disp != "" {
		s += " " + disp
	}
	if build != "" {
		s += " (build " + build + ")"
	}
	return s
}

func ft(f windows.Filetime) time.Duration {
	return time.Duration((uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime)) * 100)
}

// CPUTimes calls GetSystemTimes.
func (SystemPlatform) CPUTimes() (CPUTimes, error) {
	var idle, kernel, user windows.Filetime
	r, _, err := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if r == 0 {
		return CPUTimes{}, fmt.Errorf("GetSystemTimes: %w", err)
	}
	return CPUTimes{Idle: ft(idle), Kernel: ft(kernel), User: ft(user)}, nil
}

// Memory calls GlobalMemoryStatusEx and GetPerformanceInfo.
func (SystemPlatform) Memory() (uint64, uint64, uint64, uint64, error) {
	var ms memoryStatusEx
	ms.Length = uint32(unsafe.Sizeof(ms))
	r, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	if r == 0 {
		return 0, 0, 0, 0, fmt.Errorf("GlobalMemoryStatusEx: %w", err)
	}
	var pi performanceInfo
	pi.CB = uint32(unsafe.Sizeof(pi))
	var cTotal, cLimit uint64
	if r, _, _ := procGetPerformanceInfo.Call(uintptr(unsafe.Pointer(&pi)), uintptr(pi.CB)); r != 0 {
		cTotal = uint64(pi.CommitTotal) * uint64(pi.PageSize)
		cLimit = uint64(pi.CommitLimit) * uint64(pi.PageSize)
	}
	return ms.TotalPhys, ms.AvailPhys, cTotal, cLimit, nil
}

var driveTypes = map[uint32]string{2: "removable", 3: "fixed", 4: "network", 5: "cdrom", 6: "ramdisk"}

// Disks enumerates logical drives and their capacity.
func (SystemPlatform) Disks() ([]model.DiskUsage, error) {
	mask, _, _ := procGetLogicalDrives.Call()
	var out []model.DiskUsage
	for i := 0; i < 26; i++ {
		if mask&(1<<i) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		p, _ := windows.UTF16PtrFromString(root)
		t := windows.GetDriveType(p)
		kind, ok := driveTypes[t]
		if !ok || kind == "cdrom" {
			continue
		}
		var free, total, totalFree uint64
		r, _, _ := procGetDiskFreeSpaceExW.Call(uintptr(unsafe.Pointer(p)),
			uintptr(unsafe.Pointer(&free)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&totalFree)))
		if r == 0 || total == 0 {
			continue // e.g. empty card reader or disconnected network drive
		}
		d := model.DiskUsage{Mount: root, Type: kind, Total: total, Free: totalFree, Used: total - totalFree}
		d.Percent = float64(d.Used) / float64(total) * 100
		out = append(out, d)
	}
	return out, nil
}

// Uptime uses GetTickCount64.
func (SystemPlatform) Uptime() time.Duration {
	r, _, _ := procGetTickCount64.Call()
	return time.Duration(r) * time.Millisecond
}

// Info returns hostname and OS version string.
func (s *SystemPlatform) Info() (string, string) { return s.host, s.osName }

// Cores returns the logical processor count.
func (SystemPlatform) Cores() int { return runtime.NumCPU() }
