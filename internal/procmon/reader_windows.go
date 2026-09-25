//go:build windows

package procmon

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	psapi                    = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemoryInfo = psapi.NewProc("GetProcessMemoryInfo")
)

// processMemoryCountersEx mirrors PROCESS_MEMORY_COUNTERS_EX.
type processMemoryCountersEx struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

// SystemReader reads processes via the Toolhelp32 snapshot API plus
// OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION), which works for most
// processes without elevation. Protected processes report Access=false.
type SystemReader struct{}

// NewSystemReader returns the Windows process reader.
func NewSystemReader() Reader { return SystemReader{} }

// List enumerates processes with CreateToolhelp32Snapshot.
func (SystemReader) List() ([]RawProcess, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := windows.Process32First(snap, &e); err != nil {
		return nil, err
	}
	out := make([]RawProcess, 0, 256)
	for {
		out = append(out, RawProcess{
			PID: e.ProcessID, PPID: e.ParentProcessID, Threads: e.Threads,
			Name: windows.UTF16ToString(e.ExeFile[:]),
		})
		if err := windows.Process32Next(snap, &e); err != nil {
			break // ERROR_NO_MORE_FILES
		}
	}
	return out, nil
}

// Details fills image path, CPU time, start time and memory counters.
func (SystemReader) Details(p *RawProcess) {
	if p.PID == 0 {
		return
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.PID)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	p.Access = true

	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err == nil {
		p.Path = windows.UTF16ToString(buf[:n])
	}

	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err == nil {
		p.Started = time.Unix(0, creation.Nanoseconds())
		// FILETIME durations are in 100 ns units.
		k := uint64(kernel.HighDateTime)<<32 | uint64(kernel.LowDateTime)
		u := uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime)
		p.CPUTime = time.Duration((k + u) * 100)
	}

	var mc processMemoryCountersEx
	mc.CB = uint32(unsafe.Sizeof(mc))
	if r, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&mc)), uintptr(mc.CB)); r != 0 {
		p.WorkingSet = uint64(mc.WorkingSetSize)
		p.Private = uint64(mc.PrivateUsage)
	}
}
