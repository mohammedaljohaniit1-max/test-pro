//go:build windows

package procmon

import (
	"fmt"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGetProcessHandleCnt  = kernel32.NewProc("GetProcessHandleCount")
	procGetPriorityClass     = kernel32.NewProc("GetPriorityClass")
	procGetProcessIoCounters = kernel32.NewProc("GetProcessIoCounters")
)

type ioCounters struct {
	ReadOps, WriteOps, OtherOps       uint64
	ReadBytes, WriteBytes, OtherBytes uint64
}

// Inspect reads the command line (NtQueryInformationProcess /
// ProcessCommandLineInformation, Windows 8.1+), owning account, handle
// count, priority class and I/O counters of one process. It only needs
// PROCESS_QUERY_LIMITED_INFORMATION, like the regular sampler.
func (SystemReader) Inspect(pid uint32) Inspection {
	var in Inspection
	if pid == 0 || pid == 4 {
		in.User = `NT AUTHORITY\SYSTEM`
		return in
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		in.Errors = append(in.Errors, "OpenProcess: "+err.Error())
		return in
	}
	defer windows.CloseHandle(h)

	// Command line: the buffer holds a UNICODE_STRING followed by its data.
	var need uint32
	buf := make([]byte, 4096)
	for attempt := 0; attempt < 4; attempt++ {
		err = windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, unsafe.Pointer(&buf[0]), uint32(len(buf)), &need)
		if err == nil || need <= uint32(len(buf)) {
			break
		}
		buf = make([]byte, need)
	}
	if err == nil {
		us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
		in.CommandLine = us.String()
	} else {
		in.Errors = append(in.Errors, "command line: "+err.Error())
	}

	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err == nil {
		if tu, err := tok.GetTokenUser(); err == nil {
			if acc, dom, _, err := tu.User.Sid.LookupAccount(""); err == nil {
				in.User = dom + `\` + acc
			} else {
				in.User = tu.User.Sid.String()
			}
		}
		if tok.IsElevated() {
			in.Extra = map[string]string{"elevated": "yes"}
		}
		tok.Close()
	} else {
		in.Errors = append(in.Errors, "token: "+err.Error())
	}

	var hc uint32
	if r, _, _ := procGetProcessHandleCnt.Call(uintptr(h), uintptr(unsafe.Pointer(&hc))); r != 0 {
		in.Handles = hc
	}
	if r, _, _ := procGetPriorityClass.Call(uintptr(h)); r != 0 {
		in.Priority = priorityName(uint32(r))
	}
	var io ioCounters
	if r, _, _ := procGetProcessIoCounters.Call(uintptr(h), uintptr(unsafe.Pointer(&io))); r != 0 {
		if in.Extra == nil {
			in.Extra = map[string]string{}
		}
		in.Extra["ioReadBytes"] = strconv.FormatUint(io.ReadBytes, 10)
		in.Extra["ioWriteBytes"] = strconv.FormatUint(io.WriteBytes, 10)
		in.Extra["ioOtherOps"] = strconv.FormatUint(io.OtherOps, 10)
	}
	return in
}

func priorityName(c uint32) string {
	switch c {
	case 0x40:
		return "Idle"
	case 0x4000:
		return "Below normal"
	case 0x20:
		return "Normal"
	case 0x8000:
		return "Above normal"
	case 0x80:
		return "High"
	case 0x100:
		return "Realtime"
	}
	return fmt.Sprintf("0x%X", c)
}
