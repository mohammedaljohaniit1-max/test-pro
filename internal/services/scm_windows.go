//go:build windows

package services

import (
	"errors"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// SCM lists Win32 services through the Service Control Manager. Start type,
// account and binary path come from QueryServiceConfig; descriptions from
// QueryServiceConfig2(SERVICE_CONFIG_DESCRIPTION). Configuration rarely
// changes, so it is cached per service name and refreshed every 20th call.
type SCM struct {
	mu    sync.Mutex
	cfg   map[string]svcConfig
	calls int
}

type svcConfig struct {
	start, account, binary, desc string
}

// NewSystemLister returns the Windows SCM lister.
func NewSystemLister() Lister { return &SCM{cfg: map[string]svcConfig{}} }

func stateName(s uint32) string {
	switch s {
	case windows.SERVICE_RUNNING:
		return model.SvcRunning
	case windows.SERVICE_STOPPED:
		return model.SvcStopped
	case windows.SERVICE_START_PENDING, windows.SERVICE_CONTINUE_PENDING:
		return model.SvcStarting
	case windows.SERVICE_STOP_PENDING, windows.SERVICE_PAUSE_PENDING:
		return model.SvcStopping
	case windows.SERVICE_PAUSED:
		return model.SvcPaused
	}
	return model.SvcOther
}

func typeName(t uint32) string {
	switch {
	case t&windows.SERVICE_WIN32_SHARE_PROCESS != 0:
		return "share-process"
	case t&windows.SERVICE_WIN32_OWN_PROCESS != 0:
		return "own-process"
	case t&(windows.SERVICE_KERNEL_DRIVER|windows.SERVICE_FILE_SYSTEM_DRIVER) != 0:
		return "driver"
	}
	return "other"
}

func startName(t uint32, delayed bool) string {
	switch t {
	case windows.SERVICE_AUTO_START:
		if delayed {
			return model.StartDelayed
		}
		return model.StartAuto
	case windows.SERVICE_DEMAND_START:
		return model.StartManual
	case windows.SERVICE_DISABLED:
		return model.StartDisabled
	case windows.SERVICE_BOOT_START:
		return model.StartBoot
	case windows.SERVICE_SYSTEM_START:
		return model.StartSystem
	}
	return ""
}

// List implements Lister.
func (s *SCM) List() ([]model.Service, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE|windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, err
	}
	defer windows.CloseServiceHandle(h)
	var need, count, resume uint32
	buf := make([]byte, 256*1024)
	var out []model.Service
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.calls%20 == 0 {
		s.cfg = map[string]svcConfig{}
	}
	for {
		err := windows.EnumServicesStatusEx(h, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL,
			&buf[0], uint32(len(buf)), &need, &count, &resume, nil)
		if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
			return nil, err
		}
		ents := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), count)
		for i := range ents {
			e := &ents[i]
			name := windows.UTF16PtrToString(e.ServiceName)
			sv := model.Service{Name: name, Display: windows.UTF16PtrToString(e.DisplayName),
				State: stateName(e.ServiceStatusProcess.CurrentState), PID: e.ServiceStatusProcess.ProcessId,
				Type: typeName(e.ServiceStatusProcess.ServiceType), ExitCode: e.ServiceStatusProcess.Win32ExitCode}
			c, ok := s.cfg[name]
			if !ok {
				c = queryConfig(h, name)
				s.cfg[name] = c
			}
			sv.StartType, sv.Account, sv.Binary, sv.Description = c.start, c.account, c.binary, c.desc
			out = append(out, sv)
		}
		if err == nil {
			break
		}
		if need > uint32(len(buf)) {
			buf = make([]byte, need)
		}
	}
	return out, nil
}

func queryConfig(scm windows.Handle, name string) svcConfig {
	var c svcConfig
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return c
	}
	h, err := windows.OpenService(scm, p, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return c
	}
	defer windows.CloseServiceHandle(h)
	var need uint32
	_ = windows.QueryServiceConfig(h, nil, 0, &need)
	if need > 0 && need < 1<<20 {
		b := make([]byte, need)
		qc := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&b[0]))
		if windows.QueryServiceConfig(h, qc, need, &need) == nil {
			// SERVICE_DELAYED_AUTO_START_INFO is a single BOOL.
			var dinfo uint32
			var dn uint32
			delayed := windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
				(*byte)(unsafe.Pointer(&dinfo)), uint32(unsafe.Sizeof(dinfo)), &dn) == nil && dinfo != 0
			c.start = startName(qc.StartType, delayed)
			c.account = windows.UTF16PtrToString(qc.ServiceStartName)
			c.binary = windows.UTF16PtrToString(qc.BinaryPathName)
		}
	}
	need = 0
	_ = windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_DESCRIPTION, nil, 0, &need)
	if need > 0 && need < 1<<16 {
		b := make([]byte, need)
		if windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_DESCRIPTION, &b[0], need, &need) == nil {
			d := (*windows.SERVICE_DESCRIPTION)(unsafe.Pointer(&b[0]))
			if d.Description != nil {
				c.desc = windows.UTF16PtrToString(d.Description)
			}
		}
	}
	return c
}
