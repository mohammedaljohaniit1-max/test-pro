//go:build linux

package linuxhost

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/eventlog"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// Journal reads the systemd journal with `journalctl -o json` and maps
// entries onto the SysPulse event model. Channel "System" is the kernel +
// system services, "Application" is everything else. syslog PRIORITY maps
// to Windows levels: 0-2 critical, 3 error, 4 warning, 5-7 info.
type Journal struct {
	mu     sync.Mutex
	cursor map[string]string
	seq    map[string]uint64
}

// NewJournal returns a journald event source (nil if journalctl is missing).
func NewJournal() *Journal {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil
	}
	return &Journal{cursor: map[string]string{}, seq: map[string]uint64{}}
}

// Query implements hub.EventSource. Records are returned newest first with
// channel-local, monotonically increasing record IDs.
func (j *Journal) Query(channel string, since time.Time, max, maxLevel int, after uint64) ([]model.Event, error) {
	if max <= 0 {
		max = 2000
	}
	j.mu.Lock()
	cur := j.cursor[channel]
	j.mu.Unlock()
	args := []string{"--no-pager", "-o", "json", "-q", "--output-fields=MESSAGE,PRIORITY,SYSLOG_IDENTIFIER,_COMM,_SYSTEMD_UNIT,_TRANSPORT,_HOSTNAME,_PID,SYSLOG_FACILITY"}
	if cur != "" {
		args = append(args, "--after-cursor="+cur)
	} else {
		args = append(args, "--since=@"+strconv.FormatInt(since.Unix(), 10), "-n", strconv.Itoa(max*3))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "journalctl", args...).Output()
	if err != nil && len(out) == 0 {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, errors.New(strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	var evs []model.Event
	var last string
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 256<<10), 4<<20)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		s := func(k string) string {
			switch v := m[k].(type) {
			case string:
				return v
			case []any: // binary / repeated fields
				if len(v) > 0 {
					if x, ok := v[0].(string); ok {
						return x
					}
				}
			}
			return ""
		}
		if c := s("__CURSOR"); c != "" {
			last = c
		}
		ch := "Application"
		if s("_TRANSPORT") == "kernel" || s("_TRANSPORT") == "audit" || strings.HasPrefix(s("_SYSTEMD_UNIT"), "systemd-") ||
			s("SYSLOG_IDENTIFIER") == "systemd" || s("SYSLOG_FACILITY") == "0" || s("SYSLOG_FACILITY") == "4" || s("SYSLOG_FACILITY") == "10" {
			ch = "System"
		}
		if ch != channel {
			continue
		}
		prio, _ := strconv.Atoi(s("PRIORITY"))
		lvl := 4
		switch {
		case s("PRIORITY") == "":
			lvl = 4
		case prio <= 2:
			lvl = 1
		case prio == 3:
			lvl = 2
		case prio == 4:
			lvl = 3
		}
		if maxLevel > 0 && lvl > maxLevel {
			continue
		}
		us, _ := strconv.ParseInt(s("__REALTIME_TIMESTAMP"), 10, 64)
		t := time.UnixMicro(us)
		if t.Before(since) {
			continue
		}
		prov := s("SYSLOG_IDENTIFIER")
		if prov == "" {
			prov = s("_COMM")
		}
		if prov == "" {
			prov = s("_TRANSPORT")
		}
		msg := s("MESSAGE")
		e := model.Event{Channel: ch, Level: lvl, Provider: prov, Time: t.UTC(), Computer: s("_HOSTNAME"), Message: msg}
		e.LevelStr = eventlog.LevelName(lvl)
		e.Category = Classify(prov, s("_SYSTEMD_UNIT"), msg, lvl)
		if pid, err := strconv.ParseUint(s("_PID"), 10, 32); err == nil {
			e.EventID = uint32(pid % 100000)
		}
		evs = append(evs, e)
	}
	j.mu.Lock()
	if last != "" {
		j.cursor[channel] = last
	}
	for i := range evs {
		j.seq[channel]++
		evs[i].RecordID = j.seq[channel]
	}
	j.mu.Unlock()
	// newest first, bounded
	for i, k := 0, len(evs)-1; i < k; i, k = i+1, k-1 {
		evs[i], evs[k] = evs[k], evs[i]
	}
	if len(evs) > max {
		evs = evs[:max]
	}
	return evs, nil
}

// Classify maps a journal entry onto the SysPulse reliability categories.
func Classify(prov, unit, msg string, level int) string {
	p, m := strings.ToLower(prov), strings.ToLower(msg)
	switch {
	case strings.Contains(m, "segfault") || strings.Contains(m, "core dumped") || p == "systemd-coredump" || strings.Contains(m, "traps:"):
		return model.CatAppFault
	case (p == "systemd" || strings.HasPrefix(unit, "init")) && (strings.Contains(m, "failed with result") || strings.Contains(m, "main process exited") || strings.Contains(m, "entered failed state")):
		return model.CatServiceCrash
	case strings.Contains(m, "oom-kill") || strings.Contains(m, "out of memory"):
		return model.CatAppFault
	case strings.Contains(m, "i/o error") || strings.Contains(m, "ext4-fs") || strings.Contains(m, "xfs") || strings.Contains(m, "smart") || strings.Contains(m, "blk_update_request"):
		return model.CatDisk
	case p == "kernel" && (strings.Contains(m, "firmware") || strings.Contains(m, "driver") || strings.Contains(m, "usb")):
		return model.CatDriver
	case strings.Contains(p, "apt") || strings.Contains(p, "dpkg") || strings.Contains(p, "unattended-upgrade") || strings.Contains(p, "packagekit"):
		return model.CatUpdate
	case strings.Contains(p, "logind") && (strings.Contains(m, "suspend") || strings.Contains(m, "power")) || strings.Contains(m, "acpi"):
		return model.CatPower
	case strings.Contains(m, "unclean shutdown") || strings.Contains(m, "was not properly unmounted"):
		return model.CatUnexpectedShutdn
	}
	return model.CatOther
}
