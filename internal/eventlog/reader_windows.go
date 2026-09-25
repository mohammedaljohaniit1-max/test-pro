//go:build windows

package eventlog

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

var (
	wevtapi              = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery         = wevtapi.NewProc("EvtQuery")
	procEvtNext          = wevtapi.NewProc("EvtNext")
	procEvtRender        = wevtapi.NewProc("EvtRender")
	procEvtClose         = wevtapi.NewProc("EvtClose")
	procEvtOpenPublisher = wevtapi.NewProc("EvtOpenPublisherMetadata")
	procEvtFormatMessage = wevtapi.NewProc("EvtFormatMessage")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200
	evtRenderEventXML        = 1
	evtFormatMessageEvent    = 1
	errNoMoreItems           = 259
	batchSize                = 64
)

type evtHandle uintptr

func evtClose(h evtHandle) {
	if h != 0 {
		procEvtClose.Call(uintptr(h))
	}
}

// Reader queries one or more channels. Publisher metadata handles are cached
// because opening them is the most expensive part of message formatting.
type Reader struct {
	mu         sync.Mutex
	publishers map[string]evtHandle
}

// NewReader returns a Windows event log reader.
func NewReader() *Reader { return &Reader{publishers: map[string]evtHandle{}} }

// Close releases cached publisher handles.
func (r *Reader) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, h := range r.publishers {
		evtClose(h)
		delete(r.publishers, k)
	}
}

// Query returns up to max events from channel newer than since, newest
// first. minLevel filters by severity (e.g. 3 = warnings and worse; 0 = all).
// afterRecord, when > 0, returns only records with a greater EventRecordID
// (incremental polling).
func (r *Reader) Query(channel string, since time.Time, maxEvents int, maxLevel int, afterRecord uint64) ([]model.Event, error) {
	ms := time.Since(since).Milliseconds()
	if ms < 0 {
		ms = 0
	}
	cond := fmt.Sprintf("TimeCreated[timediff(@SystemTime) <= %d]", ms)
	if maxLevel > 0 {
		lv := ""
		for l := 1; l <= maxLevel; l++ {
			if lv != "" {
				lv += " or "
			}
			lv += "Level=" + strconv.Itoa(l)
		}
		cond += " and (" + lv + ")"
	}
	if afterRecord > 0 {
		cond += fmt.Sprintf(" and EventRecordID > %d", afterRecord)
	}
	xpath := "*[System[" + cond + "]]"
	ch, _ := windows.UTF16PtrFromString(channel)
	q, _ := windows.UTF16PtrFromString(xpath)
	h, _, err := procEvtQuery.Call(0, uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(q)),
		evtQueryChannelPath|evtQueryReverseDirection)
	if h == 0 {
		return nil, fmt.Errorf("EvtQuery(%s): %w", channel, err)
	}
	defer evtClose(evtHandle(h))

	var out []model.Event
	handles := make([]evtHandle, batchSize)
	for len(out) < maxEvents {
		var returned uint32
		ok, _, err := procEvtNext.Call(h, batchSize, uintptr(unsafe.Pointer(&handles[0])),
			1000, 0, uintptr(unsafe.Pointer(&returned)))
		if ok == 0 {
			var en syscall.Errno
			if errors.As(err, &en) && en == errNoMoreItems {
				break
			}
			return out, fmt.Errorf("EvtNext: %w", err)
		}
		for i := uint32(0); i < returned; i++ {
			if len(out) < maxEvents {
				if ev, err := r.render(handles[i]); err == nil {
					out = append(out, ev)
				}
			}
			evtClose(handles[i])
		}
	}
	return out, nil
}

func (r *Reader) render(ev evtHandle) (model.Event, error) {
	raw, err := renderXML(ev)
	if err != nil {
		return model.Event{}, err
	}
	// Parse once without a message to learn the provider, then format.
	e, err := ParseXML(raw, "")
	if err != nil {
		return e, err
	}
	if msg := r.format(e.Provider, ev); msg != "" {
		return ParseXML(raw, msg)
	}
	return e, nil
}

func renderXML(ev evtHandle) (string, error) {
	var used, props uint32
	procEvtRender.Call(0, uintptr(ev), evtRenderEventXML, 0, 0,
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
	if used == 0 {
		return "", errors.New("EvtRender: empty")
	}
	buf := make([]uint16, used/2+1)
	r, _, err := procEvtRender.Call(0, uintptr(ev), evtRenderEventXML, uintptr(len(buf)*2),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
	if r == 0 {
		return "", fmt.Errorf("EvtRender: %w", err)
	}
	return windows.UTF16ToString(buf), nil
}

func (r *Reader) publisher(name string) evtHandle {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.publishers[name]; ok {
		return h
	}
	p, _ := windows.UTF16PtrFromString(name)
	h, _, _ := procEvtOpenPublisher.Call(0, uintptr(unsafe.Pointer(p)), 0, 0, 0)
	r.publishers[name] = evtHandle(h) // cache failures (0) too
	return evtHandle(h)
}

func (r *Reader) format(provider string, ev evtHandle) string {
	if provider == "" {
		return ""
	}
	pub := r.publisher(provider)
	if pub == 0 {
		return ""
	}
	var used uint32
	procEvtFormatMessage.Call(uintptr(pub), uintptr(ev), 0, 0, 0, evtFormatMessageEvent, 0, 0, uintptr(unsafe.Pointer(&used)))
	if used == 0 || used > 1<<20 {
		return ""
	}
	buf := make([]uint16, used)
	rc, _, _ := procEvtFormatMessage.Call(uintptr(pub), uintptr(ev), 0, 0, 0, evtFormatMessageEvent,
		uintptr(used), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)))
	if rc == 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}
