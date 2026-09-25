// Package eventlog reads recent Windows System/Application events and
// classifies reliability-relevant ones (service crashes, application faults,
// unexpected shutdowns, driver and disk problems, update failures).
//
// Events are rendered by wevtapi as XML (EvtRender / EvtRenderEventXml) and
// formatted messages are obtained with EvtFormatMessage. Parsing and
// classification are platform-independent and unit tested.
package eventlog

import (
	"encoding/xml"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/model"
)

// eventXML mirrors the parts of the Windows event schema we use.
type eventXML struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Level       string `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID string `xml:"EventRecordID"`
		Channel       string `xml:"Channel"`
		Computer      string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Inner string `xml:",innerxml"`
	} `xml:"UserData"`
}

// ParseXML converts one rendered event. message may be empty (the formatted
// message is unavailable when the provider's resources are missing), in
// which case a summary is built from EventData.
func ParseXML(raw, message string) (model.Event, error) {
	var x eventXML
	if err := xml.Unmarshal([]byte(raw), &x); err != nil {
		return model.Event{}, err
	}
	e := model.Event{
		Channel:  x.System.Channel,
		Provider: x.System.Provider.Name,
		Computer: x.System.Computer,
	}
	id, _ := strconv.ParseUint(strings.TrimSpace(x.System.EventID), 10, 32)
	e.EventID = uint32(id)
	lvl, _ := strconv.Atoi(strings.TrimSpace(x.System.Level))
	e.Level = lvl
	e.RecordID, _ = strconv.ParseUint(strings.TrimSpace(x.System.EventRecordID), 10, 64)
	if t, err := time.Parse(time.RFC3339Nano, x.System.TimeCreated.SystemTime); err == nil {
		e.Time = t.UTC()
	}
	if n := len(x.EventData.Data); n > 0 {
		e.Data = make(map[string]string, n)
		for i, d := range x.EventData.Data {
			v := strings.TrimSpace(d.Value)
			if d.Name != "" {
				e.Data[d.Name] = v
			}
			e.Data["#"+strconv.Itoa(i)] = v
		}
	}
	msg := strings.TrimSpace(message)
	if msg == "" {
		var parts []string
		for _, d := range x.EventData.Data {
			v := strings.TrimSpace(d.Value)
			if v == "" {
				continue
			}
			if d.Name != "" {
				parts = append(parts, d.Name+"="+v)
			} else {
				parts = append(parts, v)
			}
		}
		msg = strings.Join(parts, "; ")
	}
	e.Message = truncate(collapseSpace(msg), 2000)
	e.LevelStr = LevelName(e.Level)
	e.Category = Classify(e.Provider, e.EventID, e.Level)
	return e, nil
}

// LevelName maps Windows event levels (0 LogAlways is shown as info).
func LevelName(l int) string {
	switch l {
	case 1:
		return "critical"
	case 2:
		return "error"
	case 3:
		return "warning"
	case 5:
		return "verbose"
	}
	return "info"
}

type rule struct {
	provider string // lower-case substring; "" matches any
	ids      []uint32
	cat      string
}

// Classification rules for well-known reliability events.
var rules = []rule{
	{"service control manager", []uint32{7031, 7034, 7024, 7023, 7000, 7009, 7011, 7022}, model.CatServiceCrash},
	{"application error", []uint32{1000}, model.CatAppFault},
	{"application hang", []uint32{1002}, model.CatAppFault},
	{"windows error reporting", []uint32{1001}, model.CatAppFault},
	{".net runtime", []uint32{1026}, model.CatAppFault},
	{"kernel-power", []uint32{41}, model.CatUnexpectedShutdn},
	{"eventlog", []uint32{6008}, model.CatUnexpectedShutdn},
	{"bugcheck", []uint32{1001}, model.CatUnexpectedShutdn},
	{"kernel-power", []uint32{42, 107, 109, 506, 507}, model.CatPower},
	{"kernel-pnp", nil, model.CatDriver},
	{"userpnp", nil, model.CatDriver},
	{"driverframeworks", nil, model.CatDriver},
	{"display", []uint32{4101}, model.CatDriver},
	{"disk", []uint32{7, 11, 15, 51, 153, 154}, model.CatDisk},
	{"ntfs", []uint32{55, 98, 130, 137}, model.CatDisk},
	{"stornvme", nil, model.CatDisk},
	{"storahci", nil, model.CatDisk},
	{"windowsupdateclient", []uint32{20, 25, 31}, model.CatUpdate},
}

// Classify assigns a category to an event.
func Classify(provider string, id uint32, level int) string {
	p := strings.ToLower(provider)
	for _, r := range rules {
		if r.provider != "" && !strings.Contains(p, r.provider) {
			continue
		}
		if r.ids == nil {
			// Provider-wide rules (e.g. driver stacks) only for warnings+.
			if level >= 1 && level <= 3 {
				return r.cat
			}
			continue
		}
		for _, x := range r.ids {
			if x == id {
				return r.cat
			}
		}
	}
	// Generic driver failures surfaced by other providers.
	if level >= 1 && level <= 3 && strings.Contains(p, "driver") {
		return model.CatDriver
	}
	return model.CatOther
}

func collapseSpace(s string) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if r == '\r' || r == '\n' || r == '\t' || r == ' ' {
			if !space {
				b.WriteByte(' ')
			}
			space = true
			continue
		}
		space = false
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && (s[cut]&0xC0) == 0x80 { // do not split a UTF-8 sequence
		cut--
	}
	return s[:cut] + "…"
}

// Bucket is one timeline bin.
type Bucket struct {
	Start    int64 `json:"start"` // unix ms
	Critical int   `json:"critical"`
	Error    int   `json:"error"`
	Warning  int   `json:"warning"`
	Info     int   `json:"info"`
}

// Summary aggregates events for the dashboard.
type Summary struct {
	Total      int               `json:"total"`
	ByLevel    map[string]int    `json:"byLevel"`
	ByCategory map[string]int    `json:"byCategory"`
	Timeline   []Bucket          `json:"timeline"`
	TopSources []model.ProcCount `json:"topSources"`
	From       int64             `json:"from"`
	To         int64             `json:"to"`
}

// Summarize buckets events into `bins` equal slots over [from, to].
func Summarize(evs []model.Event, from, to time.Time, bins int) Summary {
	if bins <= 0 {
		bins = 48
	}
	s := Summary{ByLevel: map[string]int{}, ByCategory: map[string]int{}, From: from.UnixMilli(), To: to.UnixMilli()}
	width := to.Sub(from) / time.Duration(bins)
	if width <= 0 {
		width = time.Hour
	}
	s.Timeline = make([]Bucket, bins)
	for i := range s.Timeline {
		s.Timeline[i].Start = from.Add(time.Duration(i) * width).UnixMilli()
	}
	src := map[string]int{}
	for _, e := range evs {
		s.Total++
		s.ByLevel[e.LevelStr]++
		if e.Category != model.CatOther {
			s.ByCategory[e.Category]++
		}
		if e.Level >= 1 && e.Level <= 3 {
			src[e.Provider]++
		}
		if e.Time.Before(from) || e.Time.After(to) {
			continue
		}
		i := int(e.Time.Sub(from) / width)
		if i >= bins {
			i = bins - 1
		}
		b := &s.Timeline[i]
		switch e.Level {
		case 1:
			b.Critical++
		case 2:
			b.Error++
		case 3:
			b.Warning++
		default:
			b.Info++
		}
	}
	for k, v := range src {
		s.TopSources = append(s.TopSources, model.ProcCount{Name: k, Count: v})
	}
	sort.Slice(s.TopSources, func(i, j int) bool {
		if s.TopSources[i].Count != s.TopSources[j].Count {
			return s.TopSources[i].Count > s.TopSources[j].Count
		}
		return s.TopSources[i].Name < s.TopSources[j].Name
	})
	if len(s.TopSources) > 10 {
		s.TopSources = s.TopSources[:10]
	}
	return s
}

// SortNewestFirst orders events by time descending, then record id.
func SortNewestFirst(evs []model.Event) {
	sort.Slice(evs, func(i, j int) bool {
		if !evs[i].Time.Equal(evs[j].Time) {
			return evs[i].Time.After(evs[j].Time)
		}
		return evs[i].RecordID > evs[j].RecordID
	})
}

// AuditXPath builds an XPath filter selecting the given event IDs within
// the last `window`. Used by the one-click diagnostic audits, which read
// specific IDs over a long window instead of the whole channel.
func AuditXPath(ids []uint32, window time.Duration) string {
	var b strings.Builder
	b.WriteString("*[System[(")
	for i, id := range ids {
		if i > 0 {
			b.WriteString(" or ")
		}
		b.WriteString("EventID=")
		b.WriteString(strconv.FormatUint(uint64(id), 10))
	}
	b.WriteString(")")
	if ms := window.Milliseconds(); ms > 0 {
		b.WriteString(" and TimeCreated[timediff(@SystemTime) <= ")
		b.WriteString(strconv.FormatInt(ms, 10))
		b.WriteString("]")
	}
	b.WriteString("]]")
	return b.String()
}
