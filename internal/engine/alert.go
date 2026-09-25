package engine

import (
	"encoding/json"
	"time"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/event"
)

// MaxEvidence bounds the number of contributing events attached to an alert.
const MaxEvidence = 32

// Alert is a rule match. It is immutable once emitted.
type Alert struct {
	ID          string
	Rule        string
	Fingerprint string
	Kind        string
	Severity    string
	Description string
	Tags        []string
	Key         string
	Group       string
	// EventTime is the event-time instant at which the match was established
	// (trigger event time, absence deadline, or window end).
	EventTime int64
	// DetectedAt is the wall-clock time of detection (Unix ns).
	DetectedAt int64
	// WindowStart / WindowEnd are set for aggregate alerts.
	WindowStart int64
	WindowEnd   int64
	Fields      map[string]any
	Evidence    []*event.Event
	Shard       int
	// LatencyNs is DetectedAt minus the ingestion wall time of the trigger
	// event (0 when not applicable, e.g. absence / timer-driven alerts).
	LatencyNs int64
}

// MarshalJSON renders the alert for sinks and the API.
func (a *Alert) MarshalJSON() ([]byte, error) {
	m := map[string]any{
		"id":          a.ID,
		"rule":        a.Rule,
		"fingerprint": a.Fingerprint,
		"kind":        a.Kind,
		"severity":    a.Severity,
		"key":         a.Key,
		"event_time":  time.Unix(0, a.EventTime).UTC().Format(time.RFC3339Nano),
		"detected_at": time.Unix(0, a.DetectedAt).UTC().Format(time.RFC3339Nano),
		"fields":      a.Fields,
		"shard":       a.Shard,
	}
	if a.Description != "" {
		m["description"] = a.Description
	}
	if len(a.Tags) > 0 {
		m["tags"] = a.Tags
	}
	if a.Group != "" {
		m["group"] = a.Group
	}
	if a.WindowEnd != 0 {
		m["window"] = map[string]string{
			"start": time.Unix(0, a.WindowStart).UTC().Format(time.RFC3339Nano),
			"end":   time.Unix(0, a.WindowEnd).UTC().Format(time.RFC3339Nano),
		}
	}
	if a.LatencyNs > 0 {
		m["latency_us"] = float64(a.LatencyNs) / 1e3
	}
	if len(a.Evidence) > 0 {
		ev := make([]map[string]any, len(a.Evidence))
		for i, e := range a.Evidence {
			ev[i] = e.ToJSONMap()
		}
		m["evidence"] = ev
	}
	return json.Marshal(m)
}
