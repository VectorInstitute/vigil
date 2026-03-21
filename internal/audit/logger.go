package audit

import (
	"encoding/json"
	"io"

	"github.com/VectorInstitute/vigil/internal/detector"
	"github.com/VectorInstitute/vigil/internal/events"
)

// Logger writes one JSON line per decision to an io.Writer.
type Logger struct {
	enc *json.Encoder
}

// New returns a Logger that writes to w.
func New(w io.Writer) *Logger {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &Logger{enc: enc}
}

// record is the JSON shape of a single audit log entry.
type record struct {
	TS      string `json:"ts"`
	PID     uint32 `json:"pid"`
	Comm    string `json:"comm"`
	Event   string `json:"event"`
	Action  string `json:"action"`
	Reason  string `json:"reason"`
	Path    string `json:"path,omitempty"`
	Argv    []string `json:"argv,omitempty"`
	DestIP  string `json:"dest_ip,omitempty"`
	DestPort uint16 `json:"dest_port,omitempty"`
}

// Log writes dec as a single newline-terminated JSON object.
func (l *Logger) Log(dec detector.Decision) {
	e := dec.Event
	r := record{
		TS:     e.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		PID:    e.PID,
		Comm:   e.Comm,
		Event:  e.Type.String(),
		Action: dec.Action.String(),
		Reason: dec.Reason,
	}
	switch e.Type {
	case events.FileOpen, events.Exec:
		r.Path = e.Path
		r.Argv = e.Argv
	case events.NetConnect:
		if e.DestIP != nil {
			r.DestIP = e.DestIP.String()
		}
		r.DestPort = e.DestPort
	}
	_ = l.enc.Encode(r) // json.Encoder appends \n automatically
}
