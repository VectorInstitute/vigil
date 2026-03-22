package events

import (
	"fmt"
	"net"
	"time"
)

// Type classifies what kernel event was observed.
type Type uint8

const (
	FileOpen   Type = iota // openat / open syscall
	NetConnect             // connect syscall
	Exec                   // execve syscall
	SSLData    Type = 3    // SSL/TLS payload captured via uprobe
)

func (t Type) String() string {
	switch t {
	case FileOpen:
		return "file_open"
	case NetConnect:
		return "net_connect"
	case Exec:
		return "exec"
	case SSLData:
		return "ssl_data"
	default:
		return "unknown"
	}
}

// SSLDirection indicates whether the SSL payload was sent or received.
type SSLDirection uint8

const (
	SSLSend SSLDirection = 0
	SSLRecv SSLDirection = 1
)

func (d SSLDirection) String() string {
	switch d {
	case SSLSend:
		return "send"
	case SSLRecv:
		return "recv"
	default:
		return "unknown"
	}
}

// Event is a single kernel observation emitted by an eBPF probe.
// Fields are populated depending on Type; unused fields are zero values.
type Event struct {
	Timestamp time.Time
	PID       uint32
	PPID      uint32 // parent PID
	Comm      string // process name (up to 16 chars from kernel)

	Type Type

	// FileOpen / Exec
	Path string

	// Exec only
	Argv []string

	// NetConnect
	DestIP   net.IP
	DestPort uint16

	// SSLData
	Direction SSLDirection
	Data      string
}

func (e Event) String() string {
	switch e.Type {
	case FileOpen:
		return fmt.Sprintf("[%s] pid=%d comm=%s file_open path=%s", e.Timestamp.Format(time.RFC3339), e.PID, e.Comm, e.Path)
	case NetConnect:
		return fmt.Sprintf("[%s] pid=%d comm=%s net_connect dst=%s:%d", e.Timestamp.Format(time.RFC3339), e.PID, e.Comm, e.DestIP, e.DestPort)
	case Exec:
		return fmt.Sprintf("[%s] pid=%d comm=%s exec path=%s argv=%v", e.Timestamp.Format(time.RFC3339), e.PID, e.Comm, e.Path, e.Argv)
	case SSLData:
		preview := e.Data
		if len(preview) > 64 {
			preview = preview[:64] + "..."
		}
		return fmt.Sprintf("[%s] pid=%d comm=%s ssl_data dir=%s len=%d data=%q", e.Timestamp.Format(time.RFC3339), e.PID, e.Comm, e.Direction, len(e.Data), preview)
	default:
		return fmt.Sprintf("[%s] pid=%d comm=%s unknown", e.Timestamp.Format(time.RFC3339), e.PID, e.Comm)
	}
}
