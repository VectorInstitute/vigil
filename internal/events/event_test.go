package events_test

import (
	"net"
	"testing"
	"time"

	"github.com/VectorInstitute/vigil/internal/events"
	"github.com/stretchr/testify/assert"
)

func TestEventType_String(t *testing.T) {
	assert.Equal(t, "file_open", events.FileOpen.String())
	assert.Equal(t, "net_connect", events.NetConnect.String())
	assert.Equal(t, "exec", events.Exec.String())
	assert.Equal(t, "ssl_data", events.SSLData.String())
}

func TestEvent_FileOpen(t *testing.T) {
	e := events.Event{
		Timestamp: time.Now(),
		PID:       1234,
		Comm:      "ollama",
		Type:      events.FileOpen,
		Path:      "/etc/passwd",
	}
	assert.Equal(t, events.FileOpen, e.Type)
	assert.Equal(t, "/etc/passwd", e.Path)
	assert.Equal(t, uint32(1234), e.PID)
	assert.Empty(t, e.DestIP)
	assert.Empty(t, e.Argv)
}

func TestEvent_NetConnect(t *testing.T) {
	e := events.Event{
		Timestamp: time.Now(),
		PID:       5678,
		Comm:      "ollama",
		Type:      events.NetConnect,
		DestIP:    net.ParseIP("8.8.8.8"),
		DestPort:  443,
	}
	assert.Equal(t, events.NetConnect, e.Type)
	assert.Equal(t, uint16(443), e.DestPort)
	assert.True(t, e.DestIP.Equal(net.ParseIP("8.8.8.8")))
	assert.Empty(t, e.Path)
}

func TestEvent_Exec(t *testing.T) {
	e := events.Event{
		Timestamp: time.Now(),
		PID:       9999,
		Comm:      "ollama",
		Type:      events.Exec,
		Path:      "/bin/bash",
		Argv:      []string{"/bin/bash", "-i"},
	}
	assert.Equal(t, events.Exec, e.Type)
	assert.Equal(t, "/bin/bash", e.Path)
	assert.Equal(t, []string{"/bin/bash", "-i"}, e.Argv)
}

func TestEvent_SSLData(t *testing.T) {
	e := events.Event{
		Timestamp: time.Now(),
		PID:       4242,
		PPID:      4241,
		Comm:      "claude-code",
		Type:      events.SSLData,
		Direction: events.SSLSend,
		Data:      `{"model":"claude-3","prompt":"hello"}`,
	}
	assert.Equal(t, events.SSLData, e.Type)
	assert.Equal(t, uint32(4242), e.PID)
	assert.Equal(t, uint32(4241), e.PPID)
	assert.Equal(t, "claude-code", e.Comm)
	assert.Equal(t, events.SSLSend, e.Direction)
	assert.Equal(t, "send", e.Direction.String())
	assert.Contains(t, e.Data, "prompt")
	s := e.String()
	assert.Contains(t, s, "ssl_data")
	assert.Contains(t, s, "send")
	assert.Contains(t, s, "claude-code")

	eRecv := events.Event{
		Type:      events.SSLData,
		Direction: events.SSLRecv,
	}
	assert.Equal(t, "recv", eRecv.Direction.String())
}

func TestEvent_String_FileOpen(t *testing.T) {
	e := events.Event{
		Type: events.FileOpen,
		Comm: "ollama",
		PID:  42,
		Path: "/etc/shadow",
	}
	s := e.String()
	assert.Contains(t, s, "file_open")
	assert.Contains(t, s, "/etc/shadow")
	assert.Contains(t, s, "ollama")
}

func TestEvent_String_NetConnect(t *testing.T) {
	e := events.Event{
		Type:     events.NetConnect,
		Comm:     "ollama",
		PID:      42,
		DestIP:   net.ParseIP("8.8.8.8"),
		DestPort: 53,
	}
	s := e.String()
	assert.Contains(t, s, "net_connect")
	assert.Contains(t, s, "8.8.8.8")
	assert.Contains(t, s, "53")
}

func TestEvent_String_Exec(t *testing.T) {
	e := events.Event{
		Type: events.Exec,
		Comm: "ollama",
		PID:  42,
		Path: "/bin/bash",
		Argv: []string{"/bin/bash", "-i"},
	}
	s := e.String()
	assert.Contains(t, s, "exec")
	assert.Contains(t, s, "/bin/bash")
}

func TestEventType_String_Unknown(t *testing.T) {
	assert.Equal(t, "unknown", events.Type(99).String())
}

func TestEvent_String_UnknownType(t *testing.T) {
	e := events.Event{Type: events.Type(99), Comm: "test", PID: 1}
	assert.Contains(t, e.String(), "unknown")
}
