package audit_test

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/VectorInstitute/vigil/internal/audit"
	"github.com/VectorInstitute/vigil/internal/detector"
	"github.com/VectorInstitute/vigil/internal/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeDecision(typ events.Type, action detector.Action) detector.Decision {
	e := events.Event{
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PID:       1234,
		Comm:      "ollama",
		Type:      typ,
	}
	switch typ {
	case events.FileOpen:
		e.Path = "/etc/passwd"
	case events.NetConnect:
		e.DestIP = net.ParseIP("8.8.8.8")
		e.DestPort = 443
	case events.Exec:
		e.Path = "/bin/bash"
		e.Argv = []string{"/bin/bash", "-i"}
	}
	return detector.Decision{Event: e, Action: action, Reason: "test reason"}
}

// ── JSON structure ───────────────────────────────────────────────────────────

func TestLog_ProducesValidJSON(t *testing.T) {
	var buf bytes.Buffer
	l := audit.New(&buf)
	l.Log(makeDecision(events.FileOpen, detector.Block))

	var record map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &record))
}

func TestLog_ContainsRequiredFields(t *testing.T) {
	var buf bytes.Buffer
	l := audit.New(&buf)
	l.Log(makeDecision(events.FileOpen, detector.Block))

	var record map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &record))

	for _, field := range []string{"ts", "pid", "comm", "event", "action", "reason"} {
		assert.Contains(t, record, field, "missing field %q", field)
	}
}

func TestLog_BlockDecision(t *testing.T) {
	var buf bytes.Buffer
	l := audit.New(&buf)
	l.Log(makeDecision(events.FileOpen, detector.Block))

	var record map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &record))

	assert.Equal(t, "BLOCK", record["action"])
	assert.Equal(t, "file_open", record["event"])
	assert.Equal(t, "/etc/passwd", record["path"])
	assert.Equal(t, float64(1234), record["pid"])
	assert.Equal(t, "ollama", record["comm"])
}

func TestLog_AllowDecision(t *testing.T) {
	var buf bytes.Buffer
	l := audit.New(&buf)
	l.Log(makeDecision(events.FileOpen, detector.Allow))

	var record map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &record))
	assert.Equal(t, "ALLOW", record["action"])
}

func TestLog_NetConnectIncludesIPAndPort(t *testing.T) {
	var buf bytes.Buffer
	l := audit.New(&buf)
	l.Log(makeDecision(events.NetConnect, detector.Block))

	var record map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &record))

	assert.Equal(t, "net_connect", record["event"])
	assert.Equal(t, "8.8.8.8", record["dest_ip"])
	assert.Equal(t, float64(443), record["dest_port"])
}

func TestLog_ExecIncludesArgv(t *testing.T) {
	var buf bytes.Buffer
	l := audit.New(&buf)
	l.Log(makeDecision(events.Exec, detector.Block))

	var record map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &record))

	assert.Equal(t, "exec", record["event"])
	assert.Equal(t, "/bin/bash", record["path"])
	argv, ok := record["argv"].([]any)
	require.True(t, ok)
	assert.Equal(t, "/bin/bash", argv[0])
}

// ── Each log entry is a single line ─────────────────────────────────────────

func TestLog_OneLinePerDecision(t *testing.T) {
	var buf bytes.Buffer
	l := audit.New(&buf)
	l.Log(makeDecision(events.FileOpen, detector.Block))
	l.Log(makeDecision(events.NetConnect, detector.Block))

	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	assert.Len(t, lines, 2)
	for _, line := range lines {
		var record map[string]any
		assert.NoError(t, json.Unmarshal(line, &record))
	}
}
