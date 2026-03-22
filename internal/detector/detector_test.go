package detector_test

import (
	"net"
	"testing"
	"time"

	"github.com/VectorInstitute/vigil/internal/detector"
	"github.com/VectorInstitute/vigil/internal/events"
	"github.com/VectorInstitute/vigil/internal/profiles"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newDetector(t *testing.T) *detector.Detector {
	t.Helper()
	p, err := profiles.LoadFile("../../profiles/ollama.yaml")
	require.NoError(t, err)
	return detector.New(p)
}

func evt(typ events.Type) events.Event {
	return events.Event{Timestamp: time.Now(), PID: 1234, Comm: "ollama", Type: typ}
}

// ── File open decisions ──────────────────────────────────────────────────────

func TestEvaluate_BlocksSensitiveFile(t *testing.T) {
	d := newDetector(t)
	cases := []struct {
		path   string
		reason string
	}{
		{"/etc/passwd", "denied path"},
		{"/etc/shadow", "denied path"},
		{"/root/.ssh/id_rsa", "denied path"},
		{"/home/alice/.ssh/authorized_keys", "denied path"},
	}
	for _, tc := range cases {
		e := evt(events.FileOpen)
		e.Path = tc.path
		dec := d.Evaluate(e)
		assert.Equal(t, detector.Block, dec.Action, "want BLOCK for %s", tc.path)
		assert.NotEmpty(t, dec.Reason, "want non-empty reason for %s", tc.path)
	}
}

func TestEvaluate_AllowsOllamaModelFiles(t *testing.T) {
	d := newDetector(t)
	cases := []string{
		"/home/user/.ollama/models/sha256-deadbeef",
		"/root/.ollama/models/llama3/config.json",
		"/tmp/ollama_blob_abc",
	}
	for _, path := range cases {
		e := evt(events.FileOpen)
		e.Path = path
		dec := d.Evaluate(e)
		assert.Equal(t, detector.Allow, dec.Action, "want ALLOW for %s", path)
	}
}

func TestEvaluate_BlocksUnknownPath_DefaultDeny(t *testing.T) {
	d := newDetector(t)
	e := evt(events.FileOpen)
	e.Path = "/opt/someapp/secret.bin"
	dec := d.Evaluate(e)
	assert.Equal(t, detector.Block, dec.Action)
	assert.Contains(t, dec.Reason, "default policy")
}

// ── Network connect decisions ────────────────────────────────────────────────

func TestEvaluate_AllowsLocalhost(t *testing.T) {
	d := newDetector(t)
	for _, ip := range []string{"127.0.0.1", "::1"} {
		e := evt(events.NetConnect)
		e.DestIP = net.ParseIP(ip)
		e.DestPort = 11434
		dec := d.Evaluate(e)
		assert.Equal(t, detector.Allow, dec.Action, "want ALLOW for %s", ip)
	}
}

func TestEvaluate_BlocksExternalNetwork(t *testing.T) {
	d := newDetector(t)
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "192.168.0.1"} {
		e := evt(events.NetConnect)
		e.DestIP = net.ParseIP(ip)
		e.DestPort = 443
		dec := d.Evaluate(e)
		assert.Equal(t, detector.Block, dec.Action, "want BLOCK for %s", ip)
	}
}

// ── Exec decisions ───────────────────────────────────────────────────────────

func TestEvaluate_AllowsOllamaRunner(t *testing.T) {
	d := newDetector(t)
	e := evt(events.Exec)
	e.Path = "/usr/local/bin/ollama"
	dec := d.Evaluate(e)
	assert.Equal(t, detector.Allow, dec.Action)
}

func TestEvaluate_BlocksShellExec(t *testing.T) {
	d := newDetector(t)
	for _, shell := range []string{"/bin/bash", "/bin/sh", "/usr/bin/python3"} {
		e := evt(events.Exec)
		e.Path = shell
		dec := d.Evaluate(e)
		assert.Equal(t, detector.Block, dec.Action, "want BLOCK for %s", shell)
	}
}

// ── Decision fields ──────────────────────────────────────────────────────────

func TestDecision_CarriesOriginalEvent(t *testing.T) {
	d := newDetector(t)
	e := evt(events.FileOpen)
	e.Path = "/etc/passwd"
	dec := d.Evaluate(e)
	assert.Equal(t, e, dec.Event)
}

// ── Unknown event type ───────────────────────────────────────────────────────

func TestEvaluate_UnknownEventType_PassThrough(t *testing.T) {
	d := newDetector(t)
	e := evt(events.Type(99))
	dec := d.Evaluate(e)
	assert.Equal(t, detector.Allow, dec.Action)
}

// ── Action.String ────────────────────────────────────────────────────────────

func TestAction_String(t *testing.T) {
	assert.Equal(t, "ALLOW", detector.Allow.String())
	assert.Equal(t, "BLOCK", detector.Block.String())
	assert.Equal(t, "SKIP", detector.Skip.String())
}

// ── watched_comms filtering ───────────────────────────────────────────────────

func TestEvaluate_SkipsUnwatchedProcess(t *testing.T) {
	p, err := profiles.LoadBytes([]byte(`
name: test
default_policy: deny
watched_comms: [node, bun]
`))
	require.NoError(t, err)
	d := detector.New(p)

	e := evt(events.FileOpen)
	e.Comm = "systemd"
	e.Path = "/etc/shadow"
	dec := d.Evaluate(e)
	assert.Equal(t, detector.Skip, dec.Action, "unwatched process must be skipped, not blocked")
}

func TestEvaluate_WatchedProcessEvaluatesNormally(t *testing.T) {
	p, err := profiles.LoadBytes([]byte(`
name: test
default_policy: deny
watched_comms: [node, bun]
denied_paths:
  - /etc/shadow
`))
	require.NoError(t, err)
	d := detector.New(p)

	e := evt(events.FileOpen)
	e.Comm = "node"
	e.Path = "/etc/shadow"
	dec := d.Evaluate(e)
	assert.Equal(t, detector.Block, dec.Action)
}

func TestEvaluate_EntryComm_DoesNotSkipAnyComm(t *testing.T) {
	// When entry_comm is set, BPF has already filtered by PID lineage.
	// The Go detector must not re-filter by comm name — every event from
	// the ring buffer belongs to a watched process tree.
	p, err := profiles.LoadBytes([]byte(`
name: test
entry_comm: gemini
watched_comms: [gemini, node]
default_policy: deny
denied_paths:
  - /etc/shadow
`))
	require.NoError(t, err)
	d := detector.New(p)

	// "sh" is not in watched_comms, but since entry_comm is set, it must NOT be Skipped.
	// (BPF already ensured this event came from the gemini process tree.)
	e := evt(events.FileOpen)
	e.Comm = "sh"
	e.Path = "/etc/shadow"
	dec := d.Evaluate(e)
	assert.Equal(t, detector.Block, dec.Action, "entry_comm active: child process must not be skipped")
}

func TestEvaluate_EmptyWatchedComms_WatchesAll(t *testing.T) {
	p, err := profiles.LoadBytes([]byte(`
name: test
default_policy: deny
denied_paths:
  - /etc/shadow
`))
	require.NoError(t, err)
	d := detector.New(p)

	for _, comm := range []string{"systemd", "node", "sshd", "anything"} {
		e := evt(events.FileOpen)
		e.Comm = comm
		e.Path = "/etc/shadow"
		dec := d.Evaluate(e)
		assert.Equal(t, detector.Block, dec.Action, "empty watched_comms must watch all processes (%s)", comm)
	}
}
