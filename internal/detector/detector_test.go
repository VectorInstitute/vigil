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
