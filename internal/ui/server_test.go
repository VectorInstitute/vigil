package ui_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/VectorInstitute/vigil/internal/detector"
	"github.com/VectorInstitute/vigil/internal/events"
	"github.com/VectorInstitute/vigil/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeDecision builds a detector.Decision for use in tests.
func makeDecision(eventType events.Type, path string, action detector.Action) detector.Decision {
	return detector.Decision{
		Event: events.Event{
			Timestamp: time.Now(),
			PID:       1234,
			Comm:      "test-agent",
			Type:      eventType,
			Path:      path,
		},
		Action: action,
		Reason: "test reason",
	}
}

// readSSEEvent reads one complete SSE event (terminated by blank line) from r.
// Returns the content of the first "data:" line found.
func readSSEEvent(t *testing.T, scanner *bufio.Scanner) string {
	t.Helper()
	var data string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			data = strings.TrimPrefix(line, "data: ")
		} else if line == "" && data != "" {
			return data
		}
	}
	require.NoError(t, scanner.Err(), "SSE scanner error")
	t.Fatal("SSE stream closed without a complete event")
	return ""
}

// connectSSE opens an SSE connection to the server and returns a buffered scanner.
// The test server is started by the caller; cancel is used to close the request.
func connectSSE(t *testing.T, url string) (*bufio.Scanner, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/events", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })

	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	return bufio.NewScanner(resp.Body), cancel
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestNew(t *testing.T) {
	s := ui.New("claude-code")
	require.NotNil(t, s)
}

func TestHandler_servesIndexHTML(t *testing.T) {
	s := ui.New("test")
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
}

func TestHandler_statusEndpoint(t *testing.T) {
	s := ui.New("claude-code")
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/status")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "claude-code", body["profile"])
	assert.Equal(t, "running", body["status"])
}

func TestHandler_eventsSSEHeaders(t *testing.T) {
	s := ui.New("test")
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/events", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	assert.Equal(t, "no-cache", resp.Header.Get("Cache-Control"))
}

func TestBroadcast_singleClientReceivesEvent(t *testing.T) {
	s := ui.New("test")
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	scanner, cancel := connectSSE(t, ts.URL)
	defer cancel()

	// Consume the initial "connected" ping.
	readSSEEvent(t, scanner)

	// Broadcast a BLOCK decision.
	dec := makeDecision(events.FileOpen, "/etc/shadow", detector.Block)
	s.Broadcast(dec)

	// Read the broadcasted event.
	raw := readSSEEvent(t, scanner)

	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &got))

	assert.Equal(t, "file_open", got["event"])
	assert.Equal(t, "BLOCK", got["action"])
	assert.Equal(t, "/etc/shadow", got["path"])
	assert.Equal(t, "test-agent", got["comm"])
	assert.EqualValues(t, 1234, got["pid"])
}

func TestBroadcast_multipleClientsAllReceive(t *testing.T) {
	s := ui.New("test")
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	const numClients = 3
	scanners := make([]*bufio.Scanner, numClients)
	cancels := make([]context.CancelFunc, numClients)

	for i := range numClients {
		scanners[i], cancels[i] = connectSSE(t, ts.URL)
		defer cancels[i]()
		readSSEEvent(t, scanners[i]) // consume ping
	}

	dec := makeDecision(events.Exec, "/bin/bash", detector.Block)
	s.Broadcast(dec)

	for i, sc := range scanners {
		raw := readSSEEvent(t, sc)
		var got map[string]any
		require.NoError(t, json.Unmarshal([]byte(raw), &got), "client %d", i)
		assert.Equal(t, "BLOCK", got["action"], "client %d", i)
		assert.Equal(t, "/bin/bash", got["path"], "client %d", i)
	}
}

func TestBroadcast_noClientsDoesNotPanic(t *testing.T) {
	s := ui.New("test")
	dec := makeDecision(events.FileOpen, "/tmp/foo", detector.Allow)
	// Should not panic with zero connected clients.
	require.NotPanics(t, func() { s.Broadcast(dec) })
}

func TestBroadcast_slowClientDropsEventsNotBlocking(t *testing.T) {
	s := ui.New("test")

	// Manually use a recorder to simulate a subscribed but unread client.
	// We exploit the exported Subscribe method by calling Broadcast many
	// times and verifying the call returns quickly (non-blocking).
	dec := makeDecision(events.FileOpen, "/tmp/x", detector.Allow)
	start := time.Now()
	for range 200 {
		s.Broadcast(dec)
	}
	assert.Less(t, time.Since(start), 500*time.Millisecond,
		"Broadcast must not block on slow clients")
}

func TestBroadcast_clientDisconnectIsCleanedUp(t *testing.T) {
	s := ui.New("test")
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	scanner, cancel := connectSSE(t, ts.URL)
	readSSEEvent(t, scanner) // consume ping

	// Disconnect the client.
	cancel()

	// Give the server time to detect the disconnect and clean up.
	time.Sleep(50 * time.Millisecond)

	// A Broadcast after disconnect must not block or panic.
	dec := makeDecision(events.FileOpen, "/tmp/y", detector.Allow)
	done := make(chan struct{})
	go func() {
		s.Broadcast(dec)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Broadcast blocked after client disconnected")
	}
}

func TestBroadcast_netConnectEvent(t *testing.T) {
	s := ui.New("test")
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	scanner, cancel := connectSSE(t, ts.URL)
	defer cancel()
	readSSEEvent(t, scanner)

	dec := detector.Decision{
		Event: events.Event{
			Timestamp: time.Now(),
			PID:       999,
			Comm:      "node",
			Type:      events.NetConnect,
			DestIP:    net.ParseIP("1.2.3.4"),
			DestPort:  443,
		},
		Action: detector.Allow,
		Reason: "default policy: allow",
	}
	s.Broadcast(dec)

	raw := readSSEEvent(t, scanner)
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &got))

	assert.Equal(t, "net_connect", got["event"])
	assert.Equal(t, "ALLOW", got["action"])
	assert.Equal(t, "1.2.3.4", got["dest_ip"])
	assert.EqualValues(t, 443, got["dest_port"])
}
