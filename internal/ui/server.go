// Package ui provides an HTTP server that streams vigil audit decisions to a
// browser in real time using Server-Sent Events (SSE).
package ui

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"sync"
	"time"

	"github.com/VectorInstitute/vigil/internal/detector"
	"github.com/VectorInstitute/vigil/internal/events"
)

//go:embed static
var staticFiles embed.FS

// Server streams vigil decisions to connected browsers via SSE and serves the
// embedded single-page UI.
type Server struct {
	profileName string
	version     string
	mu          sync.Mutex
	clients     map[chan []byte]struct{}
}

// New returns a Server configured for the given profile name and build version.
func New(profileName, version string) *Server {
	return &Server{
		profileName: profileName,
		version:     version,
		clients:     make(map[chan []byte]struct{}),
	}
}

// Handler returns the HTTP handler for the UI server.
// Routes:
//
//	GET /           → embedded index.html
//	GET /events     → SSE stream of audit decisions
//	GET /api/status → JSON status / profile info
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic("ui: failed to create sub-FS: " + err.Error())
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/events", s.eventsHandler)
	mux.HandleFunc("/api/status", s.statusHandler)
	return mux
}

// Broadcast sends dec to all connected SSE clients. Slow clients that have
// not consumed their channel buffer have the event dropped rather than
// blocking the caller.
func (s *Server) Broadcast(dec detector.Decision) {
	data, err := json.Marshal(toRecord(dec))
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.clients {
		select {
		case ch <- data:
		default: // client too slow — drop rather than block
		}
	}
}

// subscribe registers a new SSE client and returns its event channel along
// with an unsubscribe function that must be called when the client disconnects.
func (s *Server) subscribe() (chan []byte, func()) {
	ch := make(chan []byte, 64)
	s.mu.Lock()
	s.clients[ch] = struct{}{}
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		delete(s.clients, ch)
		s.mu.Unlock()
	}
}

func (s *Server) eventsHandler(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx/Coder proxy buffering

	ch, unsubscribe := s.subscribe()
	defer unsubscribe()

	// Send an initial ping so the browser knows the connection is live.
	fmt.Fprintf(w, "event: connected\ndata: {}\n\n")
	flusher.Flush()

	for {
		select {
		case data := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"profile": s.profileName,
		"version": s.version,
		"status":  "running",
	})
}

// ── Wire format ───────────────────────────────────────────────────────────────

type eventRecord struct {
	TS       string   `json:"ts"`
	PID      uint32   `json:"pid"`
	Comm     string   `json:"comm"`
	Event    string   `json:"event"`
	Action   string   `json:"action"`
	Reason   string   `json:"reason"`
	Path     string   `json:"path,omitempty"`
	Argv     []string `json:"argv,omitempty"`
	DestIP   string   `json:"dest_ip,omitempty"`
	DestPort uint16   `json:"dest_port,omitempty"`
}

func toRecord(dec detector.Decision) eventRecord {
	e := dec.Event
	r := eventRecord{
		TS:     e.Timestamp.UTC().Format(time.RFC3339),
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
	return r
}
