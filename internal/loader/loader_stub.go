//go:build !linux

// Package loader provides the eBPF program loader.
// On non-Linux platforms the loader is a compile-time stub; eBPF requires Linux.
package loader

import (
	"errors"
	"net"

	"github.com/VectorInstitute/vigil/internal/events"
	"github.com/VectorInstitute/vigil/internal/profiles"
)

var ErrNotLinux = errors.New("eBPF loader requires Linux")

// Loader is a no-op stub on non-Linux platforms.
type Loader struct{}

func Load(_ *profiles.Profile, _ string) (*Loader, error) { return nil, ErrNotLinux }
func (l *Loader) ReadEvent() (events.Event, error)        { return events.Event{}, ErrNotLinux }
func (l *Loader) BlockIP(_ net.IP) error                   { return ErrNotLinux }
func (l *Loader) Close() error                             { return nil }
