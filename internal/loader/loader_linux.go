//go:build linux

package loader

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/VectorInstitute/vigil/internal/events"
	"github.com/VectorInstitute/vigil/internal/profiles"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)


// Objects holds the loaded eBPF maps and programs.
// ebpf struct tags must match the exact names used in the BPF C source.
// Without tags, cilium/ebpf uses the field name as-is (not snake_case),
// so "LsmFileOpen" would look for "LsmFileOpen" not "vigil_file_open".
type objects struct {
	Events           *ebpf.Map     `ebpf:"events"`
	BlockedPaths     *ebpf.Map     `ebpf:"blocked_paths"`
	BlockedIPv4      *ebpf.Map     `ebpf:"blocked_ipv4"`
	TraceOpenat      *ebpf.Program `ebpf:"trace_openat"`
	TraceExecve      *ebpf.Program `ebpf:"trace_execve"`
	TraceConnect     *ebpf.Program `ebpf:"trace_connect"`
	LsmFileOpen      *ebpf.Program `ebpf:"vigil_file_open"`
	LsmSocketConnect *ebpf.Program `ebpf:"vigil_socket_connect"`
	LsmBprmCheck     *ebpf.Program `ebpf:"vigil_bprm_check"`
}

// Loader attaches eBPF programs to the kernel and streams events.
type Loader struct {
	objs   objects
	links  []link.Link
	reader *ringbuf.Reader
}

// Load removes the memlock limit, loads eBPF objects from the embedded .o file,
// populates block-list maps from the profile, and attaches all hooks.
func Load(p *profiles.Profile, objPath string) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("loading BPF collection from %q: %w", objPath, err)
	}

	var objs objects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	l := &Loader{objs: objs}
	if err := l.populateMaps(p); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("populating BPF maps: %w", err)
	}
	if err := l.attach(); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("attaching BPF programs: %w", err)
	}

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}
	l.reader = reader

	return l, nil
}

// populateMaps converts profile rules into BPF map entries.
func (l *Loader) populateMaps(p *profiles.Profile) error {
	one := uint8(1)

	// Denied file paths → blocked_paths map
	for _, path := range p.DeniedPaths {
		key := pathKey(path)
		if err := l.objs.BlockedPaths.Put(key, one); err != nil {
			return fmt.Errorf("blocked_paths.Put(%q): %w", path, err)
		}
	}

	// Networks NOT in allowed_networks → blocked_ipv4.
	// For the MVP we invert: any IP not in allowed list is blocked by the
	// userspace detector. The BPF map holds explicit block entries for known
	// bad IPs gathered from prior detections (updated at runtime).
	// Initial population: nothing — detector handles default-deny via Go.
	_ = one

	return nil
}

// attach wires tracepoints and LSM hooks.
func (l *Loader) attach() error {
	hooks := []struct {
		prog    *ebpf.Program
		linker  func(*ebpf.Program) (link.Link, error)
	}{
		{l.objs.TraceOpenat, func(p *ebpf.Program) (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_openat", p, nil)
		}},
		{l.objs.TraceExecve, func(p *ebpf.Program) (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_execve", p, nil)
		}},
		{l.objs.TraceConnect, func(p *ebpf.Program) (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_connect", p, nil)
		}},
		{l.objs.LsmFileOpen, func(p *ebpf.Program) (link.Link, error) {
			return link.AttachLSM(link.LSMOptions{Program: p})
		}},
		{l.objs.LsmSocketConnect, func(p *ebpf.Program) (link.Link, error) {
			return link.AttachLSM(link.LSMOptions{Program: p})
		}},
		{l.objs.LsmBprmCheck, func(p *ebpf.Program) (link.Link, error) {
			return link.AttachLSM(link.LSMOptions{Program: p})
		}},
	}

	for _, h := range hooks {
		if h.prog == nil {
			continue
		}
		lnk, err := h.linker(h.prog)
		if err != nil {
			return err
		}
		l.links = append(l.links, lnk)
	}
	return nil
}

// ReadEvent blocks until the next kernel event arrives and decodes it.
func (l *Loader) ReadEvent() (events.Event, error) {
	rec, err := l.reader.Read()
	if err != nil {
		return events.Event{}, err
	}
	return decodeEvent(rec.RawSample)
}

// Close detaches all hooks, closes maps, and frees resources.
func (l *Loader) Close() error {
	if l.reader != nil {
		_ = l.reader.Close()
	}
	for _, lnk := range l.links {
		_ = lnk.Close()
	}
	closeObj := func(c io.Closer) {
		if c != nil {
			_ = c.Close()
		}
	}
	closeObj(l.objs.Events)
	closeObj(l.objs.BlockedPaths)
	closeObj(l.objs.BlockedIPv4)
	closeObj(l.objs.TraceOpenat)
	closeObj(l.objs.TraceExecve)
	closeObj(l.objs.TraceConnect)
	closeObj(l.objs.LsmFileOpen)
	closeObj(l.objs.LsmSocketConnect)
	closeObj(l.objs.LsmBprmCheck)
	return nil
}

// BlockIP adds an IPv4 address to the runtime block map.
// Called by the daemon when the detector flags a new connection.
func (l *Loader) BlockIP(ip net.IP) error {
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("BlockIP: only IPv4 supported in MVP")
	}
	key := binary.BigEndian.Uint32(ip4)
	val := uint8(1)
	return l.objs.BlockedIPv4.Put(key, val)
}

// ── Wire format helpers ───────────────────────────────────────────────────────

// pathKey returns a fixed-size [256]byte array for use as a BPF map key.
func pathKey(path string) [256]byte {
	var k [256]byte
	copy(k[:], path)
	return k
}

// decodeEvent parses the raw bytes from the ring buffer into an events.Event.
// Layout must match struct event in bpf/headers/common.h.
func decodeEvent(raw []byte) (events.Event, error) {
	if len(raw) < 32 {
		return events.Event{}, fmt.Errorf("raw event too short: %d bytes", len(raw))
	}

	var e events.Event
	tsNs := binary.LittleEndian.Uint64(raw[0:8])
	e.Timestamp = timeFromNs(tsNs)
	e.PID = binary.LittleEndian.Uint32(raw[8:12])
	// tgid at [12:16] — unused by caller
	e.Type = events.Type(raw[16])
	// action at [17], pad [18:20]
	e.Comm = nullStr(raw[20:36])
	e.Path = nullStr(raw[36:292])

	destIP4 := binary.LittleEndian.Uint32(raw[292:296])
	e.DestPort = binary.LittleEndian.Uint16(raw[312:314])

	if destIP4 != 0 {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, destIP4)
		e.DestIP = net.IP(b)
	}

	return e, nil
}

func nullStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func timeFromNs(ns uint64) time.Time {
	return time.Unix(0, int64(ns))
}
