//go:build linux

package loader

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/VectorInstitute/vigil/internal/events"
	"github.com/VectorInstitute/vigil/internal/profiles"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Objects holds the loaded eBPF maps and programs.
// ebpf struct tags must match the exact names used in the BPF C source.
// Without tags, cilium/ebpf uses the field name as-is (not snake_case),
// so "LsmFileOpen" would look for "LsmFileOpen" not "vigil_file_open".
type objects struct {
	// Maps
	Events      *ebpf.Map `ebpf:"events"`
	SSLEvents   *ebpf.Map `ebpf:"ssl_events"`
	SSLReadArgs *ebpf.Map `ebpf:"ssl_read_args"`
	BlockedPaths *ebpf.Map `ebpf:"blocked_paths"`
	BlockedIPv4 *ebpf.Map `ebpf:"blocked_ipv4"`
	EntryComm   *ebpf.Map `ebpf:"entry_comm"`   // agent root process comm
	WatchedPids *ebpf.Map `ebpf:"watched_pids"` // agent process tree PIDs

	// Observation tracepoints
	TraceOpenat  *ebpf.Program `ebpf:"trace_openat"`
	TraceExecve  *ebpf.Program `ebpf:"trace_execve"`
	TraceConnect *ebpf.Program `ebpf:"trace_connect"`

	// Lineage tracepoints
	TraceExecLineage *ebpf.Program `ebpf:"trace_exec_lineage"`
	TraceForkLineage *ebpf.Program `ebpf:"trace_fork_lineage"`
	TraceExitLineage *ebpf.Program `ebpf:"trace_exit_lineage"`

	// LSM enforcement hooks
	LsmFileOpen      *ebpf.Program `ebpf:"vigil_file_open"`
	LsmSocketConnect *ebpf.Program `ebpf:"vigil_socket_connect"`
	LsmBprmCheck     *ebpf.Program `ebpf:"vigil_bprm_check"`

	// SSL uprobes
	UprobeSSLWrite      *ebpf.Program `ebpf:"uprobe_ssl_write"`
	UprobeSSLReadEntry  *ebpf.Program `ebpf:"uprobe_ssl_read_entry"`
	UretprobeSSLRead    *ebpf.Program `ebpf:"uretprobe_ssl_read"`
}

// Loader attaches eBPF programs to the kernel and streams events.
type Loader struct {
	objs         objects
	links        []link.Link
	reader       *ringbuf.Reader
	sslReader    *ringbuf.Reader // nil if SSL not requested
	eventCh      chan events.Event
	errCh        chan error
	doneCh       chan struct{}
	wg           sync.WaitGroup
	closeOnce    sync.Once
	bootWallTime time.Time // wall-clock time at system boot, for timestamp conversion
	entryComm    string    // agent root process comm, empty if lineage tracking disabled
}

// Load removes the memlock limit, loads eBPF objects from the embedded .o file,
// populates block-list maps from the profile, and attaches all hooks.
func Load(p *profiles.Profile, objPath, sslBinaryPath string) (*Loader, error) {
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

	l := &Loader{
		objs:         objs,
		bootWallTime: bootWallTime(),
		entryComm:    p.EntryComm,
		eventCh:      make(chan events.Event, 256),
		errCh:        make(chan error, 2),
		doneCh:       make(chan struct{}),
	}

	if err := l.populateMaps(p); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("populating BPF maps: %w", err)
	}
	// Seed watched_pids BEFORE attaching BPF programs so that when the LSM hooks
	// go live they already have all pre-existing agent processes in the map.
	if err := l.seedWatchedPids(); err != nil {
		// Non-fatal: BPF hooks will catch new sessions; log and continue.
		fmt.Fprintf(os.Stderr, "vigil: warning: seeding watched_pids: %v\n", err)
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
	l.wg.Add(1)
	go l.drainRingbuf(l.reader, false)

	if sslBinaryPath != "" {
		if err := l.attachSSLUprobes(sslBinaryPath); err != nil {
			fmt.Fprintf(os.Stderr, "vigil: warning: attaching SSL uprobes: %v\n", err)
		} else if objs.SSLEvents != nil {
			sslReader, err := ringbuf.NewReader(objs.SSLEvents)
			if err != nil {
				fmt.Fprintf(os.Stderr, "vigil: warning: creating SSL ring buffer reader: %v\n", err)
			} else {
				l.sslReader = sslReader
				l.wg.Add(1)
				go l.drainRingbuf(l.sslReader, true)
			}
		}
	}

	return l, nil
}

// attachSSLUprobes attaches uprobe/uretprobe programs to SSL_write and SSL_read
// in the given binary (typically a libssl.so path).
func (l *Loader) attachSSLUprobes(sslBinaryPath string) error {
	ex, err := link.OpenExecutable(sslBinaryPath)
	if err != nil {
		return fmt.Errorf("opening executable %q: %w", sslBinaryPath, err)
	}

	if l.objs.UprobeSSLWrite != nil {
		lnk, err := ex.Uprobe("SSL_write", l.objs.UprobeSSLWrite, nil)
		if err != nil {
			return fmt.Errorf("attaching uprobe SSL_write: %w", err)
		}
		l.links = append(l.links, lnk)
	}

	if l.objs.UprobeSSLReadEntry != nil {
		lnk, err := ex.Uprobe("SSL_read", l.objs.UprobeSSLReadEntry, nil)
		if err != nil {
			return fmt.Errorf("attaching uprobe SSL_read entry: %w", err)
		}
		l.links = append(l.links, lnk)
	}

	if l.objs.UretprobeSSLRead != nil {
		lnk, err := ex.Uretprobe("SSL_read", l.objs.UretprobeSSLRead, nil)
		if err != nil {
			return fmt.Errorf("attaching uretprobe SSL_read: %w", err)
		}
		l.links = append(l.links, lnk)
	}

	return nil
}

// drainRingbuf reads from reader and forwards decoded events to eventCh.
// isSSL determines which decoder is used.
func (l *Loader) drainRingbuf(reader *ringbuf.Reader, isSSL bool) {
	defer l.wg.Done()
	for {
		rec, err := reader.Read()
		if err != nil {
			if err != ringbuf.ErrClosed {
				select {
				case l.errCh <- err:
				default:
				}
			}
			return
		}
		var e events.Event
		var decErr error
		if isSSL {
			e, decErr = decodeSSLEvent(rec.RawSample, l.bootWallTime)
		} else {
			e, decErr = decodeEvent(rec.RawSample, l.bootWallTime)
		}
		if decErr != nil {
			continue
		}
		select {
		case l.eventCh <- e:
		case <-l.doneCh:
			return
		}
	}
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

	// entry_comm: write the agent's root process comm into the BPF array map
	// so that trace_exec_lineage can identify when the agent starts.
	// The kernel comm is at most 15 printable chars + null terminator.
	if p.EntryComm != "" {
		var val [16]byte
		copy(val[:], p.EntryComm)
		idx := uint32(0)
		if err := l.objs.EntryComm.Put(&idx, &val); err != nil {
			return fmt.Errorf("entry_comm.Put(%q): %w", p.EntryComm, err)
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
		prog   *ebpf.Program
		linker func(*ebpf.Program) (link.Link, error)
	}{
		// Observation tracepoints
		{l.objs.TraceOpenat, func(p *ebpf.Program) (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_openat", p, nil)
		}},
		{l.objs.TraceExecve, func(p *ebpf.Program) (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_execve", p, nil)
		}},
		{l.objs.TraceConnect, func(p *ebpf.Program) (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_connect", p, nil)
		}},
		// Process lineage tracepoints (always attached; entry_comm controls activity)
		// TraceExecLineage hooks sys_enter_execve (not sched_process_exec) so it
		// fires with the original filename BEFORE shebang processing. This allows
		// matching execve("/usr/bin/gemini") even though the process ultimately
		// runs as node after shebang interpretation.
		{l.objs.TraceExecLineage, func(p *ebpf.Program) (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_execve", p, nil)
		}},
		{l.objs.TraceForkLineage, func(p *ebpf.Program) (link.Link, error) {
			return link.Tracepoint("sched", "sched_process_fork", p, nil)
		}},
		{l.objs.TraceExitLineage, func(p *ebpf.Program) (link.Link, error) {
			return link.Tracepoint("sched", "sched_process_exit", p, nil)
		}},
		// LSM enforcement hooks (synchronous, system-wide)
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
	select {
	case e, ok := <-l.eventCh:
		if !ok {
			return events.Event{}, fmt.Errorf("loader closed")
		}
		return e, nil
	case err := <-l.errCh:
		return events.Event{}, err
	}
}

// seedWatchedPids scans /proc for existing processes that belong to the agent's
// process tree and adds them to watched_pids. This handles the case where the
// agent was already running when vigil started, or where the agent's entry
// binary is a shebang script whose final exec has a different comm name
// (e.g. gemini invokes node, so sched_process_exec fires with comm="node",
// not "gemini"). We match by checking if any argument in the process cmdline
// has a basename matching entry_comm.
func (l *Loader) seedWatchedPids() error {
	if l.entryComm == "" || l.objs.WatchedPids == nil {
		return nil
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("reading /proc: %w", err)
	}

	// Collect PIDs whose cmdline contains entry_comm as a basename arg.
	var roots []uint32
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if l.cmdlineMatchesEntry(uint32(pid)) {
			roots = append(roots, uint32(pid))
		}
	}

	// Expand to the full descendant tree so fork children are also seeded.
	all := l.expandProcTree(roots)
	one := uint8(1)
	for _, pid := range all {
		_ = l.objs.WatchedPids.Put(pid, one)
	}
	return nil
}

// cmdlineMatchesEntry returns true if any argument in /proc/pid/cmdline has a
// basename equal to entry_comm.
func (l *Loader) cmdlineMatchesEntry(pid uint32) bool {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	return cmdlineMatchesEntryStr(l.entryComm, string(raw))
}

// cmdlineMatchesEntryStr is the testable core: returns true if any NUL-separated
// arg in rawCmdline has a basename equal to entryComm.
func cmdlineMatchesEntryStr(entryComm, rawCmdline string) bool {
	if entryComm == "" {
		return false
	}
	for _, arg := range strings.Split(rawCmdline, "\x00") {
		if filepath.Base(arg) == entryComm {
			return true
		}
	}
	return false
}

// expandProcTree takes a set of root PIDs and returns them plus all
// their transitive children found in /proc.
func (l *Loader) expandProcTree(roots []uint32) []uint32 {
	// Build a parent→[]child map from /proc.
	children := map[uint32][]uint32{}
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		statusBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(statusBytes), "\n") {
			if !strings.HasPrefix(line, "PPid:") {
				continue
			}
			ppid, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
			if err == nil && ppid > 0 {
				children[uint32(ppid)] = append(children[uint32(ppid)], uint32(pid))
			}
			break
		}
	}

	// BFS from roots.
	seen := map[uint32]bool{}
	queue := append([]uint32(nil), roots...)
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		if seen[pid] {
			continue
		}
		seen[pid] = true
		queue = append(queue, children[pid]...)
	}

	result := make([]uint32, 0, len(seen))
	for pid := range seen {
		result = append(result, pid)
	}
	return result
}

// Close detaches all hooks, closes maps, and frees resources.
func (l *Loader) Close() error {
	l.closeOnce.Do(func() {
		close(l.doneCh)
		if l.reader != nil {
			_ = l.reader.Close()
		}
		if l.sslReader != nil {
			_ = l.sslReader.Close()
		}
		l.wg.Wait()
		close(l.eventCh)
		for _, lnk := range l.links {
			_ = lnk.Close()
		}
		closeObj := func(c io.Closer) {
			if c != nil {
				_ = c.Close()
			}
		}
		closeObj(l.objs.Events)
		closeObj(l.objs.SSLEvents)
		closeObj(l.objs.SSLReadArgs)
		closeObj(l.objs.BlockedPaths)
		closeObj(l.objs.BlockedIPv4)
		closeObj(l.objs.EntryComm)
		closeObj(l.objs.WatchedPids)
		closeObj(l.objs.TraceOpenat)
		closeObj(l.objs.TraceExecve)
		closeObj(l.objs.TraceConnect)
		closeObj(l.objs.TraceExecLineage)
		closeObj(l.objs.TraceForkLineage)
		closeObj(l.objs.TraceExitLineage)
		closeObj(l.objs.LsmFileOpen)
		closeObj(l.objs.LsmSocketConnect)
		closeObj(l.objs.LsmBprmCheck)
		closeObj(l.objs.UprobeSSLWrite)
		closeObj(l.objs.UprobeSSLReadEntry)
		closeObj(l.objs.UretprobeSSLRead)
	})
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
// New layout (320 bytes):
//
//	[0:8]    timestamp_ns
//	[8:12]   pid
//	[12:16]  tgid
//	[16:20]  ppid  (NEW)
//	[20]     event_type
//	[21]     action
//	[22:24]  _pad
//	[24:40]  comm
//	[40:296] path
//	[296:300] dest_ip4
//	[300:316] dest_ip6
//	[316:318] dest_port
//	[318]    is_ipv6
//	[319]    _pad2
func decodeEvent(raw []byte, bootWall time.Time) (events.Event, error) {
	if len(raw) < 320 {
		return events.Event{}, fmt.Errorf("raw event too short: %d bytes", len(raw))
	}

	var e events.Event
	tsNs := binary.LittleEndian.Uint64(raw[0:8])
	e.Timestamp = bootWall.Add(time.Duration(tsNs))
	e.PID  = binary.LittleEndian.Uint32(raw[8:12])
	// tgid at [12:16] — unused by caller
	e.PPID = binary.LittleEndian.Uint32(raw[16:20])
	e.Type = events.Type(raw[20])
	// action at [21], pad [22:24]
	e.Comm = nullStr(raw[24:40])
	e.Path = nullStr(raw[40:296])

	destIP4 := binary.LittleEndian.Uint32(raw[296:300])
	e.DestPort = binary.LittleEndian.Uint16(raw[316:318])

	if destIP4 != 0 {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, destIP4)
		e.DestIP = net.IP(b)
	}

	return e, nil
}

// decodeSSLEvent parses the raw bytes from the ssl_events ring buffer.
// Layout must match struct ssl_event in bpf/headers/common.h.
// Layout (4140 bytes):
//
//	[0:8]    timestamp_ns
//	[8:12]   pid
//	[12:16]  tgid
//	[16:20]  ppid
//	[20]     direction
//	[21:24]  _pad
//	[24:40]  comm
//	[40:44]  data_len
//	[44:4140] data
func decodeSSLEvent(raw []byte, bootWall time.Time) (events.Event, error) {
	if len(raw) < 44 {
		return events.Event{}, fmt.Errorf("raw ssl event too short: %d bytes", len(raw))
	}

	var e events.Event
	e.Type = events.SSLData
	tsNs := binary.LittleEndian.Uint64(raw[0:8])
	e.Timestamp = bootWall.Add(time.Duration(tsNs))
	e.PID  = binary.LittleEndian.Uint32(raw[8:12])
	// tgid at [12:16]
	e.PPID      = binary.LittleEndian.Uint32(raw[16:20])
	e.Direction = events.SSLDirection(raw[20])
	e.Comm      = nullStr(raw[24:40])
	dataLen    := binary.LittleEndian.Uint32(raw[40:44])
	if dataLen > 4096 {
		dataLen = 4096
	}
	if dataLen > 0 && len(raw) >= 44+int(dataLen) {
		e.Data = string(raw[44 : 44+dataLen])
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

// bootWallTime returns the wall-clock time at which the system booted by
// subtracting the current CLOCK_MONOTONIC reading from the current wall time.
// bpf_ktime_get_ns() returns nanoseconds since boot on the same monotonic
// clock, so: eventWallTime = bootWallTime + eventMonotonicNs.
func bootWallTime() time.Time {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		// Fallback: assume boot was now (timestamps will be relative to start).
		return time.Now()
	}
	return time.Now().Add(-time.Duration(ts.Nano()))
}
