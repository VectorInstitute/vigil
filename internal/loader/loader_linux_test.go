//go:build linux

package loader

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── cmdlineMatchesEntry ───────────────────────────────────────────────────────

func TestCmdlineMatchesEntry_basenameMatch(t *testing.T) {
	l := &Loader{entryComm: "gemini"}
	cases := []struct {
		raw  string
		want bool
	}{
		// Shebang script invoked via node: argv contains /usr/bin/gemini.
		{"node\x00--no-warnings=DEP0040\x00/usr/bin/gemini\x00", true},
		// Direct binary execution.
		{"gemini\x00", true},
		// Full path with no other args.
		{"/usr/bin/gemini\x00", true},
		// Unrelated process.
		{"python3\x00script.py\x00", false},
		// Prefix match must not trigger (gemini-cli ≠ gemini).
		{"node\x00/usr/bin/gemini-cli\x00", false},
		// Node without gemini.
		{"node\x00/usr/bin/ollama\x00", false},
	}
	for _, tc := range cases {
		got := cmdlineMatchesEntryStr(l.entryComm, tc.raw)
		assert.Equal(t, tc.want, got, "cmdline=%q", tc.raw)
	}
}

func TestCmdlineMatchesEntry_emptyEntryComm(t *testing.T) {
	l := &Loader{entryComm: ""}
	// Empty entry_comm → never matches (lineage tracking disabled).
	assert.False(t, cmdlineMatchesEntryStr(l.entryComm, "gemini\x00"))
}

// TestBootWallTime verifies that bootWallTime() returns a time in the past
// (the system booted before now) and is within a reasonable range.
func TestBootWallTime(t *testing.T) {
	before := time.Now()
	bt := bootWallTime()
	after := time.Now()

	assert.True(t, bt.Before(before), "boot time must be before the call")
	assert.True(t, bt.After(after.Add(-30*24*time.Hour)), "boot time must be within the last 30 days")
}

// TestDecodeEvent_fields verifies that every field is read from the correct
// byte offset in the 320-byte struct event layout.
func TestDecodeEvent_fields(t *testing.T) {
	raw := make([]byte, 320)

	// [0:8]    timestamp_ns = 1_000_000_000 (1 second)
	const oneSecNs = uint64(1e9)
	for i := range 8 {
		raw[i] = byte(oneSecNs >> (8 * i))
	}

	// [8:12]   pid = 1234
	binary.LittleEndian.PutUint32(raw[8:12], 1234)
	// [12:16]  tgid = 5678 (unused)
	binary.LittleEndian.PutUint32(raw[12:16], 5678)
	// [16:20]  ppid = 999
	binary.LittleEndian.PutUint32(raw[16:20], 999)
	// [20]     event_type = 0 (FileOpen)
	raw[20] = 0
	// [24:40]  comm = "ollama"
	copy(raw[24:40], "ollama\x00")
	// [40:296] path = "/etc/passwd"
	copy(raw[40:296], "/etc/passwd\x00")
	// [296:300] dest_ip4 = 8.8.8.8 in network byte order
	raw[296], raw[297], raw[298], raw[299] = 8, 8, 8, 8
	// [316:318] dest_port = 443
	binary.LittleEndian.PutUint16(raw[316:318], 443)

	knownBoot := time.Unix(0, 0) // epoch as boot time for easy arithmetic
	e, err := decodeEvent(raw, knownBoot)
	require.NoError(t, err)

	assert.Equal(t, uint32(1234), e.PID, "pid")
	assert.Equal(t, uint32(999), e.PPID, "ppid")
	assert.Equal(t, uint8(0), uint8(e.Type), "event_type")
	assert.Equal(t, "ollama", e.Comm, "comm")
	assert.Equal(t, "/etc/passwd", e.Path, "path")
	assert.Equal(t, uint16(443), e.DestPort, "dest_port")
	assert.NotNil(t, e.DestIP, "dest_ip should be set")
	assert.Equal(t, "8.8.8.8", e.DestIP.String(), "dest_ip value")
	// timestamp = boot(epoch) + 1s = Unix second 1
	assert.Equal(t, int64(1), e.Timestamp.Unix(), "timestamp")
}

// TestDecodeEvent_tooShort verifies an error is returned for truncated input.
func TestDecodeEvent_tooShort(t *testing.T) {
	_, err := decodeEvent(make([]byte, 100), time.Now())
	assert.Error(t, err)
}

// TestDecodeSSLEvent_fields verifies the ssl_event field layout.
func TestDecodeSSLEvent_fields(t *testing.T) {
	raw := make([]byte, 4140)

	// [0:8]    timestamp_ns = 2_000_000_000 (2 seconds)
	const twoSecNs = uint64(2e9)
	for i := range 8 {
		raw[i] = byte(twoSecNs >> (8 * i))
	}
	// [8:12]   pid = 7777
	binary.LittleEndian.PutUint32(raw[8:12], 7777)
	// [16:20]  ppid = 3333
	binary.LittleEndian.PutUint32(raw[16:20], 3333)
	// [20]     direction = 1 (SSLRecv)
	raw[20] = 1
	// [24:40]  comm = "claude"
	copy(raw[24:40], "claude\x00")
	// [40:44]  data_len = 12
	binary.LittleEndian.PutUint32(raw[40:44], 12)
	// [44:56]  data = "hello world!"
	copy(raw[44:], "hello world!")

	knownBoot := time.Unix(0, 0)
	e, err := decodeSSLEvent(raw, knownBoot)
	require.NoError(t, err)

	assert.Equal(t, uint32(7777), e.PID, "pid")
	assert.Equal(t, uint32(3333), e.PPID, "ppid")
	assert.Equal(t, uint8(1), uint8(e.Direction), "direction SSLRecv")
	assert.Equal(t, "claude", e.Comm, "comm")
	assert.Equal(t, "hello world!", e.Data, "data")
	assert.Equal(t, int64(2), e.Timestamp.Unix(), "timestamp")
}

// TestDecodeSSLEvent_dataLenCap verifies data_len > MAX_SSL_BUF is clamped.
func TestDecodeSSLEvent_dataLenCap(t *testing.T) {
	raw := make([]byte, 4140)
	// data_len = 99999 (exceeds MAX_SSL_BUF=4096)
	binary.LittleEndian.PutUint32(raw[40:44], 99999)
	copy(raw[44:], make([]byte, 4096)) // zeros

	e, err := decodeSSLEvent(raw, time.Now())
	require.NoError(t, err)
	// Should clamp to available buf, not crash
	assert.LessOrEqual(t, len(e.Data), 4096)
}

// TestDecodeSSLEvent_tooShort verifies an error is returned for truncated input.
func TestDecodeSSLEvent_tooShort(t *testing.T) {
	_, err := decodeSSLEvent(make([]byte, 10), time.Now())
	assert.Error(t, err)
}

// TestDecodeEvent_timestampUsesWallClock verifies that a BPF monotonic
// timestamp is correctly converted to a wall-clock time.
func TestDecodeEvent_timestampUsesWallClock(t *testing.T) {
	// Build a minimal raw event (320 bytes, all zero except timestamp).
	raw := make([]byte, 320)

	// Simulate a BPF event that fired 5 seconds after boot.
	fiveSecondsNs := uint64(5 * time.Second)
	raw[0] = byte(fiveSecondsNs)
	raw[1] = byte(fiveSecondsNs >> 8)
	raw[2] = byte(fiveSecondsNs >> 16)
	raw[3] = byte(fiveSecondsNs >> 24)
	raw[4] = byte(fiveSecondsNs >> 32)
	raw[5] = byte(fiveSecondsNs >> 40)
	raw[6] = byte(fiveSecondsNs >> 48)
	raw[7] = byte(fiveSecondsNs >> 56)

	// Use a known boot time 1 hour ago.
	knownBoot := time.Now().Add(-1 * time.Hour)
	e, err := decodeEvent(raw, knownBoot)
	require.NoError(t, err)

	expected := knownBoot.Add(5 * time.Second)
	assert.WithinDuration(t, expected, e.Timestamp, time.Millisecond,
		"event timestamp must be bootWallTime + 5s")
}

// TestDecodeEvent_timestampIsNotEpoch verifies the old bug is gone:
// timestamps must not be near the Unix epoch (Jan 1, 1970).
func TestDecodeEvent_timestampIsNotEpoch(t *testing.T) {
	raw := make([]byte, 320)

	// 2 hours of uptime in nanoseconds — typical value from bpf_ktime_get_ns.
	const twoHoursNs = uint64(2 * time.Hour)
	for i := range 8 {
		raw[i] = byte(twoHoursNs >> (8 * i))
	}

	bt := bootWallTime()
	e, err := decodeEvent(raw, bt)
	require.NoError(t, err)

	epoch := time.Unix(0, 0)
	assert.True(t, e.Timestamp.After(epoch.Add(24*time.Hour*365*10)),
		"timestamp must not be near Unix epoch (got %v)", e.Timestamp)
	assert.WithinDuration(t, time.Now(), e.Timestamp, 24*time.Hour,
		"timestamp must be close to now")
}
