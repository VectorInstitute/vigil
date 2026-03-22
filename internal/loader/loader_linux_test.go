//go:build linux

package loader

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBootWallTime verifies that bootWallTime() returns a time in the past
// (the system booted before now) and is within a reasonable range.
func TestBootWallTime(t *testing.T) {
	before := time.Now()
	bt := bootWallTime()
	after := time.Now()

	assert.True(t, bt.Before(before), "boot time must be before the call")
	assert.True(t, bt.After(after.Add(-30*24*time.Hour)), "boot time must be within the last 30 days")
}

// TestDecodeEvent_timestampUsesWallClock verifies that a BPF monotonic
// timestamp is correctly converted to a wall-clock time.
func TestDecodeEvent_timestampUsesWallClock(t *testing.T) {
	// Build a minimal raw event (320 bytes, all zero except timestamp).
	raw := make([]byte, 320)

	// Simulate a BPF event that fired 5 seconds after boot.
	const fiveSecondsNs = uint64(5 * time.Second)
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
