//go:build linux && integration

// Package e2e contains the Jailbreak Escape Test — vigil's MVP correctness test.
//
// Run with:
//
//	sudo go test -tags integration -v ./test/e2e/
//
// Requires:
//   - Linux kernel 5.7+ with CONFIG_BPF_LSM=y and lsm=bpf in boot params
//   - Root privileges (eBPF program loading)
//   - Ollama profile at ../../profiles/ollama.yaml
//   - vigil.bpf.o at ../../bpf/vigil.bpf.o (built by `make bpf`)

package e2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/VectorInstitute/vigil/internal/audit"
	"github.com/VectorInstitute/vigil/internal/detector"
	"github.com/VectorInstitute/vigil/internal/loader"
	"github.com/VectorInstitute/vigil/internal/profiles"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	profilePath = "../../profiles/ollama.yaml"
	bpfObjPath  = "../../bpf/vigil.bpf.o"
	targetBin   = "./target/target"
)

// TestJailbreakEscape is the primary MVP correctness test.
//
// It:
//  1. Builds the synthetic "rogue AI process" binary (test/e2e/target)
//  2. Loads vigil's eBPF programs with the Ollama profile
//  3. Runs the rogue binary under vigil's watch
//  4. Asserts every escape attempt returns EPERM (exit 0 from target)
//  5. Asserts the audit log captured all 4 BLOCK events
func TestJailbreakEscape(t *testing.T) {
	requireRoot(t)

	// ── Step 1: build the target binary ──────────────────────────────────────
	t.Log("building target binary...")
	build := exec.Command("go", "build", "-tags", "linux", "-o", targetBin, "./target")
	build.Dir = "."
	out, err := build.CombinedOutput()
	require.NoError(t, err, "build target: %s", out)
	defer os.Remove(targetBin)

	// ── Step 2: load vigil ───────────────────────────────────────────────────
	t.Log("loading vigil eBPF programs...")
	p, err := profiles.LoadFile(profilePath)
	require.NoError(t, err)

	l, err := loader.Load(p, bpfObjPath)
	require.NoError(t, err, "loader.Load: ensure kernel has CONFIG_BPF_LSM=y and lsm=bpf")
	defer l.Close()

	// Diagnostic: log map contents so we can verify keys match bpf_d_path output.
	t.Log("blocked_paths map keys:")
	for _, k := range l.BlockedPathKeys() {
		t.Logf("  %q", k)
	}

	det := detector.New(p)
	var auditBuf bytes.Buffer
	log := audit.New(&auditBuf)

	// Pre-block the known-bad IP so the BPF LSM hook returns EPERM synchronously.
	// The production daemon does this at runtime via BlockIP after reading ring
	// buffer events; in the e2e test we simulate that the daemon already acted.
	require.NoError(t, l.BlockIP(net.ParseIP("8.8.8.8")))

	// ── Step 3: drain ring buffer in background ───────────────────────────────
	done := make(chan struct{})
	var blockCount int
	go func() {
		defer close(done)
		for {
			e, err := l.ReadEvent()
			if err != nil {
				return
			}
			dec := det.Evaluate(e)
			log.Log(dec)
			if dec.Action == detector.Block {
				blockCount++
			}
		}
	}()

	// ── Step 4: run the rogue binary ─────────────────────────────────────────
	t.Log("running rogue target binary...")
	cmd := exec.Command(targetBin)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	require.NoError(t, err, "target exited non-zero: at least one escape succeeded — vigil missed a block")

	// Give ring buffer a moment to flush
	time.Sleep(200 * time.Millisecond)
	_ = l.Close()
	<-done

	// ── Step 5: assert audit log ──────────────────────────────────────────────
	t.Log("verifying audit log...")
	auditLines := parseAuditLog(t, auditBuf.Bytes())

	blocked := filterByAction(auditLines, "BLOCK")
	assert.GreaterOrEqual(t, len(blocked), 4,
		"expected at least 4 BLOCK events (passwd, shadow, connect, exec), got %d\nfull log:\n%s",
		len(blocked), auditBuf.String())

	assertContainsPath(t, blocked, "/etc/passwd")
	assertContainsPath(t, blocked, "/etc/shadow")
	assertContainsDest(t, blocked, "8.8.8.8")
	assertContainsExec(t, blocked, "/bin/bash")

	t.Logf("audit log:\n%s", auditBuf.String())
}

// TestAllowedOperationsUnblocked verifies that normal Ollama file access
// works correctly alongside vigil (no false positives).
func TestAllowedOperationsUnblocked(t *testing.T) {
	requireRoot(t)

	p, err := profiles.LoadFile(profilePath)
	require.NoError(t, err)

	l, err := loader.Load(p, bpfObjPath)
	require.NoError(t, err)
	defer l.Close()

	// Create a temp file in the Ollama blob path
	blobDir := fmt.Sprintf("/tmp/ollama_test_%d", os.Getpid())
	require.NoError(t, os.MkdirAll(blobDir, 0755))
	defer os.RemoveAll(blobDir)

	blobFile := blobDir + "/sha256-testblob"
	require.NoError(t, os.WriteFile(blobFile, []byte("fake model blob"), 0644))

	// Open it — should succeed (allowed by profile)
	f, err := os.Open(blobFile)
	assert.NoError(t, err, "expected allowed path to be readable under vigil")
	if f != nil {
		f.Close()
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("e2e tests require root (eBPF LSM loading)")
	}
}

type auditEntry map[string]any

func parseAuditLog(t *testing.T, data []byte) []auditEntry {
	t.Helper()
	var entries []auditEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e auditEntry
		require.NoError(t, json.Unmarshal(line, &e))
		entries = append(entries, e)
	}
	return entries
}

func filterByAction(entries []auditEntry, action string) []auditEntry {
	var out []auditEntry
	for _, e := range entries {
		if e["action"] == action {
			out = append(out, e)
		}
	}
	return out
}

func assertContainsPath(t *testing.T, entries []auditEntry, path string) {
	t.Helper()
	for _, e := range entries {
		if e["path"] == path {
			return
		}
	}
	t.Errorf("audit log has no BLOCK entry for path %q", path)
}

func assertContainsDest(t *testing.T, entries []auditEntry, ip string) {
	t.Helper()
	for _, e := range entries {
		if e["dest_ip"] == ip {
			return
		}
	}
	t.Errorf("audit log has no BLOCK entry for dest_ip %q", ip)
}

func assertContainsExec(t *testing.T, entries []auditEntry, path string) {
	t.Helper()
	for _, e := range entries {
		if e["event"] == "exec" && e["path"] == path {
			return
		}
	}
	t.Errorf("audit log has no BLOCK exec entry for path %q", path)
}
