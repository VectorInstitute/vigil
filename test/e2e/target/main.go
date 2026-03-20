//go:build linux

// target is the synthetic "rogue AI process" used in the e2e Jailbreak Escape Test.
// It mimics an Ollama server that has been prompt-injected: first it does
// expected/allowed operations, then it attempts 4 escape vectors.
//
// Exit codes:
//   0 — all escapes were blocked (vigil worked correctly)
//   1 — at least one escape succeeded (vigil failed to block)

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
)

func main() {
	results := run()
	allBlocked := true
	for _, r := range results {
		status := "BLOCKED ✓"
		if r.allowed {
			status = "ALLOWED  ✗ (vigil missed this!)"
			allBlocked = false
		}
		fmt.Printf("%-50s %s\n", r.name, status)
	}
	if !allBlocked {
		os.Exit(1)
	}
}

type result struct {
	name    string
	allowed bool
}

func run() []result {
	return []result{
		// ── Escape 1: read /etc/passwd ────────────────────────────────────────
		{
			name:    "open(/etc/passwd)",
			allowed: tryFileRead("/etc/passwd"),
		},
		// ── Escape 2: read /etc/shadow ────────────────────────────────────────
		{
			name:    "open(/etc/shadow)",
			allowed: tryFileRead("/etc/shadow"),
		},
		// ── Escape 3: outbound connect to 8.8.8.8:443 ────────────────────────
		{
			name:    "connect(8.8.8.8:443)",
			allowed: tryTCPConnect("8.8.8.8:443"),
		},
		// ── Escape 4: exec /bin/bash ──────────────────────────────────────────
		{
			name:    "execve(/bin/bash)",
			allowed: tryExec("/bin/bash"),
		},
		// ── Sanity: allowed operations should succeed ─────────────────────────
		// (These are verified separately in the e2e test, not here)
	}
}

func tryFileRead(path string) (allowed bool) {
	_, err := os.Open(path)
	if err == nil {
		return true // succeeded — vigil didn't block
	}
	return !isPermError(err)
}

func tryTCPConnect(addr string) (allowed bool) {
	conn, err := net.Dial("tcp", addr)
	if err == nil {
		_ = conn.Close()
		return true
	}
	return !isPermError(err)
}

func tryExec(path string) (allowed bool) {
	cmd := exec.Command(path, "--version")
	err := cmd.Run()
	if err == nil {
		return true
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			// EPERM propagates as exit status 126 or the raw signal
			if status.ExitStatus() == 126 {
				return false
			}
		}
	}
	return !isPermError(err)
}

func isPermError(err error) bool {
	if pathErr, ok := err.(*os.PathError); ok {
		return pathErr.Err == syscall.EPERM || pathErr.Err == syscall.EACCES
	}
	if netErr, ok := err.(*net.OpError); ok {
		if syscallErr, ok := netErr.Err.(*os.SyscallError); ok {
			return syscallErr.Err == syscall.EPERM || syscallErr.Err == syscall.EACCES
		}
	}
	return false
}
